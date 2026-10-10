package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The archive is a second home for the rotated raw logs, never a second name
// for the first one: a root that leads back to the log directory, or a name
// in it that leads back to a local file, must never cost the only copy.

const settledName = "access_raw.log-20261009-000000.gz"

// keepsSettledFile fails the test unless the local settled file is still
// there with its content.
func (h *archiverHarness) keepsSettledFile() {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.local, settledName))
	if err != nil || string(b) != "precious" {
		h.t.Fatalf("the only copy of %s is gone or changed: %q, %v (local %v)", settledName, b, err, h.ls(h.local))
	}
}

// refusesRoot checks that a root leading to the log directory is refused by
// Check, Initialise and a pass, and that nothing in the log directory is
// written, moved or deleted.
func (h *archiverHarness) refusesRoot() {
	h.t.Helper()
	h.write(h.local, settledName, "precious", h.now.Add(-30*time.Hour))
	before := h.ls(h.local)

	if st := h.a.Check(context.Background()); st.Status != ArchiveStatusLogDir || st.Mounted {
		h.t.Fatalf("check: %s mounted=%v (%s), want log_dir", st.Status, st.Mounted, st.Detail)
	}
	st, err := h.a.Initialise(context.Background())
	if !errors.Is(err, ErrArchiveNotReady) || st.Status != ArchiveStatusLogDir {
		h.t.Fatalf("initialise: %s, %v; want it refused as log_dir", st.Status, err)
	}
	h.a.runPass(context.Background())
	if got := h.a.Status(context.Background()); got.Status != ArchiveStatusLogDir || got.LastMoved != 0 {
		h.t.Fatalf("status after a pass: %+v", got)
	}
	if _, err := h.a.ListArchive(context.Background()); !errors.Is(err, ErrArchiveNotReady) {
		h.t.Fatalf("listing the log directory as the archive: %v", err)
	}
	h.keepsSettledFile()
	if got := h.ls(h.local); !eq(got, before) {
		h.t.Fatalf("the log directory changed:\n got %v\nwant %v", got, before)
	}
}

// NPG_RAW_LOG_ARCHIVE_DIR set to the log directory itself.
func TestArchiverRefusesTheLogDirectoryAsRoot(t *testing.T) {
	h := newArchiverHarness(t, false)
	h.a = rebuildArchiver(h, h.local)
	h.refusesRoot()
}

// /archive bound to the log directory: a second path to the same directory,
// which a symlink stands in for here (a bind mount is the same inode too).
func TestArchiverRefusesASecondPathToTheLogDirectory(t *testing.T) {
	h := newArchiverHarness(t, false)
	if err := os.Symlink(h.local, h.root); err != nil {
		t.Fatal(err)
	}
	h.refusesRoot()
}

// A root that holds the log directory (the volume's top bound as /archive)
// keeps the files on the log disk, so it is no archive either.
func TestArchiverRefusesAParentOfTheLogDirectory(t *testing.T) {
	h := newArchiverHarness(t, false)
	h.a = rebuildArchiver(h, filepath.Dir(h.local))
	h.refusesRoot()
}

// rebuildArchiver is the harness's archiver with another root.
func rebuildArchiver(h *archiverHarness, root string) *RawLogArchiver {
	a := NewRawLogArchiver(root, h.local, h.a.settle, h.a.settings)
	a.now, a.statfs, a.changedAt, a.ioTimeout = h.a.now, h.a.statfs, h.a.changedAt, h.a.ioTimeout
	h.root = root
	return a
}

// A name in the archive that leads back to the local file — a symlink, or a
// hard link — is not a copy of it: the local file stays, and the pass says so.
func TestArchiverKeepsTheLocalFileWhenTheArchiveNameLeadsBackToIt(t *testing.T) {
	for _, kind := range []string{"symlink", "hard link"} {
		t.Run(kind, func(t *testing.T) {
			h := newArchiverHarness(t, true)
			h.initialise()
			h.write(h.local, settledName, "precious", h.now.Add(-30*time.Hour))
			h.write(h.local, "access_raw.log-20261008-000000.gz", "other day", h.now.Add(-54*time.Hour))
			src, final := filepath.Join(h.local, settledName), filepath.Join(h.root, settledName)
			link := os.Symlink
			if kind == "hard link" {
				link = os.Link
			}
			if err := link(src, final); err != nil {
				t.Fatal(err)
			}

			h.a.runPass(context.Background())

			h.keepsSettledFile()
			if _, err := os.Lstat(final); err != nil {
				t.Fatalf("the %s in the archive was removed: %v", kind, err)
			}
			// The other day still moves.
			if _, err := os.Stat(filepath.Join(h.root, "access_raw.log-20261008-000000.gz")); err != nil {
				t.Fatalf("the other file did not move: %v", err)
			}
			if st := h.a.Status(context.Background()); !strings.Contains(st.LastError, settledName) || st.LastMoved != 1 {
				t.Fatalf("status %+v; want one move and the kept file reported", st)
			}
		})
	}
}
