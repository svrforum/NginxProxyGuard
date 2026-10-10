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
	if err := h.a.DeleteArchiveFile(context.Background(), settledName); !errors.Is(err, ErrArchiveNotReady) {
		h.t.Fatalf("deleting from the log directory as the archive: %v", err)
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

// anotherMount makes the harness's archiver see device and inode numbers that
// never match between the root and the log directory, as through an overlay,
// an SMB or NFS share or a FUSE view of the same folder: a symlink then stands
// for such a mount.
func (h *archiverHarness) anotherMount() {
	h.a.sameFile = func(os.FileInfo, os.FileInfo) bool { return false }
}

// /archive showing the log directory through another mount (an overlay with
// the log directory as its lower layer, a share of the same folder): no
// device or inode in common, so only the probe file tells.
func TestArchiverRefusesTheLogDirectorySeenThroughAnotherMount(t *testing.T) {
	h := newArchiverHarness(t, false)
	if err := os.Symlink(h.local, h.root); err != nil {
		t.Fatal(err)
	}
	h.anotherMount()
	h.refusesRoot()
	if st := h.a.Check(context.Background()); !strings.Contains(st.Detail, "through another mount") {
		t.Fatalf("detail %q; want it to say the log directory shows through another mount", st.Detail)
	}
}

// The same for a folder that holds the log directory, seen through another
// mount: root/<log directory name> is the log directory.
func TestArchiverRefusesAParentOfTheLogDirectorySeenThroughAnotherMount(t *testing.T) {
	h := newArchiverHarness(t, false)
	if err := os.Symlink(filepath.Dir(h.local), h.root); err != nil {
		t.Fatal(err)
	}
	h.anotherMount()
	h.refusesRoot()
}

// The last guard on its own: a move whose archive "copy" is the local file
// seen through another mount — after the probe file check said otherwise
// (or could not run) — keeps the local file under its name, stops the pass
// and reports the archive as the log directory.
func TestArchiverMoveKeepsAFileTheArchiveOnlyShowsThroughAnotherMount(t *testing.T) {
	h := newArchiverHarness(t, false)
	if err := os.Symlink(h.local, h.root); err != nil {
		t.Fatal(err)
	}
	h.anotherMount()
	h.write(h.local, settledName, "precious", h.now.Add(-30*time.Hour))
	before := h.ls(h.local)
	files := h.a.settledLocal(true)
	if len(files) != 1 {
		t.Fatalf("settled files %+v", files)
	}

	err := h.a.moveOne(files[0])
	if !errors.Is(err, errArchiveShowsLogDir) {
		t.Fatalf("moving onto the log directory itself: %v; want errArchiveShowsLogDir", err)
	}
	h.keepsSettledFile()
	if got := h.ls(h.local); !eq(got, before) {
		t.Fatalf("the log directory changed:\n got %v\nwant %v", got, before)
	}
	if moved, _, stop, err := h.a.moveSettled(context.Background(), true); moved != 0 || stop != ArchiveStatusLogDir || !errors.Is(err, errArchiveShowsLogDir) {
		t.Fatalf("pass: moved %d, stop %q, %v; want nothing moved and stopped as log_dir", moved, stop, err)
	}
	h.keepsSettledFile()
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusLogDir {
		t.Fatalf("status %s (%s); want log_dir", st.Status, st.Detail)
	}
}

// An archive set up before these checks existed, through another mount of the
// log directory — its marker sits in the log directory itself — lets neither
// a delete request nor the pruning remove the local files it shows.
func TestArchiverDeletesNothingThroughAnOlderSetupOfTheLogDirectory(t *testing.T) {
	h := newArchiverHarness(t, false)
	if err := os.Symlink(h.local, h.root); err != nil {
		t.Fatal(err)
	}
	h.anotherMount()
	old := "access_raw.log-" + h.now.AddDate(-2, 0, 0).Format("20060102") + "-000000.gz"
	h.write(h.local, old, "precious", h.now.AddDate(-2, 0, 0))
	h.write(h.local, rawLogArchiveMarker, `{"instance":"`+testInstance+`"}`, time.Time{})
	before := h.ls(h.local)

	if err := h.a.DeleteArchiveFile(context.Background(), old); !errors.Is(err, ErrArchiveNotReady) {
		t.Fatalf("delete request: %v; want it refused", err)
	}
	if n, err := h.a.prune(365); n != 0 || err != nil {
		t.Fatalf("prune removed %d, %v; want nothing", n, err)
	}
	if got := h.ls(h.local); !eq(got, before) {
		t.Fatalf("the log directory changed:\n got %v\nwant %v", got, before)
	}
}

// A file a pass set aside and never got to delete or put back (the process
// stopped in between) goes back under its own name and moves like any other.
func TestArchiverPutsBackAFileLeftSetAside(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	aside := setAsidePrefix + "0123456789abcdef-" + settledName
	h.write(h.local, aside, "precious", h.now.Add(-30*time.Hour))

	h.a.runPass(context.Background())

	if got := h.ls(h.local); len(got) != 0 {
		t.Fatalf("local after the pass: %v; want the file moved", got)
	}
	if b, err := os.ReadFile(filepath.Join(h.root, settledName)); err != nil || string(b) != "precious" {
		t.Fatalf("archived copy %q, %v", b, err)
	}
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
