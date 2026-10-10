package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// archiverHarness is an archiver over two temp directories with a fake clock,
// fake statfs and per-file change times.
type archiverHarness struct {
	t        *testing.T
	local    string
	root     string
	now      time.Time
	settings model.SystemSettings
	avail    uint64
	total    uint64
	changed  map[string]time.Time // name -> ctime; default: long ago (settled)
	a        *RawLogArchiver
}

const testInstance = "11111111-2222-3333-4444-555555555555"

func newArchiverHarness(t *testing.T, mounted bool) *archiverHarness {
	t.Helper()
	base := t.TempDir()
	h := &archiverHarness{
		t:     t,
		local: filepath.Join(base, "logs"),
		root:  filepath.Join(base, "archive"),
		now:   time.Date(2026, 10, 10, 12, 0, 0, 0, time.Local),
		settings: model.SystemSettings{
			ID: testInstance, RawLogArchiveEnabled: true, RawLogArchiveRetentionDays: 365, RawLogCompressRotated: true,
		},
		total:   100 << 30,
		avail:   50 << 30,
		changed: map[string]time.Time{},
	}
	if err := os.MkdirAll(h.local, 0755); err != nil {
		t.Fatal(err)
	}
	if mounted {
		if err := os.MkdirAll(h.root, 0755); err != nil {
			t.Fatal(err)
		}
	}
	a := NewRawLogArchiver(h.root, h.local, 10*time.Minute, func(context.Context) (*model.SystemSettings, error) {
		s := h.settings
		return &s, nil
	})
	a.now = func() time.Time { return h.now }
	a.statfs = func(_ context.Context, path string) (rawStatfs, error) {
		if _, err := os.Stat(path); err != nil {
			return rawStatfs{}, err
		}
		return rawStatfs{Type: 0x01021994, Frsize: 1, Blocks: h.total, Bfree: h.avail, Bavail: h.avail}, nil
	}
	a.changedAt = func(f RawLogFile) time.Time {
		if t, ok := h.changed[f.Name]; ok {
			return t
		}
		return h.now.Add(-24 * time.Hour)
	}
	a.ioTimeout = 2 * time.Second
	h.a = a
	return h
}

func (h *archiverHarness) write(dir, name, body string, mtime time.Time) {
	h.t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		h.t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *archiverHarness) ls(dir string) []string {
	h.t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"ERR " + err.Error()}
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func (h *archiverHarness) initialise() {
	h.t.Helper()
	if _, err := h.a.Initialise(context.Background()); err != nil {
		h.t.Fatalf("initialise: %v", err)
	}
}

// seed lays out the local directory of the design's scenarios.
func (h *archiverHarness) seed() {
	day := 24 * time.Hour
	h.write(h.local, "access_raw.log", "live\n", time.Time{})
	h.write(h.local, "error_raw.log", "", time.Time{})
	h.write(h.local, "access_raw.log-20261009-000003", "pending\n", h.now.Add(-time.Hour)) // delaycompress
	h.write(h.local, "access_raw.log-20261005-000002.gz", "gz-1005", h.now.Add(-5*day))
	h.write(h.local, "access_raw.log-20261006-000001.gz", "gz-1006", h.now.Add(-4*day))
	h.write(h.local, "error_raw.log-20261007-000004.gz", "gz-err-1007", h.now.Add(-3*day))
	h.write(h.local, "access_raw.log-20261010-115500.gz", "just compressed", h.now.Add(-2*day))
	h.changed["access_raw.log-20261010-115500.gz"] = h.now.Add(-2 * time.Minute)
	h.write(h.local, "notes.txt", "operator notes", time.Time{})
}

func eq(a, b []string) bool { return strings.Join(a, "|") == strings.Join(b, "|") }

// S1: no archive directory: not mounted, nothing moves, nothing is created.
func TestArchiverMissingRootIsNotMounted(t *testing.T) {
	h := newArchiverHarness(t, false)
	h.seed()
	before := h.ls(h.local)

	if st := h.a.Check(context.Background()); st.Status != ArchiveStatusNotMounted {
		t.Fatalf("check: %s (%s), want not_mounted", st.Status, st.Detail)
	}
	if _, err := h.a.Initialise(context.Background()); !errors.Is(err, ErrArchiveNotReady) {
		t.Fatalf("initialise on a missing root: %v", err)
	}
	h.a.runPass(context.Background())
	if _, err := os.Stat(h.root); !os.IsNotExist(err) {
		t.Fatal("the archiver created the archive root")
	}
	if !eq(h.ls(h.local), before) {
		t.Fatalf("local files changed: %v", h.ls(h.local))
	}
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusNotMounted {
		t.Fatalf("status: %s", st.Status)
	}
}

// S2 and S9: a directory without the marker — never initialised, or an
// unmounted share's empty mount point — gets nothing written.
func TestArchiverWithoutMarkerWritesNothing(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.a.runPass(context.Background())
	if got := h.ls(h.root); len(got) != 0 {
		t.Fatalf("archive written without a marker: %v", got)
	}
	st := h.a.Status(context.Background())
	if st.Status != ArchiveStatusNotInitialized || st.Marker != archiveMarkerMissing || st.PendingFiles != 3 {
		t.Fatalf("status %s marker %s pending %d, want not_initialized/missing/3", st.Status, st.Marker, st.PendingFiles)
	}
	// Check writes a probe file and removes it; still no marker.
	if st := h.a.Check(context.Background()); st.Status != ArchiveStatusNotInitialized || st.Writable == nil || !*st.Writable {
		t.Fatalf("check: %+v", st)
	}
	if got := h.ls(h.root); len(got) != 0 {
		t.Fatalf("check left files behind: %v", got)
	}
}

// S3 + S4: initialise writes the marker; a pass moves only settled .gz
// files, keeps their mtime and leaves everything else alone.
func TestArchiverInitialiseAndMoveSettledFiles(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.initialise()

	body, err := os.ReadFile(filepath.Join(h.root, rawLogArchiveMarker))
	if err != nil {
		t.Fatal(err)
	}
	var marker map[string]string
	if json.Unmarshal(body, &marker) != nil || marker["instance"] != testInstance {
		t.Fatalf("marker = %s", body)
	}
	if st := h.a.Check(context.Background()); st.Status != ArchiveStatusReady || st.FSType != "tmpfs" && st.FSType != "" {
		t.Fatalf("after init: %s %q", st.Status, st.FSType)
	}

	h.a.runPass(context.Background())
	wantArchive := []string{rawLogArchiveMarker, "access_raw.log-20261005-000002.gz", "access_raw.log-20261006-000001.gz", "error_raw.log-20261007-000004.gz"}
	sort.Strings(wantArchive)
	if got := h.ls(h.root); !eq(got, wantArchive) {
		t.Fatalf("archive:\n got %v\nwant %v", got, wantArchive)
	}
	wantLocal := []string{"access_raw.log", "access_raw.log-20261009-000003", "access_raw.log-20261010-115500.gz", "error_raw.log", "notes.txt"}
	if got := h.ls(h.local); !eq(got, wantLocal) {
		t.Fatalf("local:\n got %v\nwant %v", got, wantLocal)
	}
	fi, err := os.Stat(filepath.Join(h.root, "access_raw.log-20261005-000002.gz"))
	if err != nil || !fi.ModTime().Equal(h.now.Add(-5*24*time.Hour)) {
		t.Fatalf("mtime not preserved: %v %v", fi.ModTime(), err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "error_raw.log-20261007-000004.gz")); string(b) != "gz-err-1007" {
		t.Fatalf("content changed: %q", b)
	}
	st := h.a.Status(context.Background())
	if st.Status != ArchiveStatusReady || st.LastMoved != 3 || st.LastMoveAt == nil || st.PendingFiles != 0 {
		t.Fatalf("status after the pass: %+v", st)
	}
	// A re-probe keeps what the last pass reported.
	h.now = h.now.Add(time.Minute)
	if st := h.a.Status(context.Background()); st.LastMoved != 3 || st.LastMoveAt == nil {
		t.Fatalf("a refreshed status lost the last move: %+v", st)
	}
	h.now = h.now.Add(-time.Minute)

	// The listing serves the archive with its rotation times.
	files, err := h.a.ListArchive(context.Background())
	if err != nil || len(files) != 3 || files[0].Location != RawLogLocationArchive || files[0].RotatedAt == nil {
		t.Fatalf("list: %+v %v", files, err)
	}

	// With compression off, settled uncompressed rotated files move too.
	h.settings.RawLogCompressRotated = false
	h.a.runPass(context.Background())
	if _, err := os.Stat(filepath.Join(h.root, "access_raw.log-20261009-000003")); err != nil {
		t.Fatalf("uncompressed rotated file did not move with compression off: %v", err)
	}
}

// S5: a directory the API cannot write to is refused, and never claimed.
func TestArchiverUnwritableDirectory(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.a.writeProbe = func(string) error { return os.ErrPermission }
	st := h.a.Check(context.Background())
	if st.Status != ArchiveStatusUnwritable || st.Writable == nil || *st.Writable {
		t.Fatalf("check: %+v", st)
	}
	if _, err := h.a.Initialise(context.Background()); !errors.Is(err, ErrArchiveNotReady) {
		t.Fatalf("initialise must refuse an unwritable directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, rawLogArchiveMarker)); !os.IsNotExist(err) {
		t.Fatal("a marker was written into an unwritable directory")
	}
}

// S6: not enough room: the pass stops and keeps the sources.
func TestArchiverLowSpaceKeepsTheSource(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.initialise()
	h.total, h.avail = 1<<30, 50<<20 // 50 MiB free on 1 GiB: under the reserve
	h.a.runPass(context.Background())
	if got := h.ls(h.root); !eq(got, []string{rawLogArchiveMarker}) {
		t.Fatalf("moved despite low space: %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.local, "access_raw.log-20261005-000002.gz")); err != nil {
		t.Fatal("the source was not kept")
	}
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusInsufficientSpace {
		t.Fatalf("status %s, want insufficient_space", st.Status)
	}
}

func TestArchiveReserveScales(t *testing.T) {
	for total, want := range map[uint64]uint64{
		64 << 20:  64 << 20 / 10, // e2e tmpfs: a tenth
		10 << 30:  1 << 30,       // 1 GiB floor
		100 << 30: 2 << 30,       // 2%
		4 << 40:   (4 << 40) / 50,
	} {
		if got := archiveReserve(total); got != want {
			t.Errorf("archiveReserve(%d MiB) = %d MiB, want %d MiB", total>>20, got>>20, want>>20)
		}
	}
}

// S7: retention goes by the name; foreign names stay, and a pass clears the
// .part files a crashed pass left.
func TestArchiverPrunesByNameTimestamp(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	recent := h.now.Add(-time.Hour)
	h.write(h.root, "access_raw.log-"+h.now.AddDate(0, 0, -400).Format("20060102")+"-000000.gz", "old", recent)
	h.write(h.root, "access_raw.log-"+h.now.AddDate(0, 0, -100).Format("20060102")+"-000000.gz", "kept", h.now.AddDate(-3, 0, 0))
	h.write(h.root, "photo.jpg", "not ours", h.now.AddDate(-3, 0, 0))
	h.write(h.root, "access_raw.log-garbage", "not ours", h.now.AddDate(-3, 0, 0))
	h.write(h.root, "error_raw.log-20250101-000000.gz.part", "stale", h.now.Add(-48*time.Hour))
	h.write(h.root, "notes.part", "not ours", h.now.Add(-48*time.Hour))

	h.a.runPass(context.Background())
	if st := h.a.Status(context.Background()); st.LastPruned != 1 {
		t.Fatalf("last_pruned = %d, want 1", st.LastPruned)
	}
	want := []string{
		rawLogArchiveMarker,
		"access_raw.log-" + h.now.AddDate(0, 0, -100).Format("20060102") + "-000000.gz",
		"access_raw.log-garbage",
		"notes.part",
		"photo.jpg",
	}
	sort.Strings(want)
	if got := h.ls(h.root); !eq(got, want) {
		t.Fatalf("after prune:\n got %v\nwant %v", got, want)
	}
}

// S8: a pass that died mid-way resumes: a stale .part is replaced, a final
// copy with the same content just releases the source, and a different file
// of the same name is kept beside the local one.
func TestArchiverResumesAndKeepsConflicts(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.write(h.local, "access_raw.log-20261005-000002.gz", "gz-1005", time.Time{})
	h.write(h.root, "access_raw.log-20261005-000002.gz.part", "half", time.Time{})
	h.write(h.local, "access_raw.log-20261006-000001.gz", "gz-1006", time.Time{})
	h.write(h.root, "access_raw.log-20261006-000001.gz", "gz-1006", time.Time{}) // crash after rename
	h.write(h.local, "access_raw.log-20261007-000004.gz", "local version", time.Time{})
	h.write(h.root, "access_raw.log-20261007-000004.gz", "other version!", time.Time{})

	h.a.runPass(context.Background())

	if got := h.ls(h.local); !eq(got, []string{"access_raw.log-20261007-000004.gz"}) {
		t.Fatalf("local after resume: %v", got)
	}
	want := []string{rawLogArchiveMarker, "access_raw.log-20261005-000002.gz", "access_raw.log-20261006-000001.gz", "access_raw.log-20261007-000004.gz"}
	sort.Strings(want)
	if got := h.ls(h.root); !eq(got, want) {
		t.Fatalf("archive after resume: %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "access_raw.log-20261005-000002.gz")); string(b) != "gz-1005" {
		t.Fatalf("resumed copy content %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "access_raw.log-20261007-000004.gz")); string(b) != "other version!" {
		t.Fatal("a conflicting archive file was overwritten")
	}
	if st := h.a.Status(context.Background()); !strings.Contains(st.LastError, "different content") {
		t.Fatalf("the conflict was not reported: %q", st.LastError)
	}
}

// Another install's marker (or one from before a restore onto another
// machine): nothing moves, nothing is deleted, until initialised again.
func TestArchiverForeignMarker(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.write(h.root, rawLogArchiveMarker, `{"instance":"someone-else"}`, time.Time{})
	h.write(h.root, "access_raw.log-20200101-000000.gz", "theirs", time.Time{})

	h.a.runPass(context.Background())
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusForeign || st.Marker != archiveMarkerForeign {
		t.Fatalf("status %s marker %s", st.Status, st.Marker)
	}
	if got := h.ls(h.root); len(got) != 2 {
		t.Fatalf("a foreign archive was written to or pruned: %v", got)
	}
	if err := h.a.DeleteArchiveFile(context.Background(), "access_raw.log-20200101-000000.gz"); !errors.Is(err, ErrArchiveNotReady) {
		t.Fatalf("delete in a foreign archive: %v", err)
	}
	// Reading it is fine.
	if f, _, err := h.a.OpenArchiveFile(context.Background(), "access_raw.log-20200101-000000.gz"); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		f.Close()
	}
	// The operator claims it.
	h.initialise()
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusReady {
		t.Fatalf("after claiming: %s", st.Status)
	}
}

// Archiving off: no move, no prune, but the archive can still be read.
func TestArchiverDisabledMovesAndPrunesNothing(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.initialise()
	h.write(h.root, "access_raw.log-20200101-000000.gz", "very old", time.Time{})
	h.settings.RawLogArchiveEnabled = false

	h.a.runPass(context.Background())
	if _, err := os.Stat(filepath.Join(h.root, "access_raw.log-20200101-000000.gz")); err != nil {
		t.Fatal("pruned while archiving is off")
	}
	if _, err := os.Stat(filepath.Join(h.local, "access_raw.log-20261005-000002.gz")); err != nil {
		t.Fatal("moved while archiving is off")
	}
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusDisabled || st.Marker != archiveMarkerOurs {
		t.Fatalf("status %s marker %s", st.Status, st.Marker)
	}
	if files, err := h.a.ListArchive(context.Background()); err != nil || len(files) != 1 {
		t.Fatalf("listing while off: %v %v", files, err)
	}
	if _, _, _, _, _, ok := h.a.CachedDiskUsage(); ok {
		t.Fatal("CachedDiskUsage must report nothing while archiving is off")
	}
}

func TestArchiverFileAccessGuards(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.write(h.root, "access_raw.log-20261005-000002.gz", "x", time.Time{})
	if err := os.Symlink("/etc/passwd", filepath.Join(h.root, "access_raw.log-20261006-000000.gz")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../../etc/passwd", "access_raw.log", "photo.jpg", rawLogArchiveMarker, "access_raw.log-20261005-000002.gz.part"} {
		if _, _, err := h.a.OpenArchiveFile(context.Background(), name); !errors.Is(err, ErrArchiveFileName) {
			t.Errorf("open %q: %v, want ErrArchiveFileName", name, err)
		}
		if err := h.a.DeleteArchiveFile(context.Background(), name); !errors.Is(err, ErrArchiveFileName) {
			t.Errorf("delete %q: %v, want ErrArchiveFileName", name, err)
		}
	}
	if _, _, err := h.a.OpenArchiveFile(context.Background(), "access_raw.log-20261006-000000.gz"); !errors.Is(err, ErrArchiveFileName) {
		t.Errorf("a symlink was opened: %v", err)
	}
	if err := h.a.DeleteArchiveFile(context.Background(), "access_raw.log-20261005-000002.gz"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "access_raw.log-20261005-000002.gz")); !os.IsNotExist(err) {
		t.Fatal("not deleted")
	}
}

// A hung share: the first call gives up after the timeout and marks the
// archive stalled; later calls fail at once; it recovers when the call returns.
func TestArchiverStallsInsteadOfHanging(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.ioTimeout = 50 * time.Millisecond

	release := make(chan struct{})
	start := time.Now()
	err := h.a.fsCall(context.Background(), func() error { <-release; return nil })
	var stalled *ArchiveStalledError
	if !errors.As(err, &stalled) || time.Since(start) > time.Second {
		t.Fatalf("hung call: %v after %v", err, time.Since(start))
	}
	start = time.Now()
	if _, err := h.a.ListArchive(context.Background()); !errors.As(err, &stalled) || time.Since(start) > 20*time.Millisecond {
		t.Fatalf("a call while stalled must fail at once: %v after %v", err, time.Since(start))
	}
	h.a.mu.Lock()
	h.a.statusAt = time.Time{}
	h.a.mu.Unlock()
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusStalled || st.StalledSince == nil {
		t.Fatalf("status while stalled: %+v", st)
	}
	if _, _, _, _, since, _ := h.a.CachedDiskUsage(); since == nil {
		t.Fatal("CachedDiskUsage must report the stall")
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := h.a.ListArchive(context.Background()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never recovered after the share answered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// DiskGuard's hook: the archiver's own last measurement, no filesystem call.
func TestArchiverCachedDiskUsage(t *testing.T) {
	h := newArchiverHarness(t, true)
	if _, _, _, _, _, ok := h.a.CachedDiskUsage(); ok {
		t.Fatal("nothing measured yet, but ok")
	}
	h.initialise()
	h.a.runPass(context.Background())
	path, total, avail, at, stalled, ok := h.a.CachedDiskUsage()
	if !ok || path != h.root || total != h.total || avail != h.avail || !at.Equal(h.now) || stalled != nil {
		t.Fatalf("CachedDiskUsage = %q %d %d %v %v %v", path, total, avail, at, stalled, ok)
	}
	var nilArchiver *RawLogArchiver
	if _, _, _, _, _, ok := nilArchiver.CachedDiskUsage(); ok {
		t.Fatal("a nil archiver reports usage")
	}
	nilArchiver.Wake() // must not panic
}

// Start runs a pass when woken; Wake never blocks.
func TestArchiverRunsOnWake(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.seed()
	h.initialise()
	h.a.bootDelay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.a.Start(ctx); close(done) }()
	for i := 0; i < 5; i++ {
		h.a.Wake()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(h.root, "access_raw.log-20261005-000002.gz")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a wake did not run a pass")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.a.Stop()
	h.a.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// Most installs never mount an archive: with archiving off and no directory
// the status is simply "disabled" (and says nothing in the log), while Check
// still tells the operator what is there.
func TestArchiverOffAndUnmountedIsQuiet(t *testing.T) {
	h := newArchiverHarness(t, false)
	h.settings.RawLogArchiveEnabled = false
	h.a.runPass(context.Background())
	st := h.a.Status(context.Background())
	if st.Status != ArchiveStatusDisabled || st.Mounted || st.Enabled {
		t.Fatalf("off and unmounted: %+v", st)
	}
	if h.a.logged != ArchiveStatusDisabled {
		t.Fatalf("remembered status %q, want disabled", h.a.logged)
	}
	if chk := h.a.Check(context.Background()); chk.Status != ArchiveStatusNotMounted {
		t.Fatalf("check while off: %s, want not_mounted", chk.Status)
	}
}

// A rotated-looking name whose time does not parse (month 13) is not a rotated
// log: it is neither moved nor allowed to stop the pass, which used to crash
// the API on every start.
func TestArchiverIgnoresAStrayRotatedName(t *testing.T) {
	const stray = "access_raw.log-20261301-000000.gz"
	if IsArchivedRawLogName(stray) {
		t.Fatalf("%s is not a rotation time, but counts as an archived name", stray)
	}
	h := newArchiverHarness(t, true)
	h.initialise()
	h.write(h.local, stray, "stray", h.now.Add(-48*time.Hour))
	h.write(h.local, "access_raw.log-20261001-000000.gz", "settled", h.now.Add(-48*time.Hour))
	h.write(h.local, "error_raw.log-20261002-000000.gz", "settled too", h.now.Add(-48*time.Hour))

	h.a.runPass(context.Background())

	if got := h.ls(h.local); !eq(got, []string{stray}) {
		t.Fatalf("local after the pass: %v; want only the stray file", got)
	}
	if st := h.a.Status(context.Background()); st.LastMoved != 2 || st.PendingFiles != 0 {
		t.Fatalf("status %+v; want both settled files moved", st)
	}
	// The archive does not list or serve such a name either.
	h.write(h.root, stray, "stray", time.Time{})
	if files, err := h.a.ListArchive(context.Background()); err != nil || len(files) != 2 {
		t.Fatalf("archive listing %+v, %v; want the two moved files", files, err)
	}
}
