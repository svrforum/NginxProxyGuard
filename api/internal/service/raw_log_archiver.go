package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
)

// RawLogArchiver moves settled rotated raw logs from the nginx log directory
// to an archive directory — typically a NAS share the host mounts and binds
// into the API container — and deletes archived files past the archive
// retention.
//
// Safety rules, because the archive is usually a network share:
//   - NPG never creates the archive root. A missing directory is "not
//     mounted"; Docker happily binds an unmounted share's empty mount point,
//     which the marker check catches.
//   - Nothing is written until an explicit Initialise has written the marker
//     file, and only by the install whose id the marker names.
//   - Only finished files move: a rotated name, compressed when compression
//     is on (delaycompress keeps the newest one plain), and untouched (ctime)
//     for the settle time. Each is copied to <name>.part, synced, checked,
//     renamed, given its original mtime, and only then deleted locally.
//   - Archive retention goes by the time in the file name, not by mtime,
//     which some network filesystems do not keep.
//   - Every request-side filesystem call goes through one slot with a
//     timeout: a hung NFS mount blocks the kernel, so one stuck call marks
//     the archive stalled and later calls fail at once instead of piling up.
//
// When the archive is missing, unwritable or full, rotated files simply stay
// local, where logrotate's maxage (the local retention) still bounds them.
type RawLogArchiver struct {
	root     string
	localDir string
	settle   time.Duration
	settings func(ctx context.Context) (*model.SystemSettings, error)

	now          func() time.Time
	statfs       func(ctx context.Context, path string) (rawStatfs, error)
	writeProbe   func(dir string) error
	changedAt    func(f RawLogFile) time.Time // ctime; injectable for tests
	ioTimeout    time.Duration
	stallAfter   time.Duration
	bootDelay    time.Duration
	refreshEvery time.Duration

	slot    chan struct{} // request-side filesystem calls, one at a time
	wake    chan struct{}
	stop    chan struct{}
	stopper sync.Once
	running atomic.Bool

	mu           sync.Mutex
	status       RawLogArchiveStatus
	statusAt     time.Time
	statfsRaw    rawStatfs
	statfsAt     time.Time
	ioStallSince *time.Time
	progressAt   time.Time
	logged       string
	list         []RawLogFile
	listAt       time.Time
}

const rawLogArchiveMarker = ".npg-raw-log-archive"

// Archive status values.
const (
	ArchiveStatusDisabled          = "disabled"
	ArchiveStatusNotMounted        = "not_mounted"
	ArchiveStatusNotInitialized    = "not_initialized"
	ArchiveStatusForeign           = "foreign"
	ArchiveStatusUnwritable        = "unwritable"
	ArchiveStatusInsufficientSpace = "insufficient_space"
	ArchiveStatusStalled           = "stalled"
	ArchiveStatusReady             = "ready"
	// The directory is the nginx log directory, by another path or not, or
	// one of its parents: nothing moved there would leave the log disk, and
	// a file "moved" onto itself would be deleted. Never written to.
	ArchiveStatusLogDir = "log_dir"
)

// Marker states reported beside the status.
const (
	archiveMarkerMissing    = "missing"
	archiveMarkerOurs       = "ours"
	archiveMarkerForeign    = "foreign"
	archiveMarkerUnreadable = "unreadable"
)

// RawLogArchiveStatus is what GET /log-files and the archive endpoints report.
type RawLogArchiveStatus struct {
	Enabled bool   `json:"enabled"`
	Dir     string `json:"dir"`
	Status  string `json:"status"`
	// Mounted: the directory exists in the API container (a share may still
	// be unmounted behind an empty mount point; the marker tells).
	Mounted bool `json:"mounted"`
	// Marker: missing, ours, foreign or unreadable; empty when not mounted.
	Marker        string     `json:"marker,omitempty"`
	Writable      *bool      `json:"writable,omitempty"` // only after a write test (check, initialise)
	FSType        string     `json:"fs_type,omitempty"`
	TotalBytes    uint64     `json:"total_bytes,omitempty"`
	FreeBytes     uint64     `json:"free_bytes,omitempty"`
	Detail        string     `json:"detail,omitempty"`
	RetentionDays int        `json:"retention_days"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
	LastMoveAt    *time.Time `json:"last_move_at,omitempty"`
	LastMoved     int        `json:"last_moved"`
	LastPruned    int        `json:"last_pruned"`
	LastError     string     `json:"last_error,omitempty"`
	PendingFiles  int        `json:"pending_files"`
	StalledSince  *time.Time `json:"stalled_since,omitempty"`
	Running       bool       `json:"running"`
}

// ArchiveStalledError says the archive filesystem did not answer in time.
type ArchiveStalledError struct{ Since time.Time }

func (e *ArchiveStalledError) Error() string {
	return fmt.Sprintf("the archive directory has not answered since %s (is the share hung?)", e.Since.Format(time.RFC3339))
}

// ErrArchiveNotReady is returned for writes to an archive this install has
// not initialised (or that is not mounted).
var ErrArchiveNotReady = errors.New("the archive directory is not ready")

var archivePartRE = regexp.MustCompile(`^(access|error)_raw\.log-[0-9]{8}-[0-9]{6}(\.gz)?\.part$`)

// NewRawLogArchiver builds the archiver for root (the archive mount inside the
// API container) and localDir (the nginx log directory). settle is how long a
// rotated file must be left alone before it moves.
func NewRawLogArchiver(root, localDir string, settle time.Duration, settings func(ctx context.Context) (*model.SystemSettings, error)) *RawLogArchiver {
	if settle < 0 {
		settle = 0
	}
	guard := newStatfsGuard(statfsPath, statfsTimeout)
	return &RawLogArchiver{
		root:         filepath.Clean(root),
		localDir:     localDir,
		settle:       settle,
		settings:     settings,
		now:          time.Now,
		statfs:       guard.stat,
		writeProbe:   archiveWriteProbe,
		changedAt:    func(f RawLogFile) time.Time { return f.changedAt },
		ioTimeout:    8 * time.Second,
		stallAfter:   2 * time.Minute,
		bootDelay:    2 * time.Minute,
		refreshEvery: 5 * time.Minute,
		slot:         make(chan struct{}, 1),
		wake:         make(chan struct{}, 1),
		stop:         make(chan struct{}),
	}
}

// Dir is the archive root inside the API container.
func (a *RawLogArchiver) Dir() string {
	if a == nil {
		return ""
	}
	return a.root
}

// Start runs a pass bootDelay after boot, then on every Wake (hourly from the
// log rotation scheduler, after "Rotate now" and after a settings change),
// and refreshes the status — and the cached disk measurement — every few
// minutes in between. Passes never overlap.
func (a *RawLogArchiver) Start(ctx context.Context) {
	if a == nil {
		return
	}
	timer := time.NewTimer(a.bootDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-a.wake:
	case <-ctx.Done():
		return
	case <-a.stop:
		return
	}
	a.runPass(ctx)
	refresh := time.NewTicker(a.refreshEvery)
	defer refresh.Stop()
	for {
		select {
		case <-a.wake:
			a.runPass(ctx)
		case <-refresh.C:
			a.refreshStatus(ctx)
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		}
	}
}

// Stop ends Start's loop. Safe to call more than once.
func (a *RawLogArchiver) Stop() {
	if a == nil {
		return
	}
	a.stopper.Do(func() { close(a.stop) })
}

// Wake asks for a pass without waiting for it. Safe on a nil archiver.
func (a *RawLogArchiver) Wake() {
	if a == nil {
		return
	}
	select {
	case a.wake <- struct{}{}:
	default: // one is already queued
	}
}

// fsCall runs fn — archive filesystem work for a request — in its own
// goroutine, one at a time, waiting at most ioTimeout. A call that does not
// come back marks the archive stalled until it does; meanwhile every other
// call fails at once rather than parking another goroutine on the mount.
func (a *RawLogArchiver) fsCall(ctx context.Context, fn func() error) error {
	a.mu.Lock()
	if a.ioStallSince != nil {
		since := *a.ioStallSince
		a.mu.Unlock()
		return &ArchiveStalledError{Since: since}
	}
	a.mu.Unlock()

	timer := time.NewTimer(a.ioTimeout)
	defer timer.Stop()
	select {
	case a.slot <- struct{}{}:
	case <-timer.C:
		return &ArchiveStalledError{Since: a.now()}
	case <-ctx.Done():
		return ctx.Err()
	}
	start := a.now()
	done := make(chan error, 1)
	go func() {
		err := fn()
		a.mu.Lock()
		a.ioStallSince = nil // it answered
		a.mu.Unlock()
		<-a.slot
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		a.mu.Lock()
		if a.ioStallSince == nil {
			a.ioStallSince = &start
		}
		a.mu.Unlock()
		return &ArchiveStalledError{Since: start}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// archiveState is one look at the archive root.
type archiveState struct {
	status RawLogArchiveStatus
	ours   bool // marker present and naming this install
}

// probe looks at the root without writing (unless writeTest): mounted, its
// filesystem, the marker. enabled=false still reports all of it but with
// status disabled — an install that does not use the archive has nothing to
// fix and nothing to be told about.
func (a *RawLogArchiver) probe(ctx context.Context, enabled bool, instance string, writeTest bool) archiveState {
	s := a.probeDir(ctx, enabled, instance, writeTest)
	if !enabled {
		s.status.Status = ArchiveStatusDisabled
	}
	return s
}

func (a *RawLogArchiver) probeDir(ctx context.Context, enabled bool, instance string, writeTest bool) archiveState {
	now := a.now()
	st := RawLogArchiveStatus{Enabled: enabled, Dir: a.root, CheckedAt: &now}
	var isDir, logDir bool
	var marker []byte
	var markerErr error
	err := a.fsCall(ctx, func() error {
		fi, err := os.Stat(a.root)
		if err != nil {
			return err
		}
		isDir = fi.IsDir()
		if !isDir {
			return nil
		}
		if logDir = a.leadsToLogDir(fi); logDir {
			return nil
		}
		marker, markerErr = readArchiveMarker(filepath.Join(a.root, rawLogArchiveMarker))
		return nil
	})
	var stalled *ArchiveStalledError
	switch {
	case errors.As(err, &stalled):
		st.Status, st.StalledSince = ArchiveStatusStalled, &stalled.Since
		st.Detail = stalled.Error()
		return archiveState{status: st}
	case err != nil || !isDir:
		st.Status = ArchiveStatusNotMounted
		st.Detail = fmt.Sprintf("%s does not exist in the API container (or is not a directory): mount the share on the host and bind it to %s on the api service", a.root, a.root)
		return archiveState{status: st}
	case logDir:
		st.Status = ArchiveStatusLogDir
		st.Detail = fmt.Sprintf("%s is the nginx log directory %s (or one of its parents), so nothing there would leave the log disk: bind a directory on another disk or a NAS share to %s instead", a.root, a.localDir, a.root)
		return archiveState{status: st}
	}
	st.Mounted = true

	if raw, err := a.statfs(ctx, a.root); err == nil {
		total, _, avail, _ := raw.usage()
		st.FSType, st.TotalBytes, st.FreeBytes = raw.typeName(), total, avail
		a.mu.Lock()
		a.statfsRaw, a.statfsAt = raw, a.now()
		a.mu.Unlock()
	} else if s, ok := asStatfsStalled(err); ok {
		st.Status, st.StalledSince = ArchiveStatusStalled, &s.Since
		st.Detail = s.Error()
		return archiveState{status: st}
	}

	ours := false
	switch {
	case errors.Is(markerErr, os.ErrNotExist):
		st.Marker = archiveMarkerMissing
		st.Status = ArchiveStatusNotInitialized
		st.Detail = "marker missing: the share is not mounted here, or archiving was never initialised (Use this directory)"
	case markerErr != nil:
		st.Marker = archiveMarkerUnreadable
		st.Status = ArchiveStatusNotInitialized
		st.Detail = "the marker file cannot be read: " + markerErr.Error()
	default:
		var m struct {
			Instance string `json:"instance"`
		}
		if json.Unmarshal(marker, &m) != nil || m.Instance == "" {
			st.Marker = archiveMarkerUnreadable
			st.Status = ArchiveStatusNotInitialized
			st.Detail = "the marker file is not valid; initialise the directory again"
		} else if m.Instance != instance {
			st.Marker = archiveMarkerForeign
			st.Status = ArchiveStatusForeign
			st.Detail = "the directory was initialised by another NPG install (or before a backup was restored here); initialise it again to use it"
		} else {
			st.Marker = archiveMarkerOurs
			st.Status = ArchiveStatusReady
			ours = true
		}
	}

	if writeTest {
		ok := true
		if err := a.fsCall(ctx, func() error { return a.writeProbe(a.root) }); err != nil {
			ok = false
			if errors.As(err, &stalled) {
				st.Status, st.StalledSince, st.Detail = ArchiveStatusStalled, &stalled.Since, stalled.Error()
				return archiveState{status: st}
			}
			st.Status = ArchiveStatusUnwritable
			st.Detail = "cannot write to " + a.root + ": " + err.Error()
		}
		st.Writable = &ok
	}
	if st.Status == ArchiveStatusReady && st.TotalBytes > 0 && st.FreeBytes < archiveReserve(st.TotalBytes) {
		st.Status = ArchiveStatusInsufficientSpace
		st.Detail = fmt.Sprintf("only %d MiB free on the archive; %d MiB are kept free", st.FreeBytes>>20, archiveReserve(st.TotalBytes)>>20)
	}
	return archiveState{status: st, ours: ours}
}

// leadsToLogDir reports whether the archive root — root is os.Stat of it, so
// symlinks are followed — is the nginx log directory or one of its parents.
// It compares identities (device and inode), so a second bind mount of the
// same directory is caught as well as a symlink or the same path.
func (a *RawLogArchiver) leadsToLogDir(root os.FileInfo) bool {
	dir := filepath.Clean(a.localDir)
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	for {
		if fi, err := os.Stat(dir); err == nil && os.SameFile(root, fi) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// archiveReserve is the space a pass leaves free: 2% of the filesystem, and
// at least 1 GiB — but never more than a tenth, so a small archive (the e2e
// tmpfs, a USB stick) is usable at all.
func archiveReserve(total uint64) uint64 {
	r := min(uint64(1)<<30, total/10)
	return max(r, total/50)
}

func readArchiveMarker(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4096))
}

func archiveWriteProbe(dir string) error {
	f, err := os.CreateTemp(dir, ".npg-write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_, werr := f.Write([]byte("ok"))
	serr := f.Sync()
	cerr := f.Close()
	rerr := os.Remove(name)
	return errors.Join(werr, serr, cerr, rerr)
}

// loadSettings returns archiving on/off, its retention, compression and this
// install's id.
func (a *RawLogArchiver) loadSettings(ctx context.Context) (enabled bool, retention int, compress bool, instance string, err error) {
	s, err := a.settings(ctx)
	if err != nil {
		return false, 0, false, "", err
	}
	retention = s.RawLogArchiveRetentionDays
	if retention < model.RawLogArchiveRetentionDaysMin {
		retention = model.RawLogArchiveRetentionDaysDefault
	}
	return s.RawLogArchiveEnabled, retention, s.RawLogCompressRotated, s.ID, nil
}

// Check probes the directory as if archiving were on, with a write test. It
// writes and removes one temporary file and never the marker.
func (a *RawLogArchiver) Check(ctx context.Context) RawLogArchiveStatus {
	if a == nil {
		return RawLogArchiveStatus{Status: ArchiveStatusNotMounted, Detail: "the raw log archive is not available"}
	}
	_, retention, _, instance, err := a.loadSettings(ctx)
	if err != nil {
		return RawLogArchiveStatus{Dir: a.root, Status: ArchiveStatusNotInitialized, Detail: "cannot read the settings: " + err.Error()}
	}
	st := a.probe(ctx, true, instance, true).status
	st.RetentionDays = retention
	return st
}

// Initialise claims the directory for this install: a write test, then the
// marker (replacing one another install wrote). It never creates the root.
func (a *RawLogArchiver) Initialise(ctx context.Context) (RawLogArchiveStatus, error) {
	if a == nil {
		return RawLogArchiveStatus{Status: ArchiveStatusNotMounted}, ErrArchiveNotReady
	}
	enabled, retention, _, instance, err := a.loadSettings(ctx)
	if err != nil {
		return RawLogArchiveStatus{Dir: a.root}, err
	}
	pre := a.probe(ctx, true, instance, true).status
	switch pre.Status {
	case ArchiveStatusNotMounted, ArchiveStatusUnwritable, ArchiveStatusStalled, ArchiveStatusLogDir:
		pre.RetentionDays = retention
		return pre, fmt.Errorf("%w (%s): %s", ErrArchiveNotReady, pre.Status, pre.Detail)
	}
	created := a.now().UTC()
	body, _ := json.Marshal(map[string]string{
		"npg":        "raw-log-archive",
		"instance":   instance,
		"created_at": created.Format(time.RFC3339),
	})
	err = a.fsCall(ctx, func() error {
		tmp := filepath.Join(a.root, rawLogArchiveMarker+".tmp")
		if err := os.WriteFile(tmp, body, 0644); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(a.root, rawLogArchiveMarker)); err != nil {
			os.Remove(tmp)
			return err
		}
		return syncDir(a.root)
	})
	if err != nil {
		return pre, fmt.Errorf("write the archive marker: %w", err)
	}
	log.Printf("[RawLogArchive] %s initialised for this install", a.root)
	// Answer as Check does (as if archiving were on), so the operator sees
	// "ready" before switching it on; remember the real state.
	st := a.probe(ctx, true, instance, false).status
	st.RetentionDays = retention
	st.Writable = pre.Writable
	a.refreshStatus(ctx)
	if enabled {
		a.Wake()
	}
	return st, nil
}

// Status reports the archive, re-probing it (without writing) when the last
// look is older than 15 seconds.
func (a *RawLogArchiver) Status(ctx context.Context) RawLogArchiveStatus {
	if a == nil {
		return RawLogArchiveStatus{Status: ArchiveStatusNotMounted, Detail: "the raw log archive is not available"}
	}
	a.mu.Lock()
	fresh := !a.statusAt.IsZero() && a.now().Sub(a.statusAt) < 15*time.Second
	st := a.status
	a.mu.Unlock()
	if fresh {
		return a.decorate(st)
	}
	return a.refreshStatus(ctx)
}

func (a *RawLogArchiver) refreshStatus(ctx context.Context) RawLogArchiveStatus {
	enabled, retention, compress, instance, err := a.loadSettings(ctx)
	if err != nil {
		return a.decorate(RawLogArchiveStatus{Dir: a.root, Status: ArchiveStatusNotInitialized, Detail: "cannot read the settings: " + err.Error()})
	}
	st := a.probe(ctx, enabled, instance, false).status
	st.RetentionDays = retention
	st.PendingFiles = len(a.settledLocal(compress))
	return a.decorate(a.remember(st))
}

// remember stores a status, keeps what the last pass reported, and logs one
// line when the status changes. It returns the status as stored.
func (a *RawLogArchiver) remember(st RawLogArchiveStatus) RawLogArchiveStatus {
	a.mu.Lock()
	st.LastMoveAt, st.LastMoved, st.LastPruned, st.LastError = a.status.LastMoveAt, a.status.LastMoved, a.status.LastPruned, a.status.LastError
	a.status, a.statusAt = st, a.now()
	// One line per status change; the detail (free space, timestamps) moves
	// on its own and must not repeat it.
	changed := st.Status != a.logged
	a.logged = st.Status
	a.mu.Unlock()
	metrics.SetRawLogArchiveStatus(st.Status)
	if changed {
		switch st.Status {
		case ArchiveStatusReady:
			log.Printf("[RawLogArchive] ready: rotated raw logs move to %s (%s)", a.root, st.FSType)
		case ArchiveStatusDisabled:
			// Off is the default; say nothing.
		default:
			log.Printf("[RawLogArchive] %s: %s; rotated logs stay local and follow the local retention", st.Status, st.Detail)
		}
	}
	return st
}

// decorate adds what only the running process knows: a pass in progress
// and a stalled copy or call.
func (a *RawLogArchiver) decorate(st RawLogArchiveStatus) RawLogArchiveStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	st.Running = a.running.Load()
	if !st.Enabled {
		return st
	}
	if st.Running && !a.progressAt.IsZero() && a.now().Sub(a.progressAt) > a.stallAfter {
		since := a.progressAt
		st.Status, st.StalledSince = ArchiveStatusStalled, &since
		st.Detail = "moving a file to the archive has made no progress since " + since.Format(time.RFC3339)
	}
	if a.ioStallSince != nil {
		since := *a.ioStallSince
		st.Status, st.StalledSince = ArchiveStatusStalled, &since
		st.Detail = (&ArchiveStalledError{Since: since}).Error()
	}
	return st
}

// CachedDiskUsage returns the archive filesystem as the archiver last
// measured it, without touching the filesystem — DiskGuard's archive source:
// a hung share must not freeze disk alerts. total and avail are bytes as df
// shows them (avail excludes root-reserved blocks). stalledSince is set while
// the archive is stalled (see stalledSinceLocked); a share that hung before
// this process ever measured it is reported stalled with zero sizes. ok is
// false when archiving is off, the archive is not mounted, or it was never
// measured and is not stalled.
func (a *RawLogArchiver) CachedDiskUsage() (path string, total, avail uint64, measuredAt time.Time, stalledSince *time.Time, ok bool) {
	raw, at, stalled, ok := a.cachedStatfs()
	if !ok {
		return "", 0, 0, time.Time{}, nil, false
	}
	total, _, avail, _ = raw.usage()
	return a.root, total, avail, at, stalled, true
}

// cachedStatfs is CachedDiskUsage with the raw statfs result, for an adapter
// in this package (DiskGuard groups filesystems by their fsid).
func (a *RawLogArchiver) cachedStatfs() (raw rawStatfs, measuredAt time.Time, stalledSince *time.Time, ok bool) {
	if a == nil {
		return rawStatfs{}, time.Time{}, nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// A stalled share is still reported (with stalledSince); a missing one is
	// not, nor the log directory standing in for one.
	if !a.status.Enabled || a.status.Status == ArchiveStatusNotMounted || a.status.Status == ArchiveStatusLogDir {
		return rawStatfs{}, time.Time{}, nil, false
	}
	stalledSince = a.stalledSinceLocked()
	if a.statfsAt.IsZero() && stalledSince == nil {
		return rawStatfs{}, time.Time{}, nil, false
	}
	return a.statfsRaw, a.statfsAt, stalledSince, true
}

// stalledSinceLocked is when the archive stopped answering, or nil: a call
// that timed out (and has not come back), a pass that has made no progress
// for stallAfter — the rule decorate applies to the status; a copy blocked on
// a hung share holds the pass, and the refreshes queued behind it, so nothing
// else would notice — or the stall the last probe recorded. a.mu held.
func (a *RawLogArchiver) stalledSinceLocked() *time.Time {
	var since time.Time
	switch {
	case a.ioStallSince != nil:
		since = *a.ioStallSince
	case a.running.Load() && !a.progressAt.IsZero() && a.now().Sub(a.progressAt) > a.stallAfter:
		since = a.progressAt
	case a.status.StalledSince != nil:
		since = *a.status.StalledSince
	default:
		return nil
	}
	return &since
}

// ArchiveUsageSource adapts the archiver to HostUsageProvider.SetArchiveUsage:
// DiskGuard sees the archive through the archiver's own last measurement,
// read under its lock and never by a filesystem call, so a hung share cannot
// hold the tick. It reports the archive only while archiving is on and the
// archive has been measured, and a stalled share as stalled (with no numbers
// when it never answered). Safe with a nil archiver, which reports nothing.
func ArchiveUsageSource(a *RawLogArchiver) func() (ArchiveDiskUsage, bool) {
	return func() (ArchiveDiskUsage, bool) {
		raw, at, stalled, ok := a.cachedStatfs()
		if !ok {
			return ArchiveDiskUsage{}, false
		}
		u := ArchiveDiskUsage{Path: a.Dir(), Stat: raw, MeasuredAt: at}
		if stalled != nil {
			u.StalledSince = *stalled
		}
		return u, true
	}
}

// settledLocal lists the local rotated files ready to move, oldest first.
func (a *RawLogArchiver) settledLocal(compress bool) []RawLogFile {
	files, err := scanRawLogs(a.localDir, RawLogLocationLocal, IsArchivedRawLogName)
	if err != nil {
		return nil
	}
	now := a.now()
	var out []RawLogFile
	for _, f := range files {
		if compress && !f.IsCompressed {
			continue // delaycompress: compressed at the next rotation
		}
		if now.Sub(a.changedAt(f)) < a.settle {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RotatedAt.Equal(*out[j].RotatedAt) {
			return out[i].RotatedAt.Before(*out[j].RotatedAt)
		}
		return out[i].Name < out[j].Name
	})
	return out
}
