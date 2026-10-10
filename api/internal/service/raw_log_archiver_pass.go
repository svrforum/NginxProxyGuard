package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"nginx-proxy-guard/internal/metrics"
)

// The archive pass (moving settled files, pruning) and the request-side file
// operations (list, open, delete) of RawLogArchiver.

// ErrArchiveFileName is the answer for a name that is not an archived raw log.
var ErrArchiveFileName = errors.New("invalid archive file name")

// errArchiveConflict: the archive already holds something under this name
// that is not an earlier copy of the local file — a different file, or a
// link. Both are kept; the local one stays local.
type errArchiveConflict struct{ name, reason string }

func (e *errArchiveConflict) Error() string { return e.name + " " + e.reason }

const (
	conflictDifferentContent = "already exists in the archive with different content; both copies are kept"
	conflictNotAFile         = "exists in the archive but is not a regular file (a link or a directory); the local file is kept"
	conflictSameFile         = "in the archive is another name for the local file itself; the local file is kept"
)

// archiveListTTL caches the archive listing: listing a large NAS directory
// is slow, and the raw log page asks on every refresh.
const archiveListTTL = time.Minute

// touch records progress for the stall check.
func (a *RawLogArchiver) touch() {
	a.mu.Lock()
	a.progressAt = a.now()
	a.mu.Unlock()
}

// runPass prunes the archive and moves the settled local files. Passes never
// overlap; a Wake during a pass is kept for the next one.
func (a *RawLogArchiver) runPass(ctx context.Context) {
	if !a.running.CompareAndSwap(false, true) {
		return
	}
	defer a.running.Store(false)
	a.touch()

	enabled, retention, compress, instance, err := a.loadSettings(ctx)
	if err != nil {
		log.Printf("[RawLogArchive] cannot read the settings: %v", err)
		return
	}
	state := a.probe(ctx, enabled, instance, false)
	if state.cancelled {
		return // stopping
	}
	st := state.status
	st.RetentionDays = retention
	usable := enabled && state.ours && (st.Status == ArchiveStatusReady || st.Status == ArchiveStatusInsufficientSpace)
	if !usable {
		st.PendingFiles = len(a.settledLocal(compress))
		a.remember(st)
		return
	}

	a.removeStaleParts()
	pruned, pruneErr := a.prune(retention)
	moved, movedBytes, stop, moveErr := a.moveSettled(ctx, compress)
	metrics.RawLogArchivePrunedFilesTotal.Add(float64(pruned))
	metrics.RawLogArchiveMovedFilesTotal.Add(float64(moved))
	metrics.RawLogArchiveMovedBytesTotal.Add(float64(movedBytes))
	if moved > 0 || pruned > 0 {
		a.mu.Lock()
		a.invalidateListLocked()
		a.mu.Unlock()
	}

	// A destination that refuses writes (a read-only share, root_squash) is
	// reported as such rather than as a generic error every hour.
	if stop == "" && (errors.Is(moveErr, fs.ErrPermission) || errors.Is(moveErr, syscall.EROFS)) {
		stop = ArchiveStatusUnwritable
	}
	// Re-measure after the moves; a stop is the pass's own verdict.
	after := a.probe(ctx, enabled, instance, false)
	if after.cancelled {
		return // stopping
	}
	st = after.status
	st.RetentionDays = retention
	if stop != "" && st.Status == ArchiveStatusReady {
		st.Status = stop
		if stop == ArchiveStatusUnwritable && moveErr != nil {
			st.Detail = "cannot write to " + a.root + ": " + moveErr.Error()
		}
	}
	st.PendingFiles = len(a.settledLocal(compress))
	a.remember(st)

	a.mu.Lock()
	now := a.now()
	if moved > 0 { // last_move_at and last_moved describe the last pass that moved anything
		a.status.LastMoveAt, a.status.LastMoved = &now, moved
	}
	a.status.LastPruned = pruned
	a.status.LastError = ""
	if err := errors.Join(moveErr, pruneErr); err != nil {
		a.status.LastError = err.Error()
	}
	a.mu.Unlock()
	if moved > 0 || pruned > 0 || moveErr != nil || pruneErr != nil {
		log.Printf("[RawLogArchive] moved %d file(s) (%d MiB), pruned %d past %d days%s",
			moved, movedBytes>>20, pruned, retention, errSuffix(errors.Join(moveErr, pruneErr)))
	}
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return "; " + err.Error()
}

// moveSettled moves settled files oldest first. It stops at the first file
// that does not fit or fails to copy (the next one would fail the same way);
// a conflicting name is skipped. stop is a status to report, or "".
func (a *RawLogArchiver) moveSettled(ctx context.Context, compress bool) (moved int, movedBytes int64, stop string, err error) {
	var errs []error
	for _, f := range a.settledLocal(compress) {
		if ctx.Err() != nil {
			break
		}
		raw, serr := a.statfs(ctx, a.root)
		if serr != nil {
			if _, ok := asStatfsStalled(serr); ok {
				return moved, movedBytes, ArchiveStatusStalled, errors.Join(append(errs, serr)...)
			}
			return moved, movedBytes, "", errors.Join(append(errs, serr)...)
		}
		total, _, avail, _ := raw.usage()
		if avail < uint64(f.Size)+archiveReserve(total) {
			return moved, movedBytes, ArchiveStatusInsufficientSpace, errors.Join(errs...)
		}
		if merr := a.moveOne(f); merr != nil {
			var conflict *errArchiveConflict
			if errors.As(merr, &conflict) {
				errs = append(errs, merr)
				continue
			}
			return moved, movedBytes, "", errors.Join(append(errs, fmt.Errorf("move %s: %w", f.Name, merr))...)
		}
		moved++
		movedBytes += f.Size
	}
	return moved, movedBytes, "", errors.Join(errs...)
}

// progressWriter reports every chunk written, so a copy that stops making
// progress (a hung share) shows up as stalled.
type progressWriter struct {
	w    io.Writer
	tick func()
}

func (p progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.tick()
	return n, err
}

// moveOne copies one file to <name>.part, syncs and checks it, renames it into
// place, restores its mtime, and only then deletes the local file.
func (a *RawLogArchiver) moveOne(f RawLogFile) error {
	src := filepath.Join(a.localDir, f.Name)
	final := filepath.Join(a.root, f.Name)
	a.touch()

	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	// Lstat: what is under the name in the archive counts, not where a link
	// leads. Only a separate regular file can be an earlier copy; a link to
	// the local file, or the local file under a second name, would make
	// deleting the source delete the only copy.
	if fi, err := os.Lstat(final); err == nil {
		switch {
		case !fi.Mode().IsRegular():
			return &errArchiveConflict{name: f.Name, reason: conflictNotAFile}
		case os.SameFile(srcInfo, fi):
			return &errArchiveConflict{name: f.Name, reason: conflictSameFile}
		}
		// Left by a pass that died after the rename and before deleting the
		// source — or a genuinely different file of the same name.
		same, err := sameFileContent(src, final, fi.Size())
		if err != nil {
			return err
		}
		if !same {
			return &errArchiveConflict{name: f.Name, reason: conflictDifferentContent}
		}
		return removeIfExists(src)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	part := final + ".part"
	_ = os.Remove(part) // from a pass that died mid-copy; passes never overlap

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	n, cerr := io.Copy(progressWriter{out, a.touch}, in)
	serr := out.Sync()
	clerr := out.Close()
	if err := errors.Join(cerr, serr, clerr); err != nil || n != f.Size {
		os.Remove(part)
		if err == nil {
			err = fmt.Errorf("copied %d of %d bytes", n, f.Size)
		}
		return err
	}
	if err := os.Rename(part, final); err != nil {
		os.Remove(part)
		return err
	}
	_ = os.Chtimes(final, f.ModifiedAt, f.ModifiedAt) // pruning uses the name, so a share without mtimes is fine
	_ = syncDir(a.root)
	if fi, err := os.Lstat(final); err != nil || !fi.Mode().IsRegular() || fi.Size() != f.Size || os.SameFile(srcInfo, fi) {
		return fmt.Errorf("verifying %s in the archive failed; the local file is kept", f.Name)
	}
	a.touch()
	return removeIfExists(src)
}

func sameFileContent(a, b string, bSize int64) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	if ai.Size() != bSize {
		return false, nil
	}
	ha, err := fileSHA256(a)
	if err != nil {
		return false, err
	}
	hb, err := fileSHA256(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ha, hb), nil
}

func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// removeStaleParts deletes the .part files a pass that died mid-copy left
// behind. Passes never overlap and only this install writes here (the
// marker), so any .part at the start of a pass is stale.
func (a *RawLogArchiver) removeStaleParts() {
	entries, err := os.ReadDir(a.root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if archivePartRE.MatchString(e.Name()) && e.Type().IsRegular() {
			_ = os.Remove(filepath.Join(a.root, e.Name()))
		}
	}
}

// prune deletes archived files whose name says they were rotated more than
// retention days ago. Nothing else in the directory is touched.
func (a *RawLogArchiver) prune(retentionDays int) (int, error) {
	entries, err := os.ReadDir(a.root)
	if err != nil {
		return 0, err
	}
	cutoff := a.now().AddDate(0, 0, -retentionDays)
	removed := 0
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if !IsArchivedRawLogName(name) || !e.Type().IsRegular() {
			continue
		}
		at, ok := ParseRotatedAt(name)
		if !ok || !at.Before(cutoff) {
			continue
		}
		a.touch()
		if err := os.Remove(filepath.Join(a.root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// ListArchive lists the archived raw logs, cached for a minute. A listing
// counts as stalled only once it stops making progress, however long a large
// archive on a slow share takes, and it is cached when it finishes even if
// the request that started it has given up: requests meanwhile wait for it
// rather than list the share again.
func (a *RawLogArchiver) ListArchive(ctx context.Context) ([]RawLogFile, error) {
	if a == nil {
		return nil, ErrArchiveNotReady
	}
	if files, ok := a.cachedList(); ok {
		return files, nil
	}
	var files []RawLogFile
	err := a.fsCallProgress(ctx, func(tick func()) error {
		if cached, ok := a.cachedList(); ok { // finished while this call waited
			files = cached
			return nil
		}
		a.mu.Lock()
		gen := a.listGen
		a.mu.Unlock()
		fi, err := os.Stat(a.root)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("%w (%s): %s is not mounted", ErrArchiveNotReady, ArchiveStatusNotMounted, a.root)
		}
		if a.leadsToLogDir(fi) {
			return fmt.Errorf("%w (%s): %s is the nginx log directory", ErrArchiveNotReady, ArchiveStatusLogDir, a.root)
		}
		list, err := a.listDir(a.root, tick)
		if err != nil {
			return err
		}
		a.mu.Lock()
		if a.listGen == gen { // else a pass or a delete changed the archive meanwhile
			a.list, a.listAt = list, a.now()
		}
		a.mu.Unlock()
		files = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return append([]RawLogFile(nil), files...), nil
}

// ListArchiveQuick is ListArchive for a caller that can do without the
// archive's files this time, such as the log disk estimate: it waits at most
// the call timeout for a listing that is not cached, which then goes on and
// is cached for the next call.
func (a *RawLogArchiver) ListArchiveQuick(ctx context.Context) ([]RawLogFile, error) {
	if a == nil {
		return nil, ErrArchiveNotReady
	}
	ctx, cancel := context.WithTimeout(ctx, a.ioTimeout)
	defer cancel()
	return a.ListArchive(ctx)
}

// cachedList is the archive listing while it is fresh.
func (a *RawLogArchiver) cachedList() ([]RawLogFile, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.listAt.IsZero() || a.now().Sub(a.listAt) >= archiveListTTL {
		return nil, false
	}
	return append([]RawLogFile(nil), a.list...), true
}

// invalidateListLocked drops the cached listing, and any listing still
// running, after the archive changed. a.mu held.
func (a *RawLogArchiver) invalidateListLocked() {
	a.list, a.listAt = nil, time.Time{}
	a.listGen++
}

// listArchiveDir is the archive listing: the archived names, ticking as it
// reads.
func listArchiveDir(dir string, tick func()) ([]RawLogFile, error) {
	return scanRawLogsTick(dir, RawLogLocationArchive, IsArchivedRawLogName, tick)
}

// OpenArchiveFile opens one archived file for reading. Reading it can still
// block on a hung share; the open itself cannot hold the request.
func (a *RawLogArchiver) OpenArchiveFile(ctx context.Context, name string) (*os.File, os.FileInfo, error) {
	if a == nil {
		return nil, nil, ErrArchiveNotReady
	}
	if !IsArchivedRawLogName(name) {
		return nil, nil, ErrArchiveFileName
	}
	var mu sync.Mutex
	var file *os.File
	var info os.FileInfo
	abandoned := false
	err := a.fsCall(ctx, func() error {
		path := filepath.Join(a.root, name)
		li, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !li.Mode().IsRegular() {
			return ErrArchiveFileName
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if abandoned { // the request gave up waiting
			f.Close()
			return nil
		}
		file, info = f, li
		return nil
	})
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		abandoned = true
		if file != nil {
			file.Close()
		}
		return nil, nil, err
	}
	return file, info, nil
}

// DeleteArchiveFile deletes one archived file. Like every archive write it
// needs the marker of this install.
func (a *RawLogArchiver) DeleteArchiveFile(ctx context.Context, name string) error {
	if a == nil {
		return ErrArchiveNotReady
	}
	if !IsArchivedRawLogName(name) {
		return ErrArchiveFileName
	}
	_, _, _, instance, err := a.loadSettings(ctx)
	if err != nil {
		return err
	}
	if st := a.probe(ctx, true, instance, false); !st.ours {
		if st.cancelled {
			return ctx.Err()
		}
		if st.status.Status == ArchiveStatusStalled && st.status.StalledSince != nil {
			return &ArchiveStalledError{Since: *st.status.StalledSince}
		}
		return fmt.Errorf("%w (%s): %s", ErrArchiveNotReady, st.status.Status, st.status.Detail)
	}
	err = a.fsCall(ctx, func() error {
		path := filepath.Join(a.root, name)
		li, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !li.Mode().IsRegular() {
			return ErrArchiveFileName
		}
		return os.Remove(path)
	})
	if err == nil {
		a.mu.Lock()
		a.invalidateListLocked()
		a.mu.Unlock()
	}
	return err
}
