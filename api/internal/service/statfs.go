package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Filesystem statistics (statfs(2)), shared by DiskGuard (D1) and meant for
// the raw-log file views and archive (B5/B6) too. The syscall lives in
// statfs_linux.go; everything here is portable.
//
// A network mount whose server stopped answering — an NFS export that went
// away, a CIFS share on a NAS that is asleep — blocks statfs(2) in the kernel
// until the server answers. The call ignores signals, and nothing in Go can
// cancel it. Measuring such a path inline freezes the caller with it: every
// disk alert would stop because the backup NAS did. So a path an operator
// configured is measured through a statfsGuard: the call runs in its own
// goroutine, the caller waits at most a timeout, and while that goroutine is
// still stuck the path is reported as stalled straight away instead of
// starting another one. A hung mount therefore costs one parked goroutine,
// not one per tick.

// statfsTimeout bounds one statfs call. A local disk answers in microseconds;
// anything that takes seconds is a mount that is not answering.
const statfsTimeout = 3 * time.Second

// overlayFSMagic is statfs f_type for overlayfs, the root of a container. Its
// fsid is per mount, so an overlay root is matched to its backing disk by
// size, not by fsid (see rawStatfs.identity).
const overlayFSMagic = 0x794c7630

// rawStatfs is a statfs(2) result in the units df uses.
type rawStatfs struct {
	FSID   string // hex, formatted like `stat -f -c %i`; "" when unknown
	Type   int64  // f_type magic, e.g. 0xef53 for ext4
	Frsize uint64
	Blocks uint64
	Bfree  uint64
	Bavail uint64
	Files  uint64
}

// usage returns df's numbers. Used excludes the root-reserved blocks and the
// percentage is used/(used+avail): that is what Postgres, a non-root writer,
// sees — at "100%" it can no longer extend a file even though root could.
func (r rawStatfs) usage() (total, used, avail uint64, pct float64) {
	total = r.Blocks * r.Frsize
	used = (r.Blocks - r.Bfree) * r.Frsize
	avail = r.Bavail * r.Frsize
	if used+avail > 0 {
		pct = float64(used) / float64(used+avail) * 100
	}
	return
}

// typeName names the filesystem type ("ext4", "nfs", "cifs", ...), or "" when
// the magic number is not one we know. Useful to show an operator which disk
// a path really is on — "nfs 4 TB" versus "ext4 50 GB".
func (r rawStatfs) typeName() string { return fsTypeName(r.Type) }

// fsidHex formats a Linux fsid the way `stat -f -c %i` does (GNU and
// BusyBox): val[0] in the high word. Verified against BusyBox in the timescale
// image: Go [006a24fc b0c35b83] = stat 6a24fcb0c35b83.
func fsidHex(v0, v1 int32) string {
	return strconv.FormatUint(uint64(uint32(v0))<<32|uint64(uint32(v1)), 16)
}

// existingAncestor walks up to a path that exists, so a directory that has not
// been created yet (BACKUP_PATH before the first backup) is still measured on
// the filesystem it will live on.
func existingAncestor(p string) string {
	for p != "" && p != "/" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		p = filepath.Dir(p)
	}
	return "/"
}

// statfsNearest is statfs on the path, or on its nearest existing ancestor.
// The os.Stat walk can hang on a dead mount just like statfs, so it belongs
// inside the guarded call too.
func statfsNearest(path string) (rawStatfs, error) {
	return statfsPath(existingAncestor(path))
}

// statfsStalledError says a path's statfs did not come back in time. Since is
// when the still-running call started; it stays the same tick after tick
// until the mount answers.
type statfsStalledError struct {
	Path  string
	Since time.Time
}

func (e *statfsStalledError) Error() string {
	return fmt.Sprintf("statfs %s has not returned since %s (is a network mount hung?)", e.Path, e.Since.Format(time.RFC3339))
}

// asStatfsStalled reports whether err is a stall, and when it started.
func asStatfsStalled(err error) (*statfsStalledError, bool) {
	var s *statfsStalledError
	ok := errors.As(err, &s)
	return s, ok
}

// statfsGuard runs statfs calls with a timeout and at most one call in flight
// per path. See the top of this file for why.
type statfsGuard struct {
	call    func(path string) (rawStatfs, error)
	timeout time.Duration
	now     func() time.Time

	mu       sync.Mutex
	inflight map[string]time.Time // path -> when its still-running call started
}

func newStatfsGuard(call func(path string) (rawStatfs, error), timeout time.Duration) *statfsGuard {
	if timeout <= 0 {
		timeout = statfsTimeout
	}
	return &statfsGuard{call: call, timeout: timeout, now: time.Now, inflight: map[string]time.Time{}}
}

// stat measures path, waiting at most the guard's timeout (or until ctx ends).
// A call still stuck from an earlier attempt makes it return a stall at once.
func (g *statfsGuard) stat(ctx context.Context, path string) (rawStatfs, error) {
	g.mu.Lock()
	if since, busy := g.inflight[path]; busy {
		g.mu.Unlock()
		return rawStatfs{}, &statfsStalledError{Path: path, Since: since}
	}
	since := g.now()
	g.inflight[path] = since
	g.mu.Unlock()

	type result struct {
		raw rawStatfs
		err error
	}
	// Buffered, so a call that answers after the caller gave up can still
	// deliver and exit instead of leaking.
	done := make(chan result, 1)
	go func() {
		raw, err := g.call(path)
		g.mu.Lock()
		delete(g.inflight, path)
		g.mu.Unlock()
		done <- result{raw, err}
	}()

	timer := time.NewTimer(g.timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.raw, r.err
	case <-timer.C:
		return rawStatfs{}, &statfsStalledError{Path: path, Since: since}
	case <-ctx.Done():
		return rawStatfs{}, ctx.Err()
	}
}
