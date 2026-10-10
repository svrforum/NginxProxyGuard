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
//
// On ZFS (TrueNAS SCALE, Proxmox) a Docker volume is a dataset, and statfs
// describes the dataset, not the pool: f_blocks is what the dataset holds plus
// the pool's free space, f_bavail the pool's free space. avail (and so "free"
// and "days to full") is right, but the percentage is relative to the
// dataset: a dataset holding 20 GB on a pool with 40 GB free reads 33% while
// the pool is 98% full, and reaches the 90% line only with about 2.2 GB left.
// df reports the same numbers; the pool's own figure is `zpool list`. A
// percentage line cannot see this, so an operator on ZFS should watch the
// pool as well, or set NPG_DISK_WARN_PERCENT / NPG_DISK_CRITICAL_PERCENT low
// enough for the dataset's size.
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
	inflight map[string]*statfsCall // path -> its still-running call
}

// statfsCall is one statfs in flight. raw and err are set before done is
// closed and only read after.
type statfsCall struct {
	since time.Time
	done  chan struct{}
	raw   rawStatfs
	err   error
}

func newStatfsGuard(call func(path string) (rawStatfs, error), timeout time.Duration) *statfsGuard {
	if timeout <= 0 {
		timeout = statfsTimeout
	}
	return &statfsGuard{call: call, timeout: timeout, now: time.Now, inflight: map[string]*statfsCall{}}
}

// stat measures path, waiting at most the guard's timeout (or until ctx ends).
// A call already in flight for the path is shared, not repeated: a caller
// that arrives while it is young waits for its answer, within the same
// timeout, so two checks measuring one disk at the same moment both get the
// numbers. Only a call that has run past the timeout, still stuck from an
// earlier attempt, makes stat return a stall at once.
func (g *statfsGuard) stat(ctx context.Context, path string) (rawStatfs, error) {
	g.mu.Lock()
	c := g.inflight[path]
	if c != nil && g.now().Sub(c.since) >= g.timeout {
		g.mu.Unlock()
		return rawStatfs{}, &statfsStalledError{Path: path, Since: c.since}
	}
	if c == nil {
		c = &statfsCall{since: g.now(), done: make(chan struct{})}
		g.inflight[path] = c
		// The goroutine outlives a caller that gave up: a hung mount costs
		// this one goroutine until the server answers.
		go func() {
			raw, err := g.call(path)
			g.mu.Lock()
			c.raw, c.err = raw, err
			delete(g.inflight, path)
			g.mu.Unlock()
			close(c.done)
		}()
	}
	g.mu.Unlock()

	timer := time.NewTimer(max(g.timeout-g.now().Sub(c.since), 0))
	defer timer.Stop()
	select {
	case <-c.done:
		return c.raw, c.err
	case <-timer.C:
		return rawStatfs{}, &statfsStalledError{Path: path, Since: c.since}
	case <-ctx.Done():
		return rawStatfs{}, ctx.Err()
	}
}
