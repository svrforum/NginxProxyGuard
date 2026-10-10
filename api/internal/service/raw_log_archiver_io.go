package service

import (
	"context"
	"sync/atomic"
	"time"
)

// Request-side archive filesystem calls of RawLogArchiver. A hung NFS mount
// blocks the kernel, so every call runs in its own goroutine, one at a time
// (the slot), and is watched: one that makes no progress for ioTimeout marks
// the archive stalled until it returns — whether or not its caller is still
// waiting — and every other call then fails at once instead of parking
// another goroutine on the mount. A call that keeps making progress, such as
// a long listing of a slow share, is waited for however long it takes.

// archiveCall is the archive filesystem call holding the slot.
type archiveCall struct {
	since    time.Time     // a.now() at its start: when a stall began
	timeout  time.Duration // how long it may go without progress
	lastTick atomic.Int64  // archiveMono() at its start or its last progress
	done     chan struct{} // closed once fn has returned
	stalled  chan struct{} // closed when the watchdog gives up on it
	err      error         // what fn returned; read after done
}

// archiveClockBase anchors archiveMono: time.Since on it reads the monotonic
// clock, which a wall-clock step cannot move.
var archiveClockBase = time.Now()

func archiveMono() time.Duration { return time.Since(archiveClockBase) }

func (c *archiveCall) tick() { c.lastTick.Store(int64(archiveMono())) }

func (c *archiveCall) idle() time.Duration {
	return archiveMono() - time.Duration(c.lastTick.Load())
}

// fsCall runs fn, archive filesystem work for a request, as described above.
func (a *RawLogArchiver) fsCall(ctx context.Context, fn func() error) error {
	return a.fsCallProgress(ctx, func(func()) error { return fn() })
}

// fsCallProgress is fsCall for work that reports progress through tick: it
// counts as stalled only once it stops ticking.
func (a *RawLogArchiver) fsCallProgress(ctx context.Context, fn func(tick func()) error) error {
	if err := a.acquireSlot(ctx); err != nil {
		return err
	}
	call := &archiveCall{since: a.now(), timeout: a.ioTimeout, done: make(chan struct{}), stalled: make(chan struct{})}
	call.tick()
	a.mu.Lock()
	a.call = call
	a.mu.Unlock()
	go func() {
		call.err = fn(call.tick)
		a.mu.Lock()
		a.call = nil
		a.ioStallSince = nil // it answered
		a.mu.Unlock()
		<-a.slot
		close(call.done)
	}()
	go a.watch(call)
	select {
	case <-call.done:
		return call.err
	case <-call.stalled:
		select {
		case <-call.done: // it answered after all
			return call.err
		default:
			return &ArchiveStalledError{Since: call.since}
		}
	case <-ctx.Done():
		return ctx.Err() // the watchdog goes on watching the call
	}
}

// acquireSlot waits for the slot for as long as the call holding it keeps
// answering; when that call is given up on, every waiter fails at once.
func (a *RawLogArchiver) acquireSlot(ctx context.Context) error {
	for {
		a.mu.Lock()
		if a.ioStallSince != nil {
			since := *a.ioStallSince
			a.mu.Unlock()
			return &ArchiveStalledError{Since: since}
		}
		stalled := a.stallSignal
		a.mu.Unlock()
		select {
		case a.slot <- struct{}{}:
			return nil
		case <-stalled:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// watch gives up on call once it has gone call.timeout without progress: the
// archive is stalled since the call's start until the call returns, and the
// callers waiting for the slot are woken to fail.
func (a *RawLogArchiver) watch(call *archiveCall) {
	timer := time.NewTimer(call.timeout)
	defer timer.Stop()
	for {
		select {
		case <-call.done:
			return
		case <-timer.C:
		}
		if idle := call.idle(); idle < call.timeout {
			timer.Reset(call.timeout - idle)
			continue
		}
		a.mu.Lock()
		stuck := a.call == call
		if stuck {
			if a.ioStallSince == nil {
				since := call.since
				a.ioStallSince = &since
			}
			close(a.stallSignal)
			a.stallSignal = make(chan struct{})
		}
		a.mu.Unlock()
		if stuck {
			close(call.stalled)
		}
		return
	}
}
