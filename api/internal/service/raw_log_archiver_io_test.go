package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The request side of the archive: one filesystem call at a time, a hung
// share marked stalled however its callers come and go, a slow one waited
// for, and a listing kept once it has been paid for.

// A request that gives up while its call hangs: the call still marks the
// archive stalled once it has been stuck for the timeout, and later calls
// fail at once instead of each waiting out the slot.
func TestArchiverCancelledCallStillMarksTheStall(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.ioTimeout = 100 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := h.a.fsCall(ctx, func() error { <-release; return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the cancelled call: %v", err)
	}
	time.Sleep(3 * h.a.ioTimeout / 2)

	h.a.mu.Lock()
	since := h.a.ioStallSince
	h.a.mu.Unlock()
	if since == nil {
		t.Fatal("a call that hung after its request gave up never marked the archive stalled")
	}
	for i := 0; i < 3; i++ {
		start := time.Now()
		var stalled *ArchiveStalledError
		err := h.a.fsCall(context.Background(), func() error { return nil })
		if !errors.As(err, &stalled) || time.Since(start) > h.a.ioTimeout/2 {
			t.Fatalf("call %d: %v after %v; want stalled at once", i+1, err, time.Since(start))
		}
	}
}

// A status check whose request gives up while it waits for the archive has
// learnt nothing: it must not report, remember or log "not mounted".
func TestArchiverCancelledStatusCheckKeepsTheLastStatus(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.runPass(context.Background())
	if st := h.a.Status(context.Background()); st.Status != ArchiveStatusReady {
		t.Fatalf("before: %s", st.Status)
	}
	// Another call holds the slot, well within its time.
	h.a.ioTimeout = 5 * time.Second
	release := make(chan struct{})
	held := make(chan struct{})
	go func() {
		_ = h.a.fsCall(context.Background(), func() error { close(held); <-release; return nil })
	}()
	t.Cleanup(func() { close(release) })
	<-held

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if st := h.a.refreshStatus(ctx); st.Status != ArchiveStatusReady {
		t.Fatalf("a cancelled check reported %s (%s)", st.Status, st.Detail)
	}
	h.a.mu.Lock()
	remembered, logged := h.a.status.Status, h.a.logged
	h.a.mu.Unlock()
	if remembered != ArchiveStatusReady || logged != ArchiveStatusReady {
		t.Fatalf("remembered %s, logged %s; want ready", remembered, logged)
	}
}

// slowListing stands in for a large archive on a slow share: it reports
// progress every step for steps × step, then returns one file. calls counts
// how many times the archive was really listed.
func slowListing(h *archiverHarness, steps int, step time.Duration, calls *int32) {
	h.a.listDir = func(_ string, tick func()) ([]RawLogFile, error) {
		h.a.mu.Lock()
		*calls++
		h.a.mu.Unlock()
		for i := 0; i < steps; i++ {
			time.Sleep(step)
			tick()
		}
		return []RawLogFile{{Name: "access_raw.log-20261001-000000.gz", Location: RawLogLocationArchive}}, nil
	}
}

func listCalls(h *archiverHarness, calls *int32) int32 {
	h.a.mu.Lock()
	defer h.a.mu.Unlock()
	return *calls
}

// A listing that keeps moving is slow, not stalled, however much longer
// than the call timeout it takes.
func TestArchiverSlowListingIsNotAStall(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.ioTimeout = 50 * time.Millisecond
	var calls int32
	slowListing(h, 20, 10*time.Millisecond, &calls) // 200 ms

	files, err := h.a.ListArchive(context.Background())
	if err != nil || len(files) != 1 {
		t.Fatalf("slow listing: %v, %v; want its one file", files, err)
	}
	h.a.mu.Lock()
	stalled := h.a.ioStallSince
	h.a.mu.Unlock()
	if stalled != nil {
		t.Fatal("a listing that kept making progress marked the archive stalled")
	}
	// A listing that stops making progress still does.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.a.listDir = func(string, func()) ([]RawLogFile, error) { <-release; return nil, nil }
	h.a.mu.Lock()
	h.a.listAt = time.Time{}
	h.a.mu.Unlock()
	var se *ArchiveStalledError
	if _, err := h.a.ListArchive(context.Background()); !errors.As(err, &se) {
		t.Fatalf("hung listing: %v; want stalled", err)
	}
}

// A listing whose request gave up is kept when it finishes: the next request
// is served from it, and requests that come meanwhile wait for it instead of
// listing the share again.
func TestArchiverKeepsAListingTheRequestGaveUpOn(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.ioTimeout = 50 * time.Millisecond
	var calls int32
	slowListing(h, 15, 10*time.Millisecond, &calls) // 150 ms

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := h.a.ListArchive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the impatient request: %v", err)
	}
	// Meanwhile another request waits for the same listing.
	files, err := h.a.ListArchive(context.Background())
	if err != nil || len(files) != 1 {
		t.Fatalf("the waiting request: %v, %v", files, err)
	}
	if _, ok := h.a.cachedList(); !ok {
		t.Fatal("the listing was not kept")
	}
	if n := listCalls(h, &calls); n != 1 {
		t.Fatalf("the archive was listed %d times; want once", n)
	}
	// ListArchiveQuick gives up on a listing that is not cached after the
	// call timeout, and the listing still lands in the cache.
	h.a.mu.Lock()
	h.a.listAt = time.Time{}
	h.a.mu.Unlock()
	start := time.Now()
	if _, err := h.a.ListArchiveQuick(context.Background()); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 120*time.Millisecond {
		t.Fatalf("quick listing: %v after %v; want to give up after about %v", err, time.Since(start), h.a.ioTimeout)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := h.a.cachedList(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the listing a quick request gave up on was never kept")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if files, err := h.a.ListArchiveQuick(context.Background()); err != nil || len(files) != 1 {
		t.Fatalf("quick listing from the cache: %v, %v", files, err)
	}
}

// While a listing holds the slot and keeps answering, a status request is
// answered with the last status instead of queuing a probe behind it.
func TestArchiverStatusDoesNotQueueBehindAListing(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.runPass(context.Background())
	h.a.ioTimeout = 50 * time.Millisecond
	var calls int32
	slowListing(h, 30, 10*time.Millisecond, &calls) // 300 ms
	done := make(chan struct{})
	go func() { _, _ = h.a.ListArchive(context.Background()); close(done) }()
	for listCalls(h, &calls) == 0 {
		time.Sleep(time.Millisecond)
	}
	h.a.mu.Lock()
	h.a.statusAt = h.now.Add(-time.Minute) // due for a new probe
	h.a.mu.Unlock()

	start := time.Now()
	st := h.a.Status(context.Background())
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("status waited %v behind the listing", took)
	}
	if st.Status != ArchiveStatusReady {
		t.Fatalf("status during a listing: %s", st.Status)
	}
	<-done
}

// A pass that moved or deleted files makes a listing that was running
// meanwhile stale: it is not cached.
func TestArchiverDropsAListingTheArchiveChangedUnder(t *testing.T) {
	h := newArchiverHarness(t, true)
	h.initialise()
	h.a.ioTimeout = time.Second
	started := make(chan struct{})
	finish := make(chan struct{})
	h.a.listDir = func(string, func()) ([]RawLogFile, error) {
		close(started)
		<-finish
		return nil, nil
	}
	done := make(chan struct{})
	go func() { _, _ = h.a.ListArchive(context.Background()); close(done) }()
	<-started
	h.a.mu.Lock()
	h.a.invalidateListLocked()
	h.a.mu.Unlock()
	close(finish)
	<-done
	if _, ok := h.a.cachedList(); ok {
		t.Fatal("a listing from before the archive changed was cached")
	}
}
