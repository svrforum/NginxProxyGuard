package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// ── fakes ───────────────────────────────────────────────────────────────────

type fakeReclaimDay struct {
	info    repository.ReclaimChunkInfo
	raw     int64 // access/error raw_log while not nulled
	modsec  int64
	batches int64
	nulled  bool
	// keepsSpace: VACUUM FULL returns nothing (an older snapshot was open).
	keepsSpace bool
}

// fakeReclaimStore is the repository, the catalog and the runner's session
// in one, with a log of what happened and whether the shared maintenance
// lock was held at that moment.
type fakeReclaimStore struct {
	mu        sync.Mutex
	t         *testing.T
	clock     time.Time
	supported bool
	days      map[string]*fakeReclaimDay
	rows      map[string]*repository.ReclaimChunk
	job       repository.ReclaimJob
	nextXID   int64
	events    []string
	shared    bool // the shared maintenance lock is held by the runner
	jobLocked bool // another runner holds the job lock
	sessions  int

	blockers    func() int  // OlderSnapshots count
	sharedBusy  func() bool // another job holds the shared lock right now
	nullHook    func(ctx context.Context) error
	vacuumHook  func(ctx context.Context) error
	failNull    map[string]error // the UPDATE of these days fails so
	planHook    func(ctx context.Context) error
	inNull      chan struct{}
	inVacuum    chan struct{}
	finishCalls []string
}

func newFakeReclaimStore(t *testing.T) *fakeReclaimStore {
	return &fakeReclaimStore{
		t: t, clock: time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC), supported: true,
		days: map[string]*fakeReclaimDay{}, rows: map[string]*repository.ReclaimChunk{},
		job: repository.ReclaimJob{Status: model.RawReclaimIdle}, nextXID: 1000,
	}
}

const mib = int64(1) << 20

// addDay adds a compressed day N days back with the given sizes in MiB.
func (f *fakeReclaimStore) addDay(n int, sizeMiB, rawMiB, modsecMiB int64) string {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
	name := fmt.Sprintf("_timescaledb_internal._hyper_1_%d_chunk", n)
	f.days[name] = &fakeReclaimDay{
		info: repository.ReclaimChunkInfo{
			Name: name, RangeStart: start, RangeEnd: start.AddDate(0, 0, 1), Compressed: true, OldEnough: true,
			SegmentByLogType: true, CompressedRel: fmt.Sprintf("_timescaledb_internal.compress_hyper_2_%d_chunk", n),
			Bytes: sizeMiB * mib, LayoutOK: true,
		},
		raw: rawMiB * mib, modsec: modsecMiB * mib, batches: 100,
	}
	return name
}

func (f *fakeReclaimStore) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *fakeReclaimStore) log(e string) {
	f.events = append(f.events, e)
}

func (f *fakeReclaimStore) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeReclaimStore) dayByRel(rel string) *fakeReclaimDay {
	for _, d := range f.days {
		if d.info.CompressedRel == rel {
			return d
		}
	}
	return nil
}

func (f *fakeReclaimStore) row(name string) repository.ReclaimChunk {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.rows[name]; r != nil {
		return *r
	}
	return repository.ReclaimChunk{}
}

func (f *fakeReclaimStore) jobState() repository.ReclaimJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.job
}

func (f *fakeReclaimStore) Support(context.Context) (bool, string, error) {
	if !f.supported {
		return false, repository.ReclaimUnsupportedCatalog, nil
	}
	return true, "", nil
}

func (f *fakeReclaimStore) ListChunks(context.Context) ([]repository.ReclaimChunkInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []repository.ReclaimChunkInfo
	for _, d := range f.days {
		out = append(out, d.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RangeStart.Before(out[j].RangeStart) })
	return out, nil
}

func (f *fakeReclaimStore) LookupChunk(_ context.Context, name string) (*repository.ReclaimChunkInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.days[name]
	if d == nil {
		return nil, nil
	}
	info := d.info
	return &info, nil
}

func (f *fakeReclaimStore) RawLogStats(_ context.Context, rel string) (repository.RawLogStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.dayByRel(rel)
	if d == nil {
		return repository.RawLogStats{}, &pq.Error{Code: "42P01"}
	}
	st := repository.RawLogStats{ModSecBytes: d.modsec}
	if !d.nulled {
		st.RawBytes, st.PendingBatches = d.raw, d.batches
	}
	return st, nil
}

func (f *fakeReclaimStore) OlderSnapshots(context.Context, int64) (repository.SnapshotBlockers, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log(fmt.Sprintf("horizon shared=%v", f.shared))
	n := 0
	if f.blockers != nil {
		n = f.blockers()
	}
	return repository.SnapshotBlockers{Count: n, PID: 42, Kind: "client backend", State: "idle in transaction"}, nil
}

func (f *fakeReclaimStore) HorizonNow(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextXID++
	return f.nextXID, nil
}

func (f *fakeReclaimStore) OpenSession(context.Context) (repository.ReclaimSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions++
	return &fakeReclaimSession{f: f}, nil
}

func (f *fakeReclaimStore) LoadJob(context.Context) (repository.ReclaimJob, error) {
	return f.jobState(), nil
}

func (f *fakeReclaimStore) BeginJob(_ context.Context, by string, maxChunks *int) (repository.ReclaimJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock
	f.job = repository.ReclaimJob{Status: model.RawReclaimRunning, MaxChunks: maxChunks, RequestedAt: &now, RequestedBy: by, StartedAt: &now}
	return f.job, nil
}

func (f *fakeReclaimStore) ResumeJob(context.Context) (repository.ReclaimJob, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.job.Status != model.RawReclaimRunning {
		return f.job, false, nil
	}
	now := f.clock
	f.job.StartedAt, f.job.FinishedAt, f.job.LastError = &now, nil, ""
	return f.job, true, nil
}

func (f *fakeReclaimStore) FinishJob(_ context.Context, status, lastError string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock
	f.job.Status, f.job.LastError, f.job.FinishedAt = status, lastError, &now
	f.finishCalls = append(f.finishCalls, status)
	f.log("job " + status)
	return nil
}

func (f *fakeReclaimStore) ListChunkRows(context.Context) ([]repository.ReclaimChunk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []repository.ReclaimChunk
	for _, r := range f.rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RangeStart.Before(out[j].RangeStart) })
	return out, nil
}

func (f *fakeReclaimStore) PlanChunk(_ context.Context, p repository.ReclaimPlanRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rows[p.Name]
	if r == nil {
		f.rows[p.Name] = &repository.ReclaimChunk{Name: p.Name, RangeStart: p.RangeStart, RangeEnd: p.RangeEnd,
			State: "pending", BytesBefore: p.BytesBefore, RawBytes: p.RawBytes}
		return nil
	}
	if r.State == "skipped" || r.State == "failed" {
		if r.UpdateXID == nil {
			r.State, r.BytesBefore, r.RawBytes = "pending", p.BytesBefore, p.RawBytes
		} else {
			r.State = "nulled"
		}
		r.LastError = ""
	}
	return nil
}

func (f *fakeReclaimStore) MarkGoneChunks(ctx context.Context) error {
	f.mu.Lock()
	hook := f.planHook
	f.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, r := range f.rows {
		if f.days[name] == nil && r.State != "done" && r.State != "gone" {
			r.State = "gone"
		}
	}
	return nil
}

func (f *fakeReclaimStore) update(name string, fn func(r *repository.ReclaimChunk)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rows[name]
	if r == nil {
		f.t.Errorf("state change for an unknown day %s", name)
		return nil
	}
	fn(r)
	return nil
}

func (f *fakeReclaimStore) MarkGone(_ context.Context, name string) error {
	return f.update(name, func(r *repository.ReclaimChunk) { r.State = "gone" })
}

func (f *fakeReclaimStore) MarkSkipped(_ context.Context, name, reason string) error {
	return f.update(name, func(r *repository.ReclaimChunk) {
		if r.State == "pending" || r.State == "nulled" {
			r.State, r.LastError = "skipped", "skipped: "+reason
		}
	})
}

func (f *fakeReclaimStore) MarkWorked(_ context.Context, name string) error {
	return f.update(name, func(r *repository.ReclaimChunk) { now := f.clock; r.WorkedAt = &now })
}

func (f *fakeReclaimStore) MarkNulled(_ context.Context, name string, before, raw, batches, xid int64) error {
	return f.update(name, func(r *repository.ReclaimChunk) {
		r.State, r.BytesBefore, r.RawBytes, r.UpdateXID, r.LastError = "nulled", before, raw, &xid, ""
		f.log("state " + name + " nulled")
	})
}

func (f *fakeReclaimStore) MarkDone(_ context.Context, name string, before, after, raw int64) error {
	return f.update(name, func(r *repository.ReclaimChunk) {
		r.State, r.BytesBefore, r.BytesAfter, r.RawBytes, r.LastError = "done", before, after, raw, ""
		f.log("state " + name + " done")
	})
}

func (f *fakeReclaimStore) MarkVacuumIneffective(_ context.Context, name string, after int64, msg string) error {
	return f.update(name, func(r *repository.ReclaimChunk) {
		r.Attempts++
		r.BytesAfter, r.LastError = after, msg
	})
}

func (f *fakeReclaimStore) NoteChunkError(_ context.Context, name, msg string, countAttempt bool, failAfter int) (string, error) {
	var state string
	err := f.update(name, func(r *repository.ReclaimChunk) {
		if countAttempt {
			r.Attempts++
			if r.Attempts >= failAfter && (r.State == "pending" || r.State == "nulled") {
				r.State = "failed"
			}
		}
		r.LastError = msg
		state = r.State
	})
	return state, err
}

type fakeReclaimSession struct {
	f      *fakeReclaimStore
	closed bool
}

func (s *fakeReclaimSession) TryJobLock(context.Context) (bool, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	return !s.f.jobLocked, nil
}

func (s *fakeReclaimSession) TrySharedLock(context.Context) (bool, error) {
	s.f.mu.Lock()
	busy := s.f.sharedBusy
	s.f.mu.Unlock()
	if busy != nil && busy() {
		s.f.mu.Lock()
		s.f.log("shared busy")
		s.f.mu.Unlock()
		return false, nil
	}
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if s.f.shared {
		s.f.t.Error("shared maintenance lock taken twice")
	}
	s.f.shared = true
	s.f.log("lock")
	return true, nil
}

func (s *fakeReclaimSession) ReleaseSharedLock() error {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if s.f.shared {
		s.f.shared = false
		s.f.log("unlock")
	}
	return nil
}

func (s *fakeReclaimSession) NullRawLog(ctx context.Context, rel string) (int64, int64, error) {
	s.f.mu.Lock()
	hook, in := s.f.nullHook, s.f.inNull
	s.f.mu.Unlock()
	if in != nil {
		close(in)
	}
	if hook != nil {
		if err := hook(ctx); err != nil {
			return 0, 0, err
		}
	}
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if !s.f.shared {
		s.f.t.Error("UPDATE ran without the shared maintenance lock")
	}
	d := s.f.dayByRel(rel)
	if err := s.f.failNull[d.info.Name]; err != nil {
		s.f.log("null failed " + d.info.Name)
		return 0, 0, err
	}
	d.nulled = true
	s.f.nextXID++
	s.f.log("null " + d.info.Name)
	return d.batches, s.f.nextXID, nil
}

func (s *fakeReclaimSession) VacuumFull(ctx context.Context, rel string) (int64, error) {
	s.f.mu.Lock()
	hook, in := s.f.vacuumHook, s.f.inVacuum
	s.f.mu.Unlock()
	if in != nil {
		close(in)
	}
	if hook != nil {
		if err := hook(ctx); err != nil {
			return 0, err
		}
	}
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if !s.f.shared {
		s.f.t.Error("VACUUM FULL ran without the shared maintenance lock")
	}
	d := s.f.dayByRel(rel)
	s.f.log("vacuum " + d.info.Name)
	if d.nulled && !d.keepsSpace && d.raw > 0 {
		d.info.Bytes -= d.raw
		d.raw = 0
	}
	return d.info.Bytes, nil
}

func (s *fakeReclaimSession) Close() error {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if s.f.shared {
		s.f.t.Error("session closed while still holding the shared maintenance lock")
	}
	s.closed = true
	return nil
}

type fakeProbe struct {
	mu       sync.Mutex
	free     uint64
	ok       bool
	critical int // DBCritical answers true this many more times
	calls    int
}

func (p *fakeProbe) DBFree(context.Context) (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.free, p.ok
}

func (p *fakeProbe) DBCritical() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.critical > 0 {
		p.critical--
		return true
	}
	return false
}

// newTestReclaim wires a service to the fake with instant sleeps that move the
// fake clock and note whether the shared lock was held while sleeping.
func newTestReclaim(t *testing.T, f *fakeReclaimStore, probe *fakeProbe) *RawLogReclaimService {
	s := NewRawLogReclaimService(f, RawLogReclaimOptions{Pause: 30 * time.Second, ResumeDelay: 5 * time.Minute})
	s.now = f.now
	s.sleep = func(ctx context.Context, d time.Duration) {
		f.mu.Lock()
		f.clock = f.clock.Add(d)
		f.log(fmt.Sprintf("sleep %s shared=%v", d, f.shared))
		f.mu.Unlock()
	}
	if probe != nil {
		s.SetDiskProbe(probe)
	}
	t.Cleanup(s.Shutdown)
	return s
}

func plenty() *fakeProbe { return &fakeProbe{free: uint64(100 << 30), ok: true} }

// waitRun waits for the current runner to end.
func waitRun(t *testing.T, s *RawLogReclaimService) {
	t.Helper()
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	if done == nil {
		t.Fatal("no runner was started")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the runner did not finish")
	}
}

func eventsMatching(events []string, prefix string) []string {
	var out []string
	for _, e := range events {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestRawReclaimPendingNulledDone(t *testing.T) {
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 498, 231, 20)
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)

	r := f.row(day)
	if r.State != "done" || r.BytesBefore != 498*mib || r.BytesAfter != 267*mib || r.RawBytes != 231*mib {
		t.Fatalf("day = %+v; want done 498 MiB -> 267 MiB", r)
	}
	if j := f.jobState(); j.Status != model.RawReclaimDone || j.RequestedBy != "admin" || j.LastError != "" {
		t.Fatalf("job = %+v; want done, requested by admin", j)
	}
	ev := eventsMatching(f.eventLog(), "")
	want := []string{"lock", "null " + day, "unlock", "state " + day + " nulled", "horizon shared=false", "lock", "vacuum " + day, "unlock", "state " + day + " done", "job done"}
	if strings.Join(ev, "|") != strings.Join(want, "|") {
		t.Fatalf("events\n  %v\nwant\n  %v", ev, want)
	}
	st, err := s.Status(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if st.ChunksDone != 1 || st.ChunksTotal != 1 || st.ReclaimedBytes != 231*mib || st.RemainingRawBytes != 0 || st.CurrentChunk != nil {
		t.Fatalf("status = %+v", st)
	}
}

func TestRawReclaimHorizonTimeoutKeepsNulled(t *testing.T) {
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 100, 40, 0)
	f.blockers = func() int { return 1 } // an old transaction never ends
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)

	r := f.row(day)
	if r.State != "nulled" || r.Attempts != 0 || !strings.Contains(r.LastError, "pid 42") {
		t.Fatalf("day = %+v; want still nulled, no attempt counted, the blocker named", r)
	}
	if len(eventsMatching(f.eventLog(), "vacuum")) != 0 {
		t.Fatal("VACUUM FULL ran although an older transaction was open")
	}
	if j := f.jobState(); j.Status != model.RawReclaimFailed || !strings.Contains(j.LastError, "1 day(s) could not be finished") {
		t.Fatalf("job = %+v", j)
	}
	// It waited the full ten minutes, without the shared lock.
	var waited time.Duration
	for _, e := range eventsMatching(f.eventLog(), "sleep") {
		if !strings.HasSuffix(e, "shared=false") {
			t.Fatalf("slept holding the shared lock: %s", e)
		}
		waited += rawReclaimHorizonPoll
	}
	if waited < rawReclaimHorizonTimeout {
		t.Fatalf("waited %s for the horizon; want %s", waited, rawReclaimHorizonTimeout)
	}
}

func TestRawReclaimIneffectiveVacuumCountsAnAttempt(t *testing.T) {
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 100, 40, 0)
	f.days[day].keepsSpace = true
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	r := f.row(day)
	if r.State != "nulled" || r.Attempts != 1 || r.BytesAfter != 100*mib || !strings.Contains(r.LastError, "VACUUM FULL left it") {
		t.Fatalf("day = %+v; want nulled with one attempt", r)
	}

	// The next run tries it again, first, and succeeds once space comes back.
	f.mu.Lock()
	f.days[day].keepsSpace = false
	f.mu.Unlock()
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(day); r.State != "done" || r.BytesAfter != 60*mib {
		t.Fatalf("day = %+v; want done after the second run", r)
	}
}

func TestRawReclaimStopCancelsWithoutChangingTheDay(t *testing.T) {
	for _, step := range []string{"null", "vacuum"} {
		t.Run(step, func(t *testing.T) {
			f := newFakeReclaimStore(t)
			day := f.addDay(1, 100, 40, 0)
			in := make(chan struct{})
			block := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
			if step == "null" {
				f.inNull, f.nullHook = in, block
			} else {
				f.inVacuum, f.vacuumHook = in, block
			}
			s := newTestReclaim(t, f, plenty())
			if _, err := s.Start(context.Background(), "admin", nil); err != nil {
				t.Fatal(err)
			}
			<-in
			st, err := s.Stop(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if step == "vacuum" {
				want = "nulled"
			}
			if r := f.row(day); r.State != want || r.LastError != "" || r.Attempts != 0 {
				t.Fatalf("day = %+v; want %s, untouched", r, want)
			}
			if st.Status != model.RawReclaimPaused || f.jobState().Status != model.RawReclaimPaused {
				t.Fatalf("status %q / job %q; want paused", st.Status, f.jobState().Status)
			}
			if got := strings.Join(f.finishCalls, ","); got != "paused" {
				t.Fatalf("job writes %s; the runner must not overwrite the stop", got)
			}
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if running {
				t.Fatal("still running after Stop returned")
			}
		})
	}
}

func TestRawReclaimResumePicksNulledBeforePending(t *testing.T) {
	f := newFakeReclaimStore(t)
	big := f.addDay(1, 900, 500, 0)  // pending, the most raw_log
	small := f.addDay(2, 100, 40, 0) // nulled by the interrupted run
	f.days[small].nulled = true
	xid := int64(900)
	start := f.clock.Add(-time.Hour)
	// The small day was nulled by an earlier request; this request was
	// interrupted before it touched anything. Nulled-first is what orders it.
	earlier := start.Add(-time.Hour)
	f.rows[big] = &repository.ReclaimChunk{Name: big, RangeStart: f.days[big].info.RangeStart, State: "pending", BytesBefore: 900 * mib, RawBytes: 500 * mib}
	f.rows[small] = &repository.ReclaimChunk{Name: small, RangeStart: f.days[small].info.RangeStart, State: "nulled",
		BytesBefore: 100 * mib, RawBytes: 40 * mib, UpdateXID: &xid, WorkedAt: &earlier}
	f.job = repository.ReclaimJob{Status: model.RawReclaimRunning, RequestedAt: &start, RequestedBy: "admin"}

	s := newTestReclaim(t, f, plenty())
	s.ResumeIfRunning(context.Background())
	waitRun(t, s)

	var order []string
	for _, e := range f.eventLog() {
		if strings.HasPrefix(e, "vacuum ") || strings.HasPrefix(e, "null ") {
			order = append(order, e)
		}
	}
	want := []string{"vacuum " + small, "null " + big, "vacuum " + big}
	if strings.Join(order, "|") != strings.Join(want, "|") {
		t.Fatalf("order %v; want %v", order, want)
	}
	if f.row(small).State != "done" || f.row(big).State != "done" || f.jobState().Status != model.RawReclaimDone {
		t.Fatalf("small %s, big %s, job %s", f.row(small).State, f.row(big).State, f.jobState().Status)
	}
	if ev := eventsMatching(f.eventLog(), "sleep 5m0s"); len(ev) != 1 {
		t.Fatalf("resume delay sleeps: %v", ev)
	}
}

func TestRawReclaimMaxChunksLargestFirst(t *testing.T) {
	f := newFakeReclaimStore(t)
	a := f.addDay(1, 100, 10, 0)
	b := f.addDay(2, 300, 200, 0)
	c := f.addDay(3, 200, 120, 0)
	s := newTestReclaim(t, f, plenty())
	two := 2
	if _, err := s.Start(context.Background(), "admin", &two); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if f.row(b).State != "done" || f.row(c).State != "done" || f.row(a).State != "pending" {
		t.Fatalf("states a=%s b=%s c=%s; want the two largest done", f.row(a).State, f.row(b).State, f.row(c).State)
	}
	if f.jobState().Status != model.RawReclaimDone {
		t.Fatalf("job %s", f.jobState().Status)
	}
	// One pause, between the two days, and never with the lock held.
	pauses := eventsMatching(f.eventLog(), "sleep 30s")
	if len(pauses) != 1 || pauses[0] != "sleep 30s shared=false" {
		t.Fatalf("pauses %v", pauses)
	}
}

func TestRawReclaimWaitsWhileTheDiskIsCritical(t *testing.T) {
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 100, 40, 0)
	probe := plenty()
	probe.critical = 3
	s := newTestReclaim(t, f, probe)
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	ev := f.eventLog()
	firstLock := -1
	diskWaits := 0
	for i, e := range ev {
		if e == "lock" && firstLock < 0 {
			firstLock = i
		}
		if strings.HasPrefix(e, "sleep 30s") && firstLock < 0 {
			diskWaits++
		}
	}
	if diskWaits != 3 {
		t.Fatalf("waited %d times before the first rewrite; want 3 (events %v)", diskWaits, ev)
	}
	if f.row(day).State != "done" {
		t.Fatalf("day %s", f.row(day).State)
	}
}

func TestRawReclaimRefusesWhenFreeSpaceIsUnknown(t *testing.T) {
	f := newFakeReclaimStore(t)
	f.addDay(1, 100, 40, 0)

	// No probe at all (DiskGuard disabled).
	s := newTestReclaim(t, f, nil)
	_, err := s.Start(context.Background(), "admin", nil)
	var pre *RawReclaimPreconditionError
	if !errors.As(err, &pre) || pre.Code != "free_space_unknown" {
		t.Fatalf("err = %v; want free_space_unknown", err)
	}
	// A probe that cannot measure.
	s2 := newTestReclaim(t, f, &fakeProbe{ok: false})
	if _, err := s2.Start(context.Background(), "admin", nil); !errors.As(err, &pre) || pre.Code != "free_space_unknown" {
		t.Fatalf("err = %v; want free_space_unknown", err)
	}
	if f.jobState().Status != model.RawReclaimIdle || len(eventsMatching(f.eventLog(), "null")) != 0 {
		t.Fatalf("job %s, events %v: nothing may change", f.jobState().Status, f.eventLog())
	}
	// Mid-run the measurement fails: the job stops with that reason.
	probe := plenty()
	s3 := newTestReclaim(t, f, probe)
	f.nullHook = func(context.Context) error {
		probe.mu.Lock()
		probe.ok = false
		probe.mu.Unlock()
		return nil
	}
	f.addDay(2, 50, 20, 0)
	if _, err := s3.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s3)
	if j := f.jobState(); j.Status != model.RawReclaimFailed || j.LastError != rawReclaimFreeUnknownMsg {
		t.Fatalf("job = %+v", j)
	}
}

func TestRawReclaimRefusesWithoutRoom(t *testing.T) {
	f := newFakeReclaimStore(t)
	f.addDay(1, 4096, 1024, 0) // needs 2 x 3 GiB + 1 GiB
	s := newTestReclaim(t, f, &fakeProbe{free: uint64(5 << 30), ok: true})
	_, err := s.Start(context.Background(), "admin", nil)
	var pre *RawReclaimPreconditionError
	if !errors.As(err, &pre) || pre.Code != "insufficient_space" || pre.RequiredBytes != 7<<30 || pre.FreeBytes != 5<<30 {
		t.Fatalf("err = %#v", err)
	}
}

func TestRawReclaimSharedLockIsRetriedAndOnlyHeldForRewrites(t *testing.T) {
	f := newFakeReclaimStore(t)
	f.addDay(1, 100, 40, 0)
	f.addDay(2, 100, 30, 0)
	busy := 2
	f.sharedBusy = func() bool { // the emergency compression holds it twice
		f.mu.Lock()
		defer f.mu.Unlock()
		if busy > 0 {
			busy--
			return true
		}
		return false
	}
	f.blockers = func() int { return 0 }
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	ev := f.eventLog()
	if n := len(eventsMatching(ev, "shared busy")); n != 2 {
		t.Fatalf("busy answers %d; want 2", n)
	}
	if n := len(eventsMatching(ev, "lock")); n != 4 {
		t.Fatalf("lock taken %d times; want 4 (UPDATE and VACUUM FULL of two days)", n)
	}
	if n := len(eventsMatching(ev, "unlock")); n != 4 {
		t.Fatalf("lock released %d times; want 4", n)
	}
	for _, e := range ev {
		if strings.HasPrefix(e, "sleep") || strings.HasPrefix(e, "horizon") {
			if !strings.HasSuffix(e, "shared=false") {
				t.Fatalf("waited while holding the shared lock: %s (events %v)", e, ev)
			}
		}
	}
	if n := len(eventsMatching(ev, "sleep 15s")); n != 2 {
		t.Fatalf("lock retries %d; want 2", n)
	}
}

func TestRawReclaimSecondStartIsRejected(t *testing.T) {
	f := newFakeReclaimStore(t)
	f.addDay(1, 100, 40, 0)
	in := make(chan struct{})
	release := make(chan struct{})
	f.inNull = in
	f.nullHook = func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	<-in
	if _, err := s.Start(context.Background(), "admin", nil); !errors.Is(err, ErrRawReclaimRunning) {
		t.Fatalf("second Start: %v; want ErrRawReclaimRunning", err)
	}
	close(release)
	waitRun(t, s)

	// Another process holds the job lock.
	f.jobLocked = true
	f.addDay(2, 100, 40, 0)
	if _, err := s.Start(context.Background(), "admin", nil); !errors.Is(err, ErrRawReclaimRunning) {
		t.Fatalf("Start with the lock held elsewhere: %v; want ErrRawReclaimRunning", err)
	}
}

func TestRawReclaimUnsupportedRefuses(t *testing.T) {
	f := newFakeReclaimStore(t)
	f.supported = false
	s := newTestReclaim(t, f, plenty())
	_, err := s.Start(context.Background(), "admin", nil)
	var pre *RawReclaimPreconditionError
	if !errors.As(err, &pre) || pre.Code != "unsupported" || pre.Reason != repository.ReclaimUnsupportedCatalog {
		t.Fatalf("err = %v", err)
	}
	st, err := s.Status(context.Background(), true)
	if err != nil || st.Supported || st.UnsupportedReason != repository.ReclaimUnsupportedCatalog {
		t.Fatalf("status %+v, %v", st, err)
	}
}

func TestRawReclaimSkipsDaysThatStoppedQualifying(t *testing.T) {
	f := newFakeReclaimStore(t)
	keep := f.addDay(1, 100, 50, 0)
	partial := f.addDay(2, 100, 40, 0)
	gone := f.addDay(3, 100, 30, 0)
	s := newTestReclaim(t, f, plenty())
	// Planning sees all three. While the first day is being processed, one of
	// the others gets rows added after compression and one is dropped.
	var once sync.Once
	f.nullHook = func(context.Context) error {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.days[partial].info.Partial = true
			delete(f.days, gone)
		})
		return nil
	}
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(keep); r.State != "done" {
		t.Fatalf("first day = %+v", r)
	}
	if r := f.row(partial); r.State != "skipped" || !strings.Contains(r.LastError, "partially compressed") {
		t.Fatalf("partial day = %+v", r)
	}
	if r := f.row(gone); r.State != "gone" {
		t.Fatalf("dropped day = %+v", r)
	}
	if j := f.jobState(); j.Status != model.RawReclaimDone {
		t.Fatalf("job = %+v; skipped and dropped days do not fail it", j)
	}
	st, _ := s.Status(context.Background(), false)
	if st.ChunksTotal != 2 || st.ChunksSkipped != 1 || st.ChunksDone != 1 {
		t.Fatalf("status = %+v; a dropped day is not counted", st)
	}

	// A later start brings the partial day back once it qualifies again.
	f.mu.Lock()
	f.days[partial].info.Partial = false
	f.mu.Unlock()
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(partial); r.State != "done" {
		t.Fatalf("partial day after it qualified again = %+v", r)
	}
}

func TestRawReclaimLostNulledRecordIsFinished(t *testing.T) {
	// An earlier run's UPDATE committed but recording it failed: the day reads
	// pending with nothing left to remove and its space not returned.
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 100, 40, 0)
	f.days[day].nulled = true
	f.rows[day] = &repository.ReclaimChunk{Name: day, RangeStart: f.days[day].info.RangeStart, State: "pending", BytesBefore: 100 * mib, RawBytes: 40 * mib}
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(day); r.State != "done" || r.BytesAfter != 60*mib {
		t.Fatalf("day = %+v; want compacted to 60 MiB", r)
	}
	if n := len(eventsMatching(f.eventLog(), "null ")); n != 0 {
		t.Fatalf("UPDATE ran again: %v", f.eventLog())
	}
}

func TestRawReclaimUnexpectedErrorStopsTheJobAndCountsAnAttempt(t *testing.T) {
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 100, 40, 0)
	f.nullHook = func(context.Context) error {
		return fmt.Errorf("update: %w", &pq.Error{Code: "XX000", Message: "internal error at line 3"})
	}
	s := newTestReclaim(t, f, plenty())
	for i := 1; i <= rawReclaimFailAfter; i++ {
		if _, err := s.Start(context.Background(), "admin", nil); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		waitRun(t, s)
		j := f.jobState()
		if j.Status != model.RawReclaimFailed || !strings.Contains(j.LastError, "SQLSTATE XX000") || strings.Contains(j.LastError, "line 3") {
			t.Fatalf("run %d: job = %+v; want failed, the SQLSTATE kept and the driver text cut", i, j)
		}
		if got := f.row(day).Attempts; got != i {
			t.Fatalf("run %d: attempts %d", i, got)
		}
	}
	if r := f.row(day); r.State != "failed" {
		t.Fatalf("day = %+v; want failed after %d attempts", r, rawReclaimFailAfter)
	}
	// Another Start gives it one more try, which fails it again at once.
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(day); r.State != "failed" || r.Attempts != rawReclaimFailAfter+1 {
		t.Fatalf("day = %+v; want failed again after one more try", r)
	}
	// Once whatever broke it is fixed, a Start finishes it.
	f.mu.Lock()
	f.nullHook = nil
	f.mu.Unlock()
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(day); r.State != "done" {
		t.Fatalf("day = %+v; want done once it no longer fails", r)
	}
}

// A lost database connection is not the day's fault: the run stops and says
// so, but the day is not counted, so it never becomes failed this way.
func TestRawReclaimConnectionLossIsNotCountedAgainstTheDay(t *testing.T) {
	for _, lost := range []error{
		&pq.Error{Code: "57P01", Message: "terminating connection due to administrator command"},
		&pq.Error{Code: "57P02", Message: "terminating connection due to crash of another server process"},
		&pq.Error{Code: "08006", Message: "connection failure"},
		driver.ErrBadConn,
		io.EOF,
		fmt.Errorf("update: %w", io.ErrUnexpectedEOF),
	} {
		t.Run(lost.Error(), func(t *testing.T) {
			f := newFakeReclaimStore(t)
			day := f.addDay(1, 100, 40, 0)
			f.failNull = map[string]error{day: lost}
			s := newTestReclaim(t, f, plenty())
			for i := 1; i <= rawReclaimFailAfter+1; i++ {
				if _, err := s.Start(context.Background(), "admin", nil); err != nil {
					t.Fatalf("run %d: %v", i, err)
				}
				waitRun(t, s)
				if j := f.jobState(); j.Status != model.RawReclaimFailed || !strings.Contains(j.LastError, "connection to the database was lost") {
					t.Fatalf("run %d: job = %+v; want failed, naming the lost connection", i, j)
				}
			}
			if r := f.row(day); r.State != "pending" || r.Attempts != 0 {
				t.Fatalf("day = %+v; want still pending, no attempt counted", r)
			}
		})
	}
}

// failedDay records name as failed after rawReclaimFailAfter attempts; nulled
// says its UPDATE had committed, so its raw_log is gone already.
func (f *fakeReclaimStore) failedDay(name string, nulled bool) {
	d := f.days[name]
	r := &repository.ReclaimChunk{Name: name, RangeStart: d.info.RangeStart, RangeEnd: d.info.RangeEnd, State: "failed",
		BytesBefore: d.info.Bytes, RawBytes: d.raw, Attempts: rawReclaimFailAfter, LastError: "boom"}
	if nulled {
		xid := int64(500)
		r.UpdateXID = &xid
		d.nulled = true
	}
	f.rows[name] = r
}

// An explicit Start gives each failed day one more try, after every other
// day, so a day that keeps failing cannot hold up the rest; one whose
// raw_log was already removed comes back to be compacted.
func TestRawReclaimStartRetriesFailedDaysLast(t *testing.T) {
	f := newFakeReclaimStore(t)
	bad := f.addDay(1, 900, 500, 0) // the most raw_log: it would go first
	nulled := f.addDay(2, 300, 200, 0)
	good := f.addDay(3, 100, 40, 0)
	f.failedDay(bad, false)
	f.failedDay(nulled, true)
	f.failNull = map[string]error{bad: &pq.Error{Code: "XX000", Message: "still broken"}}
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)

	var order []string
	for _, e := range f.eventLog() {
		if strings.HasPrefix(e, "null ") || strings.HasPrefix(e, "vacuum ") {
			order = append(order, e)
		}
	}
	want := []string{"null " + good, "vacuum " + good, "vacuum " + nulled, "null failed " + bad}
	if strings.Join(order, "|") != strings.Join(want, "|") {
		t.Fatalf("order %v; want %v", order, want)
	}
	if r := f.row(nulled); r.State != "done" {
		t.Fatalf("the failed day whose raw_log was gone = %+v; want compacted", r)
	}
	if r := f.row(bad); r.State != "failed" || r.Attempts != rawReclaimFailAfter+1 {
		t.Fatalf("the day that still fails = %+v; want failed after one more try", r)
	}
	if j := f.jobState(); j.Status != model.RawReclaimFailed {
		t.Fatalf("job = %+v", j)
	}
}

// A resume after a restart carries on with the request as it was: failed
// days stay failed until someone presses Start.
func TestRawReclaimResumeLeavesFailedDaysAlone(t *testing.T) {
	f := newFakeReclaimStore(t)
	bad := f.addDay(1, 900, 500, 0)
	good := f.addDay(2, 100, 40, 0)
	f.failedDay(bad, false)
	start := f.clock.Add(-time.Hour)
	f.job = repository.ReclaimJob{Status: model.RawReclaimRunning, RequestedAt: &start, RequestedBy: "admin"}
	s := newTestReclaim(t, f, plenty())
	s.ResumeIfRunning(context.Background())
	waitRun(t, s)
	if r := f.row(bad); r.State != "failed" || r.Attempts != rawReclaimFailAfter {
		t.Fatalf("failed day after a resume = %+v; want left alone", r)
	}
	if r := f.row(good); r.State != "done" || f.jobState().Status != model.RawReclaimDone {
		t.Fatalf("other day %+v, job %s", r, f.jobState().Status)
	}
}

// How a failed step is taken: what stops the run, and what counts against
// the day.
func TestRawReclaimChunkErrorKinds(t *testing.T) {
	f := newFakeReclaimStore(t)
	day := f.addDay(1, 100, 40, 0)
	f.rows[day] = &repository.ReclaimChunk{Name: day, RangeStart: f.days[day].info.RangeStart, State: "pending"}
	s := newTestReclaim(t, f, plenty())
	for _, tc := range []struct {
		err     error
		kind    rawOutcomeKind
		counted bool
	}{
		{&pq.Error{Code: "55P03"}, rawOutcomeDeferred, false},
		{&pq.Error{Code: "42P01"}, rawOutcomeDeferred, false},
		{&pq.Error{Code: "57014"}, rawOutcomeDeferred, true},
		{&pq.Error{Code: "53100"}, rawOutcomeFatal, false},
		{&pq.Error{Code: "57P01"}, rawOutcomeFatal, false},
		{&pq.Error{Code: "57P03"}, rawOutcomeFatal, false},
		{&pq.Error{Code: "08003"}, rawOutcomeFatal, false},
		{driver.ErrBadConn, rawOutcomeFatal, false},
		{sql.ErrConnDone, rawOutcomeFatal, false},
		{io.EOF, rawOutcomeFatal, false},
		{&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, rawOutcomeFatal, false},
		{&pq.Error{Code: "XX000"}, rawOutcomeFatal, true},
		{errors.New("something else"), rawOutcomeFatal, true},
	} {
		before := f.row(day).Attempts
		out := s.chunkError(context.Background(), f.row(day), "compacting", tc.err)
		counted := f.row(day).Attempts > before
		if out.kind != tc.kind || counted != tc.counted {
			t.Errorf("%v: kind %d counted %v; want kind %d counted %v", tc.err, out.kind, counted, tc.kind, tc.counted)
		}
		f.mu.Lock()
		f.rows[day].Attempts, f.rows[day].State = 0, "pending"
		f.mu.Unlock()
	}
}

func TestRawReclaimLockTimeoutDefersTheDay(t *testing.T) {
	f := newFakeReclaimStore(t)
	busyDay := f.addDay(1, 100, 40, 0)
	other := f.addDay(2, 100, 30, 0)
	f.vacuumHook = func(context.Context) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.days[busyDay].nulled && f.days[busyDay].raw > 0 && f.rows[busyDay].State == "nulled" && f.rows[other].State == "pending" {
			return &pq.Error{Code: "55P03", Message: "canceling statement due to lock timeout"}
		}
		return nil
	}
	s := newTestReclaim(t, f, plenty())
	if _, err := s.Start(context.Background(), "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	if r := f.row(busyDay); r.State != "nulled" || r.Attempts != 0 || !strings.Contains(r.LastError, "in use") {
		t.Fatalf("busy day = %+v", r)
	}
	if r := f.row(other); r.State != "done" {
		t.Fatalf("other day = %+v; the busy one must not hold it up", r)
	}
}

func TestWorkOrder(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	req := t0.Add(time.Hour)
	worked := req.Add(time.Minute)
	earlier := t0
	rows := []repository.ReclaimChunk{
		{Name: "pending-small", State: "pending", RawBytes: 1, RangeStart: t0},
		{Name: "done", State: "done", RawBytes: 99, RangeStart: t0},
		{Name: "pending-big", State: "pending", RawBytes: 50, RangeStart: t0},
		{Name: "nulled-retried", State: "nulled", RawBytes: 80, Attempts: 2, RangeStart: t0},
		{Name: "nulled", State: "nulled", RawBytes: 5, RangeStart: t0},
		{Name: "pending-started", State: "pending", RawBytes: 2, WorkedAt: &worked, RangeStart: t0},
		{Name: "pending-old-request", State: "pending", RawBytes: 3, WorkedAt: &earlier, RangeStart: t0},
		{Name: "skipped", State: "skipped", RawBytes: 70, RangeStart: t0},
		{Name: "failed-before", State: "nulled", RawBytes: 99, Attempts: rawReclaimFailAfter, RangeStart: t0},
	}
	var got []string
	for _, r := range workOrder(rows, &req) {
		got = append(got, r.Name)
	}
	want := "pending-started,nulled,nulled-retried,pending-big,pending-old-request,pending-small,failed-before"
	if strings.Join(got, ",") != want {
		t.Fatalf("order %v; want %s", got, want)
	}
	if countWorked(rows, &req) != 1 {
		t.Fatal("countWorked")
	}
}

func TestRawReclaimNeedAndVerify(t *testing.T) {
	if got := rawReclaimNeed(498*mib, 231*mib); got != 2*267*mib+(1<<30) {
		t.Fatalf("need %d", got)
	}
	if got := rawReclaimNeed(10, 20); got != 1<<30 {
		t.Fatalf("need with raw > size %d", got)
	}
	if vacuumIneffective(498*mib, 267*mib, 231*mib) {
		t.Fatal("a 231 MiB drop is effective")
	}
	if !vacuumIneffective(498*mib, 400*mib, 231*mib) {
		t.Fatal("a 98 MiB drop of 231 MiB is not")
	}
	if vacuumIneffective(10*mib, 10*mib, 512<<10) {
		t.Fatal("below 1 MiB of raw_log the size cannot tell")
	}
}

// An API stop while a resumed run is still planning leaves the job running,
// to be resumed after the next start, instead of failed.
func TestRawReclaimShutdownWhileAResumePlansKeepsTheJob(t *testing.T) {
	f := newFakeReclaimStore(t)
	f.addDay(1, 100, 40, 0)
	start := f.clock.Add(-time.Hour)
	f.job = repository.ReclaimJob{Status: model.RawReclaimRunning, RequestedAt: &start, RequestedBy: "admin"}
	planning := make(chan struct{})
	f.planHook = func(ctx context.Context) error {
		close(planning)
		<-ctx.Done()
		return ctx.Err()
	}
	s := newTestReclaim(t, f, plenty())
	done := make(chan struct{})
	go func() { s.ResumeIfRunning(context.Background()); close(done) }()
	<-planning
	s.Shutdown()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the resume did not end with the API")
	}
	if j := f.jobState(); j.Status != model.RawReclaimRunning || j.LastError != "" || len(f.finishCalls) != 0 {
		t.Fatalf("job = %+v after %v; want still running, nothing recorded", j, f.finishCalls)
	}
}
