package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// Raw log reclaim: an opt-in job, started from Settings > Maintenance, that
// removes the raw_log copies of access and error lines kept inside old
// compressed log history, one day (chunk) at a time:
//
//  1. pending -> nulled: one short UPDATE of the day's compressed relation;
//     its transaction id is recorded with the state.
//  2. Wait until no snapshot or transaction at or before that id is left in
//     the cluster: VACUUM FULL keeps the removed values until then, silently.
//  3. VACUUM FULL the relation and check by size that the space came back:
//     nulled -> done, or one more attempt and nulled for the next run.
//
// Largest raw_log first, and days already nulled before the rest, so a resumed
// run first finishes what an interrupted one started. ModSecurity batches and
// uncompressed days are never touched. The repository explains the SQL.
//
// Locks: one runner per database (s.running here, RawLogReclaimJobLockKey on
// the runner's session), and StorageMaintenanceLockKey — the emergency
// compression's — only around each rewrite, never while waiting for the
// horizon or pausing between days. Before each day the job waits while the
// database disk is critical (the emergency compression's turn), and stops
// when free space is unknown or below twice the day's size without raw_log
// plus 1 GiB. The disk being merely low is when reclaiming helps; it runs.

const (
	rawReclaimDefaultPause   = 30 * time.Second
	rawReclaimResumeDelay    = 5 * time.Minute
	rawReclaimHorizonPoll    = 5 * time.Second
	rawReclaimHorizonTimeout = 10 * time.Minute
	rawReclaimLockRetry      = 15 * time.Second
	rawReclaimDiskRetry      = 30 * time.Second
	rawReclaimResumeRetry    = time.Minute
	rawReclaimResumeTries    = 30
	rawReclaimEstimateTTL    = 10 * time.Minute
	rawReclaimSupportTTL     = 10 * time.Minute
	rawReclaimStopWait       = 10 * time.Second
	// A day that hits an unexpected error this many times, or loses the
	// database connection this many times in a row, becomes failed and is
	// left alone, so one bad day cannot hold up the rest; a run started by
	// hand gives it one more try, after every other day, when it gets to it.
	rawReclaimFailAfter = 3
	// After a lost connection the database may be restarting (a crash ends
	// every session and recovery refuses new ones for a while): what the run
	// must record is tried again every few seconds, for a while.
	rawReclaimRecordRetry          = 5 * time.Second
	rawReclaimRecordFor            = 5 * time.Minute
	rawReclaimMargin         int64 = 1 << 30
	rawReclaimVerifyMinBytes int64 = 1 << 20
)

// rawReclaimNeed is the free space a day needs: VACUUM FULL writes a new copy
// of it without raw_log, plus about as much WAL, before the old copy goes.
func rawReclaimNeed(bytesBefore, rawBytes int64) int64 {
	post := bytesBefore - rawBytes
	if post < 0 {
		post = 0
	}
	return 2*post + rawReclaimMargin
}

// RawLogReclaimDiskProbe is what the job needs to know about the database's
// disk. *DiskGuard implements it (D1).
type RawLogReclaimDiskProbe interface {
	DBFree(ctx context.Context) (avail uint64, ok bool)
	DBCritical() bool
}

type rawReclaimStore interface {
	Support(ctx context.Context) (bool, string, error)
	ListChunks(ctx context.Context) ([]repository.ReclaimChunkInfo, error)
	LookupChunk(ctx context.Context, name string) (*repository.ReclaimChunkInfo, error)
	RawLogStats(ctx context.Context, rel string) (repository.RawLogStats, error)
	OlderSnapshots(ctx context.Context, xid int64) (repository.SnapshotBlockers, error)
	HorizonNow(ctx context.Context) (int64, error)
	OpenSession(ctx context.Context) (repository.ReclaimSession, error)

	LoadJob(ctx context.Context) (repository.ReclaimJob, error)
	BeginJob(ctx context.Context, by string, maxChunks *int) (repository.ReclaimJob, error)
	ResumeJob(ctx context.Context) (repository.ReclaimJob, bool, error)
	FinishJob(ctx context.Context, status, lastError string) error

	ListChunkRows(ctx context.Context) ([]repository.ReclaimChunk, error)
	PlanChunk(ctx context.Context, p repository.ReclaimPlanRow) error
	ReviveChunk(ctx context.Context, name string) (string, error)
	MarkGoneChunks(ctx context.Context) error
	MarkGone(ctx context.Context, name string) error
	MarkSkipped(ctx context.Context, name, reason string) error
	MarkWorked(ctx context.Context, name string) error
	MarkNulled(ctx context.Context, name string, bytesBefore, rawBytes, batches, xid int64) error
	MarkDone(ctx context.Context, name string, bytesBefore, bytesAfter, rawBytes int64) error
	MarkVacuumIneffective(ctx context.Context, name string, bytesAfter int64, msg string) error
	NoteChunkError(ctx context.Context, name, msg string, countAttempt bool, failAfter int) (string, error)
	NoteConnectionLoss(ctx context.Context, name, msg string, failAfter int) (string, error)
}

// ErrRawReclaimRunning: a runner already exists (409).
var ErrRawReclaimRunning = errors.New("the raw log reclaim is already running")

// RawReclaimMaxChunks is the largest max_chunks: it is stored in an integer
// column.
const RawReclaimMaxChunks = math.MaxInt32

// ErrRawReclaimInvalid: max_chunks below 1 or above RawReclaimMaxChunks (400).
var ErrRawReclaimInvalid = errors.New("max_chunks must be between 1 and 2147483647")

// RawReclaimPreconditionError is why the job cannot start now (412). Code is
// unsupported, free_space_unknown or insufficient_space.
type RawReclaimPreconditionError struct {
	Code          string
	Reason        string // the unsupported reason code
	FreeBytes     int64
	RequiredBytes int64
}

func (e *RawReclaimPreconditionError) Error() string {
	switch e.Code {
	case "unsupported":
		return "this database cannot run the raw log reclaim (" + e.Reason + ")"
	case "free_space_unknown":
		return rawReclaimFreeUnknownMsg
	}
	return fmt.Sprintf("not enough free space on the database disk: the first day needs %s, %s is free",
		formatBytes(e.RequiredBytes), formatBytes(e.FreeBytes))
}

const rawReclaimFreeUnknownMsg = "the free space on the database disk cannot be measured, so the reclaim does not run (it needs room to rewrite each day)"

// RawLogReclaimOptions: Pause is NPG_RAW_RECLAIM_PAUSE (0 is allowed);
// ResumeDelay is how long after an API start an interrupted run resumes.
type RawLogReclaimOptions struct {
	Pause       time.Duration
	ResumeDelay time.Duration
}

func DefaultRawLogReclaimOptions() RawLogReclaimOptions {
	return RawLogReclaimOptions{Pause: rawReclaimDefaultPause, ResumeDelay: rawReclaimResumeDelay}
}

type rawReclaimEstimate struct {
	at          time.Time
	reclaimable int64
	modsec      int64
	days        int
	firstNeed   int64 // what the day with the most raw_log needs
	perChunk    map[string]rawReclaimChunkStats
	stale       bool // a day finished since: measure again on the next request
}

type rawReclaimChunkStats struct {
	rel   string
	stats repository.RawLogStats
}

type rawReclaimSupport struct {
	at     time.Time
	ok     bool
	reason string
}

type RawLogReclaimService struct {
	store rawReclaimStore
	opts  RawLogReclaimOptions
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration)

	base       context.Context // ends every run: the API is stopping
	baseCancel context.CancelFunc
	estMu      sync.Mutex // one estimate at a time

	mu           sync.Mutex
	probe        RawLogReclaimDiskProbe
	running      bool // a runner, or a Start or resume preparing one, exists here
	cancel       context.CancelFunc
	done         chan struct{}
	stopping     bool // Stop recorded 'paused' for the current runner
	current      *model.LogRawReclaimChunkProgress
	resumeAt     *time.Time
	resumeCancel context.CancelFunc
	free         *int64
	est          *rawReclaimEstimate
	support      *rawReclaimSupport
}

func NewRawLogReclaimService(store rawReclaimStore, opts RawLogReclaimOptions) *RawLogReclaimService {
	base, cancel := context.WithCancel(context.Background())
	return &RawLogReclaimService{store: store, opts: opts, now: time.Now, sleep: sleepCtx, base: base, baseCancel: cancel}
}

// SetDiskProbe wires DiskGuard. Without a probe the job refuses to start.
func (s *RawLogReclaimService) SetDiskProbe(p RawLogReclaimDiskProbe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probe = p
}

func (s *RawLogReclaimService) diskProbe() RawLogReclaimDiskProbe {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.probe
}

func (s *RawLogReclaimService) supported(ctx context.Context) (bool, string, error) {
	s.mu.Lock()
	c := s.support
	s.mu.Unlock()
	if c != nil && s.now().Sub(c.at) < rawReclaimSupportTTL {
		return c.ok, c.reason, nil
	}
	ok, reason, err := s.store.Support(ctx)
	if err != nil {
		return false, "", err
	}
	s.mu.Lock()
	s.support = &rawReclaimSupport{at: s.now(), ok: ok, reason: reason}
	s.mu.Unlock()
	return ok, reason, nil
}

// claim reserves the single runner slot of this process.
func (s *RawLogReclaimService) claim() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	return true
}

func (s *RawLogReclaimService) release() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

// ── start, stop, resume ────────────────────────────────────────────────────

// Start plans the work and starts a runner. user is recorded as requested_by.
func (s *RawLogReclaimService) Start(ctx context.Context, user string, maxChunks *int) (*model.LogRawReclaimStatus, error) {
	if maxChunks != nil && (*maxChunks < 1 || *maxChunks > RawReclaimMaxChunks) {
		return nil, ErrRawReclaimInvalid
	}
	if !s.claim() {
		return nil, ErrRawReclaimRunning
	}
	started := false
	defer func() {
		if !started {
			s.release()
		}
	}()
	ok, reason, err := s.supported(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &RawReclaimPreconditionError{Code: "unsupported", Reason: reason}
	}
	probe := s.diskProbe()
	if probe == nil {
		return nil, &RawReclaimPreconditionError{Code: "free_space_unknown"}
	}
	sess, err := s.store.OpenSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !started {
			_ = sess.Close()
		}
	}()
	got, err := sess.TryJobLock(ctx)
	if err != nil {
		return nil, err
	}
	if !got {
		return nil, ErrRawReclaimRunning // another API process runs it
	}
	if err := s.plan(ctx); err != nil {
		return nil, err
	}
	rows, err := s.store.ListChunkRows(ctx)
	if err != nil {
		return nil, err
	}
	work := workOrder(rows, nil, true)
	free, fok := probe.DBFree(ctx)
	s.setFree(free, fok)
	if !fok {
		return nil, &RawReclaimPreconditionError{Code: "free_space_unknown"}
	}
	if len(work) > 0 {
		if need := rawReclaimNeed(work[0].BytesBefore, work[0].RawBytes); int64(free) < need {
			return nil, &RawReclaimPreconditionError{Code: "insufficient_space", FreeBytes: int64(free), RequiredBytes: need}
		}
	}
	job, err := s.store.BeginJob(ctx, user, maxChunks)
	if err != nil {
		return nil, err // a resume waiting for its turn still comes
	}
	s.cancelPendingResume()
	if len(work) == 0 {
		if err := s.store.FinishJob(ctx, model.RawReclaimDone, ""); err != nil {
			return nil, err
		}
		log.Printf("[RawLogReclaim] started by %s: no compressed day has raw_log left to remove", userOrSystem(user))
		return s.Status(ctx, false)
	}
	var raw int64
	for _, w := range work {
		raw += w.RawBytes
	}
	limit := "all of them"
	if maxChunks != nil {
		limit = fmt.Sprintf("at most %d", *maxChunks)
	}
	log.Printf("[RawLogReclaim] started by %s: %d day(s) hold about %s of access/error raw_log; working on %s, largest first",
		userOrSystem(user), len(work), formatBytes(raw), limit)
	s.launch(sess, job, true)
	started = true
	return s.Status(ctx, false)
}

func userOrSystem(u string) string {
	if u == "" {
		return "system"
	}
	return u
}

// launch starts the runner. retryFailed (a Start, never a resume) has it
// give each failed day one more try, after every other day.
func (s *RawLogReclaimService) launch(sess repository.ReclaimSession, job repository.ReclaimJob, retryFailed bool) {
	ctx, cancel := context.WithCancel(s.base)
	s.mu.Lock()
	s.cancel, s.done, s.stopping = cancel, make(chan struct{}), false
	done := s.done
	s.mu.Unlock()
	go s.run(ctx, sess, job, retryFailed, done)
}

// Stop records 'paused' and cancels the runner: the statement in flight is
// cancelled and its transaction rolled back, so the day keeps the state it
// had. Stopping a job that is not running changes nothing.
func (s *RawLogReclaimService) Stop(ctx context.Context) (*model.LogRawReclaimStatus, error) {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	if s.resumeCancel != nil {
		s.resumeCancel()
		s.resumeCancel, s.resumeAt = nil, nil
	}
	job, err := s.store.LoadJob(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	stopped := cancel != nil || job.Status == model.RawReclaimRunning
	if stopped {
		s.stopping = cancel != nil
		if err := s.store.FinishJob(ctx, model.RawReclaimPaused, ""); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(rawReclaimStopWait):
			log.Printf("[RawLogReclaim] the runner did not stop within %s; it will stop when its statement returns", rawReclaimStopWait)
		}
	}
	if stopped {
		log.Printf("[RawLogReclaim] paused")
	}
	return s.Status(ctx, false)
}

// Shutdown stops the runner without recording anything: the job stays
// 'running' and ResumeIfRunning picks it up after the next start. The wait is
// short because the whole API has Docker's 10-second stop grace period; a
// cancelled statement returns in milliseconds, and one that does not is
// finished by the server on its own, which the resumed run then notices.
func (s *RawLogReclaimService) Shutdown() {
	s.baseCancel()
	s.mu.Lock()
	done, active := s.done, s.cancel != nil
	s.mu.Unlock()
	if active && done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *RawLogReclaimService) cancelPendingResume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resumeCancel != nil {
		s.resumeCancel()
		s.resumeCancel, s.resumeAt = nil, nil
	}
}

// ResumeIfRunning picks up a job the last API process left running, after
// ResumeDelay so the API's own start-up work goes first. Run it in a goroutine.
func (s *RawLogReclaimService) ResumeIfRunning(ctx context.Context) {
	job, err := s.store.LoadJob(ctx)
	if err != nil {
		log.Printf("[RawLogReclaim] could not read the job state at start-up: %s", database.ScrubDriverText(err.Error()))
		return
	}
	if job.Status != model.RawReclaimRunning {
		return
	}
	rctx, cancel := context.WithCancel(s.base)
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()
	at := s.now().Add(s.opts.ResumeDelay)
	s.mu.Lock()
	s.resumeAt, s.resumeCancel = &at, cancel
	s.mu.Unlock()
	log.Printf("[RawLogReclaim] the reclaim was running when the API stopped; resuming in %s", s.opts.ResumeDelay)
	s.sleep(rctx, s.opts.ResumeDelay)
	s.mu.Lock()
	if s.resumeAt == &at {
		s.resumeAt, s.resumeCancel = nil, nil
	}
	s.mu.Unlock()
	for try := 1; rctx.Err() == nil; try++ {
		launched, retry := s.resume(rctx)
		if launched || !retry {
			return
		}
		if try >= rawReclaimResumeTries {
			log.Printf("[RawLogReclaim] another session still holds the reclaim lock; not resuming here")
			return
		}
		s.sleep(rctx, rawReclaimResumeRetry)
	}
}

// resume makes one attempt; retry means another session holds the job lock
// (typically the previous process's, still ending its last statement).
func (s *RawLogReclaimService) resume(ctx context.Context) (launched, retry bool) {
	if !s.claim() {
		return false, false // started by hand in the meantime
	}
	defer func() {
		if !launched {
			s.release()
		}
	}()
	job, err := s.store.LoadJob(ctx)
	if err != nil || job.Status != model.RawReclaimRunning {
		return false, err != nil
	}
	ok, reason, err := s.supported(ctx)
	if err != nil {
		return false, true
	}
	if !ok {
		s.finishNow(model.RawReclaimFailed, "this database cannot run the raw log reclaim ("+reason+")")
		return false, false
	}
	if s.diskProbe() == nil {
		s.finishNow(model.RawReclaimFailed, rawReclaimFreeUnknownMsg)
		return false, false
	}
	sess, err := s.store.OpenSession(ctx)
	if err != nil {
		return false, true
	}
	got, err := sess.TryJobLock(ctx)
	if err != nil || !got {
		_ = sess.Close()
		return false, true
	}
	if err := s.plan(ctx); err != nil {
		_ = sess.Close()
		if ctx.Err() != nil {
			return false, false // the API is stopping: the job stays running for the next start
		}
		s.finishNow(model.RawReclaimFailed, "planning the reclaim failed: "+err.Error())
		return false, false
	}
	job, found, err := s.store.ResumeJob(ctx)
	if err != nil || !found {
		_ = sess.Close()
		return false, err != nil
	}
	log.Printf("[RawLogReclaim] resuming the reclaim requested by %s", userOrSystem(job.RequestedBy))
	s.launch(sess, job, false)
	return true, false
}

// finishNow records an end outside a run (nothing to race with).
func (s *RawLogReclaimService) finishNow(status, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.FinishJob(ctx, status, msg); err != nil {
		log.Printf("[RawLogReclaim] could not record the job state: %s", database.ScrubDriverText(err.Error()))
	}
	if msg != "" {
		log.Printf("[RawLogReclaim] stopped: %s", database.ScrubDriverText(msg))
	}
}

// finish records how a run ended, unless Stop already recorded 'paused'.
func (s *RawLogReclaimService) finish(status, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	s.finishNow(status, msg)
}
