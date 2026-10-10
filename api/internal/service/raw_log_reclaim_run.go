package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// The raw log reclaim's planning and its run, day by day. The life cycle
// (start, stop, resume) is in raw_log_reclaim.go.

// ── planning ───────────────────────────────────────────────────────────────

// plan records the days that have raw_log to remove, retires dropped ones and
// sets aside those that no longer qualify. Failed days stay as they are: a
// run started by hand takes them last (workOrder) and brings each back only
// as it gets to it (reclaimOne), so a refused Start, or one whose max_chunks
// ends before them, leaves them failed with their error.
func (s *RawLogReclaimService) plan(ctx context.Context) error {
	if err := s.store.MarkGoneChunks(ctx); err != nil {
		return err
	}
	rows, err := s.store.ListChunkRows(ctx)
	if err != nil {
		return err
	}
	known := make(map[string]string, len(rows))
	for _, r := range rows {
		known[r.Name] = r.State
	}
	infos, err := s.store.ListChunks(ctx)
	if err != nil {
		return err
	}
	cached := s.cachedChunkStats()
	for _, c := range infos {
		state, isKnown := known[c.Name]
		if reason := c.SkipReason(); reason != "" {
			if state == "pending" || state == "nulled" {
				if err := s.store.MarkSkipped(ctx, c.Name, reason); err != nil {
					return err
				}
			}
			continue
		}
		if isKnown && state != "skipped" {
			continue
		}
		st, ok := cached[c.Name]
		if !ok || st.rel != c.CompressedRel {
			stats, err := s.store.RawLogStats(ctx, c.CompressedRel)
			if repository.IsUndefinedTable(err) {
				continue // compressed again under a new name since it was listed
			}
			if err != nil {
				return err
			}
			st = rawReclaimChunkStats{rel: c.CompressedRel, stats: stats}
		}
		if !isKnown && st.stats.PendingBatches == 0 {
			continue // nothing to remove; such days are not recorded
		}
		if err := s.store.PlanChunk(ctx, repository.ReclaimPlanRow{
			Name: c.Name, RangeStart: c.RangeStart, RangeEnd: c.RangeEnd, BytesBefore: c.Bytes, RawBytes: st.stats.RawBytes,
		}); err != nil {
			return err
		}
	}
	return nil
}

// workOrder is what is left to do, in the order a run does it: days this
// request already started (so max_chunks counts each once), then days whose
// UPDATE committed, fewer failed attempts, the most raw_log, the oldest. A
// day given one more try after failing (rawReclaimFailAfter attempts) comes
// after all of those, and with retryFailed (a run started by hand) the failed
// days still waiting for their try come last of all.
func workOrder(rows []repository.ReclaimChunk, requestedAt *time.Time, retryFailed bool) []repository.ReclaimChunk {
	var out []repository.ReclaimChunk
	for _, r := range rows {
		if r.State == "pending" || r.State == "nulled" || (retryFailed && r.State == "failed") {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if wa, wb := workedSince(a, requestedAt), workedSince(b, requestedAt); wa != wb {
			return wa
		}
		if fa, fb := a.State == "failed", b.State == "failed"; fa != fb {
			return fb
		}
		if xa, xb := a.Attempts >= rawReclaimFailAfter, b.Attempts >= rawReclaimFailAfter; xa != xb {
			return xb
		}
		if na, nb := a.UpdateXID != nil || a.State == "nulled", b.UpdateXID != nil || b.State == "nulled"; na != nb {
			return na
		}
		if a.Attempts != b.Attempts {
			return a.Attempts < b.Attempts
		}
		if a.RawBytes != b.RawBytes {
			return a.RawBytes > b.RawBytes
		}
		return a.RangeStart.Before(b.RangeStart)
	})
	return out
}

func workedSince(c repository.ReclaimChunk, since *time.Time) bool {
	return since != nil && c.WorkedAt != nil && !c.WorkedAt.Before(*since)
}

func countWorked(rows []repository.ReclaimChunk, since *time.Time) int {
	n := 0
	for _, r := range rows {
		if workedSince(r, since) {
			n++
		}
	}
	return n
}

// ── the run ────────────────────────────────────────────────────────────────

func (s *RawLogReclaimService) run(ctx context.Context, sess repository.ReclaimSession, job repository.ReclaimJob, retryFailed bool, done chan struct{}) {
	defer func() {
		_ = sess.Close()
		s.mu.Lock()
		s.running, s.cancel, s.current, s.stopping = false, nil, nil, false
		s.mu.Unlock()
		close(done)
	}()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[RawLogReclaim] the runner panicked: %v", r)
			s.finish(model.RawReclaimFailed, fmt.Sprintf("the reclaim stopped unexpectedly: %v", r))
		}
	}()

	attempted := map[string]bool{}
	var deferred int
	var lastDeferred string
	var finished int
	var reclaimed int64
	pauseNext := false
	for ctx.Err() == nil {
		rows, err := s.store.ListChunkRows(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.finish(model.RawReclaimFailed, "reading the reclaim state failed: "+err.Error())
			}
			return
		}
		var next *repository.ReclaimChunk
		for _, w := range workOrder(rows, job.RequestedAt, retryFailed) {
			if !attempted[w.Name] {
				w := w
				next = &w
				break
			}
		}
		if next != nil && job.MaxChunks != nil && !workedSince(*next, job.RequestedAt) &&
			countWorked(rows, job.RequestedAt) >= *job.MaxChunks {
			next = nil // this request's days are used up
		}
		if next == nil {
			if deferred > 0 {
				s.finish(model.RawReclaimFailed, fmt.Sprintf(
					"%d day(s) could not be finished; the last: %s. Run the reclaim again later to retry them.", deferred, lastDeferred))
				return
			}
			log.Printf("[RawLogReclaim] finished: %d day(s) done, %s returned to the disk", finished, formatBytes(reclaimed))
			s.finish(model.RawReclaimDone, "")
			return
		}
		attempted[next.Name] = true
		if pauseNext && s.opts.Pause > 0 {
			s.setStep(*next, model.RawReclaimStepPausing)
			s.sleep(ctx, s.opts.Pause)
			if ctx.Err() != nil {
				return
			}
		}
		out := s.reclaimOne(ctx, sess, *next)
		pauseNext = out.worked
		switch out.kind {
		case rawOutcomeCanceled:
			return
		case rawOutcomeFatal:
			s.finish(model.RawReclaimFailed, out.msg)
			return
		case rawOutcomeDeferred:
			deferred++
			lastDeferred = out.msg
		case rawOutcomeDone:
			finished++
			reclaimed += out.reclaimed
		}
	}
}

type rawOutcomeKind int

const (
	rawOutcomeDone rawOutcomeKind = iota
	rawOutcomeSkipped
	rawOutcomeDeferred // left for the next run
	rawOutcomeFatal    // the job stops
	rawOutcomeCanceled // stopped by Stop or shutdown: record nothing
)

type rawOutcome struct {
	kind      rawOutcomeKind
	msg       string
	worked    bool // the database rewrote something: pause before the next day
	reclaimed int64
}

func dayLabel(c repository.ReclaimChunk) string { return c.RangeStart.UTC().Format("2006-01-02") }

// reclaimOne takes one day as far as it can go.
func (s *RawLogReclaimService) reclaimOne(ctx context.Context, sess repository.ReclaimSession, c repository.ReclaimChunk) (out rawOutcome) {
	defer s.clearCurrent()
	day := dayLabel(c)
	first := model.RawReclaimStepNulling
	if c.State == "nulled" || c.UpdateXID != nil {
		first = model.RawReclaimStepWaiting
	}
	s.setStep(c, first)
	if !s.waitWhileCritical(ctx, c, first) {
		return rawOutcome{kind: rawOutcomeCanceled}
	}
	if c.State == "failed" {
		// Its one more try, now that the run gets to it: it leaves "failed"
		// only here, and keeps its attempts and its last error until this try
		// ends.
		state, err := s.store.ReviveChunk(ctx, c.Name)
		if err != nil {
			return s.chunkError(ctx, c, "checking", err)
		}
		if state == "" {
			return rawOutcome{kind: rawOutcomeSkipped} // no longer failed: changed meanwhile
		}
		c.State = state
	}
	info, err := s.store.LookupChunk(ctx, c.Name)
	if err != nil {
		return s.chunkError(ctx, c, "checking", err)
	}
	if info == nil {
		if err := s.store.MarkGone(ctx, c.Name); err != nil {
			return s.chunkError(ctx, c, "checking", err)
		}
		log.Printf("[RawLogReclaim] %s: dropped by retention in the meantime", day)
		return rawOutcome{kind: rawOutcomeSkipped}
	}
	if reason := info.SkipReason(); reason != "" {
		if err := s.store.MarkSkipped(ctx, c.Name, reason); err != nil {
			return s.chunkError(ctx, c, "checking", err)
		}
		log.Printf("[RawLogReclaim] %s: skipped, %s", day, reason)
		return rawOutcome{kind: rawOutcomeSkipped}
	}
	rel := info.CompressedRel
	if c.BytesBefore <= 0 {
		c.BytesBefore = info.Bytes
	}

	if c.State == "pending" {
		st, err := s.store.RawLogStats(ctx, rel)
		if err != nil {
			return s.chunkError(ctx, c, "measuring", err)
		}
		switch {
		case st.PendingBatches > 0:
			c.BytesBefore, c.RawBytes = info.Bytes, st.RawBytes
		case c.RawBytes > 0 && info.Bytes > c.BytesBefore-c.RawBytes/2:
			// Its raw_log is gone but its space is not: an earlier run's
			// UPDATE committed and recording it did not. Finish it as a
			// nulled day, waiting for every transaction open now.
			xid, err := s.store.HorizonNow(ctx)
			if err == nil {
				err = s.store.MarkNulled(ctx, c.Name, c.BytesBefore, c.RawBytes, 0, xid)
			}
			if err != nil {
				return s.chunkError(ctx, c, "checking", err)
			}
			c.State, c.UpdateXID = "nulled", &xid
		default:
			// Nothing left to remove (compressed again since it was planned).
			if err := s.store.MarkDone(ctx, c.Name, info.Bytes, info.Bytes, 0); err != nil {
				return s.chunkError(ctx, c, "recording", err)
			}
			return rawOutcome{kind: rawOutcomeDone}
		}
	}

	if out, ok := s.checkFreeSpace(ctx, c); !ok {
		return out
	}
	if err := s.store.MarkWorked(ctx, c.Name); err != nil {
		return s.chunkError(ctx, c, "recording", err)
	}

	if c.State == "pending" {
		var batches, xid int64
		err := s.withSharedLock(ctx, sess, c, model.RawReclaimStepNulling, func() error {
			var err error
			batches, xid, err = sess.NullRawLog(ctx, rel)
			return err
		})
		if err != nil {
			return s.chunkError(ctx, c, "removing raw_log from", err)
		}
		if err := s.store.MarkNulled(ctx, c.Name, c.BytesBefore, c.RawBytes, batches, xid); err != nil {
			// Committed but not recorded: the next run notices (see above).
			return s.chunkError(ctx, c, "recording", err)
		}
		c.State, c.UpdateXID = "nulled", &xid
		log.Printf("[RawLogReclaim] %s: removed raw_log from %d batch(es), about %s", day, batches, formatBytes(c.RawBytes))
	}

	if c.UpdateXID != nil {
		ok, blockers, err := s.waitHorizon(ctx, c, *c.UpdateXID)
		if ctx.Err() != nil {
			return rawOutcome{kind: rawOutcomeCanceled}
		}
		if err != nil {
			return s.chunkError(ctx, c, "checking for older transactions before compacting", err)
		}
		if !ok {
			msg := fmt.Sprintf("%s: %s, open since before its raw_log was removed, kept the space from being returned for %s",
				day, describeBlocker(blockers), rawReclaimHorizonTimeout)
			s.noteChunk(c, msg, false)
			log.Printf("[RawLogReclaim] %s", msg)
			return rawOutcome{kind: rawOutcomeDeferred, msg: msg, worked: true}
		}
	}

	if !s.waitWhileCritical(ctx, c, model.RawReclaimStepVacuum) {
		return rawOutcome{kind: rawOutcomeCanceled}
	}
	if out, ok := s.checkFreeSpace(ctx, c); !ok {
		return out
	}
	t0 := s.now()
	var after int64
	err = s.withSharedLock(ctx, sess, c, model.RawReclaimStepVacuum, func() error {
		var err error
		after, err = sess.VacuumFull(ctx, rel)
		return err
	})
	if err != nil {
		return s.chunkError(ctx, c, "compacting", err)
	}
	if vacuumIneffective(c.BytesBefore, after, c.RawBytes) {
		msg := fmt.Sprintf("%s: VACUUM FULL left it at %s where about %s was expected; a transaction older than the removal was probably still open",
			day, formatBytes(after), formatBytes(c.BytesBefore-c.RawBytes))
		if err := s.store.MarkVacuumIneffective(ctx, c.Name, after, msg); err != nil {
			return s.chunkError(ctx, c, "recording", err)
		}
		log.Printf("[RawLogReclaim] %s", msg)
		return rawOutcome{kind: rawOutcomeDeferred, msg: msg, worked: true}
	}
	if err := s.store.MarkDone(ctx, c.Name, c.BytesBefore, after, c.RawBytes); err != nil {
		return s.chunkError(ctx, c, "recording", err)
	}
	s.invalidateEstimate()
	freed := c.BytesBefore - after
	log.Printf("[RawLogReclaim] %s: %s -> %s (%s returned) in %s", day, formatBytes(c.BytesBefore), formatBytes(after),
		formatBytes(freed), s.now().Sub(t0).Round(time.Second))
	return rawOutcome{kind: rawOutcomeDone, worked: true, reclaimed: freed}
}

// vacuumIneffective: VACUUM FULL returned less than half of the raw_log it
// should have — it kept the old versions, because something older than the
// UPDATE was still open after all. Below 1 MiB of raw_log, page rounding is
// as large as the signal, so such days are taken as done.
func vacuumIneffective(bytesBefore, bytesAfter, rawBytes int64) bool {
	return rawBytes >= rawReclaimVerifyMinBytes && bytesAfter > bytesBefore-rawBytes/2
}

// checkFreeSpace: free >= 2 x the day without raw_log + 1 GiB, measured now.
func (s *RawLogReclaimService) checkFreeSpace(ctx context.Context, c repository.ReclaimChunk) (rawOutcome, bool) {
	probe := s.diskProbe()
	if probe == nil {
		return rawOutcome{kind: rawOutcomeFatal, msg: rawReclaimFreeUnknownMsg}, false
	}
	free, ok := probe.DBFree(ctx)
	s.setFree(free, ok)
	if ctx.Err() != nil {
		return rawOutcome{kind: rawOutcomeCanceled}, false
	}
	if !ok {
		return rawOutcome{kind: rawOutcomeFatal, msg: rawReclaimFreeUnknownMsg}, false
	}
	if need := rawReclaimNeed(c.BytesBefore, c.RawBytes); int64(free) < need {
		return rawOutcome{kind: rawOutcomeFatal, msg: fmt.Sprintf(
			"not enough free space on the database disk for %s: it needs %s (twice the day without raw_log, plus 1 GiB) and %s is free",
			dayLabel(c), formatBytes(need), formatBytes(int64(free)))}, false
	}
	return rawOutcome{}, true
}

// waitWhileCritical holds the job while the database disk is critical: that
// is the emergency compression's turn. false when the run was cancelled.
func (s *RawLogReclaimService) waitWhileCritical(ctx context.Context, c repository.ReclaimChunk, resume string) bool {
	logged := false
	for {
		p := s.diskProbe()
		if p == nil || !p.DBCritical() {
			if logged {
				s.setStep(c, resume)
			}
			return ctx.Err() == nil
		}
		if !logged {
			logged = true
			log.Printf("[RawLogReclaim] the database disk is critical: waiting before %s until it is not", dayLabel(c))
		}
		s.setStep(c, model.RawReclaimStepWaitingDisk)
		s.sleep(ctx, rawReclaimDiskRetry)
		if ctx.Err() != nil {
			return false
		}
	}
}

// withSharedLock runs fn holding StorageMaintenanceLockKey, retrying while
// another job holds it, and releases it as soon as fn returns.
func (s *RawLogReclaimService) withSharedLock(ctx context.Context, sess repository.ReclaimSession, c repository.ReclaimChunk, step string, fn func() error) error {
	for {
		got, err := sess.TrySharedLock(ctx)
		if err != nil {
			return err
		}
		if got {
			break
		}
		s.setStep(c, model.RawReclaimStepWaitingLock)
		s.sleep(ctx, rawReclaimLockRetry)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	s.setStep(c, step)
	err := fn()
	if rerr := sess.ReleaseSharedLock(); rerr != nil {
		log.Printf("[RawLogReclaim] releasing the storage maintenance lock failed: %s", database.ScrubDriverText(rerr.Error()))
		if err == nil {
			err = rerr
		}
	}
	return err
}

// waitHorizon polls until nothing at or before xid is left open, for up to
// rawReclaimHorizonTimeout. It holds no lock meanwhile.
func (s *RawLogReclaimService) waitHorizon(ctx context.Context, c repository.ReclaimChunk, xid int64) (bool, repository.SnapshotBlockers, error) {
	s.setStep(c, model.RawReclaimStepWaiting)
	deadline := s.now().Add(rawReclaimHorizonTimeout)
	for {
		b, err := s.store.OlderSnapshots(ctx, xid)
		if err != nil {
			return false, b, err
		}
		if b.Count == 0 {
			return true, b, nil
		}
		if !s.now().Before(deadline) {
			return false, b, nil
		}
		s.sleep(ctx, rawReclaimHorizonPoll)
		if ctx.Err() != nil {
			return false, b, ctx.Err()
		}
	}
}

func describeBlocker(b repository.SnapshotBlockers) string {
	what := "a transaction"
	if b.Kind != "" && b.Kind != "client backend" {
		what = b.Kind
	}
	if b.PID > 0 {
		what += fmt.Sprintf(" (pid %d", b.PID)
		if b.State != "" {
			what += ", " + b.State
		}
		what += ")"
	}
	if b.Since != nil {
		what += " started " + b.Since.UTC().Format(time.RFC3339)
	}
	if b.Count > 1 {
		what += fmt.Sprintf(" and %d more", b.Count-1)
	}
	return what
}

// chunkError sorts a failed step into: cancelled (record nothing), deferred
// to the next run (the day was busy or changed), or the job stopping.
func (s *RawLogReclaimService) chunkError(ctx context.Context, c repository.ReclaimChunk, doing string, err error) rawOutcome {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return rawOutcome{kind: rawOutcomeCanceled}
	}
	day := dayLabel(c)
	var msg string
	kind := rawOutcomeDeferred
	count := false
	switch {
	case repository.IsLockTimeout(err):
		msg = fmt.Sprintf("%s was in use while %s it", day, doing)
	case repository.IsUndefinedTable(err):
		msg = fmt.Sprintf("%s changed while %s it (dropped, or compressed again)", day, doing)
	case repository.IsDiskFull(err):
		msg = fmt.Sprintf("the database disk filled up while %s %s; the statement was rolled back and nothing was lost", doing, day)
		kind = rawOutcomeFatal
	case repository.IsQueryCanceled(err):
		msg = fmt.Sprintf("%s %s took longer than its time limit and was cancelled", doing, day)
		count = true
	case repository.IsConnectionError(err):
		// The session ended (a database restart, a dropped connection), not
		// the day's work: the run stops, and the day is not counted.
		msg = fmt.Sprintf("the connection to the database was lost while %s %s; run the reclaim again to go on", doing, day)
		if code := repository.SQLState(err); code != "" {
			msg += " (SQLSTATE " + code + ")"
		}
		kind = rawOutcomeFatal
	default:
		msg = fmt.Sprintf("%s %s failed: %s", doing, day, database.ScrubDriverText(err.Error()))
		if code := repository.SQLState(err); code != "" {
			msg += " (SQLSTATE " + code + ")"
		}
		kind, count = rawOutcomeFatal, true
	}
	s.noteChunk(c, msg, count)
	log.Printf("[RawLogReclaim] %s", msg)
	return rawOutcome{kind: kind, msg: msg}
}

func (s *RawLogReclaimService) noteChunk(c repository.ReclaimChunk, msg string, countAttempt bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state, err := s.store.NoteChunkError(ctx, c.Name, msg, countAttempt, rawReclaimFailAfter)
	if err != nil {
		log.Printf("[RawLogReclaim] could not record the error for %s: %s", dayLabel(c), database.ScrubDriverText(err.Error()))
	} else if state == "failed" {
		log.Printf("[RawLogReclaim] %s failed %d times; later runs leave it alone", dayLabel(c), rawReclaimFailAfter)
	}
}

func (s *RawLogReclaimService) setStep(c repository.ReclaimChunk, step string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.current; cur != nil && cur.Step == step && cur.RangeStart.Equal(c.RangeStart) {
		return
	}
	// In UTC, as dayLabel names the day: the database session's zone would
	// give a day's start as the evening before when it is behind UTC.
	s.current = &model.LogRawReclaimChunkProgress{RangeStart: c.RangeStart.UTC(), RangeEnd: c.RangeEnd.UTC(), Step: step, Since: s.now()}
}

func (s *RawLogReclaimService) clearCurrent() {
	s.mu.Lock()
	s.current = nil
	s.mu.Unlock()
}

func (s *RawLogReclaimService) setFree(free uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		s.free = nil
		return
	}
	v := int64(free)
	s.free = &v
}
