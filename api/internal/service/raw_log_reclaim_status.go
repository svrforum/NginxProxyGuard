package service

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// Status is what the Maintenance card shows. refreshEstimate measures the
// compressed days again when the cached estimate is older than 10 minutes
// (about 2 ms per day, more when the database is cold); without it the
// status reads only the job's own small tables, cheap enough to poll. While
// this process runs the job nothing is measured: the size of each compressed
// relation waits for the ACCESS EXCLUSIVE lock VACUUM FULL holds on the day
// it compacts, so the card would stay loading until that day is done. The
// last figures stand until the run ends.
func (s *RawLogReclaimService) Status(ctx context.Context, refreshEstimate bool) (*model.LogRawReclaimStatus, error) {
	ok, reason, err := s.supported(ctx)
	if err != nil {
		return nil, err
	}
	job, err := s.store.LoadJob(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListChunkRows(ctx)
	if err != nil {
		return nil, err
	}
	if refreshEstimate && ok && !s.runnerActive() {
		s.refreshEstimate(ctx)
	}

	st := &model.LogRawReclaimStatus{
		Status:            job.Status,
		Supported:         ok,
		UnsupportedReason: reason,
		RequestedAt:       job.RequestedAt,
		RequestedBy:       job.RequestedBy,
		StartedAt:         job.StartedAt,
		FinishedAt:        job.FinishedAt,
		MaxChunks:         job.MaxChunks,
		LastError:         job.LastError,
	}
	for _, r := range rows {
		switch r.State {
		case "gone":
			continue
		case "done":
			st.ChunksDone++
			st.BytesBefore += r.BytesBefore
			st.BytesAfter += r.BytesAfter
			if r.BytesBefore > r.BytesAfter {
				st.ReclaimedBytes += r.BytesBefore - r.BytesAfter
			}
		case "pending", "nulled":
			st.ChunksPending++
			st.RemainingRawBytes += r.RawBytes
		case "skipped":
			st.ChunksSkipped++
		case "failed":
			st.ChunksFailed++
		}
		st.ChunksTotal++
	}

	s.mu.Lock()
	if s.current != nil {
		cur := *s.current
		st.CurrentChunk = &cur
	}
	if s.resumeAt != nil {
		at := *s.resumeAt
		st.ResumeAt = &at
	}
	if s.free != nil {
		free := *s.free
		st.FreeBytes = &free
	}
	est := s.est
	s.mu.Unlock()

	if est != nil {
		reclaimable, modsec, days, at := est.reclaimable, est.modsec, est.days, est.at
		st.EstimatedReclaimableBytes, st.ModSecRawBytes, st.EstimateChunks, st.EstimatedAt = &reclaimable, &modsec, &days, &at
	}
	if work := workOrder(rows, job.RequestedAt); len(work) > 0 {
		st.RequiredFreeBytes = rawReclaimNeed(work[0].BytesBefore, work[0].RawBytes)
	} else if est != nil && est.days > 0 {
		st.RequiredFreeBytes = est.firstNeed
	}
	return st, nil
}

// refreshEstimate measures every compressed day old enough to process. One
// measurement at a time; a second caller waits and then finds it fresh.
func (s *RawLogReclaimService) refreshEstimate(ctx context.Context) {
	s.estMu.Lock()
	defer s.estMu.Unlock()
	s.mu.Lock()
	fresh := s.est != nil && !s.est.stale && s.now().Sub(s.est.at) < rawReclaimEstimateTTL
	s.mu.Unlock()
	if fresh {
		return
	}
	est := &rawReclaimEstimate{at: s.now(), perChunk: map[string]rawReclaimChunkStats{}}
	infos, err := s.store.ListChunks(ctx)
	if err != nil {
		log.Printf("[RawLogReclaim] estimate failed: %s", database.ScrubDriverText(err.Error()))
		return
	}
	var largest int64 = -1
	for _, c := range infos {
		if c.SkipReason() != "" {
			continue
		}
		st, err := s.store.RawLogStats(ctx, c.CompressedRel)
		if repository.IsUndefinedTable(err) {
			continue
		}
		if err != nil {
			log.Printf("[RawLogReclaim] estimate failed: %s", database.ScrubDriverText(err.Error()))
			return
		}
		est.perChunk[c.Name] = rawReclaimChunkStats{rel: c.CompressedRel, stats: st}
		est.modsec += st.ModSecBytes
		if st.PendingBatches == 0 {
			continue
		}
		est.reclaimable += st.RawBytes
		est.days++
		if st.RawBytes > largest {
			largest = st.RawBytes
			est.firstNeed = rawReclaimNeed(c.Bytes, st.RawBytes)
		}
	}
	if probe := s.diskProbe(); probe != nil {
		free, ok := probe.DBFree(ctx)
		s.setFree(free, ok)
	}
	s.mu.Lock()
	s.est = est
	s.mu.Unlock()
}

// runnerActive reports a runner in this process.
func (s *RawLogReclaimService) runnerActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancel != nil
}

// cachedChunkStats lends planning the estimate's per-day measurements while
// they are fresh.
func (s *RawLogReclaimService) cachedChunkStats() map[string]rawReclaimChunkStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.est == nil || s.est.stale || s.now().Sub(s.est.at) >= rawReclaimEstimateTTL {
		return nil
	}
	return s.est.perChunk
}

// invalidateEstimate: a finished day changed what is left to reclaim. The
// old figures stay on show until the next ?estimate=1 measures again.
func (s *RawLogReclaimService) invalidateEstimate() {
	s.mu.Lock()
	if s.est != nil {
		s.est.stale = true
	}
	s.mu.Unlock()
}
