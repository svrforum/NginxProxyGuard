package service

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// Emergency compression (D3).
//
// When the database disk passes the critical line, compress every CLOSED,
// uncompressed chunk now instead of waiting for the policy's compress_after.
// Lossless — compress_chunk only changes how rows are stored — and on
// production it is the difference between an 8 GB day and a 0.6 GB one.
//
// Rules, each measured on TimescaleDB 2.24.0 before it was written down:
//   - Never the chunk still being written: range_end <= now().
//   - One chunk at a time, smallest first, a fresh disk measurement before
//     each. compress_chunk needs room for the compressed copy plus its WAL
//     before it can free the original: peak extra space equalled the
//     compressed size (8 MB for a 131 MB chunk at 15x; 53 MB for 125 MB at
//     2.4x). Smallest first wins room for the larger ones.
//   - Out of room is a clean failure when it hits a data file: SQLSTATE 53100,
//     transaction rolled back, partial output removed, server up. It would be a
//     PANIC if it hit WAL — which is why the estimate is deliberately pessimistic.
//   - Never alongside the compression policy (job_stats.job_status='Running',
//     backend "Columnstore Policy [id]") and never alongside another bulk chunk
//     rewrite: repository.StorageMaintenanceLockKey, which the raw_log reclaim
//     job (C6) takes per chunk.
//   - lock_timeout 5s: a chunk someone else is busy with is skipped, not waited on.
//   - The policy job is never paused or altered: if NPG crashed mid-way, the
//     operator's compression would stay off with no sign of it.

const (
	// emergencyMinChunkBytes skips chunks too small to matter in an emergency;
	// the regular policies handle them.
	emergencyMinChunkBytes int64 = 16 << 20
	// emergencyRatioCap keeps the space estimate pessimistic. Production heap
	// ratios measured 5.3-7.1x, whole-chunk 9-11x; dev reported 13.6x.
	emergencyRatioFloor, emergencyRatioCap       = 2.0, 6.0
	emergencyMargin                        int64 = 64 << 20
	// emergencyThrottle is the pause after a chunk of 64 MiB or more, so ingest
	// and queries get the disk back between rewrites.
	emergencyThrottle    = 5 * time.Second
	emergencyRetryAfter  = 15 * time.Minute
	emergencyRetrySoon   = time.Minute
	emergencyAfterDone   = 5 * time.Minute
	emergencyPassTimeout = 2 * time.Hour
)

// compressNeed estimates the free space compress_chunk needs at its peak:
// the compressed output plus about as much WAL, plus a margin.
func compressNeed(chunkBytes int64, ratio float64) int64 {
	return int64(2*float64(chunkBytes)/clampRatio(ratio)) + emergencyMargin
}

// reserveFor is what must stay free after the estimated peak, so ingest keeps
// writing while a chunk compresses: 0.5% of the disk, at least 256 MiB.
func reserveFor(total uint64) int64 {
	r := int64(total / 200)
	if r < 256<<20 {
		r = 256 << 20
	}
	return r
}

func clampRatio(r float64) float64 {
	if r < emergencyRatioFloor {
		return emergencyRatioFloor
	}
	if r > emergencyRatioCap {
		return emergencyRatioCap
	}
	return r
}

// EmergencyPlan is what a pass would do right now. Action is a code the
// notification formatter translates: emergency_compression, dry_run,
// nothing_to_compress, insufficient_space, disabled or unavailable.
type EmergencyPlan struct {
	Action      string
	Chunks      int
	Reclaimable int64
}

type emergencyRepo interface {
	CompressionCandidates(ctx context.Context, minBytes int64) ([]repository.ChunkCandidate, error)
	CompressionRatios(ctx context.Context) (map[string]float64, error)
	CompressionPolicyRunning(ctx context.Context) (bool, error)
	WithMaintenanceLock(ctx context.Context, fn func(ctx context.Context, c repository.ChunkCompressor) error) (bool, error)
}

// EmergencyMode is NPG_DISK_EMERGENCY_COMPRESS.
type EmergencyMode string

const (
	EmergencyOn     EmergencyMode = "on"
	EmergencyOff    EmergencyMode = "off"
	EmergencyDryRun EmergencyMode = "dryrun"
)

// ParseEmergencyMode reads NPG_DISK_EMERGENCY_COMPRESS. Empty is the default,
// on; ok is false for anything it does not know, which also means on.
func ParseEmergencyMode(v string) (mode EmergencyMode, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "on", "1", "true":
		return EmergencyOn, true
	case "off", "0", "false":
		return EmergencyOff, true
	case "dryrun", "dry-run", "dry_run":
		return EmergencyDryRun, true
	}
	return EmergencyOn, false
}

// EmergencyCompressor runs D3 passes, one at a time, off the guard's tick.
type EmergencyCompressor struct {
	repo    emergencyRepo
	measure func(ctx context.Context) (*FSUsage, error)
	mode    EmergencyMode
	base    context.Context
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration)
	sysLog  func(level repository.SystemLogLevel, msg string)

	running atomic.Bool
	wg      sync.WaitGroup

	mu        sync.Mutex
	status    model.EmergencyCompressionStatus
	lastEnd   time.Time
	wait      time.Duration
	lastQuiet string // outcome of the last pass that changed nothing
}

// NewEmergencyCompressor: base ends every pass (the API shutting down); measure
// is a fresh measurement of the database disk.
func NewEmergencyCompressor(base context.Context, repo emergencyRepo, measure func(ctx context.Context) (*FSUsage, error), mode EmergencyMode) *EmergencyCompressor {
	if mode != EmergencyOff && mode != EmergencyDryRun {
		mode = EmergencyOn
	}
	return &EmergencyCompressor{
		repo: repo, measure: measure, mode: mode, base: base, now: time.Now, sleep: sleepCtx,
		status: model.EmergencyCompressionStatus{Mode: string(mode), State: "idle"},
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Mode is the configured mode.
func (e *EmergencyCompressor) Mode() EmergencyMode { return e.mode }

// Plan has no side effects; DiskGuard puts its Action in the critical alert.
func (e *EmergencyCompressor) Plan(ctx context.Context, fs FSUsage) EmergencyPlan {
	if e.mode == EmergencyOff {
		return EmergencyPlan{Action: "disabled"}
	}
	cands, err := e.repo.CompressionCandidates(ctx, emergencyMinChunkBytes)
	if err != nil {
		return EmergencyPlan{Action: "unavailable"}
	}
	if len(cands) == 0 {
		return EmergencyPlan{Action: "nothing_to_compress"}
	}
	ratios, _ := e.repo.CompressionRatios(ctx)
	plan := EmergencyPlan{Action: "insufficient_space", Chunks: len(cands)}
	for _, c := range cands {
		r := clampRatio(ratios[c.Hypertable])
		plan.Reclaimable += c.Bytes - int64(float64(c.Bytes)/r)
		if int64(fs.Avail)-compressNeed(c.Bytes, r) >= reserveFor(fs.Total) {
			plan.Action = "emergency_compression"
		}
	}
	if e.mode == EmergencyDryRun && plan.Action == "emergency_compression" {
		plan.Action = "dry_run"
	}
	return plan
}

// TriggerAsync starts a pass unless one is running or the last one ended too
// recently: 1 minute after one that stood aside (the policy or another job
// was busy), 5 after a finished one, 15 after one that ran out of room or
// failed.
func (e *EmergencyCompressor) TriggerAsync(fs FSUsage) {
	if e.mode == EmergencyOff {
		return
	}
	e.mu.Lock()
	if !e.lastEnd.IsZero() && e.now().Sub(e.lastEnd) < e.wait {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	if !e.running.CompareAndSwap(false, true) {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.running.Store(false)
		ctx, cancel := context.WithTimeout(e.base, emergencyPassTimeout)
		defer cancel()
		e.runPass(ctx, fs)
	}()
}

// SetSystemLog mirrors pass results into the Logs view (system_logs).
func (e *EmergencyCompressor) SetSystemLog(fn func(level repository.SystemLogLevel, msg string)) {
	e.sysLog = fn
}

// Wait blocks until an in-flight pass returns (tests, shutdown).
func (e *EmergencyCompressor) Wait() { e.wg.Wait() }

func (e *EmergencyCompressor) Status() model.EmergencyCompressionStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *EmergencyCompressor) begin() {
	now := e.now()
	e.mu.Lock()
	e.status = model.EmergencyCompressionStatus{Mode: string(e.mode), State: "running", StartedAt: &now}
	e.mu.Unlock()
}

// end records the outcome. A pass that changed nothing and ended exactly like
// the previous one is not logged again: at 92% with nothing left to compress,
// a pass every five minutes would otherwise write the same lines all day.
func (e *EmergencyCompressor) end(state, reason string, wait time.Duration, notes []string) {
	now := e.now()
	e.mu.Lock()
	e.status.State, e.status.Reason, e.status.FinishedAt = state, reason, &now
	e.lastEnd, e.wait = now, wait
	s := e.status
	outcome := state + "|" + reason
	repeat := s.ChunksDone == 0 && outcome == e.lastQuiet
	if s.ChunksDone == 0 {
		e.lastQuiet = outcome
	} else {
		e.lastQuiet = ""
	}
	e.mu.Unlock()
	if repeat {
		return
	}
	for _, n := range notes {
		log.Print(n)
	}
	msg := fmt.Sprintf("[DiskGuard] emergency compression %s: %d of %d chunk(s) compressed, %s freed",
		state, s.ChunksDone, s.ChunksTotal, formatBytes(s.FreedBytes))
	if reason != "" {
		msg += " (" + reason + ")"
	}
	log.Print(msg)
	if e.sysLog != nil {
		lvl := repository.LevelInfo
		if state == "blocked" {
			lvl = repository.LevelWarn
		}
		e.sysLog(lvl, msg)
	}
}

func (e *EmergencyCompressor) runPass(ctx context.Context, trigger FSUsage) {
	e.begin()
	var notes []string
	state, reason, wait := "done", "", emergencyAfterDone
	acquired, err := e.repo.WithMaintenanceLock(ctx, func(ctx context.Context, cc repository.ChunkCompressor) error {
		if running, err := e.repo.CompressionPolicyRunning(ctx); err == nil && running {
			state, reason, wait = "blocked", "policy_running", emergencyRetrySoon
			return nil
		}
		cands, err := e.repo.CompressionCandidates(ctx, emergencyMinChunkBytes)
		if err != nil {
			return err
		}
		ratios, _ := e.repo.CompressionRatios(ctx)
		sort.SliceStable(cands, func(i, j int) bool { return cands[i].Bytes < cands[j].Bytes })
		e.mu.Lock()
		e.status.ChunksTotal = len(cands)
		e.mu.Unlock()
		if len(cands) == 0 {
			reason = "nothing_to_compress"
			return nil
		}

		started := false
		var fit, noRoom, busy, failures int
		for _, c := range cands {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			before, err := e.measure(ctx)
			if err != nil {
				state, reason, wait = "blocked", "db_disk_unmeasured", emergencyRetryAfter
				return nil
			}
			need, reserve := compressNeed(c.Bytes, ratios[c.Hypertable]), reserveFor(before.Total)
			if int64(before.Avail)-need < reserve {
				noRoom++
				notes = append(notes, fmt.Sprintf("[DiskGuard] skipping %s.%s (%s, %s): needs about %s free to compress safely, %s available",
					c.Schema, c.Name, c.Hypertable, formatBytes(c.Bytes), formatBytes(need+reserve), formatBytes(int64(before.Avail))))
				continue
			}
			fit++
			if e.mode == EmergencyDryRun {
				notes = append(notes, fmt.Sprintf("[DiskGuard] dry run: would compress %s.%s (%s, %s, up to %s)",
					c.Schema, c.Name, c.Hypertable, formatBytes(c.Bytes), c.RangeEnd.Format(time.RFC3339)))
				continue
			}
			if !started {
				started = true
				log.Printf("[DiskGuard] database disk at %.1f%% (%s free): compressing closed log chunks early, smallest first (%d candidate(s)); nothing is deleted",
					trigger.UsedPercent, formatBytes(int64(trigger.Avail)), len(cands))
			}
			t0 := e.now()
			err = cc.CompressChunk(ctx, c.Schema, c.Name)
			switch {
			case err == nil:
			case repository.IsLockTimeout(err):
				busy++
				notes = append(notes, fmt.Sprintf("[DiskGuard] %s.%s is locked by another job; skipped this pass", c.Schema, c.Name))
				continue
			case repository.IsDiskFull(err):
				state, reason, wait = "blocked", "insufficient_space", emergencyRetryAfter
				log.Printf("[DiskGuard] %s.%s: the disk filled up during compression; the chunk is unchanged", c.Schema, c.Name)
				return nil
			case ctx.Err() != nil:
				return ctx.Err() // shutting down: the statement was cancelled and rolled back
			default:
				failures++
				log.Printf("[DiskGuard] compressing %s.%s failed: %s", c.Schema, c.Name, database.ScrubDriverText(err.Error()))
				if failures >= 3 {
					state, reason, wait = "blocked", "compress_failed", emergencyRetryAfter
					return nil
				}
				continue
			}
			after, aerr := e.measure(ctx)
			freed := int64(0)
			if aerr == nil && after.Avail > before.Avail {
				freed = int64(after.Avail - before.Avail)
			}
			e.mu.Lock()
			e.status.ChunksDone++
			e.status.FreedBytes += freed
			e.mu.Unlock()
			metrics.DiskEmergencyChunksCompressed.Inc()
			pct := before.UsedPercent
			if aerr == nil {
				pct = after.UsedPercent
			}
			log.Printf("[DiskGuard] compressed %s.%s (%s, %s) in %s; freed %s, database disk now %.1f%%",
				c.Schema, c.Name, c.Hypertable, formatBytes(c.Bytes), e.now().Sub(t0).Round(time.Second), formatBytes(freed), pct)
			if c.Bytes >= 64<<20 {
				e.sleep(ctx, emergencyThrottle)
			}
		}

		done := e.Status().ChunksDone
		switch {
		case e.mode == EmergencyDryRun && fit > 0:
			reason = "dry_run"
		case done > 0:
		case noRoom > 0:
			state, reason, wait = "blocked", "insufficient_space", emergencyRetryAfter
		case busy > 0:
			state, reason, wait = "blocked", "chunks_busy", emergencyRetrySoon
		case failures > 0:
			state, reason, wait = "blocked", "compress_failed", emergencyRetryAfter
		}
		return nil
	})
	switch {
	case err != nil && ctx.Err() != nil:
		state, reason, wait = "blocked", "stopped", emergencyRetrySoon
		notes = append(notes, "[DiskGuard] emergency compression interrupted (the API is stopping); the chunk in progress was rolled back")
	case err != nil:
		state, reason, wait = "blocked", "error", emergencyRetryAfter
		notes = append(notes, "[DiskGuard] emergency compression stopped: "+database.ScrubDriverText(err.Error()))
	case !acquired:
		state, reason, wait = "blocked", "another_pass_running", emergencyRetrySoon
	}
	e.end(state, reason, wait, notes)
}
