package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/repository"
)

// PipelineCanary actively validates the whole access-log pipeline end to end:
// it GETs an internal nginx location carrying a unique nonce, then confirms
// that nonce row reaches logs_partitioned within a deadline. A miss is
// localized to a failing stage by checking the access file as an intermediate
// checkpoint. Detection only — auto-heal is wired separately (Phase 2).
type PipelineCanary struct {
	canaryURL string
	logRepo   *repository.LogRepository
	collector *LogCollector
	client    *http.Client

	interval  time.Duration
	bootDelay time.Duration
	deadline  time.Duration

	mu           sync.RWMutex
	status       string // "healthy" | "broken" | "unknown"
	failureStage string // one of the classify stages, "" when healthy
	lastRunAt    time.Time
	lastOK       bool

	// optional heal hook, wired in Phase 2 (nil = detection only)
	healer func(ctx context.Context, stage string) error

	healMu          sync.Mutex // in-flight guard: at most one heal at a time
	healAttempts    int        // attempts in the current window (guarded by mu)
	healWindowStart time.Time  // start of the current heal window (guarded by mu)

	stopCh chan struct{}
}

func NewPipelineCanary(canaryURL string, logRepo *repository.LogRepository, collector *LogCollector) *PipelineCanary {
	return &PipelineCanary{
		canaryURL: canaryURL,
		logRepo:   logRepo,
		collector: collector,
		client:    &http.Client{Timeout: 5 * time.Second},
		interval:  envDuration("NPG_CANARY_INTERVAL", 5*time.Minute),
		bootDelay: envDuration("NPG_CANARY_BOOT_DELAY", 20*time.Second),
		deadline:  envDuration("NPG_CANARY_DEADLINE", 10*time.Second),
		status:    "unknown",
		stopCh:    make(chan struct{}),
	}
}

// SetHealer wires the auto-heal callback. Lock-guarded so it composes with the
// canary's running goroutine; intended to be called once at wiring time.
func (p *PipelineCanary) SetHealer(fn func(ctx context.Context, stage string) error) {
	p.mu.Lock()
	p.healer = fn
	p.mu.Unlock()
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "npgc" + hex.EncodeToString(b)
}

const (
	healMaxAttempts = 3
	healWindow      = 30 * time.Minute
)

// canHeal reports whether an auto-heal attempt is allowed for stage, given the
// attempts already made in the current window. Pure, for testability. Only the
// three nginx/tail-side stages are auto-healable; db_insert and
// nginx_unreachable must escalate.
func canHeal(stage string, attempts int, windowStart, now time.Time) bool {
	switch stage {
	case "nginx_write", "path_mismatch", "tail_stalled":
	default:
		return false
	}
	if now.Sub(windowStart) > healWindow {
		return true // window elapsed → fresh budget
	}
	return attempts < healMaxAttempts
}

// classifyCanaryFailure maps observed pipeline conditions to a failure stage.
// Pure function so the decision tree is unit-testable without I/O.
func classifyCanaryFailure(reachable, nonceInFile, tailPathMatches, accessFlushFresh bool) string {
	if !reachable {
		return "nginx_unreachable"
	}
	if !nonceInFile {
		return "nginx_write" // nginx never wrote the line to access_raw.log
	}
	if !tailPathMatches {
		return "path_mismatch" // tail is reading a different file than nginx writes
	}
	if !accessFlushFresh {
		return "tail_stalled" // file has it but tail isn't advancing
	}
	return "db_insert" // tail read it but the row never reached the DB
}

func (p *PipelineCanary) Start(ctx context.Context) {
	log.Printf("[PipelineCanary] starting (interval=%v boot_delay=%v deadline=%v target=%s)", p.interval, p.bootDelay, p.deadline, p.canaryURL)
	select {
	case <-ctx.Done():
		return
	case <-p.stopCh:
		return
	case <-time.After(p.bootDelay):
	}
	p.RunOnce(ctx)

	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-t.C:
			p.RunOnce(ctx)
		}
	}
}

func (p *PipelineCanary) Stop() { close(p.stopCh) }

// RunOnce fires one canary and records the result. Returns (ok, stage).
func (p *PipelineCanary) RunOnce(ctx context.Context) (bool, string) {
	nonce := newNonce()
	since := time.Now().Add(-2 * time.Second) // small skew margin
	reachable := p.fire(ctx, nonce)

	ok := false
	if reachable {
		ok = p.awaitRow(ctx, nonce, since)
	}

	stage := ""
	if !ok {
		stage = p.localize(reachable, nonce)
		log.Printf("[PipelineCanary] WARN: pipeline broken at stage=%q (nonce=%s target=%s). See /api/v1/health/detailed.", stage, nonce, p.canaryURL)
		p.attemptHeal(ctx, stage)
	} else if p.statusSnapshot() != "healthy" {
		log.Printf("[PipelineCanary] pipeline recovered (healthy)")
	}

	p.mu.Lock()
	p.lastRunAt = time.Now()
	p.lastOK = ok
	p.failureStage = stage
	if ok {
		p.status = "healthy"
		p.healAttempts = 0
		p.healWindowStart = time.Time{}
	} else {
		p.status = "broken"
	}
	p.mu.Unlock()
	return ok, stage
}

// attemptHeal runs the healer for a broken stage under the retry budget and the
// in-flight guard. It does NOT re-probe inline — the next scheduled (or manual)
// probe verifies recovery and resets the budget. Heal actions reuse fail-safe
// paths (nginx -t before reload), so a failed action leaves prior config intact.
func (p *PipelineCanary) attemptHeal(ctx context.Context, stage string) {
	if !p.healMu.TryLock() {
		return // a heal is already in progress
	}
	defer p.healMu.Unlock()

	p.mu.Lock()
	healer := p.healer
	now := time.Now()
	if p.healWindowStart.IsZero() || now.Sub(p.healWindowStart) > healWindow {
		p.healWindowStart = now
		p.healAttempts = 0
	}
	allowed := healer != nil && canHeal(stage, p.healAttempts, p.healWindowStart, now)
	if allowed {
		p.healAttempts++
	}
	attempts := p.healAttempts
	p.mu.Unlock()

	if healer == nil {
		return // detection only (no healer wired)
	}
	if !allowed {
		log.Printf("[PipelineCanary] auto-heal NOT attempted for stage=%q (attempts=%d/%d in window, or not healable) — escalating. Fix manually; see /api/v1/health/detailed.", stage, attempts, healMaxAttempts)
		return
	}
	log.Printf("[PipelineCanary] auto-heal attempt %d/%d for stage=%q", attempts, healMaxAttempts, stage)
	if err := healer(ctx, stage); err != nil {
		log.Printf("[PipelineCanary] auto-heal for stage=%q failed: %v", stage, err)
	}
}

func (p *PipelineCanary) fire(ctx context.Context, nonce string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.canaryURL+"?n="+nonce, nil)
	if err != nil {
		return false
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	// The /__npg_canary location returns 204. Any other status means the probe
	// did not traverse the intended path — a 403 (API source IP outside the
	// allowed private CIDRs), a 404 (location missing / config regressed), or a
	// 5xx. Treat those as unreachable so they escalate as non-healable, rather
	// than being misclassified as a downstream stage and triggering a heal
	// (ForceEnableRawLog / RestartTail) that cannot fix the real fault.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[PipelineCanary] WARN: canary probe to %s returned HTTP %d (expected 204) — check the /__npg_canary location (allow <private CIDR> / deny all / config regression).", p.canaryURL, resp.StatusCode)
		return false
	}
	return true
}

func (p *PipelineCanary) awaitRow(ctx context.Context, nonce string, since time.Time) bool {
	deadline := time.Now().Add(p.deadline)
	for time.Now().Before(deadline) {
		if ok, err := p.logRepo.CanaryRowExists(ctx, nonce, since); err == nil && ok {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(1 * time.Second):
		}
	}
	return false
}

// localize gathers evidence at the file checkpoint to classify the failure.
func (p *PipelineCanary) localize(reachable bool, nonce string) string {
	actual := p.collector.AccessLogPathActual()
	inFile := actual != "" && fileContainsRecent(actual, nonce)
	pathMatch := true
	// If nginx wrote the nonce but to a file the tail isn't reading, the nonce
	// won't be in `actual`; check the canonical file to distinguish a path
	// mismatch from nginx not writing at all.
	if !inFile && actual != canonicalAccessLogPath && fileContainsRecent(canonicalAccessLogPath, nonce) {
		inFile = true
		pathMatch = false
	}
	accessFlushFresh := p.collector.AccessLastFlushUnix() != 0 &&
		time.Since(time.Unix(p.collector.AccessLastFlushUnix(), 0)) < 2*p.interval
	return classifyCanaryFailure(reachable, inFile, pathMatch, accessFlushFresh)
}

// fileContainsRecent scans the tail (last 64KB) of a file for a substring.
func fileContainsRecent(path, needle string) bool {
	f, err := os.Open(path)
	if err != nil {
		// A missing file is a legitimate "not present". Any other open error
		// (e.g. EACCES after a logrotate create) would otherwise be silently
		// read as "nginx didn't write the line" and mis-drive classification.
		if !os.IsNotExist(err) {
			log.Printf("[PipelineCanary] WARN: cannot open %s to check nonce (heal classification may be wrong): %v", path, err)
		}
		return false
	}
	defer f.Close()
	const window = 64 * 1024
	if st, err := f.Stat(); err == nil && st.Size() > window {
		_, _ = f.Seek(-window, io.SeekEnd)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		log.Printf("[PipelineCanary] WARN: read error scanning %s for nonce (heal classification may be wrong): %v", path, err)
		return false
	}
	return strings.Contains(string(data), needle)
}

func (p *PipelineCanary) statusSnapshot() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

// Snapshot returns the canary state for the health endpoint.
func (p *PipelineCanary) Snapshot() (status, stage string, lastRunAt time.Time, lastOK bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status, p.failureStage, p.lastRunAt, p.lastOK
}

// HealState returns the current-window heal attempt count and whether the
// budget is exhausted (auto-heal has stopped and the pipeline is escalated).
func (p *PipelineCanary) HealState() (attempts int, exhausted bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healAttempts, p.healAttempts >= healMaxAttempts
}
