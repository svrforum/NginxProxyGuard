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

// SetHealer wires the Phase 2 auto-heal callback. Safe to leave unset.
func (p *PipelineCanary) SetHealer(fn func(ctx context.Context, stage string) error) { p.healer = fn }

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
		if p.healer != nil {
			if err := p.healer(ctx, stage); err != nil {
				log.Printf("[PipelineCanary] heal attempt for stage=%q failed: %v", stage, err)
			}
		}
	} else if p.statusSnapshot() != "healthy" {
		log.Printf("[PipelineCanary] pipeline recovered (healthy)")
	}

	p.mu.Lock()
	p.lastRunAt = time.Now()
	p.lastOK = ok
	p.failureStage = stage
	if ok {
		p.status = "healthy"
	} else {
		p.status = "broken"
	}
	p.mu.Unlock()
	return ok, stage
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
	return resp.StatusCode > 0
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
		return false
	}
	defer f.Close()
	const window = 64 * 1024
	if st, err := f.Stat(); err == nil && st.Size() > window {
		_, _ = f.Seek(-window, io.SeekEnd)
	}
	data, err := io.ReadAll(f)
	if err != nil {
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
