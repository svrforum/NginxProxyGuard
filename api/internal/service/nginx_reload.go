package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/repository"
)

// nginxTestReloader is the minimal nginx manager surface the reloader needs:
// a single-lock `nginx -t` + reload with transient-error retry and post-reload
// health probe (implemented by nginx.Manager.TestAndReload).
type nginxTestReloader interface {
	TestAndReload(ctx context.Context) error
}

const (
	// maxReloadRetries is how many times a failed debounced reload is
	// re-attempted (with exponential backoff) before giving up. Combined with
	// the manager's internal transient retry this rides out a multi-minute
	// nginx container restart without permanently dropping queued changes
	// (e.g. IP bans already committed to the DB).
	maxReloadRetries = 5
	// reloadExecTimeout bounds one debounced test+reload execution. It must
	// cover nginx -t (60s) + reload (30s) plus the manager's internal
	// transient-error retries.
	reloadExecTimeout = 2 * time.Minute
	// maxReloadRetryDelay caps the exponential backoff between re-attempts.
	maxReloadRetryDelay = time.Minute
)

// NginxReloader provides debounced nginx reload functionality.
// Multiple reload requests within the debounce window are coalesced into a
// single `nginx -t` + reload. Failures are retried with exponential backoff
// (bounded by maxReloadRetries); when retries are exhausted a system log
// entry is written so operators can see that queued changes (e.g. IP bans)
// are not applied.
type NginxReloader struct {
	nginx         nginxTestReloader
	systemLogRepo *repository.SystemLogRepository // optional; surfaces reload failures in the UI log viewer
	debounceTime  time.Duration
	mu            sync.Mutex
	pending       bool
	timer         *time.Timer
	lastReload    time.Time
	reloadCount   int64
	retryCount    int // consecutive failed debounced executions since the last success
}

// NewNginxReloader creates a new debounced nginx reloader.
// systemLogRepo may be nil (failures then only reach the container log).
func NewNginxReloader(nginx nginxTestReloader, systemLogRepo *repository.SystemLogRepository, debounceTime time.Duration) *NginxReloader {
	if debounceTime == 0 {
		debounceTime = 2 * time.Second // Default 2 second debounce
	}
	return &NginxReloader{
		nginx:         nginx,
		systemLogRepo: systemLogRepo,
		debounceTime:  debounceTime,
	}
}

// RequestReload queues a reload request
// Returns immediately - the actual nginx -t + reload happens after the debounce period
func (r *NginxReloader) RequestReload(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.pending = true

	// Cancel existing timer
	if r.timer != nil {
		r.timer.Stop()
	}

	// Start new timer
	r.timer = time.AfterFunc(r.debounceTime, func() {
		r.executeReload()
	})

	log.Printf("[NginxReloader] Reload queued, will execute in %v", r.debounceTime)
}

// RequestReloadImmediate performs an immediate test+reload, bypassing debounce
func (r *NginxReloader) RequestReloadImmediate(ctx context.Context) error {
	r.mu.Lock()
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.pending = false
	r.mu.Unlock()

	err := r.nginx.TestAndReload(ctx)
	if err == nil {
		r.mu.Lock()
		r.retryCount = 0
		r.mu.Unlock()
	}
	return err
}

// executeReload performs the actual nginx test + reload
func (r *NginxReloader) executeReload() {
	r.mu.Lock()
	if !r.pending {
		r.mu.Unlock()
		return
	}
	r.pending = false
	r.timer = nil
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), reloadExecTimeout)
	defer cancel()

	log.Println("[NginxReloader] Executing debounced nginx test+reload")
	if err := r.nginx.TestAndReload(ctx); err != nil {
		r.scheduleRetryOrGiveUp(err)
		return
	}

	r.mu.Lock()
	r.lastReload = time.Now()
	r.reloadCount++
	recovered := r.retryCount > 0
	r.retryCount = 0
	r.mu.Unlock()
	if recovered {
		log.Println("[NginxReloader] Reload succeeded after retry — pending config changes are now applied")
	} else {
		log.Println("[NginxReloader] Reload completed successfully")
	}
}

// scheduleRetryOrGiveUp re-arms the debounce timer with exponential backoff so
// a transient nginx failure (e.g. container restarting) doesn't permanently
// drop the queued reload — without it, changes already committed to the DB
// (IP bans, URI blocks, filter updates) would silently never reach nginx.
// After maxReloadRetries consecutive failures it gives up and writes a system
// log entry so operators can see the drift.
func (r *NginxReloader) scheduleRetryOrGiveUp(reloadErr error) {
	r.mu.Lock()
	r.retryCount++
	attempt := r.retryCount
	if attempt <= maxReloadRetries {
		delay := r.retryDelay(attempt)
		r.pending = true
		if r.timer != nil {
			r.timer.Stop()
		}
		r.timer = time.AfterFunc(delay, r.executeReload)
		r.mu.Unlock()
		log.Printf("[NginxReloader] Reload failed (attempt %d/%d), retrying in %v: %v",
			attempt, maxReloadRetries+1, delay, reloadErr)
		return
	}
	r.retryCount = 0
	r.mu.Unlock()
	log.Printf("[NginxReloader] Reload failed after %d attempts, giving up — nginx keeps running its previous config; pending changes (e.g. IP bans) are NOT applied. Check the nginx container, then save any host or security setting to retry: %v",
		attempt, reloadErr)
	r.logGiveUp(attempt, reloadErr)
}

// retryDelay returns the backoff before retry N (1-based): debounce×2^N,
// capped at maxReloadRetryDelay (2s debounce → 4s, 8s, 16s, 32s, 60s).
func (r *NginxReloader) retryDelay(attempt int) time.Duration {
	delay := r.debounceTime << uint(attempt)
	if delay > maxReloadRetryDelay {
		delay = maxReloadRetryDelay
	}
	return delay
}

// logGiveUp writes a system log entry (visible in the UI log viewer) when all
// reload retries are exhausted, mirroring proxy_host_sync's failure entries.
func (r *NginxReloader) logGiveUp(attempts int, reloadErr error) {
	if r.systemLogRepo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	details, _ := json.Marshal(map[string]string{
		"attempts": fmt.Sprintf("%d", attempts),
		"error":    reloadErr.Error(),
	})
	if err := r.systemLogRepo.Create(ctx, &repository.SystemLog{
		Source:    repository.SourceInternal,
		Level:     repository.LevelError,
		Message:   fmt.Sprintf("Nginx reload failed after %d attempts — queued changes (e.g. IP bans, URI blocks) are not applied: %s", attempts, reloadErr.Error()),
		Details:   details,
		Component: "nginx_reloader",
	}); err != nil {
		log.Printf("[NginxReloader] Failed to write system log entry: %v", err)
	}
}

// IsPending returns whether a reload is pending
func (r *NginxReloader) IsPending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending
}

// GetStats returns reload statistics
func (r *NginxReloader) GetStats() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]interface{}{
		"pending":      r.pending,
		"last_reload":  r.lastReload,
		"reload_count": r.reloadCount,
	}
}

// Flush forces any pending reload to execute immediately
func (r *NginxReloader) Flush(ctx context.Context) error {
	r.mu.Lock()
	pending := r.pending
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.pending = false
	r.mu.Unlock()

	if pending {
		log.Println("[NginxReloader] Flushing pending reload")
		err := r.nginx.TestAndReload(ctx)
		if err == nil {
			r.mu.Lock()
			r.retryCount = 0
			r.mu.Unlock()
		}
		return err
	}
	return nil
}
