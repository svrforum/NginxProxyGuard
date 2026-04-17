// api/internal/nginx/reload_retry.go
package nginx

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/metrics"
)

// reloadTransientErrorPattern matches error messages that signal a transient
// environmental issue (docker daemon blip, brief IO timeout) where retrying
// has a good chance of success. Config-level failures (nginx syntax errors,
// permission denied) must NOT match here — they would just waste retries.
var reloadTransientErrorPattern = regexp.MustCompile(
	`(?i)(docker[^\n]*connection refused|docker[^\n]*cannot connect|docker[^\n]*no such|i/o timeout|resource temporarily unavailable|context deadline exceeded|connection reset)`,
)

// isTransientReloadError reports whether err looks like a transient operational
// issue worth retrying.
func isTransientReloadError(err error) bool {
	if err == nil {
		return false
	}
	return reloadTransientErrorPattern.MatchString(err.Error())
}

// testAndReloadNginxWithRetry runs testAndReloadNginx with exponential backoff
// retry for transient errors. Non-transient errors return immediately so the
// caller can roll back user-visible changes.
//
// Must be called within executeWithLock (same contract as testAndReloadNginx).
func (m *Manager) testAndReloadNginxWithRetry(ctx context.Context) error {
	start := time.Now()
	defer func() {
		metrics.NginxReloadDurationSeconds.Observe(time.Since(start).Seconds())
	}()

	var lastErr error
	delay := config.ReloadRetryBaseDelay

	for attempt := 0; attempt <= config.ReloadMaxRetries; attempt++ {
		if attempt > 0 {
			metrics.NginxReloadRetryTotal.Inc()
			log.Printf("[NginxReload] Retry %d/%d after %v (last error: %v)",
				attempt, config.ReloadMaxRetries, delay, lastErr)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				metrics.NginxReloadTotal.WithLabelValues("failed").Inc()
				return ctx.Err()
			}
			delay *= 2
		}

		err := m.testAndReloadNginx(ctx)
		if err != nil {
			lastErr = err
			if !isTransientReloadError(err) {
				metrics.NginxReloadTotal.WithLabelValues("failed").Inc()
				// testAndReloadNginx runs `nginx -t` before `nginx -s reload`,
				// so if the message mentions "reload" the reload step failed;
				// otherwise the config test failed.
				reason := "test_failed"
				if strings.Contains(err.Error(), "reload") {
					reason = "reload_failed"
				}
				metrics.NginxReloadRollbackTotal.WithLabelValues(reason).Inc()
				return err
			}
			continue
		}

		// Reload reported success. Verify workers + HTTP probe before
		// considering the attempt complete.
		if m.healthProber != nil {
			if verifyErr := m.healthProber.Verify(ctx); verifyErr != nil {
				log.Printf("[NginxReload] Post-reload health probe failed: %v", verifyErr)
				lastErr = fmt.Errorf("post-reload health probe failed: %w", verifyErr)
				// Health failures are effectively non-transient — config must be rolled back.
				// Return immediately so the caller restores the previous-good config.
				metrics.NginxReloadTotal.WithLabelValues("failed").Inc()
				metrics.NginxReloadRollbackTotal.WithLabelValues("health_failed").Inc()
				return lastErr
			}
		}

		metrics.NginxReloadTotal.WithLabelValues("success").Inc()
		metrics.NginxLastReloadTimestampSeconds.SetToCurrentTime()
		return nil
	}

	metrics.NginxReloadTotal.WithLabelValues("failed").Inc()
	metrics.NginxReloadRollbackTotal.WithLabelValues("retry_exhausted").Inc()
	return fmt.Errorf("nginx reload failed after %d attempts: %w",
		config.ReloadMaxRetries+1, lastErr)
}
