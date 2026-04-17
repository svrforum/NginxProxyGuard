// api/internal/nginx/reload_retry.go
package nginx

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"

	"nginx-proxy-guard/internal/config"
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
	var lastErr error
	delay := config.ReloadRetryBaseDelay

	for attempt := 0; attempt <= config.ReloadMaxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("[NginxReload] Retry %d/%d after %v (last error: %v)",
				attempt, config.ReloadMaxRetries, delay, lastErr)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
			delay *= 2
		}

		err := m.testAndReloadNginx(ctx)
		if err == nil {
			return nil
		}
		lastErr = err

		if !isTransientReloadError(err) {
			return err // non-transient: caller rolls back immediately
		}
	}

	return fmt.Errorf("nginx reload failed after %d attempts: %w",
		config.ReloadMaxRetries+1, lastErr)
}
