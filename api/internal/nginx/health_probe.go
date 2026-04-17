// api/internal/nginx/health_probe.go
package nginx

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
)

// healthExecutor wraps the docker exec call so tests can substitute a fake
// without spawning real docker processes.
type healthExecutor interface {
	Exec(ctx context.Context, args ...string) (string, error)
}

type dockerHealthExecutor struct {
	containerName string
}

func (e *dockerHealthExecutor) Exec(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", e.containerName}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// HealthProber verifies nginx is serving traffic after a reload by checking
// (1) worker processes exist and (2) the /health endpoint responds 200.
type HealthProber struct {
	exec     healthExecutor
	disabled bool
}

// NewHealthProber returns a prober targeting containerName. If disabled is true,
// Verify always returns nil (opt-out via env var handled by caller).
func NewHealthProber(containerName string, disabled bool) *HealthProber {
	return &HealthProber{
		exec:     &dockerHealthExecutor{containerName: containerName},
		disabled: disabled,
	}
}

// Verify runs the two-stage probe. Returns nil on success; any failure message
// is suitable to include in user-facing error reporting.
func (p *HealthProber) Verify(ctx context.Context) error {
	if p.disabled {
		return nil
	}
	if err := p.waitForWorkersReady(ctx, config.WorkerReadyTimeout); err != nil {
		return fmt.Errorf("worker readiness: %w", err)
	}
	if err := p.probeHTTP(ctx, config.HealthProbeTimeout); err != nil {
		return fmt.Errorf("http probe: %w", err)
	}
	return nil
}

// waitForWorkersReady polls `ps` inside the container until at least one
// `nginx: worker` process is visible, or the timeout elapses.
func (p *HealthProber) waitForWorkersReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		workers, err := p.countWorkers(ctx)
		if err == nil && workers > 0 {
			return nil
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("no nginx worker process visible within %v", timeout)
}

// countWorkers returns the number of lines in `ps ax` containing "nginx: worker".
func (p *HealthProber) countWorkers(ctx context.Context) (int, error) {
	out, err := p.exec.Exec(ctx, "sh", "-c", "ps ax | grep -c 'nginx: worker' || true")
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(out)
	// `grep -c` counts grep-itself; subtract 1. Fallback: treat missing as 0.
	n, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("parse worker count %q: %w", trimmed, err)
	}
	if n > 0 {
		n-- // subtract the grep process match
	}
	return n, nil
}

// probeHTTP runs `curl -sf --max-time X http://127.0.0.1:<httpPort>/health` inside the container.
// Returns nil on 2xx; any non-2xx or network issue is an error.
func (p *HealthProber) probeHTTP(ctx context.Context, timeout time.Duration) error {
	seconds := timeout.Seconds()
	cmd := fmt.Sprintf("curl -sf --max-time %.2f http://127.0.0.1:80/health", seconds)
	_, err := p.exec.Exec(ctx, "sh", "-c", cmd)
	if err != nil {
		return fmt.Errorf("/health did not return 2xx: %w", err)
	}
	return nil
}
