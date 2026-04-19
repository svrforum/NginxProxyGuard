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
	"nginx-proxy-guard/internal/metrics"
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
// (1) worker processes exist and (2) nginx accepts TCP connections on its HTTP port.
type HealthProber struct {
	exec     healthExecutor
	httpPort string
	disabled bool
}

// NewHealthProber returns a prober targeting containerName probing on httpPort.
// If httpPort is empty, defaults to "80" (the standard nginx HTTP port in
// production). Custom ports (test environments using NGINX_HTTP_PORT, alt deployments)
// must be provided explicitly.
// If disabled is true, Verify always returns nil (opt-out via env var).
func NewHealthProber(containerName, httpPort string, disabled bool) *HealthProber {
	if httpPort == "" {
		httpPort = "80"
	}
	return &HealthProber{
		exec:     &dockerHealthExecutor{containerName: containerName},
		httpPort: httpPort,
		disabled: disabled,
	}
}

// Verify runs the two-stage probe. Returns nil on success; any failure message
// is suitable to include in user-facing error reporting.
func (p *HealthProber) Verify(ctx context.Context) error {
	if p.disabled {
		return nil
	}

	start := time.Now()
	if err := p.waitForWorkersReady(ctx, config.WorkerReadyTimeout); err != nil {
		metrics.NginxHealthProbeDurationSeconds.WithLabelValues("workers").Observe(time.Since(start).Seconds())
		metrics.NginxHealthProbeFailureTotal.WithLabelValues("workers").Inc()
		return fmt.Errorf("worker readiness: %w", err)
	}
	metrics.NginxHealthProbeDurationSeconds.WithLabelValues("workers").Observe(time.Since(start).Seconds())

	start = time.Now()
	if err := p.probeHTTP(ctx, config.HealthProbeTimeout); err != nil {
		metrics.NginxHealthProbeDurationSeconds.WithLabelValues("http").Observe(time.Since(start).Seconds())
		metrics.NginxHealthProbeFailureTotal.WithLabelValues("http").Inc()
		return fmt.Errorf("http probe: %w", err)
	}
	metrics.NginxHealthProbeDurationSeconds.WithLabelValues("http").Observe(time.Since(start).Seconds())

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

// probeHTTP checks nginx liveness via the dedicated `/health` endpoint on the
// default server (`zzz_default.conf`), which always returns 200 regardless of
// Direct IP Access policy.
//
// We deliberately avoid probing `/`: with Direct IP Access = block_444 the
// default server does `return 444;` on `/`, which drops the connection with
// no HTTP response. curl then exits 52 / http_code=000 even though nginx is
// perfectly alive — the old behaviour misread that as a reload failure and
// triggered a rollback (issue #122).
func (p *HealthProber) probeHTTP(ctx context.Context, timeout time.Duration) error {
	seconds := timeout.Seconds()
	port := p.httpPort
	if port == "" {
		port = "80"
	}
	// -s silent, -o discard body, -w emit http code, --max-time cap.
	// No -f: we want the http_code even on non-2xx so we can report it.
	cmd := fmt.Sprintf(
		"curl -s -o /dev/null -w '%%{http_code}' --max-time %.2f http://127.0.0.1:%s/health",
		seconds, port,
	)
	out, err := p.exec.Exec(ctx, "sh", "-c", cmd)
	code := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("nginx did not respond on :%s/health: %w (output: %s)", port, err, code)
	}
	// /health is owned by the default server and must return 200. Anything
	// else means the default server is missing or nginx is degraded.
	if code != "200" {
		return fmt.Errorf("/health on :%s returned %s, expected 200", port, code)
	}
	return nil
}
