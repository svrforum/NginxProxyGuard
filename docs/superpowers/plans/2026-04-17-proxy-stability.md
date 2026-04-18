# Reverse Proxy Stability + Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the single-host reload path with retry + rollback + post-reload health verification, and expose Prometheus metrics — all without regressing the 33 characterization cases landed in v2.10.0.

**Architecture:** 4 sequential phases, each an independent PR landing on main. Phase 0 extracts a `nginxCLI` interface (testability), captures current reload behavior. Phase 1 adds retry-with-backoff around the existing in-memory rollback. Phase 2 adds post-reload health probe (worker + HTTP) with auto-revert. Phase 3 wires Prometheus counters/histograms throughout and exposes `/metrics`.

**Tech Stack:** Go 1.24 (Echo v4), Docker (exec for nginx control), `github.com/prometheus/client_golang` (new Phase 3 dep), existing characterization test pattern.

**Spec:** `docs/superpowers/specs/2026-04-17-proxy-stability-design.md` (gitignored; read for full rationale).

---

## Global File Map

| Phase | File | Action | Responsibility |
|-------|------|--------|----------------|
| 0 | `api/internal/nginx/nginx_cli.go` | Create | Narrow `nginxCLI` interface + `dockerNginxCLI` impl (extracted from manager.go) |
| 0 | `api/internal/nginx/manager.go` | Modify | Add `cli nginxCLI` field; `testConfigInternal`/`reloadNginxInternal` delegate to `cli` |
| 0 | `api/internal/nginx/reload_characterization_test.go` | Create | 4 cases capturing current testAndReloadNginx behavior |
| 1 | `api/internal/config/constants.go` | Modify | Add `ReloadMaxRetries`, `ReloadRetryBaseDelay`, transient regex |
| 1 | `api/internal/nginx/reload_retry.go` | Create | `testAndReloadNginxWithRetry`, `isTransientReloadError` helper |
| 1 | `api/internal/nginx/manager.go` | Modify | 3 callers switch from `testAndReloadNginx` to `testAndReloadNginxWithRetry`; on rollback, re-reload |
| 1 | `api/internal/nginx/reload_characterization_test.go` | Modify | Extend with retry cases (transient recovery, exhausted) |
| 2 | `api/internal/nginx/health_probe.go` | Create | `HealthProber` with `waitForWorkersReady` + `probeHTTP` + `Verify` |
| 2 | `api/internal/nginx/health_probe_test.go` | Create | 4 probe cases |
| 2 | `api/internal/nginx/manager.go` | Modify | `Manager.healthProber` field + invoke after reload; env-var opt-out |
| 2 | `api/internal/nginx/reload_retry.go` | Modify | Integrate health verification into retry loop |
| 2 | `api/internal/config/constants.go` | Modify | Add `HealthProbeTimeout`, `WorkerReadyTimeout` |
| 2 | `api/internal/bootstrap/services.go` | Modify | Build `HealthProber` and attach to `Manager` |
| 2 | `api/internal/nginx/reload_characterization_test.go` | Modify | Add health-fail rollback case |
| 3 | `api/go.mod` + `api/go.sum` | Modify | Add `github.com/prometheus/client_golang v1.19+` |
| 3 | `api/internal/metrics/metrics.go` | Create | All counter/histogram/gauge definitions + `init()` registration |
| 3 | `api/internal/metrics/metrics_test.go` | Create | Unit tests for metric increment + `/metrics` handler |
| 3 | `api/internal/handler/metrics.go` | Create | Echo handler wrapping `promhttp.Handler()` |
| 3 | `api/internal/bootstrap/handlers.go` | Modify | Add `Metrics *handler.MetricsHandler` field + `InitHandlers` |
| 3 | `api/internal/bootstrap/routes.go` | Modify | Register `GET /metrics` before protected group |
| 3 | `api/internal/nginx/reload_retry.go` | Modify | Instrument retry loop with counters + histogram |
| 3 | `api/internal/nginx/health_probe.go` | Modify | Instrument probes with counters + histogram |
| 3 | `api/internal/service/proxy_host_sync.go` | Modify | Instrument auto-recovery and config status gauge |
| 3 | `api/internal/nginx/proxy_host_config.go` | Modify | Wrap `GenerateConfigFull` timing histogram |

---

## Phase 0 — Extract `nginxCLI` + Reload Characterization Tests

**Branch:** `stability0/reload-tests`
**PR title:** `test(nginx): add reload failure scenario tests`
**Risk:** 🟢 Very low — pure refactor + new tests.

### Task 0.1: Create branch

- [ ] **Step 1: Sync main and branch off**

```bash
cd /opt/stacks/nginxproxyguard
git status  # expect clean (ignore .playwright-mcp/, test-results/)
git checkout main
git pull --ff-only origin main
git checkout -b stability0/reload-tests
```

### Task 0.2: Extract `nginxCLI` interface

**Files:**
- Create: `api/internal/nginx/nginx_cli.go`
- Modify: `api/internal/nginx/manager.go` (add field, delegate calls)

- [ ] **Step 1: Create `nginx_cli.go`**

```go
// api/internal/nginx/nginx_cli.go
package nginx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// nginxCLI abstracts the two docker exec calls the manager needs so
// tests can substitute a fake implementation without touching docker.
type nginxCLI interface {
	Test(ctx context.Context) error
	Reload(ctx context.Context) error
}

// dockerNginxCLI runs nginx commands via docker exec against the configured container.
type dockerNginxCLI struct {
	containerName string
}

func newDockerNginxCLI(containerName string) *dockerNginxCLI {
	return &dockerNginxCLI{containerName: containerName}
}

// Test runs `nginx -t` inside the container. Returns a non-nil error when the
// configuration is invalid or the exec itself fails.
func (d *dockerNginxCLI) Test(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", d.containerName, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// Reload runs `nginx -s reload` inside the container. A nil error means the
// reload signal was delivered (post-signal worker health is verified separately).
func (d *dockerNginxCLI) Reload(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", d.containerName, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -s reload failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
```

- [ ] **Step 2: Add `cli` field to Manager and initialize it**

In `api/internal/nginx/manager.go`, modify the struct (around line 24-37):

```go
type Manager struct {
	configPath     string
	certsPath      string
	modsecPath     string
	nginxContainer string
	skipTest       bool
	httpPort       string
	httpsPort      string
	apiURL         string
	dnsResolver    string
	enableIPv6     bool

	cli nginxCLI // extracted for testability (Phase 0)
}
```

In `NewManager` (around line 38), after setting `nginxContainer`, initialize:

```go
// ... existing code that determines `nginxContainer` ...

m := &Manager{
	// ... existing field assignments ...
	nginxContainer: nginxContainer,
	// ... etc ...
}
m.cli = newDockerNginxCLI(nginxContainer)
return m
```

If the current `NewManager` returns a struct literal directly, convert it to a variable first so the CLI can be assigned. The existing return shape (`*Manager`) stays identical.

- [ ] **Step 3: Delegate `testConfigInternal` and `reloadNginxInternal` to `cli`**

Around line 361 (`testConfigInternal`) replace the body with:

```go
func (m *Manager) testConfigInternal(ctx context.Context) error {
	if m.skipTest {
		return nil
	}
	return m.cli.Test(ctx)
}
```

Around line 385 (`reloadNginxInternal`) replace with:

```go
func (m *Manager) reloadNginxInternal(ctx context.Context) error {
	if m.skipTest {
		return nil
	}
	return m.cli.Reload(ctx)
}
```

Delete any inline `exec.CommandContext(... "nginx", "-t" ...)` and `"nginx", "-s", "reload"` blocks these functions used to have — they now live in `dockerNginxCLI`.

- [ ] **Step 4: Build to confirm nothing else depends on removed symbols**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.dev.yml build api 2>&1 | tail -15
```

Expected: build succeeds. Fix any compile errors (unused imports are the most likely culprit).

- [ ] **Step 5: Run existing tests to confirm no regression**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/... ./internal/service/... -run Characterization -count=1 2>&1 | tail -10'
```

Expected: `ok nginx-proxy-guard/internal/nginx` and `ok nginx-proxy-guard/internal/service`.

- [ ] **Step 6: Commit**

```bash
git add api/internal/nginx/nginx_cli.go api/internal/nginx/manager.go
git commit -m "refactor(nginx): extract docker exec into nginxCLI interface for testability"
```

### Task 0.3: Create reload characterization test

**Files:**
- Create: `api/internal/nginx/reload_characterization_test.go`

- [ ] **Step 1: Write the test file with fake CLI + 4 cases**

```go
// api/internal/nginx/reload_characterization_test.go
package nginx

import (
	"context"
	"errors"
	"testing"
)

// fakeNginxCLI records calls and returns scripted errors per call.
type fakeNginxCLI struct {
	testErrs   []error
	reloadErrs []error
	testCalls   int
	reloadCalls int
}

func (f *fakeNginxCLI) Test(ctx context.Context) error {
	idx := f.testCalls
	f.testCalls++
	if idx < len(f.testErrs) {
		return f.testErrs[idx]
	}
	return nil
}

func (f *fakeNginxCLI) Reload(ctx context.Context) error {
	idx := f.reloadCalls
	f.reloadCalls++
	if idx < len(f.reloadErrs) {
		return f.reloadErrs[idx]
	}
	return nil
}

func newFakeManager(cli nginxCLI) *Manager {
	return &Manager{cli: cli}
}

func TestTestAndReloadNginx_Success(t *testing.T) {
	cli := &fakeNginxCLI{}
	m := newFakeManager(cli)
	if err := m.testAndReloadNginx(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli.testCalls != 1 {
		t.Errorf("test calls = %d, want 1", cli.testCalls)
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload calls = %d, want 1", cli.reloadCalls)
	}
}

func TestTestAndReloadNginx_TestFails_SyntaxError(t *testing.T) {
	syntaxErr := errors.New("nginx: [emerg] invalid number of arguments in \"server_name\" directive")
	cli := &fakeNginxCLI{testErrs: []error{syntaxErr}}
	m := newFakeManager(cli)
	err := m.testAndReloadNginx(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if cli.reloadCalls != 0 {
		t.Errorf("reload should not be called on test failure, got %d calls", cli.reloadCalls)
	}
}

func TestTestAndReloadNginx_ReloadFails(t *testing.T) {
	reloadErr := errors.New("reload failed: permission denied")
	cli := &fakeNginxCLI{reloadErrs: []error{reloadErr}}
	m := newFakeManager(cli)
	err := m.testAndReloadNginx(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if cli.testCalls != 1 {
		t.Errorf("test calls = %d, want 1", cli.testCalls)
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload calls = %d, want 1", cli.reloadCalls)
	}
}

func TestTestAndReloadNginx_TransientDockerError_CurrentBehavior(t *testing.T) {
	// Pre-retry behavior: transient docker errors are NOT retried and propagate as-is.
	// Phase 1 will change this test (rename + retry expectation).
	transient := errors.New("docker: connection refused")
	cli := &fakeNginxCLI{testErrs: []error{transient}}
	m := newFakeManager(cli)
	err := m.testAndReloadNginx(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if cli.testCalls != 1 {
		t.Errorf("test calls = %d, want 1 (no retry in v2.10)", cli.testCalls)
	}
}
```

- [ ] **Step 2: Run the test file**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/ -run TestTestAndReloadNginx -count=1 -v 2>&1 | tail -30'
```

Expected: 4/4 PASS. All four subtests print `--- PASS`.

- [ ] **Step 3: Run full test suite to confirm no global regressions**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/... ./internal/service/... -count=1 2>&1 | tail -5'
```

Expected: both packages `ok`.

- [ ] **Step 4: Commit**

```bash
git add api/internal/nginx/reload_characterization_test.go
git commit -m "test(nginx): add reload characterization tests with fake nginxCLI (4 cases)"
```

### Task 0.4: Push branch and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin stability0/reload-tests
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --title "test(nginx): add reload failure scenario tests" --body "$(cat <<'EOF'
## Scope
Phase 0 of proxy-stability — extract docker exec behind a narrow `nginxCLI` interface and add 4 characterization tests covering the current single-host reload path.
Spec: docs/superpowers/specs/2026-04-17-proxy-stability-design.md §3

## Changes
- New `nginx_cli.go` with `nginxCLI` interface + `dockerNginxCLI` implementation
- `Manager` gains a `cli nginxCLI` field, used by `testConfigInternal` / `reloadNginxInternal`
- New `reload_characterization_test.go` with 4 cases: success, syntax-failure short-circuits reload, reload-failure, transient-docker-error-no-retry (current behavior baseline)

## Verification
- [x] `go test ./internal/nginx/... ./internal/service/...` green
- [x] Existing 33 characterization cases unchanged
- [x] `docker compose build api` succeeds

## Out of scope
- Retry logic (Phase 1)
- Post-reload health probe (Phase 2)
- Metrics (Phase 3)
EOF
)"
```

Record the PR URL.

---

## Phase 1 — Retry + Rollback

**Branch:** `stability1/retry-rollback`
**PR title:** `feat(nginx): add reload retry and config rollback`
**Risk:** 🟡 Medium — touches every caller of `testAndReloadNginx`.

**Prerequisites:** Phase 0 PR merged.

### Task 1.1: Create branch

- [ ] **Step 1: Sync and branch**

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b stability1/retry-rollback
```

### Task 1.2: Add retry constants

**Files:**
- Modify: `api/internal/config/constants.go`

- [ ] **Step 1: Add constants after existing `NginxReloaderDebounce` (around line 95)**

```go
// Reload retry behavior — governs testAndReloadNginxWithRetry.
// Transient errors (docker/network/IO glitches) retry with exponential backoff.
// Non-transient errors (nginx syntax, reload rejection) return immediately.
const (
	ReloadMaxRetries     = 2                      // additional retries after first attempt (total 3 tries)
	ReloadRetryBaseDelay = 500 * time.Millisecond // 500ms, 1s, 2s doubling
)
```

### Task 1.3: Create retry helper file

**Files:**
- Create: `api/internal/nginx/reload_retry.go`

- [ ] **Step 1: Write the retry logic**

```go
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
```

- [ ] **Step 2: Build to catch typos**

```bash
sudo docker compose -f docker-compose.dev.yml build api 2>&1 | tail -5
```

Expected: build succeeds.

### Task 1.4: Switch callers to the retry wrapper

**Files:**
- Modify: `api/internal/nginx/manager.go`

- [ ] **Step 1: Find every direct call and replace with retry wrapper**

```bash
grep -n "m.testAndReloadNginx(" api/internal/nginx/manager.go
```

Each call site needs: `m.testAndReloadNginx(ctx)` → `m.testAndReloadNginxWithRetry(ctx)`.

Known call sites (line numbers are approximate; rely on grep to find):
1. `GenerateConfigAndReload` (~line 242): inside the `if err := m.testAndReloadNginx(ctx); err != nil {` check
2. `GenerateConfigAndReloadWithCleanup` (~line 323)
3. `RemoveConfigAndReload` (~line 352)

Apply the rename in each. Do NOT touch the rollback blocks that follow — the existing in-memory rollback (reading file content into `configBackup` etc., then restoring on failure) continues to work.

- [ ] **Step 2: On rollback, re-reload to push the restored config**

Inside each of the three callers' rollback block (after the `writeFileAtomic` that restores the backup), add a follow-up reload attempt. Example for `GenerateConfigAndReload` — find the pattern that looks like:

```go
if err := m.testAndReloadNginx(ctx); err != nil {
	log.Printf("[WARN] Nginx test failed, rolling back config for host %s", data.Host.ID)
	if configExists && len(configBackup) > 0 {
		if writeErr := m.writeFileAtomic(configFile, configBackup, 0644); writeErr != nil {
			log.Printf("[ERROR] Failed to restore proxy host config %s: %v", configFilename, writeErr)
		}
	}
	// ...existing WAF restore block...
	return err
}
```

After swapping the call to `testAndReloadNginxWithRetry` and right before the existing `return err`, insert:

```go
// After restoring backups, re-apply the previous-good config so nginx
// is guaranteed to be running the rolled-back state rather than any
// partial state from the failed attempt.
if reloadErr := m.testAndReloadNginx(ctx); reloadErr != nil {
	log.Printf("[ERROR] Rollback reload failed for host %s (config restored on disk but nginx may need manual intervention): %v",
		data.Host.ID, reloadErr)
}
return err
```

Apply the same addition to the rollback blocks in `GenerateConfigAndReloadWithCleanup` and `RemoveConfigAndReload` (adapt the log context to use `host.ID` or the relevant identifier in scope). For `RemoveConfigAndReload` the "restore" is putting a file back that deletion removed; same post-restore reload pattern applies.

- [ ] **Step 3: Build**

```bash
sudo docker compose -f docker-compose.dev.yml build api 2>&1 | tail -5
```

Expected: success.

- [ ] **Step 4: Run existing tests**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/... ./internal/service/... -count=1 2>&1 | tail -5'
```

Expected: both packages `ok`.

### Task 1.5: Extend characterization tests for retry

**Files:**
- Modify: `api/internal/nginx/reload_characterization_test.go`

- [ ] **Step 1: Rename/replace the transient-docker test and add 3 new cases**

At the end of `reload_characterization_test.go`, find `TestTestAndReloadNginx_TransientDockerError_CurrentBehavior` and replace it with the following block (which removes the obsolete "current behavior" test and adds three retry-aware tests):

```go
// TestTestAndReloadNginxWithRetry_TransientRecovery — one transient failure then success.
func TestTestAndReloadNginxWithRetry_TransientRecovery(t *testing.T) {
	transient := errors.New("docker: connection refused")
	cli := &fakeNginxCLI{testErrs: []error{transient, nil}}
	m := newFakeManager(cli)
	if err := m.testAndReloadNginxWithRetry(context.Background()); err != nil {
		t.Fatalf("expected recovery, got error: %v", err)
	}
	if cli.testCalls != 2 {
		t.Errorf("test calls = %d, want 2 (one retry)", cli.testCalls)
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload calls = %d, want 1 (reached reload after retry)", cli.reloadCalls)
	}
}

// TestTestAndReloadNginxWithRetry_TransientExhausted — all attempts transient, retries exhausted.
func TestTestAndReloadNginxWithRetry_TransientExhausted(t *testing.T) {
	transient := errors.New("i/o timeout")
	cli := &fakeNginxCLI{testErrs: []error{transient, transient, transient}}
	m := newFakeManager(cli)
	err := m.testAndReloadNginxWithRetry(context.Background())
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	// config.ReloadMaxRetries = 2, so 3 total attempts.
	if cli.testCalls != 3 {
		t.Errorf("test calls = %d, want 3", cli.testCalls)
	}
}

// TestTestAndReloadNginxWithRetry_NonTransientImmediate — syntax errors do not retry.
func TestTestAndReloadNginxWithRetry_NonTransientImmediate(t *testing.T) {
	syntaxErr := errors.New("nginx: [emerg] unknown directive \"foo\"")
	cli := &fakeNginxCLI{testErrs: []error{syntaxErr, nil, nil}}
	m := newFakeManager(cli)
	err := m.testAndReloadNginxWithRetry(context.Background())
	if err == nil {
		t.Fatal("expected error on non-transient failure")
	}
	if cli.testCalls != 1 {
		t.Errorf("test calls = %d, want 1 (no retry on non-transient)", cli.testCalls)
	}
}

// TestIsTransientReloadError — verify classification of common errors.
func TestIsTransientReloadError(t *testing.T) {
	cases := []struct {
		err       error
		transient bool
	}{
		{nil, false},
		{errors.New("docker: connection refused"), true},
		{errors.New("docker: cannot connect to the Docker daemon"), true},
		{errors.New("i/o timeout"), true},
		{errors.New("resource temporarily unavailable"), true},
		{errors.New("context deadline exceeded"), true},
		{errors.New("nginx: [emerg] unknown directive"), false},
		{errors.New("nginx: [emerg] invalid number of arguments"), false},
		{errors.New("permission denied"), false},
	}
	for _, c := range cases {
		got := isTransientReloadError(c.err)
		if got != c.transient {
			t.Errorf("isTransientReloadError(%v) = %v, want %v", c.err, got, c.transient)
		}
	}
}
```

Also delete the now-replaced `TestTestAndReloadNginx_TransientDockerError_CurrentBehavior` function (it's superseded by `TestTestAndReloadNginxWithRetry_TransientRecovery`).

- [ ] **Step 2: Run the new tests**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/ -run "TestTestAndReloadNginx|TestIsTransient" -count=1 -v 2>&1 | tail -40'
```

Expected: all tests PASS. The three original Phase 0 tests (`Success`, `TestFails_SyntaxError`, `ReloadFails`) remain green; four new tests pass.

- [ ] **Step 3: Full package test**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/... ./internal/service/... -count=1 2>&1 | tail -5'
```

Expected: both `ok`.

### Task 1.6: E2E smoke

- [ ] **Step 1: Run the relevant E2E specs**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api 2>&1 | tail -5
sudo docker compose -f docker-compose.e2e-test.yml up -d
sleep 25
cd test/e2e
npx playwright test specs/proxy-host/sync.spec.ts specs/proxy-host/crud.spec.ts --reporter=list 2>&1 | tail -20
cd ..
sudo docker compose -f docker-compose.e2e-test.yml down -v
```

Expected: all specs pass. (The dashboard flaky test is unrelated; scope to proxy-host specs.)

### Task 1.7: Commit + PR

- [ ] **Step 1: Stage & commit**

```bash
cd /opt/stacks/nginxproxyguard
git add api/internal/config/constants.go api/internal/nginx/reload_retry.go api/internal/nginx/manager.go api/internal/nginx/reload_characterization_test.go
git commit -m "feat(nginx): add reload retry with backoff and post-rollback re-reload"
```

- [ ] **Step 2: Push + open PR**

```bash
git push -u origin stability1/retry-rollback
gh pr create --title "feat(nginx): add reload retry and config rollback" --body "$(cat <<'EOF'
## Scope
Phase 1 of proxy-stability — wrap nginx test/reload in a retry loop with exponential backoff for transient errors. Extend existing in-memory rollback to re-reload nginx after restoring the previous config.
Spec: docs/superpowers/specs/2026-04-17-proxy-stability-design.md §4

## Changes
- New constants `ReloadMaxRetries=2`, `ReloadRetryBaseDelay=500ms`
- New `reload_retry.go` with `testAndReloadNginxWithRetry` and `isTransientReloadError`
- Regex `reloadTransientErrorPattern` covers docker/network/IO transient patterns
- 3 manager entry points (`GenerateConfigAndReload`, `GenerateConfigAndReloadWithCleanup`, `RemoveConfigAndReload`) now use the retry wrapper and re-reload after rollback
- 4 new characterization tests (transient recovery, exhausted, non-transient immediate, isTransient classification)

## Verification
- [x] `go test ./internal/nginx/... ./internal/service/...` green — 33 existing + 7 new cases
- [x] `docker compose build api` succeeds
- [x] E2E `specs/proxy-host/` green

## Out of scope
- Post-reload health verification (Phase 2)
- Metrics (Phase 3)
EOF
)"
```

Record the PR URL.

---

## Phase 2 — Post-Reload Health Verification

**Branch:** `stability2/health-verify`
**PR title:** `feat(nginx): verify health after reload with auto-revert`
**Risk:** 🟡 Medium — adds a blocking post-reload step.

**Prerequisites:** Phase 1 PR merged.

### Task 2.1: Create branch

- [ ] **Step 1:**

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b stability2/health-verify
```

### Task 2.2: Add health probe constants

**Files:**
- Modify: `api/internal/config/constants.go`

- [ ] **Step 1: Add after the retry constants**

```go
// Post-reload health verification — runs after a successful nginx reload.
// Failure triggers the Phase 1 rollback mechanism.
const (
	WorkerReadyTimeout = 2 * time.Second        // max wait for `nginx: worker` process to appear
	HealthProbeTimeout = 500 * time.Millisecond // single curl to /health
)
```

### Task 2.3: Create the HealthProber

**Files:**
- Create: `api/internal/nginx/health_probe.go`

- [ ] **Step 1: Write the prober**

```go
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
```

### Task 2.4: Attach HealthProber to Manager

**Files:**
- Modify: `api/internal/nginx/manager.go`
- Modify: `api/internal/bootstrap/services.go`

- [ ] **Step 1: Add field to Manager**

In the `Manager` struct (around line 24), after the existing fields, add:

```go
	healthProber *HealthProber
}
```

Provide a setter so bootstrap can attach one after construction:

```go
// SetHealthProber wires the post-reload health verifier. May be called once
// after NewManager. Pass nil or a disabled prober to opt out.
func (m *Manager) SetHealthProber(p *HealthProber) {
	m.healthProber = p
}
```

Put this setter near the other setters (e.g., near `SetEnableIPv6`).

- [ ] **Step 2: Wire in bootstrap**

In `api/internal/bootstrap/services.go`, find where `nginx.NewManager` is called (may be in `services.go` or in a different bootstrap file — use grep). Add, right after the Manager is constructed:

```go
// Post-reload health probe (opt-out via NPG_HEALTH_PROBE=false)
probeDisabled := os.Getenv("NPG_HEALTH_PROBE") == "false"
nginxContainer := os.Getenv("NGINX_CONTAINER")
if nginxContainer == "" {
    nginxContainer = "npg-proxy"
}
nginxManager.SetHealthProber(nginx.NewHealthProber(nginxContainer, probeDisabled))
```

Ensure `os` is imported in the file. Update the import block if needed.

If `nginx.NewManager` is called outside `services.go` (e.g., `container.go`), attach the prober in that same file.

### Task 2.5: Integrate health probe into retry loop

**Files:**
- Modify: `api/internal/nginx/reload_retry.go`

- [ ] **Step 1: Call Verify after a successful reload**

Replace the body of `testAndReloadNginxWithRetry` with the following (same structure, extra verification step after success):

```go
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
		if err != nil {
			lastErr = err
			if !isTransientReloadError(err) {
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
				return lastErr
			}
		}
		return nil
	}

	return fmt.Errorf("nginx reload failed after %d attempts: %w",
		config.ReloadMaxRetries+1, lastErr)
}
```

- [ ] **Step 2: Build**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.dev.yml build api 2>&1 | tail -5
```

Expected: success.

### Task 2.6: Unit tests for HealthProber

**Files:**
- Create: `api/internal/nginx/health_probe_test.go`

- [ ] **Step 1: Write the tests**

```go
// api/internal/nginx/health_probe_test.go
package nginx

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeHealthExec struct {
	outputs []string // per-call stdout
	errs    []error  // per-call error
	calls   int
}

func (f *fakeHealthExec) Exec(ctx context.Context, args ...string) (string, error) {
	i := f.calls
	f.calls++
	var out string
	var err error
	if i < len(f.outputs) {
		out = f.outputs[i]
	}
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return out, err
}

func newTestProber(f *fakeHealthExec) *HealthProber {
	return &HealthProber{exec: f}
}

func TestHealthProber_Disabled_AlwaysSucceeds(t *testing.T) {
	p := &HealthProber{exec: &fakeHealthExec{}, disabled: true}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatalf("expected nil when disabled, got %v", err)
	}
}

func TestHealthProber_WorkersReady_ThenHTTPOK(t *testing.T) {
	// First exec (countWorkers): returns "4" (grep -c reports 3 workers + grep itself)
	// Second exec (probeHTTP): returns "" with no error (curl -sf success)
	f := &fakeHealthExec{outputs: []string{"4\n", ""}}
	p := newTestProber(f)
	if err := p.Verify(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if f.calls != 2 {
		t.Errorf("exec calls = %d, want 2", f.calls)
	}
}

func TestHealthProber_WorkersTimeout(t *testing.T) {
	// countWorkers returns "1" (which becomes 0 after subtracting grep itself)
	// repeatedly — should time out.
	f := &fakeHealthExec{}
	// Preload many "1" responses so polling returns 0 workers every time.
	for i := 0; i < 50; i++ {
		f.outputs = append(f.outputs, "1\n")
	}
	p := &HealthProber{exec: f}

	// Use a very short timeout to keep the test fast.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := p.waitForWorkersReady(ctx, 250*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestHealthProber_HTTPProbeFails(t *testing.T) {
	// workers OK, curl returns non-zero.
	f := &fakeHealthExec{
		outputs: []string{"4\n", "curl: (22) The requested URL returned error: 500\n"},
		errs:    []error{nil, errors.New("exit status 22")},
	}
	p := newTestProber(f)
	err := p.Verify(context.Background())
	if err == nil {
		t.Fatal("expected http probe error, got nil")
	}
}
```

- [ ] **Step 2: Run**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/ -run TestHealthProber -count=1 -v 2>&1 | tail -25'
```

Expected: 4/4 PASS.

### Task 2.7: Extend reload characterization tests

**Files:**
- Modify: `api/internal/nginx/reload_characterization_test.go`

- [ ] **Step 1: Add a health-probe-fail case**

Append to `reload_characterization_test.go`:

```go
// TestTestAndReloadNginxWithRetry_HealthProbeFail — reload succeeds, health probe
// rejects: caller must see an error so it can roll back.
func TestTestAndReloadNginxWithRetry_HealthProbeFail(t *testing.T) {
	cli := &fakeNginxCLI{}                           // test + reload both succeed
	badExec := &fakeHealthExec{                       // health exec returns workers-ready but http fails
		outputs: []string{"4\n", ""},
		errs:    []error{nil, errors.New("exit status 22")},
	}
	m := &Manager{cli: cli, healthProber: &HealthProber{exec: badExec}}

	err := m.testAndReloadNginxWithRetry(context.Background())
	if err == nil {
		t.Fatal("expected error from failing health probe")
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload calls = %d, want 1 (no retry on health fail)", cli.reloadCalls)
	}
}
```

- [ ] **Step 2: Run all reload + probe tests**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/nginx/ -run "TestTestAndReloadNginx|TestHealthProber|TestIsTransient" -count=1 -v 2>&1 | tail -40'
```

Expected: all PASS.

### Task 2.8: Manual smoke + E2E

- [ ] **Step 1: Run E2E**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api 2>&1 | tail -5
sudo docker compose -f docker-compose.e2e-test.yml up -d
sleep 25
cd test/e2e
npx playwright test specs/proxy-host/ specs/security/waf.spec.ts --reporter=list 2>&1 | tail -15
cd ..
sudo docker compose -f docker-compose.e2e-test.yml down -v
```

Expected: green.

### Task 2.9: Commit + PR

- [ ] **Step 1: Commit**

```bash
git add api/internal/config/constants.go api/internal/nginx/health_probe.go api/internal/nginx/health_probe_test.go api/internal/nginx/manager.go api/internal/nginx/reload_retry.go api/internal/nginx/reload_characterization_test.go api/internal/bootstrap/services.go
git commit -m "feat(nginx): verify worker + /health after reload with auto-revert"
```

- [ ] **Step 2: Push + PR**

```bash
git push -u origin stability2/health-verify
gh pr create --title "feat(nginx): verify health after reload with auto-revert" --body "$(cat <<'EOF'
## Scope
Phase 2 of proxy-stability — after a successful `nginx -s reload`, verify that workers are ready and `/health` returns 200. Any failure triggers the Phase 1 rollback mechanism so nginx ends up on the last known-good config.
Spec: docs/superpowers/specs/2026-04-17-proxy-stability-design.md §5

## Changes
- New `HealthProber` with 2-stage verification (workers ready + HTTP 200 on /health)
- `Manager.healthProber` field + `SetHealthProber` setter, wired from bootstrap
- `testAndReloadNginxWithRetry` calls `Verify` after a successful reload
- Opt-out via `NPG_HEALTH_PROBE=false`
- 4 new HealthProber unit tests + 1 new reload characterization test

## Verification
- [x] `go test ./internal/nginx/...` green
- [x] `docker compose build api` succeeds
- [x] E2E `specs/proxy-host/` and `specs/security/waf.spec.ts` green

## Out of scope
- Metrics (Phase 3)
EOF
)"
```

Record the PR URL.

---

## Phase 3 — Prometheus Metrics

**Branch:** `stability3/metrics`
**PR title:** `feat(observability): expose Prometheus metrics for proxy ops`
**Risk:** 🟢 Low — additive observability, no behavior change.

**Prerequisites:** Phase 2 PR merged.

### Task 3.1: Create branch + add prometheus dependency

**Files:**
- Modify: `api/go.mod`, `api/go.sum`

- [ ] **Step 1: Branch**

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b stability3/metrics
```

- [ ] **Step 2: Add dependency via `go get` inside a golang container**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache git > /dev/null 2>&1 && go get github.com/prometheus/client_golang@v1.20.5 && go mod tidy'
```

Expected: `go.mod` grows by a `require github.com/prometheus/client_golang v1.20.5` line (or compatible); `go.sum` grows with transitive deps.

### Task 3.2: Define metrics

**Files:**
- Create: `api/internal/metrics/metrics.go`

- [ ] **Step 1: Write metric definitions**

```go
// api/internal/metrics/metrics.go
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Counters
	NginxReloadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginx_reload_total",
		Help: "Total nginx reload attempts by final status.",
	}, []string{"status"})

	NginxReloadRetryTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nginx_reload_retry_total",
		Help: "Total individual retry attempts during reload (does not count the first attempt).",
	})

	NginxReloadRollbackTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginx_reload_rollback_total",
		Help: "Total config rollbacks by reason.",
	}, []string{"reason"})

	NginxHealthProbeFailureTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginx_health_probe_failure_total",
		Help: "Total health probe failures by probe type.",
	}, []string{"probe"})

	NginxAutoRecoveryTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nginx_auto_recovery_total",
		Help: "Total hosts isolated by SyncAllConfigs auto-recovery.",
	})

	// Histograms
	NginxReloadDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_reload_duration_seconds",
		Help:    "End-to-end duration of testAndReloadNginxWithRetry including retries and health verification.",
		Buckets: prometheus.ExponentialBuckets(0.05, 2, 9),
	})

	NginxConfigGenerationDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_config_generation_duration_seconds",
		Help:    "Duration of per-host config data aggregation plus template rendering.",
		Buckets: prometheus.DefBuckets,
	})

	NginxHealthProbeDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nginx_health_probe_duration_seconds",
		Help:    "Duration of each health probe phase.",
		Buckets: prometheus.ExponentialBuckets(0.01, 2, 8),
	}, []string{"probe"})

	// Gauges
	NginxConfigStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nginx_config_status",
		Help: "Current config status per host (1=ok, 0=error).",
	}, []string{"host_id"})

	NginxLastReloadTimestampSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "nginx_last_reload_timestamp_seconds",
		Help: "Unix timestamp of the last successful nginx reload.",
	})
)

// Register adds all metrics to the default Prometheus registry. Safe to call
// at startup — re-registration panics, so call exactly once.
func Register() {
	prometheus.MustRegister(
		NginxReloadTotal,
		NginxReloadRetryTotal,
		NginxReloadRollbackTotal,
		NginxHealthProbeFailureTotal,
		NginxAutoRecoveryTotal,
		NginxReloadDurationSeconds,
		NginxConfigGenerationDurationSeconds,
		NginxHealthProbeDurationSeconds,
		NginxConfigStatus,
		NginxLastReloadTimestampSeconds,
	)
}
```

### Task 3.3: Unit tests for metrics

**Files:**
- Create: `api/internal/metrics/metrics_test.go`

- [ ] **Step 1: Test that increments propagate to the registry**

```go
// api/internal/metrics/metrics_test.go
package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestReloadCountersIncrement(t *testing.T) {
	before := testutil.ToFloat64(NginxReloadTotal.WithLabelValues("success"))
	NginxReloadTotal.WithLabelValues("success").Inc()
	after := testutil.ToFloat64(NginxReloadTotal.WithLabelValues("success"))
	if after-before != 1 {
		t.Errorf("counter delta = %v, want 1", after-before)
	}
}

func TestRollbackReasonLabels(t *testing.T) {
	reasons := []string{"test_failed", "reload_failed", "health_failed", "retry_exhausted"}
	for _, r := range reasons {
		// Ensure the label is accepted (no panic/error) and counter is reachable.
		NginxReloadRollbackTotal.WithLabelValues(r).Inc()
		got := testutil.ToFloat64(NginxReloadRollbackTotal.WithLabelValues(r))
		if got < 1 {
			t.Errorf("reason=%q counter not incremented", r)
		}
	}
}

func TestHistogramObservesDuration(t *testing.T) {
	NginxReloadDurationSeconds.Observe(0.42)
	// CollectAndFormat returns the exposed representation; we just assert no panic
	// and that the histogram line exists in the exposition.
	got := testutil.CollectAndCount(NginxReloadDurationSeconds)
	if got < 1 {
		t.Errorf("expected at least 1 sample collected, got %d", got)
	}
}

func TestGaugeSet(t *testing.T) {
	NginxConfigStatus.WithLabelValues("host-xyz").Set(1)
	if v := testutil.ToFloat64(NginxConfigStatus.WithLabelValues("host-xyz")); v != 1 {
		t.Errorf("gauge = %v, want 1", v)
	}
}

func TestRegisterIdempotentlyPanicsOnSecondCall(t *testing.T) {
	// Register() MUST only be called once; verify that calling twice panics
	// (guarding against accidental double-registration in init order changes).
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on second Register()")
		}
	}()

	// First registration in metrics_test is implicit — in real code it happens in bootstrap.
	// To simulate, call twice:
	Register()
	Register()
}

func TestHealthProbeFailureLabels(t *testing.T) {
	labels := []string{"workers", "http"}
	for _, l := range labels {
		NginxHealthProbeFailureTotal.WithLabelValues(l).Inc()
		if v := testutil.ToFloat64(NginxHealthProbeFailureTotal.WithLabelValues(l)); v < 1 {
			t.Errorf("probe=%q not incremented", l)
		}
	}
	if !strings.Contains("workers http", labels[0]) {
		t.Errorf("sanity check failed") // pointless, silences unused import if shortened
	}
}
```

- [ ] **Step 2: Run**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./internal/metrics/ -count=1 -v 2>&1 | tail -30'
```

Expected: all PASS. If `TestRegisterIdempotentlyPanicsOnSecondCall` fails because the test package also triggered a `Register()`, adjust: delete that test and instead add a package-level `sync.Once` around `Register` body to make it idempotent. Document the choice in a comment.

### Task 3.4: Create the /metrics handler

**Files:**
- Create: `api/internal/handler/metrics.go`

- [ ] **Step 1: Write the handler**

```go
// api/internal/handler/metrics.go
package handler

import (
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler exposes the Prometheus default registry over an Echo route.
type MetricsHandler struct{}

func NewMetricsHandler() *MetricsHandler { return &MetricsHandler{} }

// ServeMetrics handles GET /metrics. Output is standard Prometheus text format.
// No authentication — intended for scraping on the internal docker network only.
func (h *MetricsHandler) ServeMetrics(c echo.Context) error {
	promhttp.Handler().ServeHTTP(c.Response().Writer, c.Request())
	return nil
}
```

### Task 3.5: Register handler + route + call metrics.Register()

**Files:**
- Modify: `api/internal/bootstrap/handlers.go`
- Modify: `api/internal/bootstrap/routes.go`
- Modify: `api/internal/bootstrap/container.go` (or wherever bootstrap initialization starts — call `metrics.Register()` there)

- [ ] **Step 1: Call `metrics.Register()` once at startup**

Open `api/internal/bootstrap/container.go`. In `NewContainer`, at the very top of the function (before `InitDB`), add:

```go
metrics.Register()
```

Add the import:

```go
import (
	// ... existing ...
	"nginx-proxy-guard/internal/metrics"
)
```

- [ ] **Step 2: Add `Metrics` field to `Handlers` struct**

In `api/internal/bootstrap/handlers.go`:

```go
type Handlers struct {
	// ... existing fields ...
	Metrics *handler.MetricsHandler
}

func InitHandlers(s *Services) *Handlers {
	return &Handlers{
		// ... existing ...
		Metrics: handler.NewMetricsHandler(),
	}
}
```

- [ ] **Step 3: Register GET /metrics**

In `api/internal/bootstrap/routes.go`, `RegisterRoutes` function. Add after the existing `/health` public route and before the `protected := e.Group(...)` group:

```go
// Prometheus metrics — public on the internal network only. Operators wanting
// external access should gate via upstream ACL / firewall.
e.GET("/metrics", c.Handlers.Metrics.ServeMetrics)
```

- [ ] **Step 4: Build**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.dev.yml build api 2>&1 | tail -5
```

Expected: success.

### Task 3.6: Instrument the reload path

**Files:**
- Modify: `api/internal/nginx/reload_retry.go`

- [ ] **Step 1: Instrument `testAndReloadNginxWithRetry`**

Replace the whole function with this instrumented version. The control flow is unchanged from Phase 2; only metrics calls are added.

```go
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
				// Determine which step failed; testAndReloadNginx is test-first.
				// If the message mentions "nginx -s reload", label reload_failed; else test_failed.
				reason := "test_failed"
				if strings.Contains(err.Error(), "reload") {
					reason = "reload_failed"
				}
				metrics.NginxReloadRollbackTotal.WithLabelValues(reason).Inc()
				return err
			}
			continue
		}

		if m.healthProber != nil {
			if verifyErr := m.healthProber.Verify(ctx); verifyErr != nil {
				log.Printf("[NginxReload] Post-reload health probe failed: %v", verifyErr)
				lastErr = fmt.Errorf("post-reload health probe failed: %w", verifyErr)
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
```

Update imports:

```go
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
```

### Task 3.7: Instrument the health probe

**Files:**
- Modify: `api/internal/nginx/health_probe.go`

- [ ] **Step 1: Wrap `waitForWorkersReady` and `probeHTTP` with timing + failure counters**

In `Verify`, replace the body with:

```go
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
```

Update imports:

```go
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
```

### Task 3.8: Instrument auto-recovery and config status

**Files:**
- Modify: `api/internal/service/proxy_host_sync.go`
- Modify: `api/internal/service/sync_auto_recovery.go`

- [ ] **Step 1: Increment `NginxAutoRecoveryTotal` per isolated host**

Open `api/internal/service/sync_auto_recovery.go`. Find the point where a failing host is marked error (search for `config_status` or similar UpdateConfigStatus call). Add a metrics call next to that DB update:

```go
// After UpdateConfigStatus(hostID, "error", ...)
metrics.NginxAutoRecoveryTotal.Inc()
metrics.NginxConfigStatus.WithLabelValues(hostID).Set(0)
```

For successful status updates elsewhere in the codebase (search `UpdateConfigStatus` for "ok"), add:

```go
metrics.NginxConfigStatus.WithLabelValues(hostID).Set(1)
```

Add import to each modified file: `"nginx-proxy-guard/internal/metrics"`.

### Task 3.9: Instrument config generation duration

**Files:**
- Modify: `api/internal/nginx/proxy_host_config.go` (the file that calls `proxyHostTemplate.Execute`)

- [ ] **Step 1: Find the Generate* entry point**

```bash
grep -n "proxyHostTemplate.Execute\|func.*GenerateConfigFull" api/internal/nginx/proxy_host_template.go api/internal/nginx/proxy_host_config.go 2>/dev/null
```

Wrap the execution call with a timing histogram:

```go
// Around the existing Execute call
start := time.Now()
defer func() {
    metrics.NginxConfigGenerationDurationSeconds.Observe(time.Since(start).Seconds())
}()
// ... existing code ...
```

Place the `defer` at the start of the function that calls `Execute` — typically `GenerateConfigFull`. Import `"nginx-proxy-guard/internal/metrics"` and `"time"` if not already present.

### Task 3.10: Build and run everything

- [ ] **Step 1: Build**

```bash
sudo docker compose -f docker-compose.dev.yml build api 2>&1 | tail -5
```

- [ ] **Step 2: Run full go test suite**

```bash
sudo docker run --rm -v "$(pwd)/api:/app" -w /app golang:1.24-alpine sh -c \
  'apk add --no-cache gcc musl-dev git > /dev/null 2>&1 && GOFLAGS="-mod=mod" go test ./... -count=1 2>&1 | tail -10'
```

Expected: all packages `ok` (metrics, nginx, service, handler, bootstrap, etc.).

### Task 3.11: Manual /metrics smoke

- [ ] **Step 1: Stand up a dev stack and curl /metrics**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.dev.yml up -d api
sleep 15
curl -s http://127.0.0.1:9080/metrics | grep '^nginx_' | head -20
sudo docker compose -f docker-compose.dev.yml down
```

Expected: output lines like:
```
# HELP nginx_reload_total Total nginx reload attempts by final status.
# TYPE nginx_reload_total counter
nginx_reload_total{status="success"} 1
...
```

If `nginx_reload_total` reads 0 because no reloads happened during startup, touch any proxy host (via API or UI) then re-curl.

### Task 3.12: E2E

- [ ] **Step 1:**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api 2>&1 | tail -5
sudo docker compose -f docker-compose.e2e-test.yml up -d
sleep 25
cd test/e2e
npx playwright test specs/proxy-host/ specs/security/ --reporter=list 2>&1 | tail -15
cd ..
sudo docker compose -f docker-compose.e2e-test.yml down -v
```

Expected: green.

### Task 3.13: Commit + PR

- [ ] **Step 1:**

```bash
cd /opt/stacks/nginxproxyguard
git add api/go.mod api/go.sum api/internal/metrics/ api/internal/handler/metrics.go api/internal/bootstrap/ api/internal/nginx/reload_retry.go api/internal/nginx/health_probe.go api/internal/nginx/proxy_host_config.go api/internal/service/
git status
git commit -m "feat(observability): expose Prometheus metrics for proxy reload and health ops"
git push -u origin stability3/metrics
gh pr create --title "feat(observability): expose Prometheus metrics for proxy ops" --body "$(cat <<'EOF'
## Scope
Phase 3 of proxy-stability — expose Prometheus metrics counting reload success/failure/retry/rollback events, health probe outcomes, and auto-recovery triggers. Add a histogram for reload duration and config generation time. Expose via GET /metrics.
Spec: docs/superpowers/specs/2026-04-17-proxy-stability-design.md §6

## Changes
- New dependency: `github.com/prometheus/client_golang v1.20.5`
- New `internal/metrics` package with 10 metric definitions + tests
- New `handler.MetricsHandler` + route `GET /metrics`
- Instrumented `testAndReloadNginxWithRetry`, `HealthProber.Verify`, SyncAllConfigs auto-recovery, and `GenerateConfigFull`
- `metrics.Register()` called once at bootstrap

## Verification
- [x] `go test ./...` green (existing 40+ cases plus 6 new metrics tests)
- [x] `docker compose build api` succeeds
- [x] `curl http://127.0.0.1:9080/metrics | grep nginx_` returns Prometheus-format output
- [x] E2E `specs/proxy-host/` and `specs/security/` green

## Out of scope
- UI dashboard that visualizes these metrics
- External `/metrics` exposure / authentication integration
EOF
)"
```

Record the PR URL.

---

## Phase Completion Checklist

After each PR merges, tick:

- [ ] Phase 0: `nginxCLI` interface + 4 characterization cases ✓
- [ ] Phase 1: Retry + in-memory rollback re-reload + 4 more characterization cases ✓
- [ ] Phase 2: HealthProber (workers + /health) + 4 probe tests + 1 more characterization case ✓
- [ ] Phase 3: Prometheus `/metrics` with 10 signals + 6 metric tests ✓

### Final release

After all 4 PRs merge:

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
```

Bump versions:

```bash
# api/internal/config/constants.go → const AppVersion = "2.11.0"
# ui/package.json → "version": "2.11.0"
```

```bash
git add api/internal/config/constants.go ui/package.json
git commit -m "release: v2.11.0"
git tag v2.11.0
git push origin main v2.11.0
```

---

## Troubleshooting

**`undefined: nginxCLI` in Phase 0:**
The interface is in the same `nginx` package. If a file can't see it, verify the file's `package nginx` declaration and that it lives under `api/internal/nginx/`.

**Retry loop never retries in Phase 1 despite a docker error:**
The transient regex is case-insensitive but requires the exact substring from the fake CLI error. Check the exact error message bytes with `fmt.Printf("%q", err.Error())` in the test.

**Phase 2 health probe spuriously fails in E2E:**
The E2E nginx container may take longer than `WorkerReadyTimeout` (2s) to spin workers under load. If so, raise `WorkerReadyTimeout` in `constants.go` or make the E2E setup wait for nginx readiness before tests start.

**Phase 3 `prometheus.MustRegister` panics on double-register:**
`metrics.Register()` must be called exactly once. If tests cause a second call, either guard with `sync.Once` inside `Register` or structure tests to share the package-level registration.

**`/metrics` returns empty response:**
Verify bootstrap called `metrics.Register()` and the route is registered before `e.Start()`. Check `bootstrap/routes.go` for the line added in Task 3.5 Step 3.
