package nginx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// What docker answers while compose recreates the nginx container.
var errNginxNotRunning = errors.New("nginx -t failed: exit status 1: Error response from daemon: Container 5f0 is not running")

var errNginxRejects = errors.New(`nginx -t failed: exit status 1: nginx: [emerg] unknown directive "brotli_x" in /etc/nginx/nginx.conf:40`)

// scriptedNginxCLI answers nginx -t from a script, then with `then` once the
// script runs out, answers reloads from their own script (then nil), and
// counts calls. Safe across goroutines.
type scriptedNginxCLI struct {
	mu      sync.Mutex
	tests   []error
	then    error
	reloads []error
	nTest   int
	nReload int
}

func (f *scriptedNginxCLI) Test(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.nTest
	f.nTest++
	if i < len(f.tests) {
		return f.tests[i]
	}
	return f.then
}

func (f *scriptedNginxCLI) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.nReload
	f.nReload++
	if i < len(f.reloads) {
		return f.reloads[i]
	}
	return nil
}

func (f *scriptedNginxCLI) counts() (tests, reloads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nTest, f.nReload
}

// previousNginxConf stands in for the file the previous release rendered:
// v2.60.1 with "Enable Access Log" off, which silenced access_raw.log.
const previousNginxConf = "# previous release\nhttp {\n    access_log off;\n    include /etc/nginx/conf.d/*.conf;\n}\n"

// deferredTestManager returns a manager whose nginx.conf holds
// previousNginxConf, and the path of that file.
func deferredTestManager(t *testing.T, cli nginxCLI) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	confd := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confd, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(target, []byte(previousNginxConf), 0644); err != nil {
		t.Fatalf("seed nginx.conf: %v", err)
	}
	return &Manager{configPath: confd, cli: cli}, target
}

func readConf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// liveSettings is the global_settings row, read again on every attempt the
// way startup's step reads it.
type liveSettings struct {
	mu        sync.Mutex
	accessLog bool
	brotli    bool
}

func (l *liveSettings) save(accessLog, brotli bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accessLog, l.brotli = accessLog, brotli
}

func mainConfStep(m *Manager, live *liveSettings) DeferredStep {
	return DeferredStep{Name: "nginx.conf", Apply: func(ctx context.Context) error {
		s := baselineSettings()
		live.mu.Lock()
		s.AccessLogEnabled, s.BrotliEnabled = live.accessLog, live.brotli
		live.mu.Unlock()
		return m.GenerateMainNginxConfig(ctx, s, nil, false, TrustedProxyConfig{})
	}}
}

// On an upgrade compose starts nginx after the API, so the boot render of
// nginx.conf cannot be tested and is rolled back to the previous release's
// file. Once nginx is up it must be applied, from the settings as they are
// then, with exactly one reload.
func TestDeferredMainConfigAppliedOnceNginxIsUp(t *testing.T) {
	cli := &scriptedNginxCLI{tests: []error{
		errNginxNotRunning, // boot attempt
		errNginxNotRunning, // first check: nginx still down
		errNginxNotRunning, // second check
	}}
	m, target := deferredTestManager(t, cli)
	live := &liveSettings{accessLog: false, brotli: true}

	var boot DeferredSteps
	deferred, err := boot.Run(context.Background(), mainConfStep(m, live))
	if !deferred || !IsNginxUnreachableError(err) {
		t.Fatalf("boot attempt against a stopped nginx: deferred=%v err=%v, want deferred with the not-running error", deferred, err)
	}
	if got := readConf(t, target); got != previousNginxConf {
		t.Fatalf("an untested nginx.conf was left on disk at boot:\n%s", got)
	}

	// The operator saves Global Settings while nginx is still down: the
	// retry must apply that save, not what boot rendered.
	live.save(false, false)

	if err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, 5*time.Second); err != nil {
		t.Fatalf("ApplyWhenUp: %v", err)
	}

	want := baselineSettings()
	want.AccessLogEnabled, want.BrotliEnabled = false, false
	got := readConf(t, target)
	if got != renderOnly(t, want) {
		t.Fatalf("nginx.conf after nginx came up is not the render of the current settings:\n%s", got)
	}
	if lines := httpLevelAccessLogDirectives(t, got); len(lines) != 0 {
		t.Errorf("http-level access_log survived the upgrade: %q", lines)
	}
	if _, reloads := cli.counts(); reloads != 1 {
		t.Errorf("reloads = %d, want 1", reloads)
	}
}

// nginx is running and rejects the render: that is a config error, not a
// start-up race. The file is rolled back and nothing retries it.
func TestDeferredMainConfigRejectedAtBootIsNotRetried(t *testing.T) {
	cli := &scriptedNginxCLI{tests: []error{errNginxRejects}}
	m, target := deferredTestManager(t, cli)

	var boot DeferredSteps
	deferred, err := boot.Run(context.Background(), mainConfStep(m, &liveSettings{}))
	if deferred || err == nil {
		t.Fatalf("rejected render: deferred=%v err=%v, want not deferred with the error", deferred, err)
	}
	if n := len(boot.Steps()); n != 0 {
		t.Fatalf("%d step(s) kept for later, want none", n)
	}
	if err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, time.Second); err != nil {
		t.Fatalf("ApplyWhenUp with nothing to do: %v", err)
	}
	if tests, reloads := cli.counts(); tests != 1 || reloads != 0 {
		t.Errorf("nginx -t ran %d time(s) and reload %d, want 1 and 0", tests, reloads)
	}
	if got := readConf(t, target); got != previousNginxConf {
		t.Errorf("rejected nginx.conf was not rolled back:\n%s", got)
	}
}

// Only a step that failed because nginx was not running is kept.
func TestDeferredStepsKeepOnlyNginxNotRunningFailures(t *testing.T) {
	failWith := func(err error) func(context.Context) error {
		return func(context.Context) error { return err }
	}
	var boot DeferredSteps
	for _, s := range []DeferredStep{
		{Name: "rejected", Apply: failWith(errNginxRejects)},
		{Name: "applied", Apply: failWith(nil)},
		{Name: "no container", Apply: failWith(errors.New("nginx -t failed: exit status 1: Error: No such container: npg-proxy"))},
		{Name: "no docker", Apply: failWith(errors.New("nginx -t failed: exit status 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock."))},
		{Name: "not running", Apply: failWith(errNginxNotRunning)},
	} {
		boot.Run(context.Background(), s)
	}
	var names []string
	for _, s := range boot.Steps() {
		names = append(names, s.Name)
	}
	if got := strings.Join(names, ","); got != "no container,not running" {
		t.Errorf("kept %q, want %q", got, "no container,not running")
	}
}

// nginx comes up but rejects the render then: rolled back, reported, and no
// further checks or reload.
func TestDeferredStepRejectedOnceNginxIsUpIsNotRetried(t *testing.T) {
	cli := &scriptedNginxCLI{tests: []error{
		errNginxNotRunning, // boot attempt
		nil,                // check: nginx is up
		errNginxRejects,    // the step's own nginx -t
	}}
	m, target := deferredTestManager(t, cli)

	var boot DeferredSteps
	boot.Run(context.Background(), mainConfStep(m, &liveSettings{}))
	err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "unknown directive") {
		t.Fatalf("ApplyWhenUp = %v, want the rejection", err)
	}
	if tests, reloads := cli.counts(); tests != 3 || reloads != 0 {
		t.Errorf("nginx -t ran %d time(s) and reload %d, want 3 and 0", tests, reloads)
	}
	if got := readConf(t, target); got != previousNginxConf {
		t.Errorf("rejected nginx.conf was not rolled back:\n%s", got)
	}
}

// nginx goes away again between the check and the step (a restart): wait
// again and run the step again.
func TestDeferredApplyWaitsAgainWhenNginxGoesAway(t *testing.T) {
	cli := &scriptedNginxCLI{tests: []error{
		errNginxNotRunning, // boot attempt
		nil,                // check: up
		errNginxNotRunning, // step: gone again
		errNginxNotRunning, // check: still down
		nil,                // check: up
	}}
	m, target := deferredTestManager(t, cli)

	var boot DeferredSteps
	boot.Run(context.Background(), mainConfStep(m, &liveSettings{}))
	if err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, 5*time.Second); err != nil {
		t.Fatalf("ApplyWhenUp: %v", err)
	}
	if lines := httpLevelAccessLogDirectives(t, readConf(t, target)); len(lines) != 0 {
		t.Errorf("nginx.conf not applied: http-level %q", lines)
	}
	if _, reloads := cli.counts(); reloads != 1 {
		t.Errorf("reloads = %d, want 1", reloads)
	}
}

// Reachable is not enough: the nginx entrypoint still rewrites files in the
// shared volume before it starts nginx, and a reload needs a running master.
// Wait for nginx's worker processes.
func TestDeferredApplyWaitsForNginxWorkers(t *testing.T) {
	cli := &scriptedNginxCLI{tests: []error{errNginxNotRunning}} // boot attempt; nginx -t passes after
	noWorker := errors.New("exit status 1")                      // pgrep found nothing
	exec := &fakeHealthExec{
		outputs: []string{"", "", "114\n115\n", "4\n", "200"},
		// Two checks with the container up but no worker yet, then workers;
		// then the post-reload probe (workers, /health).
		errs: []error{noWorker, noWorker, nil, nil, nil},
	}
	m, target := deferredTestManager(t, cli)
	m.healthProber = &HealthProber{exec: exec, httpPort: "80"}

	inner := mainConfStep(m, &liveSettings{})
	armed, checksBeforeApply := false, -1
	step := DeferredStep{Name: inner.Name, Apply: func(ctx context.Context) error {
		if armed && checksBeforeApply < 0 {
			checksBeforeApply = exec.calls
		}
		return inner.Apply(ctx)
	}}

	var boot DeferredSteps
	boot.Run(context.Background(), step)
	armed = true
	if err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, 5*time.Second); err != nil {
		t.Fatalf("ApplyWhenUp: %v", err)
	}
	if checksBeforeApply != 3 {
		t.Errorf("step ran after %d worker check(s), want 3 (only once workers showed)", checksBeforeApply)
	}
	// The check must not count itself. A `ps | grep` inside `sh -c` does:
	// the shell's own command line holds the pattern, so it reads one worker
	// in a container where nginx has not started.
	if got := strings.Join(exec.cmdArgs[0], " "); got != "pgrep -f nginx: worker" {
		t.Errorf("worker check runs %q, want pgrep -f with the worker title", got)
	}
	if lines := httpLevelAccessLogDirectives(t, readConf(t, target)); len(lines) != 0 {
		t.Errorf("nginx.conf not applied: http-level %q", lines)
	}
	if _, reloads := cli.counts(); reloads != 1 {
		t.Errorf("reloads = %d, want 1", reloads)
	}
}

// With the health probe off there is no worker check, so the steps can run
// while the entrypoint has not started nginx yet. The reload then finds no
// master: that is "not up yet", so wait and run the steps again.
func TestDeferredApplyWaitsWhenNginxHasNotStarted(t *testing.T) {
	cli := &scriptedNginxCLI{
		tests:   []error{errNginxNotRunning}, // boot attempt; nginx -t passes after
		reloads: []error{errors.New(`nginx -s reload failed: exit status 1: nginx: [error] open() "/var/run/nginx.pid" failed (2: No such file or directory)`)},
	}
	m, target := deferredTestManager(t, cli)
	m.healthProber = &HealthProber{exec: &fakeHealthExec{}, disabled: true}

	var boot DeferredSteps
	boot.Run(context.Background(), mainConfStep(m, &liveSettings{}))
	if err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, 5*time.Second); err != nil {
		t.Fatalf("ApplyWhenUp: %v", err)
	}
	if lines := httpLevelAccessLogDirectives(t, readConf(t, target)); len(lines) != 0 {
		t.Errorf("nginx.conf not applied: http-level %q", lines)
	}
	if _, reloads := cli.counts(); reloads != 2 {
		t.Errorf("reloads = %d, want 2 (the one before nginx started, then the one that applied)", reloads)
	}
}

// API shutdown cancels the wait at once, also mid-poll.
func TestDeferredApplyStopsWhenCancelled(t *testing.T) {
	for _, poll := range []time.Duration{time.Hour, time.Millisecond} {
		cli := &scriptedNginxCLI{then: errNginxNotRunning}
		m, target := deferredTestManager(t, cli)
		var boot DeferredSteps
		boot.Run(context.Background(), mainConfStep(m, &liveSettings{}))

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- m.ApplyWhenUp(ctx, boot.Steps(), poll, time.Hour) }()
		if poll == time.Millisecond {
			// Let it poll a few times first.
			deadline := time.Now().Add(2 * time.Second)
			for tests, _ := cli.counts(); tests < 4 && time.Now().Before(deadline); tests, _ = cli.counts() {
				time.Sleep(time.Millisecond)
			}
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("poll %v: ApplyWhenUp = %v, want context.Canceled", poll, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("poll %v: still waiting 2s after cancel", poll)
		}
		if _, reloads := cli.counts(); reloads != 0 {
			t.Errorf("poll %v: reloads = %d, want 0", poll, reloads)
		}
		if got := readConf(t, target); got != previousNginxConf {
			t.Errorf("poll %v: nginx.conf changed without nginx:\n%s", poll, got)
		}
	}
}

// The wait is bounded: if nginx never comes up, give up with an error.
func TestDeferredApplyGivesUp(t *testing.T) {
	cli := &scriptedNginxCLI{then: errNginxNotRunning}
	m, target := deferredTestManager(t, cli)
	var boot DeferredSteps
	boot.Run(context.Background(), mainConfStep(m, &liveSettings{}))

	start := time.Now()
	err := m.ApplyWhenUp(context.Background(), boot.Steps(), time.Millisecond, 50*time.Millisecond)
	if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "is not running") {
		t.Fatalf("ApplyWhenUp = %v, want a give-up error naming the last check", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("gave up after %v, want about 50ms", took)
	}
	if _, reloads := cli.counts(); reloads != 0 {
		t.Errorf("reloads = %d, want 0", reloads)
	}
	if got := readConf(t, target); got != previousNginxConf {
		t.Errorf("nginx.conf changed without nginx:\n%s", got)
	}
}
