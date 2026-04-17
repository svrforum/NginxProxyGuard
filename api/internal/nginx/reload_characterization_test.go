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
