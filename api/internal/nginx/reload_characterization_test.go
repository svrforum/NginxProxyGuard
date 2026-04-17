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
