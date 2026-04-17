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
