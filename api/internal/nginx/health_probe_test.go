// api/internal/nginx/health_probe_test.go
package nginx

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeHealthExec struct {
	outputs  []string   // per-call stdout
	errs     []error    // per-call error
	calls    int
	cmdArgs  [][]string // captured args per call (for command assertions)
}

func (f *fakeHealthExec) Exec(ctx context.Context, args ...string) (string, error) {
	i := f.calls
	f.calls++
	f.cmdArgs = append(f.cmdArgs, append([]string{}, args...))
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
	return &HealthProber{exec: f, httpPort: "80"}
}

func TestHealthProber_Disabled_AlwaysSucceeds(t *testing.T) {
	p := &HealthProber{exec: &fakeHealthExec{}, disabled: true}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatalf("expected nil when disabled, got %v", err)
	}
}

func TestHealthProber_WorkersReady_ThenHTTPOK(t *testing.T) {
	// First exec (countWorkers): returns "4" (grep -c reports 3 workers + grep itself)
	// Second exec (probeHTTP): returns "200" with no error (curl wrote %{http_code})
	f := &fakeHealthExec{outputs: []string{"4\n", "200"}}
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

// When Direct IP Access = block_444, the default server's `location /` does
// `return 444;` — nginx drops the connection with no HTTP response, so curl
// exits 52 (empty reply, http_code = 000) even though nginx is perfectly
// healthy. The probe must target a dedicated endpoint that is unaffected by
// the block_444 policy (/health in zzz_default.conf) so it keeps working.
// Regression test for issue #122.
func TestHealthProber_ProbesHealthEndpoint(t *testing.T) {
	// workers OK, curl /health returns 200.
	f := &fakeHealthExec{outputs: []string{"4\n", "200"}}
	p := newTestProber(f)
	if err := p.Verify(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(f.cmdArgs) < 2 {
		t.Fatalf("expected at least 2 exec calls, got %d", len(f.cmdArgs))
	}
	httpCall := f.cmdArgs[1]
	var cmdStr string
	for _, a := range httpCall {
		cmdStr += " " + a
	}
	if !contains(cmdStr, "/health") {
		t.Errorf("probe command should target /health endpoint, got: %s", cmdStr)
	}
}

// /health returning non-200 must be reported as a probe failure — the contract
// is that /health is the canonical liveness endpoint. A non-200 means the
// default server is misconfigured or nginx is degraded.
func TestHealthProber_HealthNon200Fails(t *testing.T) {
	// workers OK, curl succeeds but /health returned 404.
	f := &fakeHealthExec{outputs: []string{"4\n", "404"}}
	p := newTestProber(f)
	err := p.Verify(context.Background())
	if err == nil {
		t.Fatal("expected failure on non-200 /health response, got nil")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
