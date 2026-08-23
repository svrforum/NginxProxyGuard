package service

// End-to-end coverage for managed mode (#267) through the real service,
// repository and Cloudflare client, against a scriptable mock Cloudflare API
// and a throwaway Postgres database.
//
// Needs a database, so it SKIPS unless NPG_TUNNEL_TEST_DSN points at one, e.g.
//
//	createdb npg_tunnel_test
//	NPG_TUNNEL_TEST_DSN='postgres://postgres:pw@127.0.0.1:5432/npg_tunnel_test?sslmode=disable' \
//	  go test ./internal/service/ -run TestManaged_
//
// The pure decision-table logic is covered without a database in
// cloudflare_tunnel_managed_test.go; these cases exist because every one of
// them is a path that a code review caught being wrong, and only an
// end-to-end run proves the fix:
//
// Covers, in order:
//   A self-healing   — intent on, remote still 404 -> background refresh converges
//   B mode auto-clear— switching to token mode clears intent AND restores 404
//   C conflict       — foreign catch-all is never written, and stays unwritten
//                      through a self-heal cycle
//   D token swap     — replacing the connector token cleans the OLD tunnel first
//   E removal resil. — CF down while disabling must NOT fail the save

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"

	_ "github.com/lib/pq"
)

// tunnelTestDSN gates the whole file: absent = skip, so `go test ./...` on a
// machine without Postgres stays green.
var tunnelTestDSN = os.Getenv("NPG_TUNNEL_TEST_DSN")

func requireDB(t *testing.T) {
	t.Helper()
	if tunnelTestDSN == "" {
		t.Skip("set NPG_TUNNEL_TEST_DSN to run the managed-mode integration cases")
	}
}

const (
	accA = "0123456789abcdef0123456789abcdef"
	tunA = "11111111-2222-3333-4444-555555555555"
	tunB = "99999999-8888-7777-6666-555555555555"
	apiT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func tokenFor(t *testing.T, tunnel string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"a": accA, "t": tunnel, "s": "c2VjcmV0"})
	return base64.StdEncoding.EncodeToString(b)
}

// mockCF is a scriptable Cloudflare API: per-tunnel ingress state, a PUT log,
// and a switch to simulate the API being unreachable.
type mockCF struct {
	mu      sync.Mutex
	ingress map[string][]json.RawMessage // tunnelID -> rules
	puts    map[string]int
	down    bool
	srv     *httptest.Server
}

func newMockCF(t *testing.T) *mockCF {
	t.Helper()
	m := &mockCF{ingress: map[string][]json.RawMessage{}, puts: map[string]int{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		down := m.down
		m.mu.Unlock()
		if down {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"upstream down"}],"result":null}`)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		tid := ""
		for i, p := range parts {
			if p == "cfd_tunnel" && i+1 < len(parts) {
				tid = parts[i+1]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut:
			var body struct {
				Config struct {
					Ingress []json.RawMessage `json:"ingress"`
				} `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.ingress[tid] = body.Config.Ingress
			m.puts[tid]++
			m.mu.Unlock()
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{}}`)
		case strings.HasSuffix(r.URL.Path, "/configurations"):
			m.mu.Lock()
			rules := m.ingress[tid]
			m.mu.Unlock()
			if rules == nil {
				rules = []json.RawMessage{json.RawMessage(`{"service":"http_status:404"}`)}
			}
			out, _ := json.Marshal(rules)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":{"config":{"ingress":%s},"version":3}}`, out)
		default:
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":{"id":%q,"account_tag":%q,"config_src":"cloudflare","status":"healthy"}}`, tid, accA)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockCF) setIngress(tid string, raw ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules := make([]json.RawMessage, len(raw))
	for i, r := range raw {
		rules[i] = json.RawMessage(r)
	}
	m.ingress[tid] = rules
}

func (m *mockCF) lastRule(tid string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.ingress[tid]
	if len(r) == 0 {
		return ""
	}
	return string(r[len(r)-1])
}

func (m *mockCF) putCount(tid string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts[tid]
}

func (m *mockCF) setDown(v bool) { m.mu.Lock(); m.down = v; m.mu.Unlock() }

type stubNginx struct{}

func (stubNginx) WriteCloudflaredToken(string) error            { return nil }
func (stubNginx) RemoveCloudflaredToken() error                 { return nil }
func (stubNginx) CloudflaredReady(context.Context) (int, error) { return 1, nil }
func (stubNginx) GetHTTPSPort() string                          { return "8443" }
func (stubNginx) GetHTTPPort() string                           { return "8080" }

const wantCatchall = `{"originRequest":{"noTLSVerify":true},"service":"https://localhost:8443"}`

func setupSvc(t *testing.T, m *mockCF) (*CloudflareTunnelService, *sql.DB) {
	t.Helper()
	db, err := sql.Open("postgres", tunnelTestDSN)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS public.cloudflare_tunnel (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    enabled boolean DEFAULT false,
    token text DEFAULT ''::text NOT NULL,
    mode character varying(20) DEFAULT 'token'::character varying NOT NULL,
    api_token text DEFAULT ''::text NOT NULL,
    catchall_enabled boolean DEFAULT false NOT NULL,
    catchall_applied_service text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);`); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM cloudflare_tunnel`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	svc := NewCloudflareTunnelService(repository.NewCloudflareTunnelRepository(db), stubNginx{})
	svc.cf.apiBase = m.srv.URL
	return svc, db
}

func ptrB(b bool) *bool     { return &b }
func ptrS(s string) *string { return &s }
func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A — the self-healing loop: the operator's intent is stored but the remote
// rule is still the default (e.g. the save happened while CF was down). The
// background status refresher must converge it without any re-save.
func TestManaged_SelfHealAppliesPendingIntent(t *testing.T) {
	requireDB(t)
	m := newMockCF(t)
	svc, db := setupSvc(t, m)
	ctx := context.Background()

	// Save with CF down: settings persist, remote untouched.
	m.setDown(true)
	_, err := svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{
		Enabled: ptrB(true), Token: ptrS(tokenFor(t, tunA)),
		Mode: ptrS("managed"), APIToken: ptrS(apiT), CatchallEnabled: ptrB(true),
	})
	if err == nil {
		t.Fatal("expected the save to report the Cloudflare failure")
	}
	var stored bool
	mustOK(t, db.QueryRow(`SELECT catchall_enabled FROM cloudflare_tunnel`).Scan(&stored))
	if !stored {
		t.Fatal("intent must be persisted even though the remote call failed")
	}
	if m.putCount(tunA) != 0 {
		t.Fatal("nothing should have been written while CF was down")
	}

	// CF comes back. No operator action — the background refresher heals it.
	m.setDown(false)
	svc.refreshCatchallStatus(ctx)

	if got := m.lastRule(tunA); got != wantCatchall {
		t.Fatalf("self-heal did not apply the catch-all; last rule = %s", got)
	}
	var applied string
	mustOK(t, db.QueryRow(`SELECT catchall_applied_service FROM cloudflare_tunnel`).Scan(&applied))
	if applied != "https://localhost:8443" {
		t.Fatalf("applied service not recorded: %q", applied)
	}
}

// B — leaving managed mode must clear the stored intent AND restore the
// default rule in the same save (previously a 400 naming a hidden checkbox).
func TestManaged_ModeSwitchClearsAndRestores(t *testing.T) {
	requireDB(t)
	m := newMockCF(t)
	svc, db := setupSvc(t, m)
	ctx := context.Background()

	_, err := svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{
		Enabled: ptrB(true), Token: ptrS(tokenFor(t, tunA)),
		Mode: ptrS("managed"), APIToken: ptrS(apiT), CatchallEnabled: ptrB(true),
	})
	mustOK(t, err)
	if m.lastRule(tunA) != wantCatchall {
		t.Fatalf("precondition failed: %s", m.lastRule(tunA))
	}

	// Only the mode changes — exactly what the UI sends when the radio flips.
	_, err = svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{Mode: ptrS("token")})
	mustOK(t, err)

	var enabled bool
	var applied string
	mustOK(t, db.QueryRow(`SELECT catchall_enabled, catchall_applied_service FROM cloudflare_tunnel`).Scan(&enabled, &applied))
	if enabled {
		t.Fatal("stored catch-all intent must be cleared with the mode")
	}
	if applied != "" {
		t.Fatalf("applied-service record must be cleared, got %q", applied)
	}
	if got := m.lastRule(tunA); got != `{"service":"http_status:404"}` {
		t.Fatalf("remote rule not restored: %s", got)
	}

	// And an EXPLICIT attempt to enable the catch-all outside managed mode
	// is still refused.
	_, err = svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{CatchallEnabled: ptrB(true)})
	if err == nil || !strings.Contains(err.Error(), "invalid tunnel mode") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

// C — a catch-all someone else manages is never written, on the save path or
// through a self-heal cycle.
func TestManaged_ConflictIsNeverWritten(t *testing.T) {
	requireDB(t)
	m := newMockCF(t)
	svc, _ := setupSvc(t, m)
	ctx := context.Background()

	foreign := `{"service":"http://192.0.2.10:8080"}`
	m.setIngress(tunA, `{"hostname":"a.example.com","service":"http://b:1"}`, foreign)

	_, err := svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{
		Enabled: ptrB(true), Token: ptrS(tokenFor(t, tunA)),
		Mode: ptrS("managed"), APIToken: ptrS(apiT), CatchallEnabled: ptrB(true),
	})
	mustOK(t, err) // a conflict is a state, not a save failure

	svc.mu.Lock()
	state := svc.catchallState
	svc.mu.Unlock()
	if state != CatchallConflict {
		t.Fatalf("state = %q, want conflict", state)
	}
	if m.putCount(tunA) != 0 || m.lastRule(tunA) != foreign {
		t.Fatalf("foreign rule was touched: puts=%d last=%s", m.putCount(tunA), m.lastRule(tunA))
	}

	// A self-heal pass must also leave it alone.
	svc.refreshCatchallStatus(ctx)
	if m.putCount(tunA) != 0 || m.lastRule(tunA) != foreign {
		t.Fatalf("self-heal touched the foreign rule: puts=%d last=%s", m.putCount(tunA), m.lastRule(tunA))
	}

	// Operator resolves it in the dashboard -> the next self-heal takes over.
	m.setIngress(tunA, `{"hostname":"a.example.com","service":"http://b:1"}`, `{"service":"http_status:404"}`)
	svc.refreshCatchallStatus(ctx)
	if got := m.lastRule(tunA); got != wantCatchall {
		t.Fatalf("did not take over after the conflict cleared: %s", got)
	}
}

// D — swapping the connector token must clean NPG's rule off the OLD tunnel
// before adopting the new one, instead of orphaning it.
func TestManaged_TokenSwapCleansOldTunnel(t *testing.T) {
	requireDB(t)
	m := newMockCF(t)
	svc, _ := setupSvc(t, m)
	ctx := context.Background()

	_, err := svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{
		Enabled: ptrB(true), Token: ptrS(tokenFor(t, tunA)),
		Mode: ptrS("managed"), APIToken: ptrS(apiT), CatchallEnabled: ptrB(true),
	})
	mustOK(t, err)
	if m.lastRule(tunA) != wantCatchall {
		t.Fatalf("precondition: %s", m.lastRule(tunA))
	}

	_, err = svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{Token: ptrS(tokenFor(t, tunB))})
	mustOK(t, err)

	if got := m.lastRule(tunA); got != `{"service":"http_status:404"}` {
		t.Fatalf("old tunnel was left orphaned: %s", got)
	}
	if got := m.lastRule(tunB); got != wantCatchall {
		t.Fatalf("new tunnel did not adopt the catch-all: %s", got)
	}
}

// E — turning the catch-all off while Cloudflare is unreachable must still
// succeed: the operator asked to disable, and cleanup retries later.
func TestManaged_DisableSucceedsWhenCloudflareIsDown(t *testing.T) {
	requireDB(t)
	m := newMockCF(t)
	svc, db := setupSvc(t, m)
	ctx := context.Background()

	_, err := svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{
		Enabled: ptrB(true), Token: ptrS(tokenFor(t, tunA)),
		Mode: ptrS("managed"), APIToken: ptrS(apiT), CatchallEnabled: ptrB(true),
	})
	mustOK(t, err)

	m.setDown(true)
	if _, err := svc.Update(ctx, &model.UpdateCloudflareTunnelRequest{CatchallEnabled: ptrB(false)}); err != nil {
		t.Fatalf("disabling must not fail because Cloudflare is down: %v", err)
	}
	var enabled bool
	mustOK(t, db.QueryRow(`SELECT catchall_enabled FROM cloudflare_tunnel`).Scan(&enabled))
	if enabled {
		t.Fatal("intent must be off after the save")
	}

	// CF returns -> the leftover rule is cleaned up without operator action.
	m.setDown(false)
	svc.refreshCatchallStatus(ctx)
	if got := m.lastRule(tunA); got != `{"service":"http_status:404"}` {
		t.Fatalf("leftover rule not cleaned up: %s", got)
	}
	var applied string
	mustOK(t, db.QueryRow(`SELECT catchall_applied_service FROM cloudflare_tunnel`).Scan(&applied))
	if applied != "" {
		t.Fatalf("applied-service record should be cleared, got %q", applied)
	}
}
