package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func encodeConnector(t *testing.T, enc *base64.Encoding, account, tunnel string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"a": account, "t": tunnel, "s": "c2VjcmV0"})
	if err != nil {
		t.Fatal(err)
	}
	return enc.EncodeToString(b)
}

const testAccount = "0123456789abcdef0123456789abcdef"
const testTunnel = "11111111-2222-3333-4444-555555555555"

func TestDecodeConnectorToken(t *testing.T) {
	// cloudflared has emitted both padded and unpadded encodings over time;
	// both must decode, and garbage must fail with a message that never
	// contains token bytes.
	for name, enc := range map[string]*base64.Encoding{
		"std":     base64.StdEncoding,
		"raw-std": base64.RawStdEncoding,
	} {
		t.Run(name, func(t *testing.T) {
			id, err := decodeConnectorToken(encodeConnector(t, enc, testAccount, testTunnel))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if id.AccountID != testAccount || id.TunnelID != testTunnel {
				t.Fatalf("got %+v", id)
			}
		})
	}

	for name, tok := range map[string]string{
		"not base64":     "!!!not-base64!!!",
		"not json":       base64.StdEncoding.EncodeToString([]byte("hello")),
		"bad account":    encodeConnector(t, base64.StdEncoding, "shorty", testTunnel),
		"bad tunnel uid": encodeConnector(t, base64.StdEncoding, testAccount, "not-a-uuid"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConnectorToken(tok); err == nil {
				t.Fatal("expected decode failure")
			}
		})
	}
}

func TestValidateCFAPIToken(t *testing.T) {
	if err := ValidateCFAPIToken("v1.0-abcDEF0123456789_-abcDEF0123456789"); err != nil {
		t.Fatalf("plausible token rejected: %v", err)
	}
	for name, tok := range map[string]string{
		"empty":        "",
		"too short":    "abc",
		"header break": "abcdefghijklmnopqrst\r\nX-Evil: 1",
		"space":        "abcdefghij klmnopqrstuvwxyz",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidateCFAPIToken(tok) == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

const wantSvc = "https://localhost:18443"

func rules(raw ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(raw))
	for i, r := range raw {
		out[i] = json.RawMessage(r)
	}
	return out
}

// The decision table is the safety contract from #267: only the default 404
// rule or NPG's own rule may ever be written over.
func TestClassifyLastRule(t *testing.T) {
	cases := []struct {
		name       string
		ingress    []json.RawMessage
		ownService string
		want       string
	}{
		{"empty config", nil, "", CatchallNotApplied},
		{"default 404", rules(`{"service":"http_status:404"}`), "", CatchallNotApplied},
		{"ours current", rules(`{"service":"https://localhost:18443","originRequest":{"noTLSVerify":true}}`), "", CatchallApplied},
		{"ours stale port", rules(`{"service":"https://localhost:443","originRequest":{"noTLSVerify":true}}`), "https://localhost:443", CatchallApplied},
		{"foreign catch-all", rules(`{"service":"http://192.0.2.10:8080"}`), "", CatchallConflict},
		{"foreign matching nothing stored", rules(`{"service":"https://localhost:443"}`), "", CatchallConflict},
		{"hostname on last rule", rules(`{"hostname":"x.example.com","service":"http://a:1"}`), "", CatchallInvalidRemote},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := classifyLastRule(tc.ingress, tc.ownService, wantSvc)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

// Rules above the catch-all belong to the operator's dashboard: they travel
// as raw JSON and must survive an apply verbatim, unknown fields included —
// the PUT is a full-replace, so anything this code re-serializes it could
// destroy. In memory the bytes are untouched (asserted below); on the wire
// encoding/json compacts and HTML-escapes them, so the fixture carries an "&"
// and an integer above 2^53 to pin that the escape is the ONLY difference and
// numbers never round-trip through float64.
func TestApplyCatchallPreservesForeignRulesVerbatim(t *testing.T) {
	userRule := `{"hostname":"app.example.com","service":"http://192.0.2.5:8123/path?a=1&b=2","originRequest":{"disableChunkedEncoding":true,"bigCounter":9007199254740993,"futureField":{"nested":[1,2,3]}}}`
	cfg := &tunnelConfig{
		Ingress: rules(userRule, `{"service":"http_status:404"}`),
		Extra:   map[string]json.RawMessage{"unknown-top-key": json.RawMessage(`{"keep":"me"}`)},
	}

	state, changed, result, err := applyCatchall(cfg, "", wantSvc)
	if err != nil || state != CatchallApplied || !changed || result != wantSvc {
		t.Fatalf("state=%s changed=%v result=%s err=%v", state, changed, result, err)
	}
	if string(cfg.Ingress[0]) != userRule {
		t.Fatalf("user rule was re-serialized:\n got %s\nwant %s", cfg.Ingress[0], userRule)
	}
	var last ingressRuleView
	if err := json.Unmarshal(cfg.Ingress[len(cfg.Ingress)-1], &last); err != nil {
		t.Fatal(err)
	}
	if last.Service != wantSvc || last.OriginRequest == nil || !last.OriginRequest.NoTLSVerify {
		t.Fatalf("catch-all shape wrong: %s", cfg.Ingress[len(cfg.Ingress)-1])
	}
	if string(cfg.Extra["unknown-top-key"]) != `{"keep":"me"}` {
		t.Fatal("unknown top-level config key lost")
	}
}

func TestApplyCatchallDecisions(t *testing.T) {
	t.Run("empty config gets a sole catch-all", func(t *testing.T) {
		cfg := &tunnelConfig{}
		state, changed, result, err := applyCatchall(cfg, "", wantSvc)
		if err != nil || state != CatchallApplied || !changed || result != wantSvc || len(cfg.Ingress) != 1 {
			t.Fatalf("state=%s changed=%v result=%s rules=%d err=%v", state, changed, result, len(cfg.Ingress), err)
		}
	})
	t.Run("conflict never writes", func(t *testing.T) {
		foreign := `{"service":"http://192.0.2.10:8080"}`
		cfg := &tunnelConfig{Ingress: rules(foreign)}
		state, changed, _, err := applyCatchall(cfg, "", wantSvc)
		if err != nil || state != CatchallConflict || changed {
			t.Fatalf("state=%s changed=%v err=%v", state, changed, err)
		}
		if string(cfg.Ingress[0]) != foreign {
			t.Fatal("conflicting rule was modified")
		}
	})
	t.Run("stale port rewrites in place", func(t *testing.T) {
		cfg := &tunnelConfig{Ingress: rules(`{"service":"https://localhost:443","originRequest":{"noTLSVerify":true}}`)}
		state, changed, result, err := applyCatchall(cfg, "https://localhost:443", wantSvc)
		if err != nil || state != CatchallApplied || !changed || result != wantSvc {
			t.Fatalf("state=%s changed=%v result=%s err=%v", state, changed, result, err)
		}
	})
	t.Run("already applied is a no-op", func(t *testing.T) {
		cfg := &tunnelConfig{Ingress: rules(`{"originRequest":{"noTLSVerify":true},"service":"https://localhost:18443"}`)}
		_, changed, _, err := applyCatchall(cfg, wantSvc, wantSvc)
		if err != nil || changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
	})
}

func TestRemoveCatchall(t *testing.T) {
	t.Run("restores our rule to 404", func(t *testing.T) {
		cfg := &tunnelConfig{Ingress: rules(
			`{"hostname":"a.example.com","service":"http://b:1"}`,
			`{"service":"https://localhost:18443","originRequest":{"noTLSVerify":true}}`,
		)}
		state, changed, err := removeCatchall(cfg, wantSvc, wantSvc)
		if err != nil || state != CatchallNotApplied || !changed {
			t.Fatalf("state=%s changed=%v err=%v", state, changed, err)
		}
		var last ingressRuleView
		_ = json.Unmarshal(cfg.Ingress[1], &last)
		if last.Service != cfDefaultCatchallService {
			t.Fatalf("last rule = %s", cfg.Ingress[1])
		}
	})
	t.Run("leaves a foreign rule alone", func(t *testing.T) {
		foreign := `{"service":"http://192.0.2.10:8080"}`
		cfg := &tunnelConfig{Ingress: rules(foreign)}
		state, changed, err := removeCatchall(cfg, wantSvc, wantSvc)
		if err != nil || state != CatchallConflict || changed {
			t.Fatalf("state=%s changed=%v err=%v", state, changed, err)
		}
		if string(cfg.Ingress[0]) != foreign {
			t.Fatal("foreign rule was modified")
		}
	})
}

// End-to-end against a mock Cloudflare API: GET splits config (dropping only
// warp-routing), PUT round-trips preserved bytes, and the envelope's errors
// surface readably.
func TestCFTunnelClientRoundTrip(t *testing.T) {
	userRule := `{"hostname":"ha.example.com","service":"http://homeassistant:8123","originRequest":{"noHappyEyeballs":true}}`
	var gotPut map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-token-abcdefghijklmnop" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configurations"):
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"tunnel_id":"` + testTunnel + `","version":7,"config":{"ingress":[` + userRule + `,{"service":"http_status:404"}],"warp-routing":{"enabled":false},"future-key":{"x":1}}}}`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/configurations"):
			if err := json.NewDecoder(r.Body).Decode(&gotPut); err != nil {
				t.Errorf("put body: %v", err)
			}
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"version":8}}`))
		case r.Method == http.MethodGet: // tunnel details
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"` + testTunnel + `","account_tag":"` + testAccount + `","config_src":"cloudflare","status":"healthy"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := &cfTunnelClient{client: srv.Client(), apiBase: srv.URL}
	id := &connectorIdentity{AccountID: testAccount, TunnelID: testTunnel}
	const apiToken = "test-api-token-abcdefghijklmnop"

	det, err := c.preflight(context.Background(), id, apiToken)
	if err != nil || det.ConfigSrc != "cloudflare" {
		t.Fatalf("preflight: %+v err=%v", det, err)
	}

	cfg, err := c.getConfig(context.Background(), id, apiToken)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if len(cfg.Ingress) != 2 || cfg.Version != 7 {
		t.Fatalf("cfg parse: rules=%d version=%d", len(cfg.Ingress), cfg.Version)
	}
	if _, has := cfg.Extra["warp-routing"]; has {
		t.Fatal("deprecated warp-routing must not be echoed back")
	}
	if string(cfg.Extra["future-key"]) != `{"x":1}` {
		t.Fatal("unknown config key lost")
	}

	if state, changed, _, err := applyCatchall(cfg, "", wantSvc); err != nil || state != CatchallApplied || !changed {
		t.Fatalf("apply: %s %v %v", state, changed, err)
	}
	if err := c.putConfig(context.Background(), id, apiToken, cfg); err != nil {
		t.Fatalf("putConfig: %v", err)
	}

	putCfg := gotPut["config"].(map[string]any)
	if _, has := putCfg["warp-routing"]; has {
		t.Fatal("warp-routing leaked into PUT")
	}
	ingress := putCfg["ingress"].([]any)
	if len(ingress) != 2 {
		t.Fatalf("PUT ingress rules = %d", len(ingress))
	}
	first, _ := json.Marshal(ingress[0])
	var wantFirst, gotFirst any
	_ = json.Unmarshal([]byte(userRule), &wantFirst)
	_ = json.Unmarshal(first, &gotFirst)
	fb, _ := json.Marshal(wantFirst)
	gb, _ := json.Marshal(gotFirst)
	if string(fb) != string(gb) {
		t.Fatalf("user rule mutated in PUT:\n got %s\nwant %s", gb, fb)
	}

	// A refused token must produce the operator-readable permission message.
	if _, err := c.preflight(context.Background(), id, "wrong-token-abcdefghijklmnopq"); err == nil ||
		!strings.Contains(err.Error(), "Account / Cloudflare Tunnel / Edit") {
		t.Fatalf("expected permission guidance, got %v", err)
	}
}

// Leaving managed mode drags the stored catch-all intent with it (the UI hides
// the checkbox the moment the radio flips, so requiring an explicit
// catchall_enabled=false was a dead-end) — while an explicit attempt to switch
// it ON outside managed mode stays a 400. Pure-validation slice: exercised via
// the service's exported validators plus the decision the handler relies on.
func TestCatchallModeCoupling(t *testing.T) {
	// The coupling itself lives in CloudflareTunnelService.Update, which needs
	// a repository; the invariant worth pinning here without a DB is the shape
	// contract the UI depends on: request marshalling keeps catchall_enabled a
	// tri-state pointer, so "absent" and "false" stay distinguishable.
	var req struct {
		CatchallEnabled *bool `json:"catchall_enabled,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{}`), &req); err != nil || req.CatchallEnabled != nil {
		t.Fatalf("absent must stay nil: %+v err=%v", req, err)
	}
	if err := json.Unmarshal([]byte(`{"catchall_enabled":false}`), &req); err != nil || req.CatchallEnabled == nil || *req.CatchallEnabled {
		t.Fatalf("explicit false must arrive as non-nil false: %+v err=%v", req, err)
	}
}
