package nginx

// Characterization tests for the proxy_host template.
//
// These tests freeze CURRENT behavior via golden files to protect later
// refactors (Phases 3-6 of the codebase cleanup). They are NOT specifications
// of correct behavior — if something looks odd in a golden file, preserve it
// and note the discrepancy; do not "fix" it here.
//
// Run with `-update-golden` to regenerate fixtures after a deliberate change.

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"text/template"
	"time"

	"nginx-proxy-guard/internal/model"
)

var updateGolden = flag.Bool("update-golden", false, "update golden files")

// renderProxyHostConfig renders the proxy host config into w without any
// filesystem side effects. This is a test-only helper that mirrors the core
// rendering path of (*Manager).GenerateConfigFull, but skips the SSL cert
// existence check, the cloud-IP include generation, and the atomic file write.
//
// Keep in sync with the template wiring in manager.go:
//   - Funcs: GetTemplateFuncMap plus dnsResolver + upstreamScheme
//   - Pre-processing: AdvancedConfig directive parsing + server/location split
//   - Listen ports, IPv6 flag, and apiHost injection
func renderProxyHostConfig(_ context.Context, w *bytes.Buffer, data ProxyHostConfigData) error {
	// Mirror manager.GenerateConfigFull defaults.
	if data.HTTPPort == "" {
		data.HTTPPort = "80"
	}
	if data.HTTPSPort == "" {
		data.HTTPSPort = "443"
	}

	apiHostValue := "127.0.0.1:9080"
	dnsResolverValue := "127.0.0.53 8.8.8.8"

	funcMap := GetTemplateFuncMap(apiHostValue)
	funcMap["dnsResolver"] = func() string { return dnsResolverValue }
	funcMap["upstreamScheme"] = func(u *model.Upstream) string {
		if u == nil {
			return "http"
		}
		return model.NormalizeUpstreamScheme(u.Scheme)
	}

	// Mirror AdvancedConfig preprocessing from manager.GenerateConfigFull.
	if data.Host != nil && data.Host.AdvancedConfig != "" {
		locationPattern := regexp.MustCompile(`(?m)^\s*location\s+/\s*\{`)
		data.HasCustomLocationRoot = locationPattern.MatchString(data.Host.AdvancedConfig)
		anyLocationPattern := regexp.MustCompile(`(?m)^\s*location\s+`)
		data.AdvancedConfigHasLocation = anyLocationPattern.MatchString(data.Host.AdvancedConfig)
		data.AdvancedConfigDirectives = parseAdvancedConfigDirectives(data.Host.AdvancedConfig)
		serverPart, locationPart := splitAdvancedConfigByContext(data.Host.AdvancedConfig)
		data.AdvancedConfigServerLevel = serverPart
		data.AdvancedConfigLocationLevel = locationPart
	}

	tmpl, err := template.New("proxy_host").Funcs(funcMap).Parse(proxyHostTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

// ---- Fixtures ---------------------------------------------------------------
//
// All fixtures use pinned IDs for deterministic golden output.
// Timestamps are fixed to 2024-01-01 UTC. UUIDs follow the pattern
// 00000000-0000-0000-0000-00000000000N for easy grepping.

var fixtureNow = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func baseGlobalSettings() *model.GlobalSettings {
	// Zero-valued to keep golden output minimal; the template mostly gates on
	// numeric > 0 and non-empty string checks, so zero values largely suppress
	// the global-settings overrides.
	return &model.GlobalSettings{
		ID:        "00000000-0000-0000-0000-000000000100",
		CreatedAt: fixtureNow,
		UpdatedAt: fixtureNow,
	}
}

func baseHost(id, forwardHost string, enabled bool) *model.ProxyHost {
	return &model.ProxyHost{
		ID:            id,
		DomainNames:   []string{"example.com"},
		ForwardScheme: "http",
		ForwardHost:   forwardHost,
		ForwardPort:   8080,
		Enabled:       enabled,
		CreatedAt:     fixtureNow,
		UpdatedAt:     fixtureNow,
	}
}

// 1) http_only: basic HTTP proxy, SSL off, forwards example.com → 192.168.1.10:8080.
func fixtureHTTPOnly() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000001", "192.168.1.10", true)
	host.DomainNames = []string{"example.com"}
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}

// 2) https_force: SSL enabled, ForceHTTPS, HTTP/2, explicit certificate ID.
func fixtureHTTPSForce() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000002", "192.168.1.20", true)
	host.DomainNames = []string{"secure.example.com"}
	host.SSLEnabled = true
	host.SSLForceHTTPS = true
	host.SSLHTTP2 = true
	certID := "00000000-0000-0000-0000-00000000cert"
	host.CertificateID = &certID
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}

// 3) waf_blocking: WAF enabled, blocking mode, paranoia 2, anomaly 5.
//
// Exclusions are NOT rendered into the proxy host config itself — they are
// written to a separate modsec/host_{id}.conf by GenerateHostWAFConfig. The
// main template only toggles modsecurity on/off and references the file path.
// The "3 exclusions" part of this case exists for completeness (the data shape
// a caller would pass) but the golden file reflects only what the proxy host
// template emits.
func fixtureWAFBlocking() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000003", "192.168.1.30", true)
	host.DomainNames = []string{"waf.example.com"}
	host.WAFEnabled = true
	host.WAFMode = "blocking"
	host.WAFParanoiaLevel = 2
	host.WAFAnomalyThreshold = 5
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}

// 4) cache_enabled: proxy cache on with a valid TTL.
func fixtureCacheEnabled() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000004", "192.168.1.40", true)
	host.DomainNames = []string{"cache.example.com"}
	host.CacheEnabled = true
	host.CacheStaticOnly = true
	host.CacheTTL = "1h"
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}

// 5) advanced_config_conflict: user supplies proxy_connect_timeout in
// AdvancedConfig; template auto-generated proxy_connect_timeout must be
// suppressed via the hasDirective gate.
func fixtureAdvancedConfigConflict() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000005", "192.168.1.50", true)
	host.DomainNames = []string{"advanced.example.com"}
	host.AdvancedConfig = "proxy_connect_timeout 10s;\n"
	// Give the template a nonzero value so we can verify it is suppressed.
	host.ProxyConnectTimeout = 60
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}

// 6) upstream_load_balance: upstream with least_conn + 3 backends.
func fixtureUpstreamLB() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000006", "unused-direct-host", true)
	host.DomainNames = []string{"lb.example.com"}
	// When Upstream has servers, the template routes to upstream instead of
	// ForwardHost:ForwardPort, but the forward fields remain in the data.
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
		Upstream: &model.Upstream{
			ID:          "00000000-0000-0000-0000-00000000upst",
			ProxyHostID: host.ID,
			Name:        "backend_pool",
			Scheme:      "http",
			LoadBalance: "least_conn",
			Servers: []model.UpstreamServer{
				{Address: "10.0.0.1", Port: 8080, Weight: 1, MaxFails: 0, FailTimeout: 0},
				{Address: "10.0.0.2", Port: 8080, Weight: 1, MaxFails: 0, FailTimeout: 0},
				{Address: "10.0.0.3", Port: 8080, Weight: 1, MaxFails: 0, FailTimeout: 0},
			},
			CreatedAt: fixtureNow,
			UpdatedAt: fixtureNow,
		},
	}
}

// 7) https_force_custom_location: SSL+ForceHTTPS with user-supplied
// `location / { ... }` in AdvancedConfig. This pins the issue #129 fix —
// the HTTP→HTTPS redirect must happen at server-block level so the user's
// location does not shadow it, and ACME / NPG challenge paths must be
// excluded from the redirect.
func fixtureHTTPSForceCustomLocation() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000007", "192.168.1.70", true)
	host.DomainNames = []string{"custom.example.com"}
	host.SSLEnabled = true
	host.SSLForceHTTPS = true
	certID := "00000000-0000-0000-0000-00000000cert"
	host.CertificateID = &certID
	host.AdvancedConfig = "location / {\n    proxy_pass http://192.168.1.70:8080;\n}\n"
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}

// ---- Tests ------------------------------------------------------------------

func TestProxyHostTemplate_Characterization(t *testing.T) {
	cases := []struct {
		name string
		data ProxyHostConfigData
	}{
		{name: "http_only", data: fixtureHTTPOnly()},
		{name: "https_force", data: fixtureHTTPSForce()},
		{name: "waf_blocking", data: fixtureWAFBlocking()},
		{name: "cache_enabled", data: fixtureCacheEnabled()},
		{name: "advanced_config_conflict", data: fixtureAdvancedConfigConflict()},
		{name: "upstream_load_balance", data: fixtureUpstreamLB()},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderProxyHostConfig(context.Background(), &buf, tc.data); err != nil {
				t.Fatalf("render failed: %v", err)
			}
			compareGolden(t, "proxy_host_"+tc.name+".conf", buf.Bytes())
		})
	}
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)

	if *updateGolden {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated golden file: %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update-golden to create)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n--- diff preview ---\n%s", name, diffPreview(want, got))
	}
}

// diffPreview returns a short head-of-diff for debugging without dumping
// thousands of lines on a mismatch.
func diffPreview(want, got []byte) string {
	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(got), "\n")
	max := len(wantLines)
	if len(gotLines) > max {
		max = len(gotLines)
	}
	var sb strings.Builder
	shown := 0
	for i := 0; i < max && shown < 10; i++ {
		var wl, gl string
		if i < len(wantLines) {
			wl = wantLines[i]
		}
		if i < len(gotLines) {
			gl = gotLines[i]
		}
		if wl != gl {
			sb.WriteString("want[")
			sb.WriteString(itoa(i))
			sb.WriteString("]: ")
			sb.WriteString(wl)
			sb.WriteString("\n got[")
			sb.WriteString(itoa(i))
			sb.WriteString("]: ")
			sb.WriteString(gl)
			sb.WriteString("\n")
			shown++
		}
	}
	if shown == 0 {
		return "(no line diffs; trailing-byte or whitespace diff)"
	}
	return sb.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestForceHTTPSCustomLocationRedirects pins issue #129: when SSLForceHTTPS
// is on and the user supplies their own `location /`, the HTTP→HTTPS
// redirect must still fire and ACME/NPG-challenge paths must be excluded.
//
// This is an assertion test (not a golden compare) because the bug is about
// specific directives appearing/missing, and a golden file would obscure the
// signal with noise from unrelated parts of the config.
func TestForceHTTPSCustomLocationRedirects(t *testing.T) {
	var buf bytes.Buffer
	if err := renderProxyHostConfig(context.Background(), &buf, fixtureHTTPSForceCustomLocation()); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	out := buf.String()

	// Split on the HTTPS server block so we only look at the HTTP server.
	// The first `server {` … first `}` (top-level) covers the HTTP server.
	httpServer := extractFirstServerBlock(t, out)

	// Server-level if with ACME + NPG challenge bypass must be present.
	if !strings.Contains(httpServer, `if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/")`) {
		t.Errorf("HTTP server is missing the server-level bypass `if`; got:\n%s", httpServer)
	}

	// Redirect must be present.
	if !strings.Contains(httpServer, "return 301 https://$host$request_uri;") {
		t.Errorf("HTTP server is missing the 301 redirect; got:\n%s", httpServer)
	}

	// The OLD pattern — auto-generated `location / { return 301 ... }` —
	// must NOT appear; only the user's `location /` should be present in
	// the HTTP server (rendered via the standard advanced-config inject).
	if strings.Contains(httpServer, "location / {\n        return 301") {
		t.Errorf("HTTP server still contains the old auto-generated location/return block; should be replaced by server-level if. Got:\n%s", httpServer)
	}

	// User's location block (proxy_pass) is rendered into HTTP server too —
	// dead code at runtime (server-level return short-circuits non-bypass
	// requests) but expected as part of the AdvancedConfig server-level inject.
	if !strings.Contains(httpServer, "proxy_pass http://192.168.1.70:8080") {
		t.Errorf("HTTP server is missing user's proxy_pass directive; got:\n%s", httpServer)
	}
}

// extractFirstServerBlock returns the substring covering the FIRST top-level
// `server { … }` block in the config (which is the HTTP server in our
// template). Uses brace counting because nginx server bodies contain nested
// `{}` (location blocks, if-blocks).
func extractFirstServerBlock(t *testing.T, full string) string {
	t.Helper()
	start := strings.Index(full, "server {")
	if start < 0 {
		t.Fatalf("no `server {` block found in rendered config")
	}
	depth := 0
	for i := start; i < len(full); i++ {
		switch full[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return full[start : i+1]
			}
		}
	}
	t.Fatalf("unterminated server block starting at offset %d", start)
	return ""
}
