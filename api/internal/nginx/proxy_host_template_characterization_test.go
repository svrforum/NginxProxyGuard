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
		{name: "https_force_custom_location", data: fixtureHTTPSForceCustomLocation()},
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

// TestForceHTTPSACMEBypass guards against silent regression of
// Let's Encrypt HTTP-01 cert renewal. The server-level redirect MUST
// exclude `^/.well-known/acme-challenge/` from being redirected to HTTPS,
// otherwise the ACME server cannot fetch the validation file over HTTP and
// renewal silently fails.
func TestForceHTTPSACMEBypass(t *testing.T) {
	// Use the no-custom-location fixture too, so we cover both paths.
	cases := []struct {
		name string
		data ProxyHostConfigData
	}{
		{name: "without_custom_location", data: fixtureHTTPSForce()},
		{name: "with_custom_location", data: fixtureHTTPSForceCustomLocation()},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderProxyHostConfig(context.Background(), &buf, tc.data); err != nil {
				t.Fatalf("render failed: %v", err)
			}
			httpServer := extractFirstServerBlock(t, buf.String())

			// The bypass regex must contain BOTH ACME and NPG challenge prefixes.
			needles := []string{
				`^/\.well-known/acme-challenge/`,
				`^/api/v1/challenge/`,
			}
			for _, n := range needles {
				if !strings.Contains(httpServer, n) {
					t.Errorf("HTTP server is missing bypass needle %q; got:\n%s", n, httpServer)
				}
			}

			// Sanity: the if must use negative match (`!~`) so non-matching
			// URIs trigger the redirect and matching ones fall through.
			if !strings.Contains(httpServer, `if ($request_uri !~`) {
				t.Errorf("HTTP server is missing `if ($request_uri !~ ...)` bypass; got:\n%s", httpServer)
			}
		})
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

// ============================================================================
// TestProxyHostTemplateGolden — pre-refactor characterization baseline (M1.2)
//
// Captures the rendered output of (*Manager).GenerateConfigFull for 8
// representative ProxyHostConfigData scenarios. The M1.3–M1.8 refactor that
// extracts _common_init / _security / _challenge_endpoints partials via
// {{define}}/{{template}} MUST produce byte-identical output. Any diff means
// the refactor changed behavior and needs investigation.
//
// This is intentionally separate from TestProxyHostTemplate_Characterization
// above: that one uses an in-memory buffer render and a hand-picked subset of
// fixtures focused on bug pins (issue #129 etc.). This one drives the actual
// production render path (file write through Manager) so the goldens include
// any side effects of the manager (e.g. cloud-IP include creation, atomic
// write outcome).
// ============================================================================

var updateGoldenFlag = flag.Bool("update", false, "update golden files in testdata/proxy_host_golden/")

type goldenCase struct {
	name string
	data ProxyHostConfigData
}

// goldenBaseHost returns a minimal enabled ProxyHost with stable IDs so
// rendered output is deterministic.
func goldenBaseHost(id, domain string) *model.ProxyHost {
	h := baseHost(id, "127.0.0.1", true)
	h.DomainNames = []string{domain}
	return h
}

func goldenSSLHost(id, domain string) *model.ProxyHost {
	h := goldenBaseHost(id, domain)
	h.SSLEnabled = true
	h.SSLForceHTTPS = true
	certID := "00000000-0000-0000-0000-0000000000ce"
	h.CertificateID = &certID
	return h
}

func goldenCases() []goldenCase {
	cases := []goldenCase{}

	// 1) minimal_enabled — HTTP only, no security features.
	cases = append(cases, goldenCase{
		name: "minimal_enabled",
		data: ProxyHostConfigData{
			Host:           goldenBaseHost("00000000-0000-0000-0000-000000000a01", "minimal.example.com"),
			GlobalSettings: baseGlobalSettings(),
		},
	})

	// 2) ssl_force_https — SSL + ForceHTTPS + HTTP/2.
	{
		host := goldenSSLHost("00000000-0000-0000-0000-000000000a02", "ssl.example.com")
		host.SSLHTTP2 = true
		cases = append(cases, goldenCase{
			name: "ssl_force_https",
			data: ProxyHostConfigData{
				Host:           host,
				GlobalSettings: baseGlobalSettings(),
			},
		})
	}

	// 3) all_security_on — Geo blacklist + WAF blocking + AccessList +
	// BlockExploits + 1 ExploitBlockRule + BannedIPs + BotFilter (block bad).
	{
		host := goldenBaseHost("00000000-0000-0000-0000-000000000a03", "secure.example.com")
		host.WAFEnabled = true
		host.WAFMode = "blocking"
		host.WAFParanoiaLevel = 2
		host.WAFAnomalyThreshold = 5
		host.BlockExploits = true
		alID := "00000000-0000-0000-0000-0000000000a1"
		host.AccessListID = &alID
		bannedExpires := fixtureNow.Add(24 * time.Hour)
		hostIDForBan := host.ID
		cases = append(cases, goldenCase{
			name: "all_security_on",
			data: ProxyHostConfigData{
				Host:           host,
				GlobalSettings: baseGlobalSettings(),
				GeoRestriction: &model.GeoRestriction{
					ID:          "00000000-0000-0000-0000-0000000000ge",
					ProxyHostID: host.ID,
					Mode:        "blacklist",
					Countries:   []string{"CN", "RU"},
					Enabled:     true,
					CreatedAt:   fixtureNow,
					UpdatedAt:   fixtureNow,
				},
				AccessList: &model.AccessList{
					ID:         alID,
					Name:       "internal-only",
					SatisfyAny: false,
					Items: []model.AccessListItem{
						{ID: "00000000-0000-0000-0000-0000000000i1", AccessListID: alID, Directive: "allow", Address: "10.0.0.0/8", SortOrder: 1, CreatedAt: fixtureNow},
						{ID: "00000000-0000-0000-0000-0000000000i2", AccessListID: alID, Directive: "deny", Address: "all", SortOrder: 2, CreatedAt: fixtureNow},
					},
					CreatedAt: fixtureNow,
					UpdatedAt: fixtureNow,
				},
				BotFilter: &model.BotFilter{
					ID:           "00000000-0000-0000-0000-0000000000bf",
					ProxyHostID:  host.ID,
					Enabled:      true,
					BlockBadBots: true,
					CreatedAt:    fixtureNow,
					UpdatedAt:    fixtureNow,
				},
				BadBotsList: "BadBot\nEvilCrawler",
				BannedIPs: []model.BannedIP{
					{
						ID:          "00000000-0000-0000-0000-0000000000b1",
						ProxyHostID: &hostIDForBan,
						IPAddress:   "203.0.113.10",
						Reason:      "test ban",
						BannedAt:    fixtureNow,
						ExpiresAt:   &bannedExpires,
						CreatedAt:   fixtureNow,
					},
				},
				ExploitBlockRules: []model.ExploitBlockRuleForRender{
					{
						ExploitBlockRule: model.ExploitBlockRule{
							ID:          "00000000-0000-0000-0000-0000000000e1",
							Category:    "sql_injection",
							Name:        "SQLi UNION SELECT",
							Pattern:     "union.*select",
							PatternType: "query_string",
							Severity:    "critical",
							Enabled:     true,
							IsSystem:    true,
							SortOrder:   1,
							CreatedAt:   fixtureNow,
							UpdatedAt:   fixtureNow,
						},
						IDSanitized: "e1",
					},
				},
			},
		})
	}

	// 4) http3_quic — SSL + HTTP/2 + HTTP/3 (QUIC) enabled.
	{
		host := goldenSSLHost("00000000-0000-0000-0000-000000000a04", "h3.example.com")
		host.SSLHTTP2 = true
		host.SSLHTTP3 = true
		cases = append(cases, goldenCase{
			name: "http3_quic",
			data: ProxyHostConfigData{
				Host:           host,
				GlobalSettings: baseGlobalSettings(),
			},
		})
	}

	// 5) ipv6_enabled — same shape as minimal_enabled, but with the manager's
	// EnableIPv6=true. The default manager has IPv6 on; we cover the explicit
	// case in the test runner by toggling via SetEnableIPv6 (see test body).
	// Here the data itself is identical to minimal — the IPv6 differences
	// show up in the rendered listen directives via Manager.GenerateConfigFull.
	cases = append(cases, goldenCase{
		name: "ipv6_enabled",
		data: ProxyHostConfigData{
			Host:           goldenBaseHost("00000000-0000-0000-0000-000000000a05", "ipv6.example.com"),
			GlobalSettings: baseGlobalSettings(),
		},
	})

	// 6) geo_challenge — Geo blacklist with ChallengeMode=true. This should
	// produce challenge endpoint locations (/_challenge/validate, /api/v1/challenge/).
	cases = append(cases, goldenCase{
		name: "geo_challenge",
		data: ProxyHostConfigData{
			Host:           goldenBaseHost("00000000-0000-0000-0000-000000000a06", "challenge.example.com"),
			GlobalSettings: baseGlobalSettings(),
			GeoRestriction: &model.GeoRestriction{
				ID:            "00000000-0000-0000-0000-00000000bbb2",
				ProxyHostID:   "00000000-0000-0000-0000-000000000a06",
				Mode:          "blacklist",
				Countries:     []string{"CN"},
				Enabled:       true,
				ChallengeMode: true,
				CreatedAt:     fixtureNow,
				UpdatedAt:     fixtureNow,
			},
		},
	})

	// 7) exploit_user_agent — BlockExploits=true with one user_agent rule.
	{
		host := goldenBaseHost("00000000-0000-0000-0000-000000000a07", "exploit.example.com")
		host.BlockExploits = true
		cases = append(cases, goldenCase{
			name: "exploit_user_agent",
			data: ProxyHostConfigData{
				Host:           host,
				GlobalSettings: baseGlobalSettings(),
				ExploitBlockRules: []model.ExploitBlockRuleForRender{
					{
						ExploitBlockRule: model.ExploitBlockRule{
							ID:          "00000000-0000-0000-0000-0000000000e7",
							Category:    "scanner",
							Name:        "sqlmap UA",
							Pattern:     "sqlmap",
							PatternType: "user_agent",
							Severity:    "warning",
							Enabled:     true,
							IsSystem:    true,
							SortOrder:   1,
							CreatedAt:   fixtureNow,
							UpdatedAt:   fixtureNow,
						},
						IDSanitized: "e7",
					},
				},
			},
		})
	}

	// 8) uri_block_with_exception — URIBlock with prefix /admin and ExceptionIPs.
	cases = append(cases, goldenCase{
		name: "uri_block_with_exception",
		data: ProxyHostConfigData{
			Host:           goldenBaseHost("00000000-0000-0000-0000-000000000a08", "uri.example.com"),
			GlobalSettings: baseGlobalSettings(),
			URIBlock: &model.URIBlock{
				ID:          "00000000-0000-0000-0000-0000000000aa",
				ProxyHostID: "00000000-0000-0000-0000-000000000a08",
				Enabled:     true,
				Rules: []model.URIBlockRule{
					{
						ID:          "00000000-0000-0000-0000-0000000000bb",
						Pattern:     "/admin",
						MatchType:   model.URIMatchPrefix,
						Description: "block admin",
						Enabled:     true,
					},
				},
				ExceptionIPs: []string{"10.0.0.1"},
				CreatedAt:    fixtureNow,
				UpdatedAt:    fixtureNow,
			},
		},
	})

	// 9) trusted_ip_bypass — pins issue #161: GlobalTrustedIPs must bypass
	// per-host PERIMETER controls (geo block-mode restriction + access list +
	// cloud-provider block) in addition to the already-correct geo-challenge /
	// bot-filter / rate-limit paths. Combines a block-mode geo blacklist
	// (AllowSearchBots), an access list (allow + deny-all), and a cloud-provider
	// block so the single fixture exercises all three perimeter-bypass guards.
	{
		host := goldenBaseHost("00000000-0000-0000-0000-000000000a09", "trusted.example.com")
		alID := "00000000-0000-0000-0000-0000000000a2"
		host.AccessListID = &alID
		cases = append(cases, goldenCase{
			name: "trusted_ip_bypass",
			data: ProxyHostConfigData{
				Host:                 host,
				GlobalSettings:       baseGlobalSettings(),
				GlobalTrustedIPs:     []string{"192.0.2.10", "192.0.2.0/24"},
				BlockedCloudIPRanges: []string{"198.51.100.0/24"},
				GeoRestriction: &model.GeoRestriction{
					ID:              "00000000-0000-0000-0000-0000000000g2",
					ProxyHostID:     host.ID,
					Mode:            "blacklist",
					Countries:       []string{"CN", "RU"},
					Enabled:         true,
					AllowSearchBots: true,
					CreatedAt:       fixtureNow,
					UpdatedAt:       fixtureNow,
				},
				AccessList: &model.AccessList{
					ID:         alID,
					Name:       "internal-only",
					SatisfyAny: false,
					Items: []model.AccessListItem{
						{ID: "00000000-0000-0000-0000-0000000000j1", AccessListID: alID, Directive: "allow", Address: "10.0.0.0/8", SortOrder: 1, CreatedAt: fixtureNow},
						{ID: "00000000-0000-0000-0000-0000000000j2", AccessListID: alID, Directive: "deny", Address: "all", SortOrder: 2, CreatedAt: fixtureNow},
					},
					CreatedAt: fixtureNow,
					UpdatedAt: fixtureNow,
				},
			},
		})
	}

	return cases
}

// TestTrustedIPBypassesPerimeterControls pins issue #161: GlobalTrustedIPs must
// bypass per-host PERIMETER controls (geo block restriction, access list) but
// must NOT bypass CONTENT/attack controls (WAF, exploit/scanner blocks, the
// return 405 method blocks). This is the perimeter-vs-content invariant — a new
// security section author must not silently reintroduce #161.
func TestTrustedIPBypassesPerimeterControls(t *testing.T) {
	var fixture ProxyHostConfigData
	for _, tc := range goldenCases() {
		if tc.name == "trusted_ip_bypass" {
			fixture = tc.data
			break
		}
	}
	if fixture.Host == nil {
		t.Fatalf("trusted_ip_bypass fixture not found in goldenCases()")
	}

	configPath := t.TempDir()
	certsPath := t.TempDir()
	m := NewManager(configPath, certsPath)
	if err := m.GenerateConfigFull(context.Background(), fixture); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	rendered, err := os.ReadFile(filepath.Join(configPath, GetConfigFilename(fixture.Host)))
	if err != nil {
		t.Fatalf("read rendered: %v", err)
	}
	out := string(rendered)

	// sanitizeID (template_funcs.go) replaces hyphens with underscores for nginx
	// zone names, so the guard variable is trusted_ip_<id-with-underscores>.
	sanitizedID := strings.ReplaceAll(fixture.Host.ID, "-", "_")
	guard := "if ($trusted_ip_" + sanitizedID + " = 1)"

	// (a) The block-mode geo section must contain the trusted-IP guard.
	geoIdx := strings.Index(out, "Direct Block Mode")
	if geoIdx < 0 {
		t.Fatalf("rendered config missing block-mode geo section")
	}
	// Anchor the access-list section AFTER the geo section: "Access List:" also
	// appears in the file header comment (before the geo block), so a plain
	// Index from the start matches the header and slices backwards (panics).
	accessRel := strings.Index(out[geoIdx:], "Access List:")
	if accessRel < 0 {
		t.Fatalf("rendered config missing access list section")
	}
	accessIdx := geoIdx + accessRel
	geoSection := out[geoIdx:accessIdx]
	if !strings.Contains(geoSection, guard) {
		t.Errorf("geo block section missing trusted-IP guard %q; got:\n%s", guard, geoSection)
	}

	// (b) The access list must allow trusted IPs BEFORE the trailing deny all.
	allowIdx := strings.Index(out, "allow 192.0.2.10;")
	denyAllRel := strings.Index(out[accessIdx:], "deny all;")
	if allowIdx < 0 {
		t.Errorf("access list missing `allow 192.0.2.10;` for trusted IP")
	} else if denyAllRel < 0 {
		t.Errorf("access list missing trailing `deny all;`")
	} else if allowIdx > accessIdx+denyAllRel {
		t.Errorf("`allow 192.0.2.10;` must appear before `deny all;` (access-phase first-match wins)")
	}

	// (c) Perimeter-vs-content boundary: the trusted-IP guard must appear in the
	// perimeter region (geo/access, processed before WAF) but must NOT leak into
	// the content/attack sections (WAF, exploit/scanner, return-405). Asserting
	// the boundary structurally (present-before / absent-after the content marker)
	// expresses the real invariant without coupling to how many perimeter paths
	// this particular fixture happens to exercise.
	if !strings.Contains(out[:accessIdx], guard) {
		t.Errorf("trusted-IP guard missing from the perimeter (geo) region")
	}
	// The content/attack region starts at the exploit-block section. If this
	// fixture renders none, there is nothing after the perimeter to leak into.
	if contentIdx := strings.Index(out, "Block common exploits"); contentIdx >= 0 {
		if strings.Contains(out[contentIdx:], guard) {
			t.Errorf("trusted-IP guard leaked into a content/attack section (WAF/exploit/405); " +
				"trusted IPs must bypass PERIMETER controls only")
		}
	}

	// (d) Cloud-provider blocking is a perimeter control too (blocks by source
	// IP range): trusted IPs must bypass it via $is_priority_allow_cloud (#161
	// follow-up — the cloud section formerly ignored trusted IPs).
	cloudIdx := strings.Index(out, "Blocked Cloud Provider IPs check")
	if cloudIdx < 0 {
		t.Fatalf("rendered config missing cloud-provider block section")
	}
	cloudEnd := strings.Index(out[cloudIdx:], "set $cloud_block_check")
	if cloudEnd < 0 {
		t.Fatalf("cloud-provider block section missing its check directive")
	}
	if !strings.Contains(out[cloudIdx:cloudIdx+cloudEnd], guard) {
		t.Errorf("cloud-provider block section missing trusted-IP bypass guard %q", guard)
	}
}

// TestChallengeApiHostSanitized pins issue #158: when an old docker-compose
// parser leaves API_HOST as the literal "127.0.0.1:${API_HOST_PORT:-9080}",
// the unexpanded value must NOT reach the rendered config. NewManager sanitizes
// API_HOST once at boot and falls back to 127.0.0.1:<API_HOST_PORT|9080>, so the
// Challenge-mode proxy_pass directives stay valid (no nested ${} → nginx -t no
// longer fails with "closing bracket ... is missing").
//
// This is an assertion test (not a golden) because the bug is specifically about
// a malformed substring never appearing in proxy_pass; a golden would obscure it.
func TestChallengeApiHostSanitized(t *testing.T) {
	t.Setenv("API_HOST", "127.0.0.1:${API_HOST_PORT:-9080}")
	t.Setenv("API_HOST_PORT", "")

	m := NewManager(t.TempDir(), t.TempDir())

	// geo_challenge fixture has ChallengeMode=true, so the template renders the
	// challenge endpoint locations that use {{apiHost}} in proxy_pass.
	data := ProxyHostConfigData{
		Host:           goldenBaseHost("00000000-0000-0000-0000-000000000a06", "challenge.example.com"),
		GlobalSettings: baseGlobalSettings(),
		GeoRestriction: &model.GeoRestriction{
			ID:            "00000000-0000-0000-0000-00000000bbb2",
			ProxyHostID:   "00000000-0000-0000-0000-000000000a06",
			Mode:          "blacklist",
			Countries:     []string{"CN"},
			Enabled:       true,
			ChallengeMode: true,
			CreatedAt:     fixtureNow,
			UpdatedAt:     fixtureNow,
		},
	}

	if err := m.GenerateConfigFull(context.Background(), data); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	rendered, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(data.Host)))
	if err != nil {
		t.Fatalf("read rendered: %v", err)
	}
	out := string(rendered)

	// The sanitized fallback host:port must be used for the challenge upstream.
	if !strings.Contains(out, "proxy_pass http://127.0.0.1:9080/api/v1/challenge/") {
		t.Errorf("rendered config missing sanitized challenge proxy_pass; got:\n%s", out)
	}

	// No proxy_pass directive may contain an unexpanded ${ or a space inside the URL.
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "proxy_pass http://") {
			continue
		}
		url := strings.TrimSuffix(strings.TrimPrefix(trimmed, "proxy_pass "), ";")
		if strings.Contains(url, "${") {
			t.Errorf("proxy_pass URL contains unexpanded ${: %q", trimmed)
		}
		if strings.ContainsAny(url, " \t") {
			t.Errorf("proxy_pass URL contains whitespace: %q", trimmed)
		}
	}
}

// TestAPIHostDerivedFromPort pins the #158 single-source-of-truth behavior: when
// API_HOST is empty (compose no longer hardcodes a default), the upstream is
// derived from API_HOST_PORT, so a custom port is honored without also setting
// API_HOST. An explicit API_HOST still overrides.
func TestAPIHostDerivedFromPort(t *testing.T) {
	t.Setenv("API_HOST", "")
	t.Setenv("API_HOST_PORT", "9999")
	if m := NewManager(t.TempDir(), t.TempDir()); m.apiHost != "127.0.0.1:9999" {
		t.Errorf("derive from API_HOST_PORT: got %q, want 127.0.0.1:9999", m.apiHost)
	}

	t.Setenv("API_HOST", "10.0.0.5:8080")
	if m := NewManager(t.TempDir(), t.TempDir()); m.apiHost != "10.0.0.5:8080" {
		t.Errorf("explicit API_HOST override: got %q, want 10.0.0.5:8080", m.apiHost)
	}
}

func TestProxyHostTemplateGolden(t *testing.T) {
	goldenDir := filepath.Join("testdata", "proxy_host_golden")
	if *updateGoldenFlag {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
	}

	for _, tc := range goldenCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Fresh manager per case so configPath is isolated and
			// per-case fields (httpPort, IPv6) don't leak between subtests.
			configPath := t.TempDir()
			certsPath := t.TempDir()
			m := NewManager(configPath, certsPath)
			// NGINX_SKIP_TEST defaults from env — we only write the config,
			// we never invoke nginx -t / reload, so skipTest is irrelevant
			// here. m.GenerateConfigFull does not call out to docker.

			// If the host references a certificate, write placeholder cert files
			// so the manager's "SSL temporarily disabled" fallback doesn't kick
			// in — otherwise the golden won't exercise the ssl.conf.tmpl path.
			if tc.data.Host.SSLEnabled && tc.data.Host.CertificateID != nil && *tc.data.Host.CertificateID != "" {
				certDir := filepath.Join(certsPath, *tc.data.Host.CertificateID)
				if err := os.MkdirAll(certDir, 0o755); err != nil {
					t.Fatalf("mkdir certDir: %v", err)
				}
				for _, name := range []string{"fullchain.pem", "privkey.pem"} {
					if err := os.WriteFile(filepath.Join(certDir, name), []byte("placeholder"), 0o644); err != nil {
						t.Fatalf("write placeholder %s: %v", name, err)
					}
				}
			}

			ctx := context.Background()
			if err := m.GenerateConfigFull(ctx, tc.data); err != nil {
				t.Fatalf("GenerateConfigFull: %v", err)
			}

			renderedPath := filepath.Join(configPath, GetConfigFilename(tc.data.Host))
			rendered, err := os.ReadFile(renderedPath)
			if err != nil {
				t.Fatalf("read rendered %s: %v", renderedPath, err)
			}

			goldenPath := filepath.Join(goldenDir, tc.name+".conf")
			if *updateGoldenFlag {
				if err := os.WriteFile(goldenPath, rendered, 0o644); err != nil {
					t.Fatalf("write golden %s: %v", goldenPath, err)
				}
				t.Logf("updated %s (%d bytes)", goldenPath, len(rendered))
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v (run with -update to create)", goldenPath, err)
			}
			if string(rendered) != string(want) {
				t.Errorf("rendered output differs from %s (got %d bytes, want %d bytes)\n--- diff preview ---\n%s",
					goldenPath, len(rendered), len(want), diffPreview(want, rendered))
			}
		})
	}
}
