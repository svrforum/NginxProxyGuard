package nginx

// Path-scoped exemptions decide on the normalized request path.
//
// An exemption keyed on the raw $request_uri (or ModSecurity's REQUEST_URI)
// also covered "/api/../admin" and "/api/%2e%2e/admin": nginx routes those to
// /admin and proxy_pass forwards the raw target, which the backend resolves to
// /admin as well. These tests pin the pieces of the fix that a golden file
// cannot show: where the variable is defined, that it is written before
// anything reads it, which paths fail closed, and what each converted
// predicate renders.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// newRequestPathTestManager returns a Manager writing into temp dirs, with
// nginx -t skipped (no docker in unit tests).
func newRequestPathTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	m := &Manager{
		configPath:       filepath.Join(root, "conf.d"),
		streamConfigPath: filepath.Join(root, "stream.d"),
		certsPath:        filepath.Join(root, "certs"),
		modsecPath:       filepath.Join(root, "modsec"),
		skipTest:         true,
		httpPort:         "80",
		httpsPort:        "443",
		apiHost:          "127.0.0.1:9080",
		dnsResolver:      "127.0.0.11",
	}
	for _, d := range []string{m.configPath, m.streamConfigPath, m.certsPath, m.modsecPath} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return m, root
}

var requestPathDefinition = regexp.MustCompile(`map\s+\S+\s+\$npg_request_path\s*\{`)

func TestUnsafeRequestPathPattern(t *testing.T) {
	re := regexp.MustCompile(`(?i)(?:` + unsafeRequestPathPattern + `)`)
	// What has to fail closed: a path that holds a dot segment a backend may
	// resolve above the prefix nginx routed it under. nginx hands the map a
	// $uri whose plain "/../" is already gone, so these are the spellings it
	// leaves in place; ModSecurity hands the guard a REQUEST_FILENAME that is
	// not resolved, so a literal "/../" has to match there too.
	unsafe := []string{
		"/api/../admin",           // plain dot segment (REQUEST_FILENAME, not resolved)
		"/api/./x",                // single dot segment
		"/api/x/..",               // trailing, no slash
		"/api/..;/admin",          // Tomcat/Jetty: ..; is ..
		"/api/x/..;",              // trailing ..;
		`/api/..\admin`,           // ..\ — Windows separator
		`/api/x\..\admin`,         // \..\ — backslash both sides
		"/api/%2e%2e/admin",       // from %252e%252e: double-encoded dot segment
		"/api/%2E%2E/admin",       // case-insensitive
		"/api/%252e%252e/admin",   // from %25252e%25252e: triple-encoded
		"/api/x%5c..%5cadmin",     // from %255c: encoded backslash around ..
		"/api/%u002e%u002e/admin", // IIS %u dot
		"/api/..%20/admin",        // .. then a trailing space (Windows strips it)
		"/api/.%20/x",             // . then a trailing space
		"/api/....//admin",        // four dots, then //
		"/api/\n../admin",         // WHATWG URL parsers drop tab/newline
		"/api/\t../admin",
		"/api/x\r",
		"/api/x\x7f",
		// The overlong-UTF-8 dot and slash (\xc0\xae, \xc0\xaf, ...) are matched
		// as single bytes by PCRE, which nginx and libmodsecurity use. Go's RE2
		// reads \xc0 as the rune U+00C0 and encodes it as two UTF-8 bytes, so it
		// cannot exercise a lone 0xc0 byte here; the isolated-image probe covers
		// "..%c0%af" and friends (they return 403).
	}
	for _, p := range unsafe {
		if !re.MatchString(p) {
			t.Errorf("%q must fail closed (no exemption), but the unsafe-path pattern does not match it", p)
		}
	}
	// What must stay exempt: an ordinary path with no dot segment. A lone
	// backslash, a doubly-encoded slash inside a name or a stray "%" does not
	// let a request leave its prefix, so none of these is refused — that is the
	// narrowing #286 and this change are about (a broad set stripped the
	// operator's exclusions from Jenkins/Harbor paths and % in a filename).
	safe := []string{
		"/",
		"/api/x",
		"/api/v1/challenge/page",
		"/.well-known/acme-challenge/Tok-en_123", // ".well-known" is not a dot segment
		"/files/my docs/report.pdf",
		"/c++/x",
		`/api\x`,                                // a lone backslash is just a separator, no dot
		"/job/p/job/feature%252Ffoo",            // double-encoded slash inside a name (#2)
		"/files/100%25users.csv",                // a literal percent in a name (#2)
		"/remote.php/dav/%25USERPROFILE%25.txt", // literal %u-looking name
		"/100%",                                 // a trailing percent, nothing after it
		"/a;b/c",                                // a ";" path parameter that is not "..;"
		"/a..b/c",                               // dots inside a segment, not a dot segment
		"/..b/c",                                // ".." with a letter after it is a name
		"/.hidden/x",                            // a dotfile is not a dot segment
		"/caf\xc3\xa9",                          // UTF-8 "é" is not an overlong slash
	}
	for _, p := range safe {
		if re.MatchString(p) {
			t.Errorf("%q is an ordinary path but the unsafe-path pattern matches it", p)
		}
	}
}

// TestUnsafeRequestPathPatternIsLinear guards against catastrophic backtracking
// on PCRE (nginx and libmodsecurity): an unbounded quantifier here let a crafted
// path blow SecPcreMatchLimit and fail the WAF guard open. RE2 cannot backtrack,
// so this only proves the shape is bounded, not the PCRE run time; the real
// check is the isolated-image probe. The budget is generous to stay stable on a
// loaded CI box, not tight.
func TestUnsafeRequestPathPatternIsLinear(t *testing.T) {
	re := regexp.MustCompile(`(?i)(?:` + unsafeRequestPathPattern + `)`)
	for _, pad := range []string{"%2520", "%2525", "/.x", "..%20", "a"} {
		adversarial := "/public/." + strings.Repeat(pad, 20000) + "x/..;/admin"
		start := time.Now()
		re.MatchString(adversarial)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("matching %d copies of %q took %v; the pattern is not linear", 20000, pad, d)
		}
	}
}

func TestRequestPathMapContent(t *testing.T) {
	content := string(requestPathMapContent)
	if n := len(requestPathDefinition.FindAllString(content, -1)); n != 1 {
		t.Fatalf("npg_request_path.conf must define $npg_request_path exactly once, found %d:\n%s", n, content)
	}
	// Keyed on $uri, nginx's decoded and normalized path. Not volatile: the
	// value is computed once and survives error_page/auth_request re-runs.
	if !strings.Contains(content, "map $uri $npg_request_path {") {
		t.Errorf("map must read $uri:\n%s", content)
	}
	if strings.Contains(content, "volatile") {
		t.Errorf("map must stay cacheable; volatile re-evaluates it after internal redirects:\n%s", content)
	}
	if !strings.Contains(content, "    default $uri;\n") {
		t.Errorf("map default must be $uri:\n%s", content)
	}
	if !strings.Contains(content, `"~*(?:`+unsafeRequestPathPattern+`)" "";`) {
		t.Errorf("unsafe paths must map to the empty string:\n%s", content)
	}
	// $npg_request_target is $npg_request_path with the query string from the
	// raw target appended, defined once in the same file. Exploit-rule URI
	// exclusions and Block Exploits exceptions test it so a pattern written
	// against the query ("rest_route=", "^/i/\?c=feed") keeps working; a bare
	// $args is empty again after an error_page redirect. It falls back to
	// $npg_request_path, so an unsafe path's "" carries into it too.
	if n := strings.Count(content, "$npg_request_target {"); n != 1 {
		t.Fatalf("npg_request_path.conf must define $npg_request_target exactly once, found %d:\n%s", n, content)
	}
	if !strings.Contains(content, "map $request_uri $npg_request_target {") {
		t.Errorf("target map must read $request_uri (it is the only source of the query string):\n%s", content)
	}
	if !strings.Contains(content, "    default $npg_request_path;\n") {
		t.Errorf("target map default must be $npg_request_path, so an unsafe \"\" carries over:\n%s", content)
	}
}

// The map is ensured before host_common.conf is written, because every host
// config includes host_common.conf: a reference without its definition fails
// nginx -t for the whole server, and the nginx entrypoint's boot recovery only
// disables per-host files, so nginx would not start at all.
func TestEnsureHostCommonIncludeWritesRequestPathMapFirst(t *testing.T) {
	t.Run("fresh install writes both", func(t *testing.T) {
		m, _ := newRequestPathTestManager(t)
		if err := m.ensureHostCommonInclude(); err != nil {
			t.Fatalf("ensureHostCommonInclude: %v", err)
		}
		gotMap, err := os.ReadFile(filepath.Join(m.configPath, requestPathMapFile))
		if err != nil {
			t.Fatalf("map file missing after ensureHostCommonInclude: %v", err)
		}
		if !bytes.Equal(gotMap, requestPathMapContent) {
			t.Errorf("map file content differs from requestPathMapContent")
		}
		common, err := os.ReadFile(filepath.Join(m.configPath, "includes", "host_common.conf"))
		if err != nil {
			t.Fatalf("host_common.conf missing: %v", err)
		}
		if !strings.Contains(string(common), "$npg_request_path") {
			t.Errorf("host_common.conf no longer reads $npg_request_path; this test guards nothing")
		}
	})

	t.Run("map write failure leaves host_common unwritten", func(t *testing.T) {
		m, _ := newRequestPathTestManager(t)
		// A directory where the map file belongs makes the atomic rename fail.
		if err := os.MkdirAll(filepath.Join(m.configPath, requestPathMapFile, "blocker"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := m.ensureHostCommonInclude(); err == nil {
			t.Fatal("ensureHostCommonInclude succeeded although the map could not be written")
		}
		if _, err := os.Stat(filepath.Join(m.configPath, "includes", "host_common.conf")); !os.IsNotExist(err) {
			t.Fatalf("host_common.conf was written without the map that defines its variable (stat err=%v)", err)
		}
	})

	t.Run("stale map is rewritten", func(t *testing.T) {
		m, _ := newRequestPathTestManager(t)
		path := filepath.Join(m.configPath, requestPathMapFile)
		if err := os.WriteFile(path, []byte("# stale\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := m.ensureRequestPathMap(); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, requestPathMapContent) {
			t.Errorf("stale map file was not replaced")
		}
	})
}

// The variable must be defined in exactly one file of everything the API
// writes, and that file must sit directly in conf.d/ (http level, loaded by the
// conf.d/*.conf include). nginx accepts a second map for the same variable
// silently and keeps the last one parsed, so nginx -t would not catch a
// duplicate.
func TestRequestPathDefinedOnceAcrossGeneratedFiles(t *testing.T) {
	m, root := newRequestPathTestManager(t)
	ctx := context.Background()
	if err := m.GenerateMainNginxConfig(ctx, baselineSettings(), nil, false, TrustedProxyConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureFilterSubscriptionFiles(); err != nil {
		t.Fatal(err)
	}
	if err := m.GenerateDefaultServerConfig(ctx, "allow"); err != nil {
		t.Fatal(err)
	}
	host := &model.ProxyHost{
		ID: "00000000-0000-0000-0000-0000000000f1", DomainNames: []string{"path.example.com"},
		ForwardScheme: "http", ForwardHost: "192.0.2.10", ForwardPort: 8080, Enabled: true,
		BlockExploits: true, BlockExploitsExceptions: "^/wp-json/", WAFEnabled: true, WAFMode: "blocking",
	}
	if err := m.GenerateConfigFull(ctx, ProxyHostConfigData{Host: host, ExploitBlockRules: exploitRulesWithExclusions()}); err != nil {
		t.Fatal(err)
	}
	if err := m.GenerateHostWAFConfig(ctx, host, []model.WAFRuleExclusion{{RuleID: 942100, ScopeType: "uri", ScopeValue: "/api"}}, nil); err != nil {
		t.Fatal(err)
	}

	var defined []string
	var readers []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for range requestPathDefinition.FindAll(b, -1) {
			defined = append(defined, rel)
		}
		if bytes.Contains(b, []byte("$npg_request_path")) {
			readers = append(readers, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("conf.d", requestPathMapFile)
	if len(defined) != 1 || defined[0] != want {
		t.Fatalf("$npg_request_path must be defined once, in %s; definitions found in: %q", want, defined)
	}
	// Sanity: the definition has readers, so this test is not vacuous.
	if len(readers) < 3 {
		t.Fatalf("expected the map file, host_common.conf and the host config to mention $npg_request_path, got %v", readers)
	}
}

func exploitRulesWithExclusions() []model.ExploitBlockRuleForRender {
	return []model.ExploitBlockRuleForRender{
		{
			ExploitBlockRule: model.ExploitBlockRule{ID: "qs-0001", Category: "rfi", Name: "URL Parameter Injection",
				Pattern: `[a-zA-Z0-9_]=https?://`, PatternType: "query_string", Enabled: true},
			URIExclusions: []string{"^/api/upload", "^/?$"},
			IDSanitized:   "qs_0001",
		},
		{
			ExploitBlockRule: model.ExploitBlockRule{ID: "uri-0001", Category: "rfi", Name: "Dotenv File Access",
				Pattern: `/\.env(\.|$|/)`, PatternType: "request_uri", Enabled: true},
			URIExclusions: []string{"^/docs/"},
			IDSanitized:   "uri_0001",
		},
	}
}

func renderForTest(t *testing.T, data ProxyHostConfigData) string {
	t.Helper()
	var buf bytes.Buffer
	if err := renderProxyHostConfig(context.Background(), &buf, data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	return buf.String()
}

// Every predicate that grants an exemption reads $npg_request_path (the skip
// where the path alone decides it) or $npg_request_target (path + query, where
// the operator's pattern may name a query argument). The raw $request_uri stays
// only where it DETECTS an attack (request_uri rule patterns) or keys non-
// security behaviour (cache bypass, redirect targets). Every exemption is
// cancelled when $npg_request_path is "" (an unsafe path), whatever it matched.
func TestExemptionPredicatesReadNormalizedPath(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	common := string(m.hostCommonIncludeContent())
	for _, want := range []string{
		`if ($npg_request_path ~ "^/\.well-known/acme-challenge/") {`,
		`if ($npg_request_path ~ "^/api/v1/challenge/") {`,
	} {
		if !strings.Contains(common, want) {
			t.Errorf("host_common.conf is missing %q:\n%s", want, common)
		}
	}
	if strings.Contains(common, "if ($request_uri") {
		t.Errorf("host_common.conf still decides the security skip on $request_uri:\n%s", common)
	}

	geoChallenge := &model.GeoRestriction{Enabled: true, Mode: "whitelist", Countries: []string{"KR"}, ChallengeMode: true}
	customRoot := "location / {\n    proxy_pass http://192.0.2.20:8080;\n}\n"
	certID := "00000000-0000-0000-0000-00000000cert"

	httpHost := baseHost("00000000-0000-0000-0000-0000000000f2", "192.0.2.20", true)
	httpHost.AdvancedConfig = customRoot
	sslNoForce := baseHost("00000000-0000-0000-0000-0000000000f3", "192.0.2.20", true)
	sslNoForce.SSLEnabled, sslNoForce.CertificateID, sslNoForce.AdvancedConfig = true, &certID, customRoot
	exploitHost := baseHost("00000000-0000-0000-0000-0000000000f4", "192.0.2.20", true)
	exploitHost.BlockExploits = true
	exploitHost.BlockExploitsExceptions = "^/wp-json/\n^/?$"
	fallbackHost := baseHost("00000000-0000-0000-0000-0000000000f5", "192.0.2.20", true)
	fallbackHost.BlockExploits = true
	fallbackHost.BlockExploitsExceptions = "^/wp-json/"

	cases := []struct {
		name  string
		data  ProxyHostConfigData
		wants []string
	}{
		{
			// Server-level $need_challenge for a custom `location /`: waf.conf.tmpl
			// (HTTP server, no SSL) and cache.conf.tmpl (HTTPS server).
			name: "challenge_bypass_http_custom_root",
			data: ProxyHostConfigData{Host: httpHost, GeoRestriction: geoChallenge},
			wants: []string{
				"    if ($npg_request_path ~ \"^/api/v1/challenge/\") {\n        set $need_challenge 0;",
				"    if ($npg_request_path ~ \"^/\\.well-known/acme-challenge/\") {\n        set $need_challenge 0;",
			},
		},
		{
			name: "challenge_bypass_ssl_custom_root",
			data: ProxyHostConfigData{Host: sslNoForce, GeoRestriction: geoChallenge},
			wants: []string{
				"    if ($npg_request_path ~ \"^/api/v1/challenge/\") {\n        set $need_challenge 0;",
				"    if ($npg_request_path ~ \"^/\\.well-known/acme-challenge/\") {\n        set $need_challenge 0;",
			},
		},
		{
			name: "exploit_exclusions_and_exceptions",
			data: ProxyHostConfigData{Host: exploitHost, ExploitBlockRules: exploitRulesWithExclusions(), GlobalBlockExploitsExceptions: "^/webapi/"},
			wants: []string{
				`if ($npg_request_target ~* "^/api/upload") { set $exploit_skip_qs_0001 "1"; }`,
				// "^/?$" matches "" but is rendered untouched; the per-rule guard
				// below cancels the skip when the path is unsafe.
				`if ($npg_request_target ~* "^/?$") { set $exploit_skip_qs_0001 "1"; }`,
				`if ($npg_request_path = "") { set $exploit_skip_qs_0001 "0"; }`,
				`if ($npg_request_target ~* "^/docs/") { set $rfi_skip_uri_0001 "1"; }`,
				`if ($npg_request_path = "") { set $rfi_skip_uri_0001 "0"; }`,
				"    if ($npg_request_target ~* \"^/webapi/\") {\n        set $exploit_qs_exempt 1;",
				"    if ($npg_request_target ~* \"^/wp-json/\") {\n        set $rfi_exempt 1;",
				// The exception block fails closed on an unsafe path as a whole.
				"    if ($npg_request_path = \"\") {\n        set $exploit_qs_exempt 0;",
				"    if ($npg_request_path = \"\") {\n        set $rfi_exempt 0;",
				"    if ($exploit_qs_exempt = 1) {\n        set $exploit_qs_block 0;",
				"    if ($rfi_exempt = 1) {\n        set $rfi_block 0;",
				// Detection keeps looking at the raw request target.
				`if ($request_uri ~* "/\.env(\.|$|/)") { set $rfi_match_uri_0001 "1"; }`,
			},
		},
		{
			name: "fallback_rules_exceptions",
			data: ProxyHostConfigData{Host: fallbackHost},
			wants: []string{
				"    if ($npg_request_target ~* \"^/wp-json/\") {\n        set $rfi_exempt 1;",
				"    if ($npg_request_path = \"\") {\n        set $rfi_exempt 0;",
				"    if ($rfi_exempt = 1) {\n        set $rfi_block 0;",
			},
		},
	}
	// Raw-target lines that are allowed to stay: attack detection, and the
	// cache-bypass keys (not an exemption from any security check).
	allowedRaw := []string{
		`if ($request_uri ~* "/\.env(\.|$|/)")`,
		`if ($request_uri ~* \.(js|css|`,
		`if ($request_uri ~* ^/api/)`,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderForTest(t, tc.data)
			for _, w := range tc.wants {
				if !strings.Contains(out, w) {
					t.Errorf("rendered config is missing %q", w)
				}
			}
			for _, line := range strings.Split(out, "\n") {
				if !strings.Contains(line, "if ($request_uri") {
					continue
				}
				ok := false
				for _, a := range allowedRaw {
					if strings.Contains(line, a) {
						ok = true
					}
				}
				if !ok {
					t.Errorf("an exemption still tests the raw request target: %s", strings.TrimSpace(line))
				}
			}
		})
	}
}

func TestExemptionPattern(t *testing.T) {
	cases := []struct{ in, want string }{
		// A plain path pattern is rendered untouched.
		{"^/wp-json/", "^/wp-json/"},
		{"/hooks/", "/hooks/"},
		{`^/wp-admin/admin-ajax\.php`, `^/wp-admin/admin-ajax\.php`},
		// A %HH escape outside a class is widened so it matches BOTH the query
		// string as sent and the once-decoded path. This is what keeps an
		// encoded path pattern (a space, a Korean path copied from the log)
		// working now that the test is on $npg_request_target, not $request_uri.
		{"^/files/my%20docs/", `^/files/my(?:%20|\x20)docs/`},
		{"%2e%2e", `(?:%2e|\x2e)(?:%2e|\x2e)`},
		{"^/%EC%9C%84/", `^/(?:%EC|\xEC)(?:%9C|\x9C)(?:%84|\x84)/`},
		// A pattern that names a query argument still works; "?" is a quantifier
		// and "\?" a literal, neither is a %HH escape.
		{"rest_route=", "rest_route="},
		{`^/i/\?c=feed`, `^/i/\?c=feed`},
		{"^/?$", "^/?$"},
		// An escaped percent is the same literal "%" to PCRE, and on
		// $request_uri it matched the same encoded path, so it is widened too.
		// So is a %HH inside \Q...\E, written outside the quote.
		{`\%20`, `(?:%20|\x20)`},
		{`\Q%20\E`, `(?:%20|\x20)`},
		{`\Qa.%41+b\E`, `\Qa.\E(?:%41|\x41)\Q+b\E`},
		{`\Q/q%41/`, `\Q/q\E(?:%41|\x41)\Q/\E`}, // a quote without \E runs to the end
		{`\Qa.b\E%41`, `\Qa.b\E(?:%41|\x41)`},   // a quote with no %HH is copied as written
		// Inside a character class the bytes are literal; leave them alone so a
		// class such as [%0-9] is not turned into nonsense.
		{`[a%25b]`, `[a%25b]`},
		{"/100%", "/100%"}, // a trailing "%" with no hex after it
		{`\c%41`, `\c%41`}, // \c takes the "%" as its argument
		// PCRE-only syntax Go cannot compile is copied verbatim, so a pattern
		// nginx already accepts is never turned into one it rejects.
		{"^/(?=admin)", "^/(?=admin)"},
		// A verb name and a callout string are text, not pattern: widened, a
		// %HH in them left an unmatched ")" and failed nginx -t.
		{"(*MARK:%41)^/m%42", `(*MARK:%41)^/m(?:%42|\x42)`},
		{"(*:%41)(*SKIP)%42", `(*:%41)(*SKIP)(?:%42|\x42)`},
		{"(?C%41%)^/c", "(?C%41%)^/c"},
		{"(?C'%41''%42')%43", `(?C'%41''%42')(?:%43|\x43)`}, // a doubled delimiter stands for itself
		{"(?C{%41}}%42})%43", `(?C{%41}}%42})(?:%43|\x43)`},
		{"(?C1)%41", `(?C1)(?:%41|\x41)`},
		// The stored text is unescaped by nginx's tokenizer before PCRE sees
		// it, so it is widened as PCRE reads it and escaped for the string
		// again. "\\" is one backslash to PCRE: ^/a\\%2F is ^/a\%2F, a literal
		// %2F, and is widened as one. Widened as stored, it reached PCRE as
		// ^/a\(?:%2F|\x2F), which does not compile.
		{`^/a\\%2F`, `^/a(?:%2F|\x2F)`},
		{`^/b\\%41`, `^/b(?:%41|\x41)`},
		{`\\Q%20\\E%41`, `(?:%20|\x20)(?:%41|\x41)`},
		{`[\\]%41]%42`, `[\]%41](?:%42|\x42)`},
		{`^/c\\\\%41`, `^/c\\\(?:%41|\x41)`}, // PCRE: an escaped backslash, then %41
		// A bare quote is escaped for the string; \' has always been just "'".
		{`a"b`, `a\"b`},
		{`a\"b`, `a\"b`},
		{`a\'b%41`, `a'b(?:%41|\x41)`},
		// \t is a tab to PCRE and \\t PCRE's own tab escape; both stay so.
		{`^/t\tx`, `^/t\tx`},
		{`^/t\\tx`, `^/t\\tx`},
	}
	for _, tc := range cases {
		if got := exemptionPattern(tc.in); got != tc.want {
			t.Errorf("exemptionPattern(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// What PCRE compiles is what nginx's tokenizer makes of the quoted string
// (unquoteNginxString, checked against nginx 1.30 with `return 200 "..."`).
// quoteNginxString must give every byte string back through it unchanged and
// never end the string early.
func TestQuoteNginxStringRoundTrip(t *testing.T) {
	alphabet := []string{`\`, `"`, `'`, "t", "r", "n", "x", "%", "\t", "\r", "\n", "a"}
	var check func(s string, depth int)
	check = func(s string, depth int) {
		q := quoteNginxString(s)
		if got := unquoteNginxString(q); got != s {
			t.Errorf("unquoteNginxString(quoteNginxString(%q)) = %q", s, got)
		}
		for i := 0; i < len(q); i++ {
			if q[i] == '\\' {
				i++ // the tokenizer skips the escaped byte
				if i == len(q) {
					t.Errorf("quoteNginxString(%q) = %q escapes the closing quote", s, q)
				}
			} else if q[i] == '"' {
				t.Errorf("quoteNginxString(%q) = %q ends the string early", s, q)
			}
		}
		if depth > 0 {
			for _, c := range alphabet {
				check(s+c, depth-1)
			}
		}
	}
	check("", 4)
}

// Widening grows a %HH from 3 bytes to 12, and nginx refuses a config token
// longer than 4094 bytes, which fails nginx -t for the whole config. Block
// Exploits exceptions have no length limit, so a pattern whose widened form
// does not fit gets each %HH as \xHH: it keeps matching the decoded path, as
// it matched the encoded one on $request_uri. Rendered unwidened, a long
// Korean path copied from the log stopped matching anything in the path.
func TestExemptionPatternLength(t *testing.T) {
	korean := "^/" + strings.Repeat("%EC%9C%84%ED%82%A4/", 68) + "x.html" // 1,300 bytes, 408 escapes
	wantKorean := "^/" + strings.Repeat(`\xEC\x9C\x84\xED\x82\xA4/`, 68) + "x.html"
	if got := exemptionPattern(korean); got != wantKorean {
		t.Errorf("a %d-byte pattern widens to more than %d bytes and must render with \\xHH, got %d bytes", len(korean), maxExemptionPattern, len(got))
	}
	shorter := "^/" + strings.Repeat("%EC%9C%84%ED%82%A4/", 10)
	if got := exemptionPattern(shorter); !strings.Contains(got, `(?:%EC|\xEC)`) {
		t.Errorf("a pattern whose widened form fits must be widened, got %q", got)
	}
	fits := strings.Repeat("a", maxExemptionPattern-12) + "%41"
	if got := exemptionPattern(fits); len(got) != maxExemptionPattern || !strings.HasSuffix(got, `(?:%41|\x41)`) {
		t.Errorf("a widened pattern of exactly %d bytes must be kept, got %d bytes", maxExemptionPattern, len(got))
	}
	over := fits + "b"
	if got, want := exemptionPattern(over), strings.Repeat("a", maxExemptionPattern-12)+`\x41b`; got != want {
		t.Errorf("a widened pattern over %d bytes must render with \\xHH, got %d bytes", maxExemptionPattern, len(got))
	}
	// Too long even as \xHH (3,003 bytes, 1,001 escapes): rendered as written.
	tooLong := strings.Repeat("%41", 1001)
	if got := exemptionPattern(tooLong); got != tooLong {
		t.Errorf("a pattern whose \\xHH form is over %d bytes must render as written, got %d bytes", maxExemptionPattern, len(got))
	}
}

// Both kinds of call site render the stored pattern through exemptionPattern
// and write the result between the quotes as it is. The URI-exclusion sites no
// longer wrap it in escapeNginxPattern, which would leave it unchanged anyway:
// every quote in exemptionPattern's result is already escaped.
func TestExemptionPatternCallSites(t *testing.T) {
	host := baseHost("00000000-0000-0000-0000-0000000000f9", "192.0.2.20", true)
	host.BlockExploits = true
	host.BlockExploitsExceptions = `^/b\\%41` + "\n" + `^/q"x`
	rules := exploitRulesWithExclusions()
	rules[0].URIExclusions = []string{`^/a\\%2F`, `^/f%41`}
	out := renderForTest(t, ProxyHostConfigData{Host: host, ExploitBlockRules: rules})
	for _, want := range []string{
		`if ($npg_request_target ~* "^/a(?:%2F|\x2F)") { set $exploit_skip_qs_0001 "1"; }`,
		`if ($npg_request_target ~* "^/f(?:%41|\x41)") { set $exploit_skip_qs_0001 "1"; }`,
		"    if ($npg_request_target ~* \"^/b(?:%41|\\x41)\") {\n        set $exploit_qs_exempt 1;",
		"    if ($npg_request_target ~* \"^/q\\\"x\") {\n        set $exploit_qs_exempt 1;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config is missing %q", want)
		}
	}
}

// The ACME challenge skip must spell the "." in "^/.well-known/..." escaped, so
// the regex does not also match "/Xwell-known/...". An SSL host without forced
// HTTPS renders that line twice — once in the HTTP server (waf.conf.tmpl) and
// once in the HTTPS server (cache.conf.tmpl) — so a whole-config Contains on the
// escaped line passes even when one copy regresses. This asserts it per server
// block: reverting either template is caught in the block it belongs to.
func TestChallengeACMESkipEscapedInEveryServerBlock(t *testing.T) {
	certID := "00000000-0000-0000-0000-00000000cert"
	host := baseHost("00000000-0000-0000-0000-0000000000f8", "192.0.2.20", true)
	host.SSLEnabled, host.CertificateID = true, &certID
	host.AdvancedConfig = "location / {\n    proxy_pass http://192.0.2.20:8080;\n}\n"
	out := renderForTest(t, ProxyHostConfigData{
		Host:           host,
		GeoRestriction: &model.GeoRestriction{Enabled: true, Mode: "whitelist", Countries: []string{"KR"}, ChallengeMode: true},
	})
	blocks := splitServerBlocks(t, out)
	if len(blocks) != 2 {
		t.Fatalf("an SSL host without forced HTTPS should render an HTTP and an HTTPS server block, got %d", len(blocks))
	}
	seen := 0
	for i, b := range blocks {
		if !strings.Contains(b, "acme-challenge/") {
			continue
		}
		seen++
		if !strings.Contains(b, `if ($npg_request_path ~ "^/\.well-known/acme-challenge/")`) {
			t.Errorf("server block %d skips the ACME challenge on an unescaped dot (matches /Xwell-known/...):\n%s", i, b)
		}
	}
	if seen < 2 {
		t.Errorf("expected the ACME skip in both the HTTP (waf.conf) and HTTPS (cache.conf) server blocks, saw it in %d", seen)
	}
}

// splitServerBlocks returns each top-level `server { ... }` block in a rendered
// config, brace-balanced the same way extractFirstServerBlock finds the first.
func splitServerBlocks(t *testing.T, full string) []string {
	t.Helper()
	var blocks []string
	for rest := full; ; {
		start := strings.Index(rest, "server {")
		if start < 0 {
			return blocks
		}
		depth := 0
		end := -1
		for i := start; i < len(rest); i++ {
			switch rest[i] {
			case '{':
				depth++
			case '}':
				if depth--; depth == 0 {
					end = i + 1
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatalf("unterminated server block starting at offset %d", start)
		}
		blocks = append(blocks, rest[start:end])
		rest = rest[end:]
	}
}

// A ForwardAuth bypass location switches authentication off for a prefix and
// forwards the request target as sent. nginx routes it on the normalized path,
// but "/public/..;/admin" is /admin to Tomcat, and "/public/%252e%252e/admin"
// is /admin to a backend that decodes twice — so the location refuses any path
// $npg_request_path marks as unsafe instead of serving it unauthenticated.
func TestForwardAuthBypassRefusesUnsafePaths(t *testing.T) {
	host := baseHost("00000000-0000-0000-0000-0000000000f7", "192.0.2.30", true)
	host.AuthBypassPaths = []string{"/public/", "/healthz"}
	out := renderForTest(t, ProxyHostConfigData{
		Host:         host,
		AuthProvider: &model.AuthProvider{Type: "authelia", ProviderURL: "http://192.0.2.40:9091", TimeoutMs: 2000, Enabled: true},
	})
	for _, p := range host.AuthBypassPaths {
		head := "    location " + p + " {\n        auth_request off;\n"
		i := strings.Index(out, head)
		if i < 0 {
			t.Fatalf("bypass location %s not rendered:\n%s", p, out)
		}
		block := out[i : i+strings.Index(out[i:], "\n    }\n")]
		guard := strings.Index(block, "        if ($npg_request_path = \"\") {\n            set $block_reason_var \"access_denied\";\n            return 403;\n        }\n")
		proxy := strings.Index(block, "proxy_pass ")
		if guard < 0 || proxy < 0 || guard > proxy {
			t.Errorf("bypass location %s must refuse an unsafe path before proxying it:\n%s", p, block)
		}
	}
}
