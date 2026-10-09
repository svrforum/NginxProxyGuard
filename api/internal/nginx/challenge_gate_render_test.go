package nginx

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// blockAt returns the brace-balanced block whose header starts at the first
// occurrence of header in s ("" when absent).
func blockAt(s, header string) string {
	start := strings.Index(s, header)
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func gateTestHost(id string, ssl, force bool, advanced string) *model.ProxyHost {
	h := baseHost(id, "192.0.2.20", true)
	if ssl {
		cert := "00000000-0000-0000-0000-00000000cert"
		h.SSLEnabled, h.SSLForceHTTPS, h.CertificateID = true, force, &cert
	}
	h.AdvancedConfig = advanced
	return h
}

func geoChallenge(allowBots bool) *model.GeoRestriction {
	return &model.GeoRestriction{Enabled: true, Mode: "whitelist", Countries: []string{"KR"}, ChallengeMode: true, AllowSearchBots: allowBots}
}

// The three shapes a challenge-mode host renders: HTTP only, SSL with both
// server blocks serving content, and SSL with the HTTP block redirecting.
var gateTLSModes = []struct {
	name       string
	ssl, force bool
}{{"http", false, false}, {"ssl", true, false}, {"ssl force", true, true}}

// nginx makes the challenge decision and the API only checks tokens. The gate
// answers 204 for a visitor it does not challenge (no API round-trip) and 401
// for a challenged visitor without a token. It never reads $is_search_bot
// (_security already cleared $geo_blocked for the search bots a host allows),
// and it tells the API "challenged" with a constant, so no header the client
// sends can say otherwise.
func TestChallengeGateDecidesLocally(t *testing.T) {
	for _, mode := range gateTLSModes {
		out := renderForTest(t, ProxyHostConfigData{
			Host:              gateTestHost("00000000-0000-0000-0000-0000000000e1", mode.ssl, mode.force, ""),
			GeoRestriction:    geoChallenge(true),
			SearchEnginesList: "Googlebot",
		})
		for i, b := range splitServerBlocks(t, out) {
			gate := blockAt(b, "location = /_challenge/validate {")
			if gate == "" {
				t.Fatalf("%s server %d: no challenge gate", mode.name, i)
			}
			for _, want := range []string{
				"if ($geo_blocked = 0) {\n            return 204;",
				"if ($cookie_ng_challenge = \"\") {\n            return 401;",
				"proxy_pass http://127.0.0.1:9080/api/v1/challenge/validate;",
				"proxy_set_header X-Geo-Blocked 1;",
				// A server-level "error_page 401" must not reach the subrequest:
				// it would turn the 401 into a 302, auth_request would answer
				// 500, and location /'s @api_fallback would let the visitor in.
				"error_page 401 = @challenge_gate_deny;",
			} {
				if !strings.Contains(gate, want) {
					t.Errorf("%s server %d: gate lacks %q:\n%s", mode.name, i, want, gate)
				}
			}
			for _, bad := range []string{"$is_search_bot", "X-Geo-Blocked $geo_blocked", "$challenge_gate"} {
				if strings.Contains(gate, bad) {
					t.Errorf("%s server %d: gate still uses %q", mode.name, i, bad)
				}
			}
			if deny := blockAt(b, "location @challenge_gate_deny {"); !strings.Contains(deny, "return 401;") {
				t.Errorf("%s server %d: @challenge_gate_deny missing or not a plain 401: %q", mode.name, i, deny)
			}
		}
	}
}

// nginx asks the API about tokens through the internal gate, which proxies to
// the API directly. The public path is not needed by anyone, and answering it
// told any client whether a token was valid: every server block that serves
// the challenge endpoints answers it with 404 itself.
func TestPublicChallengeValidateAnswers404(t *testing.T) {
	cases := []struct {
		name string
		data ProxyHostConfigData
	}{
		{"cloud ssl", ProxyHostConfigData{Host: gateTestHost("00000000-0000-0000-0000-0000000000e5", true, true, ""),
			BlockedCloudIPRanges: []string{"198.51.100.0/24"}, CloudProviderChallengeMode: true}},
	}
	for _, mode := range gateTLSModes {
		cases = append(cases, struct {
			name string
			data ProxyHostConfigData
		}{"geo " + mode.name, ProxyHostConfigData{Host: gateTestHost("00000000-0000-0000-0000-0000000000e2", mode.ssl, mode.force, ""),
			GeoRestriction: geoChallenge(false)}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := 0
			for i, b := range splitServerBlocks(t, renderForTest(t, tc.data)) {
				if blockAt(b, "location /api/v1/challenge/ {") == "" {
					continue
				}
				seen++
				if v := blockAt(b, "location = /api/v1/challenge/validate {"); !strings.Contains(v, "return 404;") {
					t.Errorf("server %d proxies the public validate path to the API: %q", i, v)
				}
			}
			if seen == 0 {
				t.Fatal("no server block serves the challenge endpoints")
			}
		})
	}
}

// Every location of a challenge-mode server sits behind the gate, locations
// from Advanced Config included, and gets the same token check as
// location /. NPG's own pass-through locations opt out.
func TestChallengeGateCoversCustomLocations(t *testing.T) {
	for _, adv := range []string{
		"",
		"location / {\n    proxy_pass http://192.0.2.20:8080;\n}\n",
		"location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n",
	} {
		for _, mode := range gateTLSModes {
			name := mode.name + " " + strings.SplitN(adv, " {", 2)[0]
			out := renderForTest(t, ProxyHostConfigData{
				Host:           gateTestHost("00000000-0000-0000-0000-0000000000e6", mode.ssl, mode.force, adv),
				GeoRestriction: geoChallenge(false),
			})
			if strings.Contains(out, "$need_challenge") {
				t.Errorf("%s: cookie-presence check still rendered", name)
			}
			for i, b := range splitServerBlocks(t, out) {
				if mode.force && i == 0 {
					// The HTTP server of a forced-HTTPS host redirects every path
					// except ACME and the challenge endpoints: it serves no content.
					if !strings.Contains(b, "return 301 https://$host$request_uri;") {
						t.Errorf("%s: the HTTP server of a forced-HTTPS host does not redirect", name)
					}
					continue
				}
				for _, want := range []string{
					"\n    auth_request /_challenge/validate;\n",
					"\n    auth_request_set $challenge_gate_status $upstream_status;\n",
					"\n    error_page 401 = @challenge_redirect;\n",
				} {
					if !strings.Contains(b, want) {
						t.Errorf("%s server %d: server-level gate lacks %q", name, i, strings.TrimSpace(want))
					}
				}
				if !strings.Contains(blockAt(b, "location @challenge_redirect {"), "return 302 /api/v1/challenge/page?") {
					t.Errorf("%s server %d: @challenge_redirect missing", name, i)
				}
				for _, loc := range []string{"location /api/v1/challenge/ {", "location = /api/v1/challenge/page {", "location @api_fallback {", "location /.well-known/acme-challenge/ {"} {
					if l := blockAt(b, loc); l != "" && !strings.Contains(l, "auth_request off;") {
						t.Errorf("%s server %d: %s is gated", name, i, loc)
					}
				}
				if adv == "" {
					// location / keeps failing open to @api_fallback when the API is down.
					if root := blockAt(b, "location / {"); !strings.Contains(root, "error_page 500 502 503 504 = @api_fallback;") {
						t.Errorf("%s server %d: location / lost its API-down fallback", name, i)
					}
				}
			}
		}
	}

	m, _ := newRequestPathTestManager(t)
	common := string(m.hostCommonIncludeContent())
	if !strings.Contains(blockAt(common, "location @blocked {"), "auth_request off;") {
		t.Error("@blocked would be gated again (a 401 would replace the 403)")
	}
	for _, code := range []string{"502", "503", "504"} {
		if !strings.Contains(common, "location = /error_"+code+".html { internal; auth_request off;") {
			t.Errorf("error page %s is gated", code)
		}
	}
}

// The gate covers locations that may send a 401 of their own, such as Basic
// auth in a custom location, which nginx checks before the gate. Only the
// gate's 401 redirects to the challenge: a challenged visitor without a token,
// or with one the API rejected. Any other 401 is passed on as a 401, so a
// Basic auth prompt still appears; both answers refuse the request.
func TestChallengeRedirectOnlyForTheGates401(t *testing.T) {
	out := renderForTest(t, ProxyHostConfigData{
		Host:           gateTestHost("00000000-0000-0000-0000-0000000000e8", true, false, "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n"),
		GeoRestriction: geoChallenge(false),
	})
	for i, b := range splitServerBlocks(t, out) {
		r := blockAt(b, "location @challenge_redirect {")
		for _, want := range []string{
			"if ($geo_blocked = 0) {\n            return 401;",
			"set $challenge_refused 401;\n        if ($cookie_ng_challenge != \"\") {\n            set $challenge_refused $challenge_gate_status;",
			"if ($challenge_refused != 401) {\n            return 401;",
		} {
			if !strings.Contains(r, want) {
				t.Errorf("server %d: @challenge_redirect lacks %q:\n%s", i, want, r)
			}
		}
		if strings.Index(r, "return 302") < strings.Index(r, "$challenge_refused != 401") {
			t.Errorf("server %d: @challenge_redirect redirects before checking who sent the 401:\n%s", i, r)
		}
	}
}

// An access list in "satisfy any" mode would accept a request when ANY access
// check passes, and the gate passes every visitor it does not challenge: next
// to the gate, the list would stop applying to them. On challenge-mode hosts
// both must pass; elsewhere (e.g. next to ForwardAuth) "satisfy any" stays.
func TestChallengeGateDoesNotLoosenAccessLists(t *testing.T) {
	al := &model.AccessList{ID: "00000000-0000-0000-0000-0000000000ac", Name: "lan", SatisfyAny: true,
		Items: []model.AccessListItem{{ID: "00000000-0000-0000-0000-0000000000ad", Directive: "allow", Address: "192.0.2.0/24", SortOrder: 1}}}
	for _, mode := range gateTLSModes {
		h := gateTestHost("00000000-0000-0000-0000-0000000000e9", mode.ssl, mode.force, "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n")
		challenge := renderForTest(t, ProxyHostConfigData{Host: h, GeoRestriction: geoChallenge(false), AccessList: al})
		if strings.Contains(challenge, "satisfy any;") {
			t.Errorf("%s: challenge-mode host renders \"satisfy any\" next to the gate", mode.name)
		}
		if !strings.Contains(challenge, "allow 192.0.2.0/24;") || !strings.Contains(challenge, "deny all;") {
			t.Errorf("%s: access list not rendered", mode.name)
		}
		plain := renderForTest(t, ProxyHostConfigData{Host: h, AccessList: al})
		if !strings.Contains(plain, "    satisfy any;") {
			t.Errorf("%s: \"satisfy any\" lost on a host without the challenge", mode.name)
		}
	}
}

// directives returns the directive lines of a location block: trimmed, without
// the header, the closing brace, comments and blank lines.
func directives(block string) []string {
	var out []string
	lines := strings.Split(block, "\n")
	for _, l := range lines[1 : len(lines)-1] {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// The challenge page is NPG's answer to a request that was already logged (the
// 302 carrying block_reason). Every server block that serves the challenge
// endpoints gets an exact-match page location that is not access-logged and
// otherwise proxies exactly like the prefix location; verify, verify-redirect
// and favicon stay logged.
func TestChallengePageIsNotAccessLogged(t *testing.T) {
	cases := []struct {
		name string
		data ProxyHostConfigData
	}{
		{"cloud ssl", ProxyHostConfigData{Host: gateTestHost("00000000-0000-0000-0000-0000000000e5", true, true, ""),
			BlockedCloudIPRanges: []string{"198.51.100.0/24"}, CloudProviderChallengeMode: true}},
	}
	for _, mode := range gateTLSModes {
		cases = append(cases, struct {
			name string
			data ProxyHostConfigData
		}{"geo " + mode.name, ProxyHostConfigData{Host: gateTestHost("00000000-0000-0000-0000-0000000000e2", mode.ssl, mode.force, ""),
			GeoRestriction: geoChallenge(false)}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := 0
			for i, b := range splitServerBlocks(t, renderForTest(t, tc.data)) {
				prefix := blockAt(b, "location /api/v1/challenge/ {")
				if prefix == "" {
					continue
				}
				seen++
				page := blockAt(b, "location = /api/v1/challenge/page {")
				if page == "" {
					t.Fatalf("server %d serves /api/v1/challenge/ without the unlogged page location", i)
				}
				if strings.Contains(prefix, "access_log") {
					t.Errorf("server %d: verify and favicon are no longer logged:\n%s", i, prefix)
				}
				// Same directives as the prefix location, plus access_log off.
				want := []string{"access_log off;"}
				for _, d := range directives(prefix) {
					want = append(want, strings.Replace(d, "/api/v1/challenge/;", "/api/v1/challenge/page;", 1))
				}
				if got := directives(page); strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("server %d: page location\n%s\nwant\n%s", i, strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
			}
			if seen == 0 {
				t.Fatal("no server block serves the challenge endpoints")
			}
		})
	}
}
