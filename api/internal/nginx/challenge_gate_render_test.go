package nginx

import (
	"bytes"
	"context"
	"log"
	"os"
	"slices"
	"strconv"
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

// cloudChallenge sets the cloud provider challenge the way the service does:
// challenge mode together with the blocked providers' ranges.
func cloudChallenge(d *ProxyHostConfigData) {
	d.BlockedCloudIPRanges, d.CloudProviderChallengeMode = []string{"198.51.100.0/24"}, true
}

// The challenges that put a host behind the gate: the geo challenge, the
// cloud provider challenge, and both on one host.
var gateChallenges = []struct {
	name  string
	cloud bool
	set   func(*ProxyHostConfigData)
}{
	{"geo", false, func(d *ProxyHostConfigData) { d.GeoRestriction = geoChallenge(false) }},
	{"cloud", true, cloudChallenge},
	{"geo+cloud", true, func(d *ProxyHostConfigData) { d.GeoRestriction = geoChallenge(false); cloudChallenge(d) }},
}

// challengeData returns the template data of a host behind the given challenge.
func challengeData(h *model.ProxyHost, set func(*ProxyHostConfigData)) ProxyHostConfigData {
	d := ProxyHostConfigData{Host: h}
	set(&d)
	return d
}

// nginx makes the challenge decision and the API only checks tokens. The gate
// answers 204 for a visitor it does not challenge (no API round-trip) and 401
// for a challenged visitor without a token. It never reads $is_search_bot
// (_security already cleared $geo_blocked for the search bots a host allows),
// and it tells the API "challenged" with a constant, so no header the client
// sends can say otherwise. With the cloud provider challenge, a visitor is
// let through only when neither challenge applies: $geo_blocked is 0 for a
// visitor from a challenged cloud range too.
func TestChallengeGateDecidesLocally(t *testing.T) {
	for _, ch := range gateChallenges {
		for _, mode := range gateTLSModes {
			t.Run(ch.name+" "+mode.name, func(t *testing.T) {
				d := challengeData(gateTestHost("00000000-0000-0000-0000-0000000000e1", mode.ssl, mode.force, ""), ch.set)
				if d.GeoRestriction != nil {
					d.GeoRestriction.AllowSearchBots = true
				}
				d.SearchEnginesList = "Googlebot"
				notChallenged := "if ($geo_blocked = 0) {\n            return 204;"
				bad := []string{"$is_search_bot", "X-Geo-Blocked $geo_blocked", "$challenge_gate"}
				if ch.cloud {
					notChallenged = "set $challenge_needed \"${geo_blocked}${cloud_challenge}\";\n        if ($challenge_needed = \"00\") {\n            return 204;"
					bad = append(bad, "if ($geo_blocked = 0)")
				}
				for i, b := range splitServerBlocks(t, renderForTest(t, d)) {
					gate := blockAt(b, "location = /_challenge/validate {")
					if gate == "" {
						t.Errorf("server %d: no challenge gate", i)
						continue
					}
					for _, want := range []string{
						notChallenged,
						"if ($cookie_ng_challenge = \"\") {\n            return 401;",
						"proxy_pass http://127.0.0.1:9080/api/v1/challenge/validate;",
						"proxy_set_header X-Geo-Blocked 1;",
						// A server-level "error_page 401" must not reach the subrequest:
						// it would turn the 401 into a 302, auth_request would answer
						// 500, and location /'s @api_fallback would let the visitor in.
						"error_page 401 = @challenge_gate_deny;",
					} {
						if !strings.Contains(gate, want) {
							t.Errorf("server %d: gate lacks %q:\n%s", i, want, gate)
						}
					}
					for _, bad := range bad {
						if strings.Contains(gate, bad) {
							t.Errorf("server %d: gate uses %q:\n%s", i, bad, gate)
						}
					}
					if deny := blockAt(b, "location @challenge_gate_deny {"); !strings.Contains(deny, "return 401;") {
						t.Errorf("server %d: @challenge_gate_deny missing or not a plain 401: %q", i, deny)
					}
				}
			})
		}
	}
}

// nginx asks the API about tokens through the internal gate, which proxies to
// the API directly. The public path is not needed by anyone, and answering it
// told any client whether a token was valid: every server block that serves
// the challenge endpoints answers it with 404 itself.
func TestPublicChallengeValidateAnswers404(t *testing.T) {
	for _, ch := range gateChallenges {
		for _, mode := range gateTLSModes {
			t.Run(ch.name+" "+mode.name, func(t *testing.T) {
				d := challengeData(gateTestHost("00000000-0000-0000-0000-0000000000e2", mode.ssl, mode.force, ""), ch.set)
				blocks := splitServerBlocks(t, renderForTest(t, d))
				for i, b := range blocks {
					// Every server block serves the challenge endpoints, the HTTP
					// block of an SSL host included: it is where a visitor's
					// http:// request lands.
					if blockAt(b, "location /api/v1/challenge/ {") == "" {
						t.Errorf("server %d of %d does not serve the challenge endpoints", i, len(blocks))
						continue
					}
					if v := blockAt(b, "location = /api/v1/challenge/validate {"); !strings.Contains(v, "return 404;") {
						t.Errorf("server %d proxies the public validate path to the API: %q", i, v)
					}
				}
			})
		}
	}
}

// Every location of a challenge-mode server sits behind the gate, locations
// from Advanced Config included, and gets the same token check as
// location /. NPG's own pass-through locations opt out.
func TestChallengeGateCoversCustomLocations(t *testing.T) {
	for _, ch := range gateChallenges {
		for _, adv := range []string{
			"",
			"location / {\n    proxy_pass http://192.0.2.20:8080;\n}\n",
			"location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n",
		} {
			for _, mode := range gateTLSModes {
				name := ch.name + " " + mode.name + " " + strings.SplitN(adv, " {", 2)[0]
				out := renderForTest(t, challengeData(gateTestHost("00000000-0000-0000-0000-0000000000e6", mode.ssl, mode.force, adv), ch.set))
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
						if root := blockAt(b, "location / {"); !strings.Contains(root, "error_page 500 = @api_fallback;") {
							t.Errorf("%s server %d: location / lost its API-down fallback", name, i)
						}
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
	for _, ch := range gateChallenges {
		out := renderForTest(t, challengeData(gateTestHost("00000000-0000-0000-0000-0000000000e8", true, false, "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n"), ch.set))
		notChallenged := "if ($geo_blocked = 0) {\n            return 401;"
		if ch.cloud {
			notChallenged = "set $challenge_needed \"${geo_blocked}${cloud_challenge}\";\n        if ($challenge_needed = \"00\") {\n            return 401;"
		}
		for i, b := range splitServerBlocks(t, out) {
			r := blockAt(b, "location @challenge_redirect {")
			for _, want := range []string{
				notChallenged,
				"set $challenge_refused 401;\n        if ($cookie_ng_challenge != \"\") {\n            set $challenge_refused $challenge_gate_status;",
				"if ($challenge_refused != 401) {\n            return 401;",
			} {
				if !strings.Contains(r, want) {
					t.Errorf("%s server %d: @challenge_redirect lacks %q:\n%s", ch.name, i, want, r)
				}
			}
			if strings.Index(r, "return 302") < strings.Index(r, "$challenge_refused != 401") {
				t.Errorf("%s server %d: @challenge_redirect redirects before checking who sent the 401:\n%s", ch.name, i, r)
			}
			if ch.cloud && strings.Contains(r, "if ($geo_blocked = 0)") {
				// A visitor challenged for a cloud range has $geo_blocked 0.
				t.Errorf("%s server %d: @challenge_redirect passes a cloud-challenged visitor's 401 on as a plain 401:\n%s", ch.name, i, r)
			}
		}
	}
}

// A visitor challenged for a cloud provider range is sent to the challenge
// page with reason=cloud_provider; one challenged by the geo restriction (on
// a host with both, too) with reason=geo_restriction. Hosts without the cloud
// challenge keep the single geo redirect.
func TestChallengeRedirectNamesTheReason(t *testing.T) {
	cloudRedirect := "if ($geo_blocked != 1) {\n            return 302 /api/v1/challenge/page?host=00000000-0000-0000-0000-0000000000ed&reason=cloud_provider&return="
	for _, ch := range gateChallenges {
		for _, mode := range gateTLSModes {
			out := renderForTest(t, challengeData(gateTestHost("00000000-0000-0000-0000-0000000000ed", mode.ssl, mode.force, ""), ch.set))
			for i, b := range splitServerBlocks(t, out) {
				r := blockAt(b, "location @challenge_redirect {")
				if mode.force && i == 0 {
					if r != "" {
						t.Errorf("%s %s: the redirecting HTTP server has @challenge_redirect", ch.name, mode.name)
					}
					continue
				}
				geo := strings.Index(r, "reason=geo_restriction&return=")
				cloud := strings.Index(r, cloudRedirect)
				if geo < 0 {
					t.Errorf("%s %s server %d: no geo_restriction redirect:\n%s", ch.name, mode.name, i, r)
				}
				if ch.cloud != (cloud >= 0) {
					t.Errorf("%s %s server %d: cloud_provider redirect rendered %v, want %v:\n%s", ch.name, mode.name, i, cloud >= 0, ch.cloud, r)
				}
				if cloud > geo {
					t.Errorf("%s %s server %d: the cloud_provider redirect comes after the unconditional geo one:\n%s", ch.name, mode.name, i, r)
				}
			}
		}
	}
}

// An access list in "satisfy any" mode would accept a request when ANY access
// check passes, and the gate passes every visitor it does not challenge: next
// to the gate, the list would stop applying to them. On challenge-mode hosts
// both must pass; elsewhere (e.g. next to ForwardAuth, where the cloud
// provider challenge blocks instead of using the gate) "satisfy any" stays.
func TestChallengeGateDoesNotLoosenAccessLists(t *testing.T) {
	al := &model.AccessList{ID: "00000000-0000-0000-0000-0000000000ac", Name: "lan", SatisfyAny: true,
		Items: []model.AccessListItem{{ID: "00000000-0000-0000-0000-0000000000ad", Directive: "allow", Address: "192.0.2.0/24", SortOrder: 1}}}
	for _, mode := range gateTLSModes {
		h := gateTestHost("00000000-0000-0000-0000-0000000000e9", mode.ssl, mode.force, "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n")
		for _, ch := range gateChallenges {
			d := challengeData(h, ch.set)
			d.AccessList = al
			challenge := renderForTest(t, d)
			if strings.Contains(challenge, "satisfy any;") {
				t.Errorf("%s %s: challenge-mode host renders \"satisfy any\" next to the gate", ch.name, mode.name)
			}
			if !strings.Contains(challenge, "allow 192.0.2.0/24;") || !strings.Contains(challenge, "deny all;") {
				t.Errorf("%s %s: access list not rendered", ch.name, mode.name)
			}
		}
		plain := renderForTest(t, ProxyHostConfigData{Host: h, AccessList: al})
		if !strings.Contains(plain, "    satisfy any;") {
			t.Errorf("%s: \"satisfy any\" lost on a host without the challenge", mode.name)
		}
		fa := challengeData(gateTestHost("00000000-0000-0000-0000-0000000000e9", mode.ssl, mode.force, ""), cloudChallenge)
		fa.AccessList = al
		fa.AuthProvider = &model.AuthProvider{Type: "authelia", ProviderURL: "http://192.0.2.40:9091", TimeoutMs: 2000, Enabled: true}
		if out := renderForTest(t, fa); !strings.Contains(out, "    satisfy any;") {
			t.Errorf("%s: \"satisfy any\" lost next to ForwardAuth on a host whose cloud challenge blocks", mode.name)
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
	type pageCase struct {
		name string
		data ProxyHostConfigData
	}
	var cases []pageCase
	for _, ch := range gateChallenges {
		for _, mode := range gateTLSModes {
			cases = append(cases, pageCase{ch.name + " " + mode.name,
				challengeData(gateTestHost("00000000-0000-0000-0000-0000000000e2", mode.ssl, mode.force, ""), ch.set)})
		}
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

// serverLevel returns the directives named name that sit directly in the
// server block (not in a location or other nested block), trimmed.
func serverLevel(serverBlock, name string) []string {
	var out []string
	depth := 0
	for _, l := range strings.Split(serverBlock, "\n") {
		t := strings.TrimSpace(l)
		if depth == 1 && strings.HasPrefix(t, name+" ") {
			out = append(out, t)
		}
		depth += strings.Count(t, "{") - strings.Count(t, "}")
	}
	return out
}

// A legacy Advanced Config can still hold an auth_request of its own for the
// whole server: refused when saving since v2.25.0, but kept by hosts saved
// before and by restored backups. A block takes one auth_request, so next to
// the challenge's server-level gate nginx -t failed and the boot sync dropped
// the host. Such a host keeps the gate in location / only; an auth_request
// inside a location, or in a comment, leaves the server-level gate in place.
func TestChallengeGateYieldsToAdvancedConfigAuthRequest(t *testing.T) {
	ext := "location = /ext {\n    internal;\n    proxy_pass http://192.0.2.20:9000/auth;\n}\n"
	app := "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n"
	for _, tc := range []struct {
		name, adv  string
		own        string // the Advanced Config's server-level auth_request, "" if none
		customRoot bool
	}{
		{"server level", "auth_request /ext;\n" + app + ext, "auth_request /ext;", false},
		{"server level off", "auth_request off;\n" + app, "auth_request off;", false},
		{"custom location /", "auth_request /ext;\nlocation / {\n    proxy_pass http://192.0.2.20:8080;\n}\n" + ext, "auth_request /ext;", true},
		{"inside a location", "location /app/ {\n    auth_request /ext;\n    proxy_pass http://192.0.2.20:8080;\n}\n" + ext, "", false},
		{"commented out", "# auth_request /ext;\n" + app, "", false},
	} {
		for _, mode := range gateTLSModes {
			name := tc.name + " " + mode.name
			out := renderForTest(t, ProxyHostConfigData{
				Host:           gateTestHost("00000000-0000-0000-0000-0000000000ea", mode.ssl, mode.force, tc.adv),
				GeoRestriction: geoChallenge(false),
			})
			for i, b := range splitServerBlocks(t, out) {
				if mode.force && i == 0 {
					continue // redirects everything but ACME and the challenge endpoints
				}
				auth := serverLevel(b, "auth_request")
				if tc.own == "" {
					if len(auth) != 1 || auth[0] != "auth_request /_challenge/validate;" {
						t.Errorf("%s server %d: server-level auth_request %q, want only the gate", name, i, auth)
					}
					continue
				}
				if len(auth) != 1 || auth[0] != tc.own {
					t.Errorf("%s server %d: server-level auth_request %q, want only the host's own %q", name, i, auth, tc.own)
				}
				if ep := serverLevel(b, "error_page"); slices.Contains(ep, "error_page 401 = @challenge_redirect;") {
					t.Errorf("%s server %d: the gate's error_page 401 is still set for the whole server", name, i)
				}
				// @challenge_redirect reads $challenge_gate_status: still declared.
				if set := serverLevel(b, "auth_request_set"); !slices.Equal(set, []string{"auth_request_set $challenge_gate_status $upstream_status;"}) {
					t.Errorf("%s server %d: server-level auth_request_set %q", name, i, set)
				}
				if tc.customRoot {
					continue // no location / of NPG's own to keep the gate in
				}
				root := blockAt(b, "location / {")
				for _, want := range []string{
					"auth_request /_challenge/validate;",
					"error_page 401 = @challenge_redirect;",
					"error_page 500 = @api_fallback;",
				} {
					if !strings.Contains(root, want) {
						t.Errorf("%s server %d: location / lacks %q", name, i, want)
					}
				}
			}
		}
	}
}

func TestAdvancedConfigHasTopLevel(t *testing.T) {
	for _, tc := range []struct {
		cfg  string
		want bool
	}{
		{"auth_request /ext;", true},
		{"  auth_request off;\n", true},
		{"proxy_set_header X-A b; auth_request /ext;", true},
		{"location /a/ {\n    auth_request /ext;\n}\n", false},
		{"location /a/ { proxy_pass http://192.0.2.1; }\nauth_request /ext;", true},
		{"if ($x) {\n    auth_request /ext;\n}", false},
		{"auth_request_set $a $upstream_status;", false},
		{"# auth_request /ext;\nclient_max_body_size 1m;", false},
		{"add_header X-Note \"auth_request /x;\";", false},
		{"add_header X-Note 'a { b'; auth_request /ext;", true},
		{"", false},
	} {
		if got := advancedConfigHasTopLevel(tc.cfg, "auth_request"); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

// The warning names each host once per process, not at every regeneration.
func TestAdvancedConfigAuthRequestWarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	m, _ := newRequestPathTestManager(t)
	h := gateTestHost("00000000-0000-0000-0000-0000000000eb", false, false, "auth_request /ext;\nlocation = /ext {\n    internal;\n    proxy_pass http://192.0.2.20:9000/auth;\n}\n")
	advancedAuthRequestWarned.Delete(h.ID) // -count > 1
	for i := 0; i < 3; i++ {
		if err := m.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: h, GeoRestriction: geoChallenge(false)}); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), h.ID); n != 1 {
		t.Fatalf("host named %d times, want once:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "auth provider (ForwardAuth)") {
		t.Errorf("the warning does not say what to do instead:\n%s", buf.String())
	}
}

// The gate refuses on any answer from a running API other than a valid token.
// auth_request turns a status other than 2xx, 401 and 403 into a 500, and
// location / sends a 500 to @api_fallback, the pass-through for an API that
// cannot be reached: a request header the API rejects (400) or its rate limit
// (429) let a challenged visitor through. The gate intercepts the API's errors
// and refuses; only an unreachable or slow API (502, 503, 504) still reaches
// location /'s fallback. Every gate: HTTP and HTTPS server blocks, with and
// without locations from Advanced Config.
func TestChallengeGateRefusesWhenTheAPIRefuses(t *testing.T) {
	denyCodes := func(gate string) map[string]bool {
		codes := map[string]bool{}
		for _, d := range directives(gate) {
			if f := strings.Fields(strings.TrimSuffix(d, ";")); len(f) > 3 && f[0] == "error_page" && f[len(f)-1] == "@challenge_gate_deny" {
				for _, c := range f[1 : len(f)-2] {
					codes[c] = true
				}
			}
		}
		return codes
	}
	for _, ch := range gateChallenges {
		for _, adv := range []string{
			"",
			"location / {\n    proxy_pass http://192.0.2.20:8080;\n}\n",
			"auth_request /ext;\nlocation = /ext {\n    internal;\n    proxy_pass http://192.0.2.20:9000/auth;\n}\n",
		} {
			if ch.name == "cloud" && strings.HasPrefix(adv, "auth_request") {
				continue // no gate: next to the host's own auth_request the cloud challenge blocks
			}
			for _, mode := range gateTLSModes {
				name := ch.name + " " + mode.name + " " + strings.SplitN(adv, "\n", 2)[0]
				out := renderForTest(t, challengeData(gateTestHost("00000000-0000-0000-0000-0000000000ec", mode.ssl, mode.force, adv), ch.set))
				for i, b := range splitServerBlocks(t, out) {
					gate := blockAt(b, "location = /_challenge/validate {")
					if gate == "" {
						t.Errorf("%s server %d: no challenge gate", name, i)
						continue
					}
					if !slices.Contains(directives(gate), "proxy_intercept_errors on;") {
						t.Errorf("%s server %d: the gate passes the API's errors on to auth_request:\n%s", name, i, gate)
					}
					codes := denyCodes(gate)
					for _, c := range []string{"400", "401", "404", "405", "408", "413", "429", "431", "500"} {
						if !codes[c] {
							t.Errorf("%s server %d: an API %s does not refuse at the gate", name, i, c)
						}
					}
					for _, c := range []string{"502", "503", "504"} {
						if codes[c] {
							t.Errorf("%s server %d: an unreachable API (%s) refuses at the gate; location / must keep its fallback", name, i, c)
						}
					}
					if root := blockAt(b, "location / {"); root != "" && adv == "" && !strings.Contains(root, "error_page 500 = @api_fallback;") {
						t.Errorf("%s server %d: location / lost its fallback for an unreachable API", name, i)
					}
				}
			}
		}
	}
}

// errorPageTargets maps each status code to the target of the first
// error_page naming it, the one nginx uses ("= @api_fallback", "@blocked",
// "/error_503.html").
func errorPageTargets(dirs []string) map[string]string {
	targets := map[string]string{}
	for _, d := range dirs {
		f := strings.Fields(strings.TrimSuffix(d, ";"))
		if len(f) < 3 || f[0] != "error_page" {
			continue
		}
		n := 1
		for n < len(f) && strings.Trim(f[n], "0123456789") == "" {
			n++
		}
		for _, code := range f[1:n] {
			if _, seen := targets[code]; !seen {
				targets[code] = strings.Join(f[n:], " ")
			}
		}
	}
	return targets
}

// @api_fallback passes a request to the upstream without the gate. It is
// for the gate's own failure only: auth_request answers 500 when the API
// cannot be reached or does not answer in time. location / used to send 502,
// 503 and 504 there too, and the rate limit and the connection limit answer
// 503 before the gate runs: a challenged visitor without a token who went
// over a 503 rate limit, or over the global connection limit, was served by
// the upstream. location / sends nothing but 500 there and keeps every other
// error page the server sets (an error_page in a location replaces all of
// the server's); @api_fallback refuses a 500 the gate did not cause.
func TestChallengeFallbackOnlyForTheGatesFailure(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	var common []string
	for _, l := range strings.Split(string(m.hostCommonIncludeContent()), "\n") {
		if strings.HasPrefix(l, "error_page ") {
			common = append(common, l)
		}
	}
	if len(common) == 0 {
		t.Fatal("host_common.conf sets no error_page; this test guards nothing")
	}
	rateLimit := func(code int) func(*ProxyHostConfigData) {
		return func(d *ProxyHostConfigData) {
			d.RateLimit = &model.RateLimit{Enabled: true, RequestsPerSecond: 1, BurstSize: 1, ZoneSize: "10m", LimitBy: "ip", LimitResponse: code}
		}
	}
	exploitRule := func(patternType, pattern string) func(*ProxyHostConfigData) {
		return func(d *ProxyHostConfigData) {
			d.Host.BlockExploits = true
			d.ExploitBlockRules = []model.ExploitBlockRuleForRender{{ExploitBlockRule: model.ExploitBlockRule{
				ID: "00000000-0000-0000-0000-0000000000f1", Name: "rule", Pattern: pattern, PatternType: patternType, Enabled: true},
				IDSanitized: "00000000_0000_0000_0000_0000000000f1"}}
		}
	}
	for _, v := range []struct {
		name, adv string
		set       func(*ProxyHostConfigData)
	}{
		{"plain", "", func(*ProxyHostConfigData) {}},
		{"rate limit 503", "", rateLimit(503)},
		{"rate limit 429", "", rateLimit(429)},
		{"exploit fallback rules", "", func(d *ProxyHostConfigData) { d.Host.BlockExploits = true }},
		{"exploit method rules", "", exploitRule("request_method", "^TRACE$")},
		// No method rule: no @blocked_method, which location / must not name.
		{"exploit query rules", "", exploitRule("query_string", "union.*select")},
		{"legacy auth_request, rate limit 503", "auth_request /ext;\nlocation = /ext {\n    internal;\n    proxy_pass http://192.0.2.20:9000/auth;\n}\n", rateLimit(503)},
	} {
		for _, ch := range gateChallenges {
			if ch.cloud && v.adv != "" {
				continue // no gate: next to the host's own auth_request the cloud challenge blocks
			}
			for _, mode := range gateTLSModes {
				name := v.name + " " + ch.name + " " + mode.name
				d := challengeData(gateTestHost("00000000-0000-0000-0000-0000000000f0", mode.ssl, mode.force, v.adv), ch.set)
				v.set(&d)
				seen := 0
				for i, b := range splitServerBlocks(t, renderForTest(t, d)) {
					if fb := blockAt(b, "location @api_fallback {"); !strings.Contains(fb, "if ($challenge_gate_status = \"\") {\n            return 500;\n        }") ||
						strings.Index(fb, "$challenge_gate_status") > strings.Index(fb, "proxy_pass ") {
						t.Errorf("%s server %d: @api_fallback passes on a 500 the gate did not cause:\n%s", name, i, fb)
					}
					root := blockAt(b, "location / {")
					if !strings.Contains(root, "auth_request /_challenge/validate;") {
						continue // the HTTP server of a forced-HTTPS host redirects
					}
					seen++
					got := errorPageTargets(directives(root))
					for code, target := range got {
						if target == "= @api_fallback" && code != "500" {
							t.Errorf("%s server %d: location / sends %s to @api_fallback, which skips the gate", name, i, code)
						}
					}
					if got["500"] != "= @api_fallback" || got["401"] != "= @challenge_redirect" {
						t.Errorf("%s server %d: location / gate errors: 401 -> %q, 500 -> %q", name, i, got["401"], got["500"])
					}
					// Every error page the server sets (host_common.conf is
					// included before the server's own) reaches location / too,
					// and no other: a page the server does not have is a
					// location that does not exist.
					want := errorPageTargets(append(append([]string{}, common...), serverLevel(b, "error_page")...))
					codes := map[string]bool{}
					for code := range got {
						codes[code] = true
					}
					for code := range want {
						codes[code] = true
					}
					for code := range codes {
						if code != "401" && code != "500" && got[code] != want[code] {
							t.Errorf("%s server %d: location / answers %s with %q, the server with %q", name, i, code, got[code], want[code])
						}
					}
					if d.RateLimit != nil && want[strconv.Itoa(d.RateLimit.LimitResponse)] == "" {
						t.Errorf("%s server %d: the rate limit's %d has no error page; this case guards nothing", name, i, d.RateLimit.LimitResponse)
					}
				}
				if seen == 0 {
					t.Errorf("%s: no location / behind the gate", name)
				}
			}
		}
	}
}

// The cloud provider challenge goes through the same gate as the geo
// challenge. It used to return a rewrite-phase 418 that sent every visitor
// from a challenged range to the challenge page: a solved challenge was never
// honoured, ModSecurity's phase 2 never saw those requests, and on a host
// without SSL the challenge page was passed to the protected upstream.
// _security now only marks the request, every server block serves the
// challenge endpoints, and the gate checks the token in the access phase,
// after ModSecurity.
func TestCloudChallengeUsesTheGate(t *testing.T) {
	mark := "    set $cloud_challenge 0;\n    if ($cloud_block_check_00000000_0000_0000_0000_0000000000ee = \"10\") {\n" +
		"        set $cloud_challenge 1;\n        set $block_reason_var \"cloud_provider_challenge\";\n    }\n"
	for _, mode := range gateTLSModes {
		for _, cache := range []bool{false, true} {
			name := mode.name
			if cache {
				name += " cache"
			}
			h := gateTestHost("00000000-0000-0000-0000-0000000000ee", mode.ssl, mode.force, "")
			h.CacheEnabled = cache
			h.WAFEnabled, h.WAFMode = true, "blocking"
			out := renderForTest(t, challengeData(h, cloudChallenge))
			for _, bad := range []string{"return 418", "error_page 418", "@cloud_challenge"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s: still renders %q", name, bad)
				}
			}
			for i, b := range splitServerBlocks(t, out) {
				if !strings.Contains(b, mark) {
					t.Errorf("%s server %d: the cloud check does not just mark the request:\n%s", name, i,
						blockAt(b, "if ($cloud_block_check_00000000_0000_0000_0000_0000000000ee"))
				}
				// The challenge page is NPG's own, in every server block.
				if page := blockAt(b, "location = /api/v1/challenge/page {"); !strings.Contains(page, "proxy_pass http://127.0.0.1:9080/api/v1/challenge/page;") {
					t.Errorf("%s server %d: the challenge page is not proxied to the API: %q", name, i, page)
				}
				if mode.force && i == 0 {
					continue // redirects everything but ACME and the challenge endpoints
				}
				if !slices.Contains(serverLevel(b, "auth_request"), "auth_request /_challenge/validate;") {
					t.Errorf("%s server %d: no server-level challenge gate", name, i)
				}
				if root := blockAt(b, "location / {"); !strings.Contains(root, "auth_request /_challenge/validate;") {
					t.Errorf("%s server %d: location / is not behind the gate", name, i)
				}
				if !strings.Contains(blockAt(b, "location @challenge_redirect {"), "reason=cloud_provider") {
					t.Errorf("%s server %d: @challenge_redirect does not send reason=cloud_provider", name, i)
				}
			}
		}
	}
}

// A location takes one auth_request. Where the host has one of its own - an
// auth provider (ForwardAuth) in location /, or one left at the top level of
// a legacy Advanced Config (refused when saving since v2.25.0), for the whole
// server or rendered into location / itself - the gate cannot go next to it
// without replacing that login or failing nginx -t. There the cloud provider
// challenge blocks (403) instead, as it did for visitors who could never get
// past it before. An auth_request inside a custom location, or a commented
// one, leaves the gate in place.
func TestCloudChallengeBlocksNextToItsOwnAuthRequest(t *testing.T) {
	ext := "location = /ext {\n    internal;\n    proxy_pass http://192.0.2.20:9000/auth;\n}\n"
	app := "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\n"
	for _, tc := range []struct {
		name     string
		adv      string
		provider bool
		block    bool
	}{
		{"auth provider", "", true, true},
		{"advanced config, whole server", "auth_request /ext;\n" + app + ext, false, true},
		{"advanced config, custom location /", "auth_request /ext;\nlocation / {\n    proxy_pass http://192.0.2.20:8080;\n}\n" + ext, false, true},
		{"advanced config, rendered into location /", "auth_request /ext;\nclient_max_body_size 10m;", false, true},
		{"advanced config, inside a location", "location /app/ {\n    auth_request /ext;\n    proxy_pass http://192.0.2.20:8080;\n}\n" + ext, false, false},
		{"advanced config, commented out", "# auth_request /ext;\n" + app, false, false},
	} {
		for _, mode := range gateTLSModes {
			name := tc.name + " " + mode.name
			d := challengeData(gateTestHost("00000000-0000-0000-0000-0000000000ef", mode.ssl, mode.force, tc.adv), cloudChallenge)
			if tc.provider {
				d.AuthProvider = &model.AuthProvider{Type: "authelia", ProviderURL: "http://192.0.2.40:9091", TimeoutMs: 2000, Enabled: true}
			}
			out := renderForTest(t, d)
			blocks := strings.Contains(out, "set $block_reason_var \"cloud_provider_block\";\n        return 403;")
			gated := strings.Contains(out, "location = /_challenge/validate {")
			if blocks != tc.block || gated == tc.block {
				t.Errorf("%s: blocks %v and renders the gate %v; want blocking %v", name, blocks, gated, tc.block)
			}
			if tc.block && strings.Contains(out, "$cloud_challenge") {
				t.Errorf("%s: blocks but still marks $cloud_challenge", name)
			}
			for i, b := range splitServerBlocks(t, out) {
				if n := len(serverLevel(b, "auth_request")); n > 1 {
					t.Errorf("%s server %d: %d server-level auth_request", name, i, n)
				}
				if n := strings.Count(blockAt(b, "location / {"), "\n        auth_request "); n > 1 {
					t.Errorf("%s server %d: %d auth_request in location /", name, i, n)
				}
			}
		}
	}

	// Geo and cloud challenge next to a legacy server-wide auth_request: the
	// geo challenge keeps its gate in location / (as before), the cloud
	// challenge blocks.
	d := challengeData(gateTestHost("00000000-0000-0000-0000-0000000000ef", true, false, "auth_request /ext;\n"+app+ext), cloudChallenge)
	d.GeoRestriction = geoChallenge(false)
	out := renderForTest(t, d)
	if !strings.Contains(out, "set $block_reason_var \"cloud_provider_block\";\n        return 403;") || strings.Contains(out, "$cloud_challenge") {
		t.Error("geo+cloud next to a legacy auth_request: the cloud challenge does not block")
	}
	for i, b := range splitServerBlocks(t, out) {
		if !strings.Contains(blockAt(b, "location / {"), "auth_request /_challenge/validate;") {
			t.Errorf("geo+cloud next to a legacy auth_request, server %d: location / lost the geo gate", i)
		}
	}
}
