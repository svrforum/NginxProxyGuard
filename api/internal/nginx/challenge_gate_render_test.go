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
