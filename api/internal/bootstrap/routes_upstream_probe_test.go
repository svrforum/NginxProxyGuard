package bootstrap

import (
	"net/http"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// POST /test/proxy-host/:id, the list's health dot, probes this URL. An IPv6
// forward host must come out bracketed exactly once: net/url rejects both
// "http://2001:db8::1:8080" and "http://[[2001:db8::1]]:8080", and a host
// stored in brackets by an older version is the second case. (#314)
func TestUpstreamProbeURL(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		host   string
		port   int
		want   string
	}{
		{"http", "2001:db8::1", 8080, "http://[2001:db8::1]:8080"},
		{"http", "[2001:db8::1]", 8080, "http://[2001:db8::1]:8080"},
		{"https", "192.0.2.10", 8443, "https://192.0.2.10:8443"},
		{"http", "backend.example.com", 80, "http://backend.example.com:80"},
	} {
		got := upstreamProbeURL(&model.ProxyHost{ForwardScheme: tc.scheme, ForwardHost: tc.host, ForwardPort: tc.port})
		if got != tc.want {
			t.Errorf("upstreamProbeURL(%q) = %q, want %q", tc.host, got, tc.want)
		}
		if _, err := http.NewRequest(http.MethodHead, got, nil); err != nil {
			t.Errorf("upstreamProbeURL(%q) = %q, not a usable URL: %v", tc.host, got, err)
		}
	}
}

// The API container's default network has IPv6 disabled, so a direct probe of
// any IPv6 upstream fails with "network unreachable". Those are retried from
// the host-network nginx container like a private IPv4 address; a public IPv4
// address or a hostname is not. (#314)
func TestProbeUpstreamFromNginx(t *testing.T) {
	for host, want := range map[string]bool{
		"2001:db8::1":         true,
		"[2001:db8::1]":       true,
		"::1":                 true,
		"172.18.0.2":          true,
		"192.0.2.10":          false,
		"::ffff:192.0.2.10":   false,
		"backend.example.com": false,
		"":                    false,
	} {
		if got := probeUpstreamFromNginx(host); got != want {
			t.Errorf("probeUpstreamFromNginx(%q) = %v, want %v", host, got, want)
		}
	}
}
