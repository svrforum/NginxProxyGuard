package bootstrap

import (
	"net/http"
	"testing"
)

func extractFor(t *testing.T, remoteAddr, xff string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return buildIPExtractor()(req)
}

// A private peer is a client unless explicitly configured as a proxy.
func TestBuildIPExtractor_DefaultRejectsPrivateHops(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDR", "")

	if got := extractFor(t, "192.168.77.203:44444", "6.6.6.6, 203.0.113.50"); got != "192.168.77.203" {
		t.Errorf("expected the peer, got %s", got)
	}
	if got := extractFor(t, "172.18.0.1:44444", "10.9.9.9, 192.168.77.50"); got != "172.18.0.1" {
		t.Errorf("expected the bridge peer, got %s", got)
	}
}

// With TRUSTED_PROXY_CIDR set, only loopback and the listed ranges count as
// proxy hops. A private caller outside them is the client, whatever it sends.
func TestBuildIPExtractor_CIDRRestrictsTrust(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDR", "172.16.0.0/12, 192.168.77.203/32")

	// trusted host-network proxy hop -> appended client wins
	if got := extractFor(t, "192.168.77.203:44444", "6.6.6.6, 203.0.113.50"); got != "203.0.113.50" {
		t.Errorf("expected the appended client, got %s", got)
	}
	// a LAN machine that is NOT the proxy: its XFF is now ignored
	if got := extractFor(t, "192.168.77.50:44444", "6.6.6.6"); got != "192.168.77.50" {
		t.Errorf("expected the peer itself, got %s", got)
	}
	// and a chain it forges past the proxy is cut at the untrusted hop
	if got := extractFor(t, "192.168.77.203:44444", "6.6.6.6, 192.168.77.50"); got != "192.168.77.50" {
		t.Errorf("expected the first untrusted hop, got %s", got)
	}
}

func TestBuildIPExtractor_InvalidCIDRKeepsSafeDefault(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDR", "not-a-cidr")

	if got := extractFor(t, "192.168.77.203:44444", "6.6.6.6, 203.0.113.50"); got != "192.168.77.203" {
		t.Errorf("expected default behavior on unusable config, got %s", got)
	}
}
