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

// The default trust set must keep #254's behavior: npg-proxy runs in host
// network mode, so proxied panel traffic reaches the API from the HOST's LAN
// address. Skipping that hop and reading the appended client from XFF is what
// keeps every panel user from sharing one login-lockout key.
func TestBuildIPExtractor_DefaultTrustsPrivateHops(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDR", "")

	// host-network nginx (LAN address) forwarding an internet client; a forged
	// entry sits further left and must never be reached.
	if got := extractFor(t, "192.168.1.203:44444", "6.6.6.6, 203.0.113.50"); got != "203.0.113.50" {
		t.Errorf("expected the appended client, got %s", got)
	}
	// docker-bridge UI nginx forwarding a LAN client: the client is private, so
	// the walk trusts its hop too and reads what it supplied — the documented
	// limit of the default. Pinned so a change here is a decision, not a drift.
	if got := extractFor(t, "172.18.0.1:44444", "10.9.9.9, 192.168.1.50"); got != "10.9.9.9" {
		t.Errorf("expected the documented spoofable-from-LAN behavior, got %s", got)
	}
}

// With TRUSTED_PROXY_CIDR set, only loopback and the listed ranges count as
// proxy hops. A private caller outside them is the client, whatever it sends.
func TestBuildIPExtractor_CIDRRestrictsTrust(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDR", "172.16.0.0/12, 192.168.1.203/32")

	// trusted host-network proxy hop -> appended client wins
	if got := extractFor(t, "192.168.1.203:44444", "6.6.6.6, 203.0.113.50"); got != "203.0.113.50" {
		t.Errorf("expected the appended client, got %s", got)
	}
	// a LAN machine that is NOT the proxy: its XFF is now ignored
	if got := extractFor(t, "192.168.1.50:44444", "6.6.6.6"); got != "192.168.1.50" {
		t.Errorf("expected the peer itself, got %s", got)
	}
	// and a chain it forges past the proxy is cut at the untrusted hop
	if got := extractFor(t, "192.168.1.203:44444", "6.6.6.6, 192.168.1.50"); got != "192.168.1.50" {
		t.Errorf("expected the first untrusted hop, got %s", got)
	}
}

// A malformed value must not fail closed into loopback-only: that would hand
// the proxy's own address to every client and share one lockout key — the
// exact #254 failure. Keep the default instead and say so in the log.
func TestBuildIPExtractor_InvalidCIDRKeepsDefault(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDR", "not-a-cidr")

	if got := extractFor(t, "192.168.1.203:44444", "6.6.6.6, 203.0.113.50"); got != "203.0.113.50" {
		t.Errorf("expected default behavior on unusable config, got %s", got)
	}
}
