package model

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNormalizeRealIPHeader(t *testing.T) {
	// Empty must resolve, not error: a row written before the column existed
	// holds "", and erroring there would block every settings save.
	if got, err := NormalizeRealIPHeader(""); err != nil || got != RealIPHeaderDefault {
		t.Fatalf(`NormalizeRealIPHeader(""): got %q, %v; want %q, nil`, got, err, RealIPHeaderDefault)
	}
	if got, err := NormalizeRealIPHeader("  cf-connecting-ip  "); err != nil || got != "CF-Connecting-IP" {
		t.Fatalf("case/space normalization: got %q, %v", got, err)
	}
	// The value lands inside an nginx directive, so anything outside the
	// allowlist is a config-injection vector.
	for _, bad := range []string{"X-Evil", "X-Forwarded-For; return 200", "Host\nreal_ip_header X-Real-IP"} {
		if _, err := NormalizeRealIPHeader(bad); err == nil {
			t.Errorf("header %q should be rejected", bad)
		} else if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("header %q: error does not wrap ErrInvalidInput", bad)
		}
	}
}

func TestNormalizeTrustedProxyPreset(t *testing.T) {
	if got, err := NormalizeTrustedProxyPreset(""); err != nil || got != TrustedProxyPresetNone {
		t.Fatalf(`empty preset: got %q, %v; want %q, nil`, got, err, TrustedProxyPresetNone)
	}
	if got, err := NormalizeTrustedProxyPreset("CloudFlare"); err != nil || got != TrustedProxyPresetCloudflare {
		t.Fatalf("case normalization: got %q, %v", got, err)
	}
	if _, err := NormalizeTrustedProxyPreset("fastly"); err == nil {
		t.Error("unknown preset should be rejected")
	}
}

func TestValidateTrustedProxyCIDRs(t *testing.T) {
	if err := ValidateTrustedProxyCIDRs(""); err != nil {
		t.Fatalf("empty list must be valid (it clears the setting): %v", err)
	}
	valid := "203.0.113.0/24\n# a comment\n198.51.100.7\n2001:db8::/32"
	if err := ValidateTrustedProxyCIDRs(valid); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}

	// The whole Cloudflare preset must pass its own validator, or turning the
	// preset on would produce a list the operator cannot then edit and save.
	if err := ValidateTrustedProxyCIDRs(strings.Join(CloudflareRanges, "\n")); err != nil {
		t.Fatalf("shipped Cloudflare ranges fail validation: %v", err)
	}

	for _, bad := range []string{"not-an-ip", "203.0.113.0/33", "203.0.113.0/", "10.0.0.1/8/8"} {
		if err := ValidateTrustedProxyCIDRs(bad); err == nil {
			t.Errorf("entry %q should be rejected", bad)
		}
	}

	// Trusting everything is the one shape that makes the header forgeable by
	// anyone who can reach the box. ::/1 matters as much as ::/0 — rejecting
	// only the literal catch-all would wave through half the address space.
	for _, bad := range []string{"0.0.0.0/0", "::/0", "::/1", "2000::/3", "2606:4700::/16"} {
		if err := ValidateTrustedProxyCIDRs(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}

	// Real CDN IPv6 allocations must fit: Cloudflare's broadest is a /29.
	for _, ok := range []string{"2a06:98c0::/29", "2606:4700::/32", "2001:db8::/64", "2001:db8::1"} {
		if err := ValidateTrustedProxyCIDRs(ok); err != nil {
			t.Errorf("IPv6 range %q rejected: %v", ok, err)
		}
	}

	// The regression this exists for: a prefix-length floor would accept this
	// — 256 entries, every one a /8, none of them 0.0.0.0/0 — while trusting
	// the entire IPv4 internet. Counting addresses is what catches it.
	var everything []string
	for i := 0; i < 256; i++ {
		everything = append(everything, fmt.Sprintf("%d.0.0.0/8", i))
	}
	if err := ValidateTrustedProxyCIDRs(strings.Join(everything, "\n")); err == nil {
		t.Error("256 x /8 covers the whole IPv4 internet and must be rejected")
	}

	// A single oversized block is the same problem in one line. 240.0.0.0/4 is
	// reserved and assigned to nobody, so the test carries no real allocation.
	if err := ValidateTrustedProxyCIDRs("240.0.0.0/4"); err == nil {
		t.Error("a /4 (268M addresses) should exceed the address budget")
	}

	// A realistic operator allocation must still fit.
	if err := ValidateTrustedProxyCIDRs("203.0.113.0/24\n198.51.100.0/22"); err != nil {
		t.Errorf("ordinary allocation rejected: %v", err)
	}

	// Private space does not count against the budget. Found by the e2e spec:
	// 10.0.0.0/8 is 16.7M addresses and was rejected — while being a range NPG
	// already trusts by default, and the single most ordinary answer to "where
	// is my internal reverse proxy". An internet client cannot send from these,
	// so trusting them cannot enable forgery.
	for _, lan := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16",
	} {
		if err := ValidateTrustedProxyCIDRs(lan); err != nil {
			t.Errorf("non-routable range %q rejected: %v", lan, err)
		}
	}

	// The exemption must not leak: a public range stays budgeted even when
	// listed next to private ones.
	if err := ValidateTrustedProxyCIDRs("10.0.0.0/8\n240.0.0.0/4"); err == nil {
		t.Error("a public oversized block must still be rejected alongside private ranges")
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	valid, invalid := ParseTrustedProxyCIDRs("203.0.113.0/24, 203.0.113.0/24\nbogus\n\n# note\n198.51.100.7 # inline")
	if len(invalid) != 1 || invalid[0] != "bogus" {
		t.Fatalf("invalid entries: got %v, want [bogus]", invalid)
	}
	if len(valid) != 2 {
		t.Fatalf("valid entries: got %v, want 2 (deduped)", valid)
	}
	// Host bits are normalized to the network address so the stored value
	// equals what nginx enforces and de-duplication can see equal entries.
	valid, _ = ParseTrustedProxyCIDRs("10.1.2.3/8")
	if len(valid) != 1 || valid[0] != "10.0.0.0/8" {
		t.Fatalf("normalization: got %v, want [10.0.0.0/8]", valid)
	}
}

// Two addresses must never be auto-banned, and the boundary between them and
// "ban this LAN device on purpose" is the whole point of the rule.
func TestUnbannableReason(t *testing.T) {
	declared := []string{"104.16.0.0/13", "203.0.113.7"}

	// Loopback: a self-ban renders 127.0.0.1 into every host's geo block, and
	// that check runs in the server rewrite phase — before the per-host ACME
	// location — so it breaks certificate renewal everywhere at once. The
	// loopback SSL server answers 444 unconditionally, so a local self-probe
	// can reach a fail-code threshold on its own.
	for _, ip := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
		if UnbannableReason(ip, declared) == "" {
			t.Errorf("loopback %q must never be auto-banned", ip)
		}
	}

	// A declared proxy carries many clients.
	for _, ip := range []string{"104.16.0.1", "104.23.255.255", "203.0.113.7"} {
		if UnbannableReason(ip, declared) == "" {
			t.Errorf("declared proxy address %q must never be auto-banned", ip)
		}
	}

	// Everything else stays bannable — including private addresses. The
	// always-trusted RFC1918 ranges are a default, not a claim that a LAN
	// address is a proxy, so an operator must still be able to ban a LAN device.
	for _, ip := range []string{"192.0.2.10", "198.51.100.4", "192.168.77.50", "10.1.2.3", "203.0.113.8"} {
		if why := UnbannableReason(ip, declared); why != "" {
			t.Errorf("%q should be bannable, refused with: %s", ip, why)
		}
	}

	// No declared proxies: only loopback is protected.
	if UnbannableReason("104.16.0.1", nil) != "" {
		t.Error("with no trusted proxies configured a CDN address is not distinguishable and must stay bannable — the guard for that case is the enable-time precondition, not an address test")
	}
	if UnbannableReason("127.0.0.1", nil) == "" {
		t.Error("loopback must be protected even with no trusted proxies configured")
	}

	// Garbage in, no crash, no accidental protection.
	if UnbannableReason("not-an-ip", declared) != "" {
		t.Error("an unparseable address must not be treated as protected")
	}
}
