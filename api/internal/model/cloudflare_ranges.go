package model

// CloudflareRangesUpdated is the date the list below was taken from
// https://www.cloudflare.com/ips/. It is surfaced in the UI so an operator can
// see how old the shipped list is; Cloudflare's ranges change rarely, and
// anything they add later can be pasted into the custom list without waiting
// for a release.
const CloudflareRangesUpdated = "2026-08-29"

// CloudflareRanges are Cloudflare's published edge networks — the addresses
// that connect to your origin when a hostname is proxied (orange cloud).
//
// This list only decides whose forwarded-client-address header nginx believes.
// It does not allow or block anything by itself, and it is additive: the
// private/loopback ranges NPG has always trusted stay in place, so a host
// behind Docker or a LAN proxy keeps working.
//
// Not needed for Cloudflare Tunnel: cloudflared connects over loopback, which
// is already trusted.
var CloudflareRanges = []string{
	// IPv4 — https://www.cloudflare.com/ips-v4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// IPv6 — https://www.cloudflare.com/ips-v6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// TrustedProxyRangesForPreset returns the built-in ranges a preset contributes.
func TrustedProxyRangesForPreset(preset string) []string {
	if preset == TrustedProxyPresetCloudflare {
		out := make([]string, len(CloudflareRanges))
		copy(out, CloudflareRanges)
		return out
	}
	return nil
}
