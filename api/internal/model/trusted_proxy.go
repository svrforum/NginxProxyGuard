package model

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

// Trusted proxies decide whose X-Forwarded-For (or other real-IP header) nginx
// believes. Getting this wrong is not a cosmetic mistake: $remote_addr feeds
// GeoIP country matching, per-host access lists, banned IPs, fail2ban
// attribution, the rate-limit key and ModSecurity's REMOTE_ADDR all at once, so
// trusting a source that can reach the box directly lets a client choose its
// own apparent address and walk through every one of them.
//
// nginx itself has no ordering flaw here — the peer is checked against
// set_real_ip_from before the header is honoured, and re-checked at each hop —
// so a client connecting from outside the trusted list can forge nothing. The
// whole security of the feature therefore rests on the list naming only proxies
// the operator actually controls or trusts.

const (
	// RealIPHeaderDefault is what NPG has always used and what every install
	// that never touches this setting keeps using.
	RealIPHeaderDefault = "X-Forwarded-For"

	// TrustedProxyPresetNone / Cloudflare select the built-in range list.
	TrustedProxyPresetNone       = "none"
	TrustedProxyPresetCloudflare = "cloudflare"

	// maxTrustedProxyEntries bounds the list so a paste cannot balloon
	// nginx.conf.
	maxTrustedProxyEntries = 256

	// maxTrustedProxyAddresses bounds the TOTAL number of IPv4 addresses the
	// operator list may cover. A per-prefix floor (say "nothing shorter than
	// /8") looks like a safety net and is not one: 0.0.0.0/8 through
	// 255.0.0.0/8 is 256 entries, every one of them a /8, and together they
	// trust the entire internet. Counting addresses catches that, and catches
	// a single stray public /8 too.
	//
	// 4,194,304 is a /10 — comfortably more than any home or business
	// allocation, far less than a meaningful slice of the internet.
	maxTrustedProxyAddresses = 1 << 22
)

// AlwaysTrustedProxyRanges are the private/loopback networks NPG has always
// trusted and still does. They are emitted before any operator entry and are
// not removable: Docker's own bridge, a LAN reverse proxy and the local
// cloudflared connector all depend on them, and dropping them would strand
// every containerised deployment.
func AlwaysTrustedProxyRanges() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1",
		"fc00::/7",
	}
}

// RealIPHeaders are the header names nginx may be told to read the client
// address from. The list is closed on purpose: the value is rendered into
// nginx.conf, and a free-form string there is a config-injection vector.
var RealIPHeaders = []string{
	RealIPHeaderDefault,
	"X-Real-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
}

// TrustedProxyPresets are the accepted preset identifiers.
var TrustedProxyPresets = []string{TrustedProxyPresetNone, TrustedProxyPresetCloudflare}

// NormalizeRealIPHeader canonicalizes the caller's header name against the
// allowlist (case-insensitively) and rejects anything else.
//
// An empty value resolves to the default rather than erroring: a row created
// before this column existed, or a fresh install whose defaults were never read
// back, must still render a working nginx.conf. Rendering an empty value would
// emit `real_ip_header ;`, which fails nginx -t and takes the whole generated
// nginx.conf down with it.
func NormalizeRealIPHeader(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return RealIPHeaderDefault, nil
	}
	for _, allowed := range RealIPHeaders {
		if strings.EqualFold(trimmed, allowed) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("%w: unsupported real IP header %q: must be one of %s", ErrInvalidInput, trimmed, strings.Join(RealIPHeaders, ", "))
}

// NormalizeTrustedProxyPreset validates the preset identifier, treating an
// empty value as "none" for the same reason NormalizeRealIPHeader does.
func NormalizeTrustedProxyPreset(preset string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(preset))
	if trimmed == "" {
		return TrustedProxyPresetNone, nil
	}
	for _, allowed := range TrustedProxyPresets {
		if trimmed == allowed {
			return trimmed, nil
		}
	}
	return "", fmt.Errorf("%w: unknown trusted proxy preset %q: must be one of %s", ErrInvalidInput, preset, strings.Join(TrustedProxyPresets, ", "))
}

// ParseTrustedProxyCIDRs splits the operator's list into entries nginx can use,
// returning the usable ones and the rejects separately. Comments and blank
// lines are dropped; entries are normalized to their network address and
// de-duplicated.
//
// Rejects come back to the caller rather than being dropped silently: the write
// path answers 400 naming the value, and the render path skips them. The render
// skip is not optional — one bad token inside set_real_ip_from is an [emerg]
// that blocks the reload for every host on the instance.
func ParseTrustedProxyCIDRs(raw string) (valid, invalid []string) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})
	for _, field := range fields {
		entry := strings.TrimSpace(field)
		if idx := strings.Index(entry, "#"); idx >= 0 {
			entry = strings.TrimSpace(entry[:idx])
		}
		if entry == "" {
			continue
		}
		normalized, ok := normalizeIPOrCIDR(entry)
		if !ok {
			invalid = append(invalid, entry)
			continue
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		valid = append(valid, normalized)
	}
	return valid, invalid
}

// ValidateTrustedProxyCIDRs rejects a list nginx could not use, and one that
// would trust so much of the internet that the header becomes forgeable.
func ValidateTrustedProxyCIDRs(raw string) error {
	valid, invalid := ParseTrustedProxyCIDRs(raw)
	if len(invalid) > 0 {
		return fmt.Errorf("%w: invalid trusted proxy entry %q: expected an IP address or CIDR range", ErrInvalidInput, invalid[0])
	}
	if len(valid) > maxTrustedProxyEntries {
		return fmt.Errorf("%w: too many trusted proxy entries (%d, max %d)", ErrInvalidInput, len(valid), maxTrustedProxyEntries)
	}
	total := new(big.Int)
	for _, entry := range valid {
		if strings.Contains(entry, ":") {
			// IPv6 allocations are enormous by design and a /64 per site is
			// normal, so counting addresses is meaningless there. Reject only
			// the catch-all.
			if entry == "::/0" {
				return fmt.Errorf("%w: trusted proxy entry ::/0 would trust every client", ErrInvalidInput)
			}
			continue
		}
		if entry == "0.0.0.0/0" {
			return fmt.Errorf("%w: trusted proxy entry 0.0.0.0/0 would trust every client", ErrInvalidInput)
		}
		total.Add(total, big.NewInt(ipv4AddressCount(entry)))
	}
	if total.Cmp(big.NewInt(maxTrustedProxyAddresses)) > 0 {
		return fmt.Errorf("%w: trusted proxy list covers %s addresses (max %d). Trusting that much of the internet lets clients forge their own address",
			ErrInvalidInput, total.String(), maxTrustedProxyAddresses)
	}
	return nil
}

// ipv4AddressCount returns how many addresses an entry covers. A bare address
// counts as one.
func ipv4AddressCount(entry string) int64 {
	if !strings.Contains(entry, "/") {
		return 1
	}
	_, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		return 1
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 0 || ones > bits {
		return 1
	}
	return int64(1) << uint(bits-ones)
}
