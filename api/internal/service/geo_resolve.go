package service

import "nginx-proxy-guard/internal/model"

// resolveGeo collapses the global geo default and a host's own geo row into the
// single effective *model.GeoRestriction the nginx template consumes. The
// template is unchanged — it always reads one object — so this resolver is the
// only place the global-vs-host precedence lives.
//
// 3-state:
//   - override: host has its own enabled geo  -> use host (current behavior)
//   - disable:  host.DisableGlobal            -> no geo block
//   - inherit:  otherwise                     -> global default (when enabled)
//
// The host's AllowedIPs are ALWAYS preserved (unioned in) because the cloud and
// bot-filter template sections read GeoRestriction.AllowedIPs as priority-allow
// IPs regardless of whether a geo block is active. Dropping them here would
// silently break cloud/bot priority-allow — a side effect this design forbids.
func resolveGeo(global *model.GlobalGeoRestriction, host *model.GeoRestriction) *model.GeoRestriction {
	var hostAllowed []string
	if host != nil {
		hostAllowed = host.AllowedIPs
	}

	// Override: host runs its own geo restriction.
	if host != nil && host.Enabled {
		return host
	}

	// Disable: no geo block for this host, but keep its AllowedIPs alive so the
	// cloud/bot priority-allow sections still see them.
	if host != nil && host.DisableGlobal {
		if len(hostAllowed) == 0 {
			return nil
		}
		return &model.GeoRestriction{Enabled: false, AllowedIPs: hostAllowed}
	}

	// Inherit: use the global default when it is enabled.
	if global != nil && global.Enabled {
		return &model.GeoRestriction{
			Mode:            global.Mode,
			Countries:       global.Countries,
			AllowedIPs:      unionStrings(hostAllowed, global.AllowedIPs),
			AllowPrivateIPs: global.AllowPrivateIPs,
			AllowSearchBots: global.AllowSearchBots,
			Enabled:         true,
			ChallengeMode:   global.ChallengeMode,
		}
	}

	// Inherit but the global default is off: preserve host AllowedIPs if any
	// (cloud/bot priority-allow), otherwise there is nothing to render.
	if len(hostAllowed) > 0 {
		return &model.GeoRestriction{Enabled: false, AllowedIPs: hostAllowed}
	}
	return nil
}

// unionStrings returns a and b concatenated with duplicates removed, preserving
// first-seen order (a's entries first).
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
