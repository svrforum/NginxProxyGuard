package service

import "nginx-proxy-guard/internal/model"

// resolveRateLimit collapses the global rate-limit default and a host's own
// rate_limit row into the single effective *model.RateLimit the template reads.
// Same 3-state as the other features. The nginx limit_req zone is per-host, so
// the inherited result carries the host's ID (for a unique zone name) but the
// global's values.
//
// WhitelistIPs follows the same all-or-nothing rule as every other field here
// and is deliberately NOT unioned: an overriding host uses only its own
// exception list, an inheriting host only the global one. resolveGeo does union
// its address list, but for a different reason — those addresses are read by the
// cloud and bot sections even when geo itself is off, so they have consumers
// outside the resolved object. The rate-limit list has no such consumer, and
// unioning would take away an overriding host's ability to narrow the
// exceptions it grants. Operators wanting a bypass that survives an override
// have one already: the global trusted-IP list (#263).
func resolveRateLimit(global *model.GlobalRateLimit, host *model.RateLimit, hostID string) *model.RateLimit {
	// Override: host runs its own rate limit.
	if host != nil && host.Enabled {
		return host
	}
	// Disable: host opted out of the global default.
	if host != nil && host.DisableGlobal {
		return nil
	}
	// Inherit: build a per-host zone from the global values when enabled.
	if global != nil && global.Enabled {
		return &model.RateLimit{
			ProxyHostID:       hostID,
			Enabled:           true,
			RequestsPerSecond: global.RequestsPerSecond,
			BurstSize:         global.BurstSize,
			ZoneSize:          global.ZoneSize,
			LimitBy:           global.LimitBy,
			LimitResponse:     global.LimitResponse,
			WhitelistIPs:      global.WhitelistIPs,
		}
	}
	return nil
}
