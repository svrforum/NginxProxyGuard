package service

import "nginx-proxy-guard/internal/model"

// resolveWAF collapses the global WAF default and a host's own WAF columns into
// the effective host used for config generation (#198 slice 6). WAF settings are
// read directly off *model.ProxyHost by the config/manager layer, so an
// inheriting host (waf_use_global=true) gets a COPY with its WAF fields
// overwritten by the global values — the original host row is never mutated.
//
//	waf_use_global=false → host's own WAF columns (override, or disable via waf_enabled=false)
//	waf_use_global=true  → global enabled/mode/paranoia/threshold (inherit)
func resolveWAF(global *model.GlobalWAF, host *model.ProxyHost) *model.ProxyHost {
	if host == nil || !host.WAFUseGlobal || global == nil {
		return host
	}
	c := *host
	c.WAFEnabled = global.Enabled
	c.WAFMode = global.Mode
	c.WAFParanoiaLevel = global.ParanoiaLevel
	c.WAFAnomalyThreshold = global.AnomalyThreshold
	return &c
}
