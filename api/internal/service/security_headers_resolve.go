package service

import "nginx-proxy-guard/internal/model"

// resolveSecurityHeaders collapses the global security-headers default and a
// host's own security_headers row into the single effective *model.SecurityHeaders
// the template reads. Same 3-state as resolveBotFilter (override / disable /
// inherit). Inherit builds a fresh SecurityHeaders from the global.
func resolveSecurityHeaders(global *model.GlobalSecurityHeaders, host *model.SecurityHeaders) *model.SecurityHeaders {
	// Override: host runs its own security headers.
	if host != nil && host.Enabled {
		return host
	}
	// Disable: host opted out of the global default.
	if host != nil && host.DisableGlobal {
		return nil
	}
	// Inherit: use the global default when enabled.
	if global != nil && global.Enabled {
		return &model.SecurityHeaders{
			Enabled:               true,
			HSTSEnabled:           global.HSTSEnabled,
			HSTSMaxAge:            global.HSTSMaxAge,
			HSTSIncludeSubdomains: global.HSTSIncludeSubdomains,
			HSTSPreload:           global.HSTSPreload,
			XFrameOptions:         global.XFrameOptions,
			XContentTypeOptions:   global.XContentTypeOptions,
			XXSSProtection:        global.XXSSProtection,
			ReferrerPolicy:        global.ReferrerPolicy,
			ContentSecurityPolicy: global.ContentSecurityPolicy,
			PermissionsPolicy:     global.PermissionsPolicy,
			CustomHeaders:         global.CustomHeaders,
		}
	}
	return nil
}
