package middleware

// Route → permission registry (#222).
//
// Authorization is default-deny: a route that appears in none of the three sets
// below is reachable only by a superuser, and logs a warning. The coverage test
// in bootstrap fails the build when a route has no decision, so "we forgot to
// map it" surfaces as a red test rather than as a silent hole.
//
// Keys are "METHOD /exact/registered/path" — the pattern as registered, with its
// parameter names (`:id` vs `:proxyHostId`) intact. Do NOT derive an area from
// the URL prefix: /api/v1/settings/* is registered by five different functions
// and /api/v1/proxy-hosts/:id/* by five more, so a prefix rule would grant the
// wrong area.

// SelfRoutes are a user's own account: reading who they are, changing their own
// password, username, language, font, and managing their own 2FA.
//
// No role may take these away — an account that cannot change its own password
// is a broken account, not a restricted one. They require authentication and
// nothing else.
var SelfRoutes = map[string]bool{
	"GET /api/v1/auth/me":              true,
	"GET /api/v1/auth/account":         true,
	"GET /api/v1/auth/language":        true,
	"GET /api/v1/auth/font":            true,
	"PUT /api/v1/auth/language":        true,
	"PUT /api/v1/auth/font":            true,
	"POST /api/v1/auth/change-password":    true,
	"POST /api/v1/auth/change-credentials": true,
	"POST /api/v1/auth/change-username":    true,
	"POST /api/v1/auth/2fa/setup":          true,
	"POST /api/v1/auth/2fa/enable":         true,
	"POST /api/v1/auth/2fa/disable":        true,
}

// PublicRoutes need no permission: unauthenticated endpoints and operational
// probes. /metrics stays here because a Prometheus scrape has no session, and
// /health because breaking a container health check would take the service down.
var PublicRoutes = map[string]bool{
	"GET /health":                    true,
	"GET /metrics":                   true,
	"GET /api/v1/status":             true,
	"GET /api/v1/health/detailed":    true,
	"POST /api/v1/health/canary":     true,
	"GET /api/v1/public/ui-settings": true,

	// Login flow — no session exists yet.
	"POST /api/v1/auth/login":      true,
	"POST /api/v1/auth/logout":     true,
	"GET /api/v1/auth/status":      true,
	"POST /api/v1/auth/verify-2fa": true,

	// CAPTCHA challenge. These are hit by VISITORS' browsers, not by operators
	// (registerPublicRoutes in bootstrap/routes.go). Requiring a permission here
	// would break the geo/cloud challenge for every unauthenticated visitor.
	"GET /api/v1/challenge/page":            true,
	"POST /api/v1/challenge/verify":         true,
	"POST /api/v1/challenge/verify-redirect": true,
	"GET /api/v1/challenge/validate":        true,
	"GET /api/v1/challenge/favicon.ico":     true,
}

// routePermissions maps a route to the single permission it requires.
//
// Notes on the non-obvious entries:
//   - /settings/global-{waf,bot-filter,geo,security-headers,rate-limit,cloud-providers}
//     are the global DEFAULTS for those security features, so they belong to the
//     waf area the UI shows them under, not to settings.
//   - /test/nginx-config and /test/proxy-host/:id shell out through docker exec
//     to run nginx -t and probe the target, so they are settings:write and not a
//     read despite being GET-shaped work.
//   - backup has no write verb (read/create/restore); DELETE folds into create,
//     matching how the legacy backup:create scope already gated it.
//   - /api/docs requires settings:read (D7): publishing the whole API surface
//     anonymously contradicts having permissions at all.
var routePermissions = map[string]string{
	"GET /api/docs": "settings:read",
	"GET /api/docs/swagger.yaml": "settings:read",
	"GET /api/v1/access-lists": "access:read",
	"POST /api/v1/access-lists": "access:write",
	"DELETE /api/v1/access-lists/:id": "access:write",
	"GET /api/v1/access-lists/:id": "access:read",
	"PUT /api/v1/access-lists/:id": "access:write",
	"GET /api/v1/api-tokens": "apitoken:read",
	"POST /api/v1/api-tokens": "apitoken:write",
	"DELETE /api/v1/api-tokens/:id": "apitoken:write",
	"GET /api/v1/api-tokens/:id": "apitoken:read",
	"PUT /api/v1/api-tokens/:id": "apitoken:write",
	"POST /api/v1/api-tokens/:id/revoke": "apitoken:write",
	"GET /api/v1/api-tokens/:id/usage": "apitoken:read",
	"GET /api/v1/api-tokens/permissions": "apitoken:read",
	"GET /api/v1/audit-logs": "audit:read",
	"GET /api/v1/audit-logs/actions": "audit:read",
	"GET /api/v1/audit-logs/api-tokens": "audit:read",
	"GET /api/v1/audit-logs/resource-types": "audit:read",
	"GET /api/v1/auth-providers": "authprovider:read",
	"POST /api/v1/auth-providers": "authprovider:write",
	"DELETE /api/v1/auth-providers/:id": "authprovider:write",
	"GET /api/v1/auth-providers/:id": "authprovider:read",
	"PUT /api/v1/auth-providers/:id": "authprovider:write",
	"GET /api/v1/backups": "backup:read",
	"POST /api/v1/backups": "backup:create",
	"DELETE /api/v1/backups/:id": "backup:create",
	"GET /api/v1/backups/:id": "backup:read",
	"GET /api/v1/backups/:id/download": "backup:read",
	"POST /api/v1/backups/:id/restore": "backup:restore",
	"GET /api/v1/backups/stats": "backup:read",
	"POST /api/v1/backups/upload-restore": "backup:restore",
	"DELETE /api/v1/banned-ips": "waf:write",
	"GET /api/v1/banned-ips": "waf:read",
	"POST /api/v1/banned-ips": "waf:write",
	"DELETE /api/v1/banned-ips/:id": "waf:write",
	"POST /api/v1/banned-ips/bulk-unban": "waf:write",
	"GET /api/v1/banned-ips/history": "waf:read",
	"GET /api/v1/banned-ips/history/ip/:ip": "waf:read",
	"GET /api/v1/banned-ips/history/stats": "waf:read",
	"GET /api/v1/bots/known": "waf:read",
	"GET /api/v1/certificates": "certificate:read",
	"POST /api/v1/certificates": "certificate:write",
	"DELETE /api/v1/certificates/:id": "certificate:delete",
	"GET /api/v1/certificates/:id": "certificate:read",
	"GET /api/v1/certificates/:id/download": "certificate:read",
	"DELETE /api/v1/certificates/:id/error": "certificate:delete",
	"GET /api/v1/certificates/:id/logs": "certificate:read",
	"POST /api/v1/certificates/:id/renew": "certificate:write",
	"PUT /api/v1/certificates/:id/upload": "certificate:write",
	"DELETE /api/v1/certificates/errors": "certificate:delete",
	"GET /api/v1/certificates/expiring": "certificate:read",
	"GET /api/v1/certificates/history": "certificate:read",
	"POST /api/v1/certificates/upload": "certificate:write",
	"GET /api/v1/challenge-config": "settings:read",
	"PUT /api/v1/challenge-config": "settings:write",
	"GET /api/v1/challenge-config/stats": "settings:read",
	"GET /api/v1/cloud-providers": "waf:read",
	"POST /api/v1/cloud-providers": "waf:write",
	"DELETE /api/v1/cloud-providers/:slug": "waf:write",
	"GET /api/v1/cloud-providers/:slug": "waf:read",
	"PUT /api/v1/cloud-providers/:slug": "waf:write",
	"GET /api/v1/cloud-providers/by-region": "waf:read",
	"GET /api/v1/dashboard": "dashboard:read",
	"GET /api/v1/dashboard/containers": "dashboard:read",
	"GET /api/v1/dashboard/geoip-stats": "dashboard:read",
	"GET /api/v1/dashboard/health": "dashboard:read",
	"GET /api/v1/dashboard/health/history": "dashboard:read",
	"GET /api/v1/dashboard/stats/hourly": "dashboard:read",
	"GET /api/v1/ddns-records": "ddns:read",
	"POST /api/v1/ddns-records": "ddns:write",
	"DELETE /api/v1/ddns-records/:id": "ddns:write",
	"GET /api/v1/ddns-records/:id": "ddns:read",
	"PUT /api/v1/ddns-records/:id": "ddns:write",
	"POST /api/v1/ddns-records/:id/sync": "ddns:write",
	"POST /api/v1/ddns-records/import-from-hosts": "ddns:write",
	"POST /api/v1/ddns-records/sync": "ddns:write",
	"GET /api/v1/dns-providers": "ddns:read",
	"POST /api/v1/dns-providers": "ddns:write",
	"DELETE /api/v1/dns-providers/:id": "ddns:write",
	"GET /api/v1/dns-providers/:id": "ddns:read",
	"PUT /api/v1/dns-providers/:id": "ddns:write",
	"GET /api/v1/dns-providers/default": "ddns:read",
	"POST /api/v1/dns-providers/test": "ddns:write",
	"GET /api/v1/docker/containers": "dashboard:read",
	"GET /api/v1/exploit-rules": "waf:read",
	"POST /api/v1/exploit-rules": "waf:write",
	"DELETE /api/v1/exploit-rules/:id": "waf:write",
	"GET /api/v1/exploit-rules/:id": "waf:read",
	"PUT /api/v1/exploit-rules/:id": "waf:write",
	"DELETE /api/v1/exploit-rules/:id/global-exclude": "waf:write",
	"POST /api/v1/exploit-rules/:id/global-exclude": "waf:write",
	"POST /api/v1/exploit-rules/:id/toggle": "waf:write",
	"GET /api/v1/exploit-rules/hosts": "waf:read",
	"GET /api/v1/exploit-rules/hosts/:hostId/rules": "waf:read",
	"DELETE /api/v1/exploit-rules/hosts/:hostId/rules/:ruleId/exclude": "waf:write",
	"POST /api/v1/exploit-rules/hosts/:hostId/rules/:ruleId/exclude": "waf:write",
	"GET /api/v1/filter-subscriptions": "waf:read",
	"POST /api/v1/filter-subscriptions": "waf:write",
	"DELETE /api/v1/filter-subscriptions/:id": "waf:write",
	"GET /api/v1/filter-subscriptions/:id": "waf:read",
	"PUT /api/v1/filter-subscriptions/:id": "waf:write",
	"DELETE /api/v1/filter-subscriptions/:id/entry-exclusions": "waf:write",
	"GET /api/v1/filter-subscriptions/:id/entry-exclusions": "waf:read",
	"POST /api/v1/filter-subscriptions/:id/entry-exclusions": "waf:write",
	"GET /api/v1/filter-subscriptions/:id/exclusions": "waf:read",
	"DELETE /api/v1/filter-subscriptions/:id/exclusions/:hostId": "waf:write",
	"POST /api/v1/filter-subscriptions/:id/exclusions/:hostId": "waf:write",
	"POST /api/v1/filter-subscriptions/:id/refresh": "waf:write",
	"GET /api/v1/filter-subscriptions/catalog": "waf:read",
	"POST /api/v1/filter-subscriptions/catalog/subscribe": "waf:write",
	"GET /api/v1/geo/countries": "waf:read",
	"GET /api/v1/global-uri-block": "waf:read",
	"PUT /api/v1/global-uri-block": "waf:write",
	"POST /api/v1/global-uri-block/rules": "waf:write",
	"DELETE /api/v1/global-uri-block/rules/:ruleId": "waf:write",
	"GET /api/v1/log-filter-presets": "logs:read",
	"POST /api/v1/log-filter-presets": "logs:write",
	"DELETE /api/v1/log-filter-presets/:id": "logs:write",
	"PUT /api/v1/log-filter-presets/:id": "logs:write",
	"GET /api/v1/logs": "logs:read",
	"POST /api/v1/logs": "logs:write",
	"GET /api/v1/logs/autocomplete/countries": "logs:read",
	"GET /api/v1/logs/autocomplete/hosts": "logs:read",
	"GET /api/v1/logs/autocomplete/ips": "logs:read",
	"GET /api/v1/logs/autocomplete/methods": "logs:read",
	"GET /api/v1/logs/autocomplete/uris": "logs:read",
	"GET /api/v1/logs/autocomplete/user-agents": "logs:read",
	"POST /api/v1/logs/cleanup": "logs:write",
	"GET /api/v1/logs/settings": "logs:read",
	"PUT /api/v1/logs/settings": "logs:write",
	"GET /api/v1/logs/stats": "logs:read",
	"GET /api/v1/proxy-hosts": "proxy:read",
	"POST /api/v1/proxy-hosts": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:id": "proxy:delete",
	"GET /api/v1/proxy-hosts/:id": "proxy:read",
	"PUT /api/v1/proxy-hosts/:id": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:id/challenge": "proxy:delete",
	"GET /api/v1/proxy-hosts/:id/challenge": "proxy:read",
	"PUT /api/v1/proxy-hosts/:id/challenge": "proxy:write",
	"POST /api/v1/proxy-hosts/:id/clone": "proxy:write",
	"PUT /api/v1/proxy-hosts/:id/favorite": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:id/geo": "proxy:delete",
	"GET /api/v1/proxy-hosts/:id/geo": "proxy:read",
	"POST /api/v1/proxy-hosts/:id/geo": "proxy:write",
	"PUT /api/v1/proxy-hosts/:id/geo": "proxy:write",
	"POST /api/v1/proxy-hosts/:id/regenerate": "proxy:write",
	"POST /api/v1/proxy-hosts/:id/test": "proxy:write",
	"GET /api/v1/proxy-hosts/:proxyHostId/blocked-cloud-providers": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/blocked-cloud-providers": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/bot-filter": "proxy:delete",
	"GET /api/v1/proxy-hosts/:proxyHostId/bot-filter": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/bot-filter": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/fail2ban": "proxy:delete",
	"GET /api/v1/proxy-hosts/:proxyHostId/fail2ban": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/fail2ban": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/rate-limit": "proxy:delete",
	"GET /api/v1/proxy-hosts/:proxyHostId/rate-limit": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/rate-limit": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/security-headers": "proxy:delete",
	"GET /api/v1/proxy-hosts/:proxyHostId/security-headers": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/security-headers": "proxy:write",
	"POST /api/v1/proxy-hosts/:proxyHostId/security-headers/preset/:preset": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/upstream": "proxy:delete",
	"GET /api/v1/proxy-hosts/:proxyHostId/upstream": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/upstream": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/uri-block": "proxy:delete",
	"GET /api/v1/proxy-hosts/:proxyHostId/uri-block": "proxy:read",
	"PUT /api/v1/proxy-hosts/:proxyHostId/uri-block": "proxy:write",
	"POST /api/v1/proxy-hosts/:proxyHostId/uri-block/rules": "proxy:write",
	"DELETE /api/v1/proxy-hosts/:proxyHostId/uri-block/rules/:ruleId": "proxy:delete",
	"GET /api/v1/proxy-hosts/by-domain/:domain": "proxy:read",
	"POST /api/v1/proxy-hosts/sync": "proxy:write",
	"GET /api/v1/redirect-hosts": "redirect:read",
	"POST /api/v1/redirect-hosts": "redirect:write",
	"DELETE /api/v1/redirect-hosts/:id": "redirect:delete",
	"GET /api/v1/redirect-hosts/:id": "redirect:read",
	"PUT /api/v1/redirect-hosts/:id": "redirect:write",
	"POST /api/v1/redirect-hosts/sync": "redirect:write",
	"GET /api/v1/security-headers/presets": "proxy:read",
	"GET /api/v1/settings": "settings:read",
	"PUT /api/v1/settings": "settings:write",
	"GET /api/v1/settings/cloudflare-tunnel": "settings:read",
	"PUT /api/v1/settings/cloudflare-tunnel": "settings:write",
	"GET /api/v1/settings/cloudflare-tunnel/status": "settings:read",
	"GET /api/v1/settings/global-bot-filter": "waf:read",
	"PUT /api/v1/settings/global-bot-filter": "waf:write",
	"GET /api/v1/settings/global-cloud-providers": "waf:read",
	"PUT /api/v1/settings/global-cloud-providers": "waf:write",
	"GET /api/v1/settings/global-geo": "waf:read",
	"PUT /api/v1/settings/global-geo": "waf:write",
	"GET /api/v1/settings/global-rate-limit": "waf:read",
	"PUT /api/v1/settings/global-rate-limit": "waf:write",
	"GET /api/v1/settings/global-security-headers": "waf:read",
	"PUT /api/v1/settings/global-security-headers": "waf:write",
	"GET /api/v1/settings/global-waf": "waf:read",
	"PUT /api/v1/settings/global-waf": "waf:write",
	"POST /api/v1/settings/preset/:preset": "settings:write",
	"GET /api/v1/settings/presets": "settings:read",
	"POST /api/v1/settings/reset": "settings:write",
	"GET /api/v1/system-logs": "logs:read",
	"POST /api/v1/system-logs/cleanup": "logs:write",
	"GET /api/v1/system-logs/levels": "logs:read",
	"GET /api/v1/system-logs/sources": "logs:read",
	"GET /api/v1/system-logs/stats": "logs:read",
	"GET /api/v1/system-settings": "settings:read",
	"PUT /api/v1/system-settings": "settings:write",
	"POST /api/v1/system-settings/acme/test": "settings:write",
	"GET /api/v1/system-settings/geoip/history": "settings:read",
	"GET /api/v1/system-settings/geoip/status": "settings:read",
	"POST /api/v1/system-settings/geoip/update": "settings:write",
	"GET /api/v1/system-settings/log-files": "settings:read",
	"DELETE /api/v1/system-settings/log-files/:filename": "settings:write",
	"GET /api/v1/system-settings/log-files/:filename/download": "settings:read",
	"GET /api/v1/system-settings/log-files/:filename/view": "settings:read",
	"POST /api/v1/system-settings/log-files/rotate": "settings:write",
	"GET /api/v1/system-settings/logs": "settings:read",
	"PUT /api/v1/system-settings/logs": "settings:write",
	"GET /api/v1/system-settings/update/check": "settings:read",
	"GET /api/v1/test/backup-restore": "settings:read",
	"GET /api/v1/test/dashboard/queries": "settings:read",
	"POST /api/v1/test/nginx-config": "settings:write",
	"POST /api/v1/test/proxy-host/:id": "settings:write",
	"GET /api/v1/test/system/self-check": "settings:read",
	"GET /api/v1/upstreams/:id/health": "proxy:read",
	"GET /api/v1/uri-blocks": "waf:read",
	"POST /api/v1/uri-blocks/bulk-add-rule": "waf:write",
	"GET /api/v1/waf-test/patterns": "waf:read",
	"POST /api/v1/waf-test/test": "waf:write",
	"POST /api/v1/waf-test/test-all": "waf:write",
	"GET /api/v1/waf/global/exclusions": "waf:read",
	"GET /api/v1/waf/global/history": "waf:read",
	"GET /api/v1/waf/global/rules": "waf:read",
	"DELETE /api/v1/waf/global/rules/:ruleId/disable": "waf:write",
	"POST /api/v1/waf/global/rules/:ruleId/disable": "waf:write",
	"GET /api/v1/waf/hosts": "waf:read",
	"GET /api/v1/waf/hosts/:id/config": "waf:read",
	"GET /api/v1/waf/hosts/:id/history": "waf:read",
	"DELETE /api/v1/waf/hosts/:id/rules/:ruleId/disable": "waf:write",
	"POST /api/v1/waf/hosts/:id/rules/:ruleId/disable": "waf:write",
	"GET /api/v1/waf/rules": "waf:read",
	"POST /api/v1/waf/rules/disable-by-host": "waf:write",
}

// RoutePermission returns the permission a route requires, and whether the route
// has a mapping at all. A false second return means "no decision recorded" —
// callers must treat that as deny-except-superuser, never as allow.
func RoutePermission(method, path string) (string, bool) {
	p, ok := routePermissions[method+" "+path]
	return p, ok
}

// RouteDecisionExists reports whether a route has any authorization decision:
// a permission mapping, or membership in the self/public sets.
func RouteDecisionExists(method, path string) bool {
	key := method + " " + path
	if SelfRoutes[key] || PublicRoutes[key] {
		return true
	}
	_, ok := routePermissions[key]
	return ok
}
