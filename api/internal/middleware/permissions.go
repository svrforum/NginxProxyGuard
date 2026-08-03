package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
)

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

// PublicRoutes need no PERMISSION. Two kinds live here: genuinely
// unauthenticated endpoints (login, the visitor-facing CAPTCHA, /metrics,
// /health), and endpoints that require a session but no specific grant
// (/api/v1/health/detailed and /api/v1/status are registered in
// registerProtectedAuthRoutes, so AuthMiddleware still applies to them — they
// simply carry no permission). Authentication is decided elsewhere; this map
// only says "no permission needed".
var PublicRoutes = map[string]bool{
	"GET /health":                    true,
	"GET /metrics":                   true,
	"GET /api/v1/status":             true,
	"GET /api/v1/health/detailed":    true,
	"POST /api/v1/health/canary":     true,
	"GET /api/v1/public/ui-settings": true,

	// Swagger UI. D7 wanted these behind settings:read, but the UI links to
	// /api/docs with a plain <a target="_blank"> (APITokenManager.tsx) and the
	// session token lives in localStorage, so a browser navigation carries no
	// Authorization header — bearer auth would 401 the docs for administrators
	// too. Moving them needs a different access mechanism (cookie auth or a
	// short-lived signed URL) and is deferred out of increment 1.
	"GET /api/docs":              true,
	"GET /api/docs/swagger.yaml": true,

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

	// OIDC SSO (#227). The login screen reads the provider list before anyone
	// has signed in, and the browser reaches start/callback carrying no NPG
	// credential — establishing one is the point. The list response is limited
	// to id/slug/name so an anonymous caller learns nothing about the IdP.
	"GET /api/v1/auth/sso/providers":       true,
	"GET /api/v1/auth/sso/:slug/start":     true,
	"GET /api/v1/auth/sso/:slug/callback":  true,
}

// routePermissions maps a route to the single permission it requires.
//
// Notes on the non-obvious entries:
//   - /settings/global-{waf,bot-filter,geo,security-headers,rate-limit,cloud-providers}
//     are the global DEFAULTS for those security features, so they belong to the
//     waf area the UI shows them under, not to settings.
//   - /test/nginx-config shells out through docker exec to run nginx -t, so it is
//     settings:write and not a read despite being GET-shaped work.
//   - /test/proxy-host/:id only probes the host's already-configured target over
//     HTTP and stores nothing, and the host list fires it per row on render, so it
//     is proxy:read — anything stricter makes a read-only role's own list 403.
//   - backup has no write verb (read/create/restore); DELETE folds into create,
//     matching how the legacy backup:create scope already gated it.
//   - /api/docs requires settings:read (D7): publishing the whole API surface
//     anonymously contradicts having permissions at all.
var routePermissions = map[string]string{
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
	"GET /api/v1/dns-providers": "dnsprovider:read",
	"POST /api/v1/dns-providers": "dnsprovider:write",
	"DELETE /api/v1/dns-providers/:id": "dnsprovider:write",
	"GET /api/v1/dns-providers/:id": "dnsprovider:read",
	"PUT /api/v1/dns-providers/:id": "dnsprovider:write",
	"GET /api/v1/dns-providers/default": "dnsprovider:read",
	"POST /api/v1/dns-providers/test": "dnsprovider:write",
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
	// Identity administration (#222 increment 2). Guarded by the user/role areas
	// so holding settings does not confer the ability to create administrators.
	"GET /api/v1/permission-areas": "role:read",
	"GET /api/v1/roles": "role:read",
	"POST /api/v1/roles": "role:write",
	"PUT /api/v1/roles/:id": "role:write",
	"DELETE /api/v1/roles/:id": "role:write",
	"GET /api/v1/users": "user:read",
	"GET /api/v1/users/:id": "user:read",
	"POST /api/v1/users": "user:write",
	"PUT /api/v1/users/:id/role": "user:write",
	"PUT /api/v1/users/:id/password": "user:write",
	"DELETE /api/v1/users/:id": "user:write",
	"POST /api/v1/users/:id/end-sessions": "user:write",

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
	"GET /api/v1/sso-providers": "user:read",
	"POST /api/v1/sso-providers": "user:write",
	"PUT /api/v1/sso-providers/:id": "user:write",
	"DELETE /api/v1/sso-providers/:id": "user:write",
	"POST /api/v1/sso-providers/test": "user:write",
	"GET /api/v1/notification-channels": "settings:read",
	"POST /api/v1/notification-channels": "settings:write",
	"PUT /api/v1/notification-channels/:id": "settings:write",
	"DELETE /api/v1/notification-channels/:id": "settings:write",
	"POST /api/v1/notification-channels/:id/test": "settings:write",
	"GET /api/v1/notification-channels/:id/deliveries": "settings:read",
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
	"POST /api/v1/test/proxy-host/:id": "proxy:read",
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

// Authorizer decides whether a principal holds a permission. Implemented by
// service.AuthzService; declared here as an interface so the middleware package
// does not import service (which imports repository, which would cycle).
type Authorizer interface {
	CanUser(ctx context.Context, userID, permission string) bool
	CanToken(ctx context.Context, token *model.APIToken, permission string) bool
}

// RequireRoutePermission enforces the registry for every request that reaches
// it, for BOTH humans and API tokens.
//
// It is attached once to the /api/v1 group immediately after the auth chain in
// registerTokenProtectedRoutes, which is what makes the three buckets line up
// with registration order: the self routes and the public routes are registered
// earlier in the same group and therefore never reach this middleware, while
// every resource route is registered after it. Echo snapshots group middleware
// at Add time (v4.15 group.go), so this ordering is load-bearing — moving the
// Use call earlier would gate the self routes and lock users out of their own
// password change.
//
// Before this existed, RequireAPIPermission returned early for any non-token
// request, so an authenticated session passed every permission check in the
// application. (#222)
func RequireRoutePermission(authz Authorizer) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if authz == nil {
				return next(c) // not wired (tests, or a build without RBAC): pre-RBAC behavior
			}
			// Published for in-handler field checks (see HasPermissionFromContext),
			// so handlers need no constructor change to ask a permission question.
			c.Set(ContextKeyAuthorizer, authz)
			// Echo's per-group not-found catch-alls (paths ending in /*) carry no
			// endpoint to protect. Enforcing them would turn a 404 for an unknown
			// path into a 403 for every non-superuser, which is both misleading and
			// a behavior change for lesser roles.
			if strings.HasSuffix(c.Path(), "/*") {
				return next(c)
			}

			permission, mapped := RoutePermission(c.Request().Method, c.Path())
			if !mapped {
				// Default-deny. The coverage test should have caught this before
				// release, so log loudly: home-server operators read container
				// logs, and a silently 403ing endpoint is hard to diagnose.
				log.Printf("[Authz] no permission mapping for %s %s — allowing superusers only. "+
					"Add it to middleware/permissions.go.", c.Request().Method, c.Path())
				return requireSuperuser(c, authz, next)
			}

			if token, ok := c.Get("api_token").(*model.APIToken); ok && token != nil {
				if !authz.CanToken(c.Request().Context(), token, permission) {
					return forbidden(c, permission)
				}
				return next(c)
			}

			userID, _ := c.Get("user_id").(string)
			if userID == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			}
			if !authz.CanUser(c.Request().Context(), userID, permission) {
				return forbidden(c, permission)
			}
			return next(c)
		}
	}
}

// requireSuperuser is the fallback for an unmapped route: only a principal that
// passes an area permission no ordinary role is given can proceed. role:write is
// used as the probe because it is administration-only by construction.
func requireSuperuser(c echo.Context, authz Authorizer, next echo.HandlerFunc) error {
	const probe = "role:write"
	if token, ok := c.Get("api_token").(*model.APIToken); ok && token != nil {
		if !authz.CanToken(c.Request().Context(), token, probe) {
			return forbidden(c, probe)
		}
		return next(c)
	}
	userID, _ := c.Get("user_id").(string)
	if userID == "" || !authz.CanUser(c.Request().Context(), userID, probe) {
		return forbidden(c, probe)
	}
	return next(c)
}

func forbidden(c echo.Context, permission string) error {
	return c.JSON(http.StatusForbidden, map[string]string{
		"error":    "insufficient permissions",
		"required": permission,
	})
}

// ContextKeyAuthorizer is where RequireRoutePermission publishes the authorizer
// for in-handler checks.
const ContextKeyAuthorizer = "authz"

// HasPermissionFromContext answers a permission question from inside a handler,
// for the cases where authorization depends on a field rather than the route —
// see the ddns_remove_provider gate in handler/proxy_host.go. Route middleware
// alone would leave those checks token-only and blind to roles.
//
// Returns true when no authorizer is present, which is the pre-RBAC behavior for
// routes outside the enforced group.
func HasPermissionFromContext(c echo.Context, permission string) bool {
	authz, _ := c.Get(ContextKeyAuthorizer).(Authorizer)
	return HasPermission(c, authz, permission)
}

// HasPermission answers a permission question for an explicit authorizer.
func HasPermission(c echo.Context, authz Authorizer, permission string) bool {
	if authz == nil {
		return true // not wired: pre-RBAC behavior
	}
	if token, ok := c.Get("api_token").(*model.APIToken); ok && token != nil {
		return authz.CanToken(c.Request().Context(), token, permission)
	}
	userID, _ := c.Get("user_id").(string)
	return userID != "" && authz.CanUser(c.Request().Context(), userID, permission)
}
