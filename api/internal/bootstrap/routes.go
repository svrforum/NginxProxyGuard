package bootstrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/handler"
	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// RegisterMiddleware configures CORS, security headers, rate limiting,
// logger, and recovery middleware for the Echo instance.
func RegisterMiddleware(e *echo.Echo, cfg *config.Config) {
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: resolveCORSOrigins(),
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            config.HSTSMaxAge,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://www.google.com https://www.gstatic.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https://validator.swagger.io; connect-src 'self' https://unpkg.com; frame-src https://challenges.cloudflare.com https://www.google.com",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	if os.Getenv("RATE_LIMIT_ENABLED") != "false" {
		rateLimit := 100.0
		if rl := os.Getenv("RATE_LIMIT_RPS"); rl != "" {
			if parsed, err := strconv.ParseFloat(rl, 64); err == nil && parsed > 0 {
				rateLimit = parsed
			}
		}
		e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(rateLimit))))
	}
}

// resolveCORSOrigins parses CORS_ALLOWED_ORIGINS and falls back to the
// development origins used historically.
func resolveCORSOrigins() []string {
	corsOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	var allowedOrigins []string
	if corsOrigins != "" {
		for _, origin := range strings.Split(corsOrigins, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" && origin != "*" {
				allowedOrigins = append(allowedOrigins, origin)
			}
		}
	}
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:5173", "http://localhost:81"}
	}
	return allowedOrigins
}

// RegisterRoutes wires the HTTP endpoints onto the Echo instance.
// Kept in one place to make the route surface easy to audit.
func RegisterRoutes(e *echo.Echo, c *Container) {
	registerHealth(e, c)
	registerSwagger(e, c.Handlers.Swagger)

	// Prometheus metrics — public on the internal network only. Operators
	// wanting external access should gate via upstream ACL / firewall.
	e.GET("/metrics", c.Handlers.Metrics.ServeMetrics)

	v1 := e.Group("/api/v1")
	v1.Use(authMiddleware.APIRateLimit(c.Cache, authMiddleware.DefaultAPIRateLimitConfig()))

	registerPublicRoutes(v1, c)
	registerProtectedAuthRoutes(v1, c)
	registerTokenProtectedRoutes(v1, c)
}

func registerHealth(e *echo.Echo, c *Container) {
	startTime := time.Now()
	e.GET("/health", func(ec echo.Context) error {
		isHealthy := true
		dbStatus := config.StatusOK
		if err := c.DB.Health(); err != nil {
			dbStatus = config.StatusError
			isHealthy = false
		}
		cacheStatus := config.StatusDisabled
		if c.Cache != nil {
			if c.Cache.IsReady() {
				cacheStatus = config.StatusOK
			} else {
				cacheStatus = config.StatusConnecting
			}
		}

		status := config.StatusHealthy
		httpStatus := http.StatusOK
		if !isHealthy {
			status = config.StatusUnhealthy
			httpStatus = http.StatusServiceUnavailable
		}

		return ec.JSON(httpStatus, map[string]interface{}{
			"status":    status,
			"version":   config.AppVersion,
			"database":  dbStatus,
			"cache":     cacheStatus,
			"uptime":    time.Since(startTime).String(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})
}

func registerSwagger(e *echo.Echo, swagger *handler.SwaggerHandler) {
	e.GET("/api/docs", swagger.ServeUI)
	e.GET("/api/docs/swagger.yaml", swagger.ServeSpec)
}

func registerPublicRoutes(v1 *echo.Group, c *Container) {
	auth := v1.Group("/auth")
	{
		auth.POST("/login", c.Handlers.Auth.Login)
		auth.POST("/logout", c.Handlers.Auth.Logout)
		auth.GET("/status", c.Handlers.Auth.GetStatus)
		auth.POST("/verify-2fa", c.Handlers.Auth.Verify2FA)
	}

	challenge := v1.Group("/challenge")
	{
		challenge.GET("/page", c.Handlers.Challenge.GetChallengePage)
		challenge.POST("/verify", c.Handlers.Challenge.VerifyCaptcha)
		challenge.POST("/verify-redirect", c.Handlers.Challenge.VerifyAndRedirect)
		challenge.GET("/validate", c.Handlers.Challenge.ValidateToken)
		challenge.GET("/favicon.ico", handler.ServeFavicon)
	}

	v1.GET("/public/ui-settings", c.Handlers.SystemSettings.GetPublicUISettings)
}

func registerProtectedAuthRoutes(v1 *echo.Group, c *Container) {
	protected := v1.Group("")
	protected.Use(authMiddleware.AuthMiddleware(c.Services.Auth))
	// Server-side initial-setup gate: while the logged-in user still has the
	// default credentials (is_initial_setup=true), only change-credentials and
	// read-only auth status are reachable (H1). No-op for set-up users.
	protected.Use(authMiddleware.InitialSetupRequired)

	protected.GET("/auth/me", c.Handlers.Auth.GetCurrentUser)
	protected.POST("/auth/change-credentials", c.Handlers.Auth.ChangeCredentials)
	protected.POST("/auth/change-password", c.Handlers.Auth.ChangePassword)
	protected.POST("/auth/change-username", c.Handlers.Auth.ChangeUsername)
	protected.GET("/auth/account", c.Handlers.Auth.GetAccountInfo)
	protected.POST("/auth/2fa/setup", c.Handlers.Auth.Setup2FA)
	protected.POST("/auth/2fa/enable", c.Handlers.Auth.Enable2FA)
	protected.POST("/auth/2fa/disable", c.Handlers.Auth.Disable2FA)
	protected.GET("/auth/language", c.Handlers.Auth.GetLanguage)
	protected.PUT("/auth/language", c.Handlers.Auth.SetLanguage)
	protected.GET("/auth/font", c.Handlers.Auth.GetFontFamily)
	protected.PUT("/auth/font", c.Handlers.Auth.SetFontFamily)

	protected.GET("/health/detailed", c.Handlers.HealthDetailed.GetDetailed)
	protected.POST("/health/canary", c.Handlers.HealthDetailed.RunCanary)

	protected.GET("/status", func(ec echo.Context) error {
		dbStatus := config.StatusOK
		if err := c.DB.Health(); err != nil {
			dbStatus = config.StatusError
		}
		nginxStatus := config.StatusOK
		if err := c.Nginx.TestConfig(ec.Request().Context()); err != nil {
			nginxStatus = config.StatusError
		}
		return ec.JSON(http.StatusOK, map[string]string{
			"api":      config.StatusOK,
			"database": dbStatus,
			"nginx":    nginxStatus,
		})
	})
}

func registerTokenProtectedRoutes(v1 *echo.Group, c *Container) {
	v1.Use(authMiddleware.APITokenAuth(c.Repositories.APIToken, c.Repositories.AuditLog))
	v1.Use(authMiddleware.AuthMiddleware(c.Services.Auth))
	// Block initial-setup (default-credential) session users from every
	// resource endpoint until they change their credentials (H1). No-op for
	// API tokens (no *model.User in context) and for set-up users.
	v1.Use(authMiddleware.InitialSetupRequired)

	registerAPITokenRoutes(v1, c.Handlers.APIToken)
	registerProxyHostRoutes(v1, c.Handlers.ProxyHost)
	registerDNSProviderRoutes(v1, c.Handlers.DNSProvider)
	registerDDNSRoutes(v1, c.Handlers.DDNS)
	registerCertificateRoutes(v1, c.Handlers.Certificate)
	registerLogRoutes(v1, c.Handlers.Log)
	registerWAFTestRoutes(v1, c.Handlers.WAFTest)
	registerWAFRoutes(v1, c.Handlers.WAF)
	registerExploitRuleRoutes(v1, c.Handlers.ExploitBlockRule)
	registerAccessListRoutes(v1, c.Handlers.AccessList)
	registerAuthProviderRoutes(v1, c.Handlers.AuthProvider)
	registerRedirectHostRoutes(v1, c.Handlers.RedirectHost)
	registerGeoRoutes(v1, c.Handlers.Geo)
	registerSecurityRoutes(v1, c.Handlers.Security)
	registerSettingsRoutes(v1, c.Handlers.Settings)
	registerSystemLogRoutes(v1, c.Handlers.SystemLog)
	registerSystemSettingsRoutes(v1, c.Handlers.SystemSettings)
	registerAuditLogRoutes(v1, c.Handlers.AuditLog)
	registerChallengeConfigRoutes(v1, c.Handlers.Challenge)
	registerCloudProviderRoutes(v1, c.Handlers.CloudProvider)
	registerFilterSubscriptionRoutes(v1, c.Handlers.FilterSubscription)
	registerTestRoutes(v1, c)
}

func registerAPITokenRoutes(v1 *echo.Group, h *handler.APITokenHandler) {
	// Token management is privileged: no dedicated scope exists, so reads
	// require settings:read and mutations settings:write. This blocks a
	// non-admin token from minting/revoking tokens (only a "*" token passes).
	tokenRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	tokenWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)

	g := v1.Group("/api-tokens")
	g.GET("", h.ListTokens, tokenRead)
	g.POST("", h.CreateToken, tokenWrite)
	g.GET("/permissions", h.GetPermissions, tokenRead)
	g.GET("/:id", h.GetToken, tokenRead)
	g.PUT("/:id", h.UpdateToken, tokenWrite)
	g.POST("/:id/revoke", h.RevokeToken, tokenWrite)
	g.DELETE("/:id", h.DeleteToken, tokenWrite)
	g.GET("/:id/usage", h.GetTokenUsage, tokenRead)
}

func registerProxyHostRoutes(v1 *echo.Group, h *handler.ProxyHostHandler) {
	// RequireAPIPermission is a no-op for session requests; it only enforces
	// scopes when the caller authenticated with an API token (H2).
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	g := v1.Group("/proxy-hosts")
	g.GET("", h.List, proxyRead)
	g.POST("", h.Create, proxyWrite)
	g.GET("/by-domain/:domain", h.GetByDomain, proxyRead)
	g.POST("/sync", h.SyncAll, proxyWrite)
	g.GET("/:id", h.GetByID, proxyRead)
	g.PUT("/:id", h.Update, proxyWrite)
	g.DELETE("/:id", h.Delete, proxyDelete)
	g.POST("/:id/regenerate", h.Regenerate, proxyWrite)
	g.POST("/:id/test", h.TestHost, proxyRead)
	g.POST("/:id/clone", h.Clone, proxyWrite)
	g.PUT("/:id/favorite", h.ToggleFavorite, proxyWrite)
}

func registerDNSProviderRoutes(v1 *echo.Group, h *handler.DNSProviderHandler) {
	// DNS providers back certificate DNS-01 issuance → certificate scopes (H2).
	certRead := authMiddleware.RequireAPIPermission(model.PermissionCertRead)
	certWrite := authMiddleware.RequireAPIPermission(model.PermissionCertWrite)
	certDelete := authMiddleware.RequireAPIPermission(model.PermissionCertDelete)

	g := v1.Group("/dns-providers")
	g.GET("", h.List, certRead)
	g.POST("", h.Create, certWrite)
	g.POST("/test", h.Test, certRead)
	g.GET("/default", h.GetDefault, certRead)
	g.GET("/:id", h.Get, certRead)
	g.PUT("/:id", h.Update, certWrite)
	g.DELETE("/:id", h.Delete, certDelete)
}

func registerDDNSRoutes(v1 *echo.Group, h *handler.DDNSHandler) {
	// DDNS records are infrastructure/DNS configuration → settings scopes (H2).
	settingsRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	settingsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)

	g := v1.Group("/ddns-records")
	g.GET("", h.List, settingsRead)
	g.POST("", h.Create, settingsWrite)
	g.POST("/sync", h.SyncAll, settingsWrite)
	g.POST("/import-from-hosts", h.ImportFromHosts, settingsWrite)
	g.GET("/:id", h.Get, settingsRead)
	g.PUT("/:id", h.Update, settingsWrite)
	g.DELETE("/:id", h.Delete, settingsWrite)
	g.POST("/:id/sync", h.SyncOne, settingsWrite)
}

func registerCertificateRoutes(v1 *echo.Group, h *handler.CertificateHandler) {
	certRead := authMiddleware.RequireAPIPermission(model.PermissionCertRead)
	certWrite := authMiddleware.RequireAPIPermission(model.PermissionCertWrite)
	certDelete := authMiddleware.RequireAPIPermission(model.PermissionCertDelete)

	g := v1.Group("/certificates")
	g.GET("", h.List, certRead)
	g.POST("", h.Create, certWrite)
	g.POST("/upload", h.Upload, certWrite)
	g.GET("/expiring", h.GetExpiring, certRead)
	g.GET("/history", h.ListHistory, certRead)
	g.DELETE("/errors", h.BulkDeleteErrors, certDelete)
	g.GET("/:id", h.Get, certRead)
	g.DELETE("/:id", h.Delete, certDelete)
	g.DELETE("/:id/error", h.ClearError, certWrite)
	g.PUT("/:id/upload", h.UpdateUpload, certWrite)
	g.POST("/:id/renew", h.Renew, certWrite)
	g.GET("/:id/logs", h.GetLogs, certRead)
	g.GET("/:id/download", h.Download, certRead)
}

func registerLogRoutes(v1 *echo.Group, h *handler.LogHandler) {
	logsRead := authMiddleware.RequireAPIPermission(model.PermissionLogsRead)
	// No logs:write scope exists; mutating log endpoints (settings, cleanup,
	// manual create) are administrative, so require settings:write.
	logsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)

	g := v1.Group("/logs")
	g.GET("", echo.WrapHandler(http.HandlerFunc(h.List)), logsRead)
	g.POST("", echo.WrapHandler(http.HandlerFunc(h.Create)), logsWrite)
	g.GET("/stats", echo.WrapHandler(http.HandlerFunc(h.GetStats)), logsRead)
	g.GET("/settings", echo.WrapHandler(http.HandlerFunc(h.GetSettings)), logsRead)
	g.PUT("/settings", echo.WrapHandler(http.HandlerFunc(h.UpdateSettings)), logsWrite)
	g.POST("/cleanup", echo.WrapHandler(http.HandlerFunc(h.Cleanup)), logsWrite)
	g.GET("/autocomplete/hosts", echo.WrapHandler(http.HandlerFunc(h.GetDistinctHosts)), logsRead)
	g.GET("/autocomplete/ips", echo.WrapHandler(http.HandlerFunc(h.GetDistinctIPs)), logsRead)
	g.GET("/autocomplete/user-agents", echo.WrapHandler(http.HandlerFunc(h.GetDistinctUserAgents)), logsRead)
	g.GET("/autocomplete/countries", echo.WrapHandler(http.HandlerFunc(h.GetDistinctCountries)), logsRead)
	g.GET("/autocomplete/uris", echo.WrapHandler(http.HandlerFunc(h.GetDistinctURIs)), logsRead)
	g.GET("/autocomplete/methods", echo.WrapHandler(http.HandlerFunc(h.GetDistinctMethods)), logsRead)
}

func registerWAFTestRoutes(v1 *echo.Group, h *handler.WAFTestHandler) {
	// WAF self-test is read-only diagnostics over the WAF → waf:read (H2).
	wafRead := authMiddleware.RequireAPIPermission(model.PermissionWAFRead)

	g := v1.Group("/waf-test")
	g.GET("/patterns", echo.WrapHandler(http.HandlerFunc(h.ListPatterns)), wafRead)
	g.POST("/test", echo.WrapHandler(http.HandlerFunc(h.Test)), wafRead)
	g.POST("/test-all", echo.WrapHandler(http.HandlerFunc(h.TestAll)), wafRead)
}

func registerWAFRoutes(v1 *echo.Group, h *handler.WAFHandler) {
	wafRead := authMiddleware.RequireAPIPermission(model.PermissionWAFRead)
	wafWrite := authMiddleware.RequireAPIPermission(model.PermissionWAFWrite)

	g := v1.Group("/waf")
	g.GET("/rules", echo.WrapHandler(http.HandlerFunc(h.GetRules)), wafRead)
	g.GET("/hosts", echo.WrapHandler(http.HandlerFunc(h.GetHostConfigs)), wafRead)
	g.GET("/hosts/:id/config", echo.WrapHandler(http.HandlerFunc(h.GetHostConfig)), wafRead)
	g.GET("/hosts/:id/history", echo.WrapHandler(http.HandlerFunc(h.GetPolicyHistory)), wafRead)
	g.POST("/hosts/:id/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.DisableRule)), wafWrite)
	g.POST("/rules/disable-by-host", echo.WrapHandler(http.HandlerFunc(h.DisableRuleByHost)), wafWrite)
	g.DELETE("/hosts/:id/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.EnableRule)), wafWrite)
	g.GET("/global/rules", echo.WrapHandler(http.HandlerFunc(h.GetGlobalRules)), wafRead)
	g.GET("/global/exclusions", echo.WrapHandler(http.HandlerFunc(h.GetGlobalExclusions)), wafRead)
	g.GET("/global/history", echo.WrapHandler(http.HandlerFunc(h.GetGlobalPolicyHistory)), wafRead)
	g.POST("/global/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.DisableGlobalRule)), wafWrite)
	g.DELETE("/global/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.EnableGlobalRule)), wafWrite)
}

func registerExploitRuleRoutes(v1 *echo.Group, h *handler.ExploitBlockRuleHandler) {
	// Exploit-block rules are WAF-adjacent security rules → waf scopes (H2).
	wafRead := authMiddleware.RequireAPIPermission(model.PermissionWAFRead)
	wafWrite := authMiddleware.RequireAPIPermission(model.PermissionWAFWrite)

	g := v1.Group("/exploit-rules")
	g.GET("", echo.WrapHandler(http.HandlerFunc(h.ListRules)), wafRead)
	g.GET("/:id", echo.WrapHandler(http.HandlerFunc(h.GetRule)), wafRead)
	g.POST("", echo.WrapHandler(http.HandlerFunc(h.CreateRule)), wafWrite)
	g.PUT("/:id", echo.WrapHandler(http.HandlerFunc(h.UpdateRule)), wafWrite)
	g.DELETE("/:id", echo.WrapHandler(http.HandlerFunc(h.DeleteRule)), wafWrite)
	g.POST("/:id/toggle", echo.WrapHandler(http.HandlerFunc(h.ToggleRule)), wafWrite)
	g.POST("/:id/global-exclude", echo.WrapHandler(http.HandlerFunc(h.AddGlobalExclusion)), wafWrite)
	g.DELETE("/:id/global-exclude", echo.WrapHandler(http.HandlerFunc(h.RemoveGlobalExclusion)), wafWrite)
	g.GET("/hosts", echo.WrapHandler(http.HandlerFunc(h.ListHostsWithExploitBlocking)), wafRead)
	g.GET("/hosts/:hostId/rules", echo.WrapHandler(http.HandlerFunc(h.GetHostRules)), wafRead)
	g.POST("/hosts/:hostId/rules/:ruleId/exclude", echo.WrapHandler(http.HandlerFunc(h.AddHostExclusion)), wafWrite)
	g.DELETE("/hosts/:hostId/rules/:ruleId/exclude", echo.WrapHandler(http.HandlerFunc(h.RemoveHostExclusion)), wafWrite)
}

func registerAccessListRoutes(v1 *echo.Group, h *handler.AccessListHandler) {
	// Access lists are applied to proxy hosts → proxy scopes (H2).
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	g := v1.Group("/access-lists")
	g.GET("", h.List, proxyRead)
	g.POST("", h.Create, proxyWrite)
	g.GET("/:id", h.Get, proxyRead)
	g.PUT("/:id", h.Update, proxyWrite)
	g.DELETE("/:id", h.Delete, proxyDelete)
}

// registerAuthProviderRoutes wires the ForwardAuth provider CRUD (#179). Auth
// providers gate proxy hosts → proxy scopes.
func registerAuthProviderRoutes(v1 *echo.Group, h *handler.AuthProviderHandler) {
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	g := v1.Group("/auth-providers")
	g.GET("", h.List, proxyRead)
	g.POST("", h.Create, proxyWrite)
	g.GET("/:id", h.Get, proxyRead)
	g.PUT("/:id", h.Update, proxyWrite)
	g.DELETE("/:id", h.Delete, proxyDelete)
}

func registerRedirectHostRoutes(v1 *echo.Group, h *handler.RedirectHostHandler) {
	// Redirect hosts are proxy-host-like resources → proxy scopes (H2).
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	g := v1.Group("/redirect-hosts")
	g.GET("", h.List, proxyRead)
	g.POST("", h.Create, proxyWrite)
	g.POST("/sync", h.SyncAll, proxyWrite)
	g.GET("/:id", h.Get, proxyRead)
	g.PUT("/:id", h.Update, proxyWrite)
	g.DELETE("/:id", h.Delete, proxyDelete)
}

func registerGeoRoutes(v1 *echo.Group, h *handler.GeoHandler) {
	// GeoIP filtering is per-proxy-host configuration → proxy scopes (H2).
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	v1.GET("/proxy-hosts/:id/geo", h.GetByProxyHost, proxyRead)
	v1.POST("/proxy-hosts/:id/geo", h.SetForProxyHost, proxyWrite)
	v1.PUT("/proxy-hosts/:id/geo", h.UpdateForProxyHost, proxyWrite)
	v1.DELETE("/proxy-hosts/:id/geo", h.DeleteForProxyHost, proxyDelete)
	v1.GET("/geo/countries", h.GetCountryCodes, proxyRead)
}

func registerSecurityRoutes(v1 *echo.Group, h *handler.SecurityHandler) {
	// All security features here are per-proxy-host (or global) proxy
	// configuration, so they map to the proxy scopes (H2).
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	// Rate limit (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/rate-limit", h.GetRateLimit, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/rate-limit", h.UpsertRateLimit, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/rate-limit", h.DeleteRateLimit, proxyDelete)

	// Fail2ban (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/fail2ban", h.GetFail2ban, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/fail2ban", h.UpsertFail2ban, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/fail2ban", h.DeleteFail2ban, proxyDelete)

	// Banned IPs
	bannedIPs := v1.Group("/banned-ips")
	bannedIPs.GET("", h.ListBannedIPs, proxyRead)
	bannedIPs.POST("", h.BanIP, proxyWrite)
	bannedIPs.POST("/bulk-unban", h.UnbanIPsBulk, proxyWrite)
	bannedIPs.DELETE("/:id", h.UnbanIP, proxyDelete)
	bannedIPs.DELETE("", h.UnbanIPByAddress, proxyDelete)
	bannedIPs.GET("/history", h.GetIPBanHistory, proxyRead)
	bannedIPs.GET("/history/stats", h.GetIPBanHistoryStats, proxyRead)
	bannedIPs.GET("/history/ip/:ip", h.GetIPBanHistoryByIP, proxyRead)

	// Bot filter (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/bot-filter", h.GetBotFilter, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/bot-filter", h.UpsertBotFilter, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/bot-filter", h.DeleteBotFilter, proxyDelete)
	v1.GET("/bots/known", h.GetKnownBots, proxyRead)

	// URI block (per proxy host)
	v1.GET("/uri-blocks", h.ListAllURIBlocks, proxyRead)
	v1.POST("/uri-blocks/bulk-add-rule", h.BulkAddURIBlockRule, proxyWrite)
	v1.GET("/proxy-hosts/:proxyHostId/uri-block", h.GetURIBlock, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/uri-block", h.UpsertURIBlock, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/uri-block", h.DeleteURIBlock, proxyDelete)
	v1.POST("/proxy-hosts/:proxyHostId/uri-block/rules", h.AddURIBlockRule, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/uri-block/rules/:ruleId", h.RemoveURIBlockRule, proxyDelete)

	// Global URI block
	v1.GET("/global-uri-block", h.GetGlobalURIBlock, proxyRead)
	v1.PUT("/global-uri-block", h.UpdateGlobalURIBlock, proxyWrite)
	v1.POST("/global-uri-block/rules", h.AddGlobalURIBlockRule, proxyWrite)
	v1.DELETE("/global-uri-block/rules/:ruleId", h.RemoveGlobalURIBlockRule, proxyDelete)

	// Security headers (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/security-headers", h.GetSecurityHeaders, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/security-headers", h.UpsertSecurityHeaders, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/security-headers", h.DeleteSecurityHeaders, proxyDelete)
	v1.GET("/security-headers/presets", h.GetSecurityHeaderPresets, proxyRead)
	v1.POST("/proxy-hosts/:proxyHostId/security-headers/preset/:preset", h.ApplySecurityHeaderPreset, proxyWrite)

	// Upstream (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/upstream", h.GetUpstream, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/upstream", h.UpsertUpstream, proxyWrite)
	v1.DELETE("/proxy-hosts/:proxyHostId/upstream", h.DeleteUpstream, proxyDelete)
	v1.GET("/upstreams/:id/health", h.GetUpstreamHealth, proxyRead)
}

func registerSettingsRoutes(v1 *echo.Group, h *handler.SettingsHandler) {
	settingsRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	settingsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)

	settings := v1.Group("/settings")
	settings.GET("", h.GetGlobalSettings, settingsRead)
	settings.PUT("", h.UpdateGlobalSettings, settingsWrite)
	settings.POST("/reset", h.ResetGlobalSettings, settingsWrite)
	settings.GET("/presets", h.GetSettingsPresets, settingsRead)
	settings.POST("/preset/:preset", h.ApplySettingsPreset, settingsWrite)

	dashboard := v1.Group("/dashboard")
	dashboard.GET("", h.GetDashboard, settingsRead)
	dashboard.GET("/health", h.GetSystemHealth, settingsRead)
	dashboard.GET("/health/history", h.GetSystemHealthHistory, settingsRead)
	dashboard.GET("/stats/hourly", h.GetHourlyStats, settingsRead)
	dashboard.GET("/containers", h.GetDockerStats, settingsRead)
	dashboard.GET("/geoip-stats", h.GetGeoIPStats, settingsRead)

	v1.GET("/docker/containers", h.ListDockerContainers, settingsRead)

	backupRead := authMiddleware.RequireAPIPermission(model.PermissionBackupRead)
	backupCreate := authMiddleware.RequireAPIPermission(model.PermissionBackupCreate)
	backupRestore := authMiddleware.RequireAPIPermission(model.PermissionBackupRestore)

	backups := v1.Group("/backups")
	backups.GET("", h.ListBackups, backupRead)
	backups.POST("", h.CreateBackup, backupCreate)
	backups.POST("/upload-restore", h.UploadAndRestoreBackup, backupRestore)
	backups.GET("/stats", h.GetBackupStats, backupRead)
	backups.GET("/:id", h.GetBackup, backupRead)
	backups.GET("/:id/download", h.DownloadBackup, backupRead)
	backups.DELETE("/:id", h.DeleteBackup, backupCreate)
	backups.POST("/:id/restore", h.RestoreBackup, backupRestore)
}

func registerSystemLogRoutes(v1 *echo.Group, h *handler.SystemLogHandler) {
	// System logs are administrative observability data → settings scopes (H2).
	settingsRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	settingsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)

	g := v1.Group("/system-logs")
	g.GET("", h.List, settingsRead)
	g.GET("/stats", h.GetStats, settingsRead)
	g.POST("/cleanup", h.Cleanup, settingsWrite)
	g.GET("/sources", h.GetSources, settingsRead)
	g.GET("/levels", h.GetLevels, settingsRead)
}

func registerSystemSettingsRoutes(v1 *echo.Group, h *handler.SystemSettingsHandler) {
	settingsRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	settingsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)

	g := v1.Group("/system-settings")
	g.GET("", h.GetSystemSettings, settingsRead)
	g.PUT("", h.UpdateSystemSettings, settingsWrite)
	g.GET("/geoip/status", h.GetGeoIPStatus, settingsRead)
	g.POST("/geoip/update", h.UpdateGeoIPDatabases, settingsWrite)
	g.GET("/geoip/history", h.GetGeoIPHistory, settingsRead)
	g.GET("/update/check", h.CheckUpdate, settingsRead)
	g.POST("/acme/test", h.TestACME, settingsWrite)

	g.GET("/log-files", h.ListLogFiles, settingsRead)
	g.GET("/log-files/:filename/download", h.DownloadLogFile, settingsRead)
	g.GET("/log-files/:filename/view", h.ViewLogFile, settingsRead)
	g.DELETE("/log-files/:filename", h.DeleteLogFile, settingsWrite)
	g.POST("/log-files/rotate", h.TriggerLogRotation, settingsWrite)

	g.GET("/logs", h.GetSystemLogConfig, settingsRead)
	g.PUT("/logs", h.UpdateSystemLogConfig, settingsWrite)
}

func registerAuditLogRoutes(v1 *echo.Group, h *handler.AuditLogHandler) {
	// Audit logs are administrative read-only observability data.
	auditRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)

	g := v1.Group("/audit-logs")
	g.GET("", h.ListAuditLogs, auditRead)
	g.GET("/actions", h.GetActions, auditRead)
	g.GET("/resource-types", h.GetResourceTypes, auditRead)
	g.GET("/api-tokens", h.ListAPITokenUsage, auditRead)
}

func registerChallengeConfigRoutes(v1 *echo.Group, h *handler.ChallengeHandler) {
	// Global challenge config is a settings-level concern; per-proxy-host
	// challenge config maps to proxy scopes (H2).
	settingsRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	settingsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	challengeConfig := v1.Group("/challenge-config")
	challengeConfig.GET("", h.GetGlobalConfig, settingsRead)
	challengeConfig.PUT("", h.UpdateGlobalConfig, settingsWrite)
	challengeConfig.GET("/stats", h.GetStats, settingsRead)

	v1.GET("/proxy-hosts/:id/challenge", h.GetProxyHostConfig, proxyRead)
	v1.PUT("/proxy-hosts/:id/challenge", h.UpdateProxyHostConfig, proxyWrite)
	v1.DELETE("/proxy-hosts/:id/challenge", h.DeleteProxyHostConfig, proxyDelete)
}

func registerCloudProviderRoutes(v1 *echo.Group, h *handler.CloudProviderHandler) {
	// Provider catalog is a settings-level concern; per-proxy-host blocked
	// providers map to proxy scopes (H2).
	settingsRead := authMiddleware.RequireAPIPermission(model.PermissionSettingsRead)
	settingsWrite := authMiddleware.RequireAPIPermission(model.PermissionSettingsWrite)
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)

	g := v1.Group("/cloud-providers")
	g.GET("", h.ListProviders, settingsRead)
	g.GET("/by-region", h.ListProvidersByRegion, settingsRead)
	g.GET("/:slug", h.GetProvider, settingsRead)
	g.POST("", h.CreateProvider, settingsWrite)
	g.PUT("/:slug", h.UpdateProvider, settingsWrite)
	g.DELETE("/:slug", h.DeleteProvider, settingsWrite)

	v1.GET("/proxy-hosts/:proxyHostId/blocked-cloud-providers", h.GetBlockedProviders, proxyRead)
	v1.PUT("/proxy-hosts/:proxyHostId/blocked-cloud-providers", h.SetBlockedProviders, proxyWrite)
}

func registerFilterSubscriptionRoutes(v1 *echo.Group, h *handler.FilterSubscriptionHandler) {
	// Filter subscriptions are security block-lists applied to proxy hosts →
	// proxy scopes (H2).
	proxyRead := authMiddleware.RequireAPIPermission(model.PermissionProxyRead)
	proxyWrite := authMiddleware.RequireAPIPermission(model.PermissionProxyWrite)
	proxyDelete := authMiddleware.RequireAPIPermission(model.PermissionProxyDelete)

	g := v1.Group("/filter-subscriptions")
	g.GET("/catalog", h.GetCatalog, proxyRead)
	g.POST("/catalog/subscribe", h.SubscribeFromCatalog, proxyWrite)
	g.GET("", h.List, proxyRead)
	g.POST("", h.Create, proxyWrite)
	g.GET("/:id", h.GetByID, proxyRead)
	g.PUT("/:id", h.Update, proxyWrite)
	g.DELETE("/:id", h.Delete, proxyDelete)
	g.POST("/:id/refresh", h.Refresh, proxyWrite)
	g.GET("/:id/exclusions", h.ListExclusions, proxyRead)
	g.POST("/:id/exclusions/:hostId", h.AddExclusion, proxyWrite)
	g.DELETE("/:id/exclusions/:hostId", h.RemoveExclusion, proxyDelete)
	g.GET("/:id/entry-exclusions", h.ListEntryExclusions, proxyRead)
	g.POST("/:id/entry-exclusions", h.AddEntryExclusion, proxyWrite)
	g.DELETE("/:id/entry-exclusions", h.RemoveEntryExclusion, proxyDelete)
}

func registerTestRoutes(v1 *echo.Group, c *Container) {
	test := v1.Group("/test")
	// Diagnostic/self-check endpoints are administrative reads → settings:read.
	// No-op for session requests (H2).
	test.Use(authMiddleware.RequireAPIPermission(model.PermissionSettingsRead))

	test.POST("/nginx-config", func(ec echo.Context) error {
		if err := c.Nginx.TestConfig(ec.Request().Context()); err != nil {
			return ec.JSON(http.StatusBadRequest, map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
		}
		return ec.JSON(http.StatusOK, map[string]string{
			"status":  "ok",
			"message": "Nginx configuration is valid",
		})
	})

	test.POST("/proxy-host/:id", func(ec echo.Context) error {
		id := ec.Param("id")
		host, err := c.Services.ProxyHost.GetByID(ec.Request().Context(), id)
		if err != nil {
			return ec.JSON(http.StatusInternalServerError, map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
		}
		if host == nil {
			return ec.JSON(http.StatusNotFound, map[string]string{
				"status": "error",
				"error":  "Proxy host not found",
			})
		}

		if host.IsStream() {
			result, err := service.NewProxyHostTester().TestUpstream(ec.Request().Context(), host)
			if err != nil {
				return ec.JSON(http.StatusInternalServerError, map[string]string{
					"status": "error",
					"error":  err.Error(),
				})
			}
			status := config.StatusOK
			if !result.Success {
				status = config.StatusError
			}
			return ec.JSON(http.StatusOK, map[string]interface{}{
				"status":           status,
				"host":             host,
				"upstream":         result.Domain,
				"response_time_ms": result.ResponseTime,
				"error":            result.Error,
			})
		}

		upstreamURL := fmt.Sprintf("%s://%s:%d", host.ForwardScheme, host.ForwardHost, host.ForwardPort)
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, err := http.NewRequest("HEAD", upstreamURL, nil)
		if err != nil {
			return ec.JSON(http.StatusOK, map[string]interface{}{
				"status":   config.StatusError,
				"error":    "Failed to create request",
				"host":     host,
				"upstream": upstreamURL,
			})
		}
		resp, err := client.Do(req)
		if err != nil {
			// If forward_host is a private IP (docker internal), retry via nginx container
			if ip := net.ParseIP(host.ForwardHost); ip != nil && ip.IsPrivate() {
				testCtx, cancel := context.WithTimeout(ec.Request().Context(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(testCtx, "docker", "exec", c.Config.NginxContainer,
					"curl", "-sk", "--head", "--max-time", "4",
					"-o", "/dev/null", "-w", "%{http_code}", upstreamURL)
				if output, execErr := cmd.CombinedOutput(); execErr == nil {
					if code, _ := strconv.Atoi(strings.TrimSpace(string(output))); code > 0 {
						return ec.JSON(http.StatusOK, map[string]interface{}{
							"status":      config.StatusOK,
							"host":        host,
							"upstream":    upstreamURL,
							"status_code": code,
						})
					}
				}
			}
			return ec.JSON(http.StatusOK, map[string]interface{}{
				"status":   config.StatusError,
				"error":    "Connection failed",
				"host":     host,
				"upstream": upstreamURL,
			})
		}
		defer resp.Body.Close()

		return ec.JSON(http.StatusOK, map[string]interface{}{
			"status":      config.StatusOK,
			"host":        host,
			"upstream":    upstreamURL,
			"status_code": resp.StatusCode,
		})
	})

	test.GET("/system/self-check", c.Handlers.Settings.SelfCheck)
	test.GET("/backup-restore", c.Handlers.Settings.TestBackupRestore)
	test.GET("/dashboard/queries", c.Handlers.Settings.TestDashboardQueries)
}
