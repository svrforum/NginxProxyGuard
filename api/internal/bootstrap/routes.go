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

	registerAPITokenRoutes(v1, c.Handlers.APIToken)
	registerProxyHostRoutes(v1, c.Handlers.ProxyHost)
	registerDNSProviderRoutes(v1, c.Handlers.DNSProvider)
	registerCertificateRoutes(v1, c.Handlers.Certificate)
	registerLogRoutes(v1, c.Handlers.Log)
	registerWAFTestRoutes(v1, c.Handlers.WAFTest)
	registerWAFRoutes(v1, c.Handlers.WAF)
	registerExploitRuleRoutes(v1, c.Handlers.ExploitBlockRule)
	registerAccessListRoutes(v1, c.Handlers.AccessList)
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
	g := v1.Group("/api-tokens")
	g.GET("", h.ListTokens)
	g.POST("", h.CreateToken)
	g.GET("/permissions", h.GetPermissions)
	g.GET("/:id", h.GetToken)
	g.PUT("/:id", h.UpdateToken)
	g.POST("/:id/revoke", h.RevokeToken)
	g.DELETE("/:id", h.DeleteToken)
	g.GET("/:id/usage", h.GetTokenUsage)
}

func registerProxyHostRoutes(v1 *echo.Group, h *handler.ProxyHostHandler) {
	g := v1.Group("/proxy-hosts")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/by-domain/:domain", h.GetByDomain)
	g.POST("/sync", h.SyncAll)
	g.GET("/:id", h.GetByID)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.POST("/:id/regenerate", h.Regenerate)
	g.POST("/:id/test", h.TestHost)
	g.POST("/:id/clone", h.Clone)
	g.PUT("/:id/favorite", h.ToggleFavorite)
}

func registerDNSProviderRoutes(v1 *echo.Group, h *handler.DNSProviderHandler) {
	g := v1.Group("/dns-providers")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.POST("/test", h.Test)
	g.GET("/default", h.GetDefault)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}

func registerCertificateRoutes(v1 *echo.Group, h *handler.CertificateHandler) {
	g := v1.Group("/certificates")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.POST("/upload", h.Upload)
	g.GET("/expiring", h.GetExpiring)
	g.GET("/history", h.ListHistory)
	g.DELETE("/errors", h.BulkDeleteErrors)
	g.GET("/:id", h.Get)
	g.DELETE("/:id", h.Delete)
	g.DELETE("/:id/error", h.ClearError)
	g.PUT("/:id/upload", h.UpdateUpload)
	g.POST("/:id/renew", h.Renew)
	g.GET("/:id/logs", h.GetLogs)
	g.GET("/:id/download", h.Download)
}

func registerLogRoutes(v1 *echo.Group, h *handler.LogHandler) {
	g := v1.Group("/logs")
	g.GET("", echo.WrapHandler(http.HandlerFunc(h.List)))
	g.POST("", echo.WrapHandler(http.HandlerFunc(h.Create)))
	g.GET("/stats", echo.WrapHandler(http.HandlerFunc(h.GetStats)))
	g.GET("/settings", echo.WrapHandler(http.HandlerFunc(h.GetSettings)))
	g.PUT("/settings", echo.WrapHandler(http.HandlerFunc(h.UpdateSettings)))
	g.POST("/cleanup", echo.WrapHandler(http.HandlerFunc(h.Cleanup)))
	g.GET("/autocomplete/hosts", echo.WrapHandler(http.HandlerFunc(h.GetDistinctHosts)))
	g.GET("/autocomplete/ips", echo.WrapHandler(http.HandlerFunc(h.GetDistinctIPs)))
	g.GET("/autocomplete/user-agents", echo.WrapHandler(http.HandlerFunc(h.GetDistinctUserAgents)))
	g.GET("/autocomplete/countries", echo.WrapHandler(http.HandlerFunc(h.GetDistinctCountries)))
	g.GET("/autocomplete/uris", echo.WrapHandler(http.HandlerFunc(h.GetDistinctURIs)))
	g.GET("/autocomplete/methods", echo.WrapHandler(http.HandlerFunc(h.GetDistinctMethods)))
}

func registerWAFTestRoutes(v1 *echo.Group, h *handler.WAFTestHandler) {
	g := v1.Group("/waf-test")
	g.GET("/patterns", echo.WrapHandler(http.HandlerFunc(h.ListPatterns)))
	g.POST("/test", echo.WrapHandler(http.HandlerFunc(h.Test)))
	g.POST("/test-all", echo.WrapHandler(http.HandlerFunc(h.TestAll)))
}

func registerWAFRoutes(v1 *echo.Group, h *handler.WAFHandler) {
	g := v1.Group("/waf")
	g.GET("/rules", echo.WrapHandler(http.HandlerFunc(h.GetRules)))
	g.GET("/hosts", echo.WrapHandler(http.HandlerFunc(h.GetHostConfigs)))
	g.GET("/hosts/:id/config", echo.WrapHandler(http.HandlerFunc(h.GetHostConfig)))
	g.GET("/hosts/:id/history", echo.WrapHandler(http.HandlerFunc(h.GetPolicyHistory)))
	g.POST("/hosts/:id/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.DisableRule)))
	g.POST("/rules/disable-by-host", echo.WrapHandler(http.HandlerFunc(h.DisableRuleByHost)))
	g.DELETE("/hosts/:id/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.EnableRule)))
	g.GET("/global/rules", echo.WrapHandler(http.HandlerFunc(h.GetGlobalRules)))
	g.GET("/global/exclusions", echo.WrapHandler(http.HandlerFunc(h.GetGlobalExclusions)))
	g.GET("/global/history", echo.WrapHandler(http.HandlerFunc(h.GetGlobalPolicyHistory)))
	g.POST("/global/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.DisableGlobalRule)))
	g.DELETE("/global/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(h.EnableGlobalRule)))
}

func registerExploitRuleRoutes(v1 *echo.Group, h *handler.ExploitBlockRuleHandler) {
	g := v1.Group("/exploit-rules")
	g.GET("", echo.WrapHandler(http.HandlerFunc(h.ListRules)))
	g.GET("/:id", echo.WrapHandler(http.HandlerFunc(h.GetRule)))
	g.POST("", echo.WrapHandler(http.HandlerFunc(h.CreateRule)))
	g.PUT("/:id", echo.WrapHandler(http.HandlerFunc(h.UpdateRule)))
	g.DELETE("/:id", echo.WrapHandler(http.HandlerFunc(h.DeleteRule)))
	g.POST("/:id/toggle", echo.WrapHandler(http.HandlerFunc(h.ToggleRule)))
	g.POST("/:id/global-exclude", echo.WrapHandler(http.HandlerFunc(h.AddGlobalExclusion)))
	g.DELETE("/:id/global-exclude", echo.WrapHandler(http.HandlerFunc(h.RemoveGlobalExclusion)))
	g.GET("/hosts", echo.WrapHandler(http.HandlerFunc(h.ListHostsWithExploitBlocking)))
	g.GET("/hosts/:hostId/rules", echo.WrapHandler(http.HandlerFunc(h.GetHostRules)))
	g.POST("/hosts/:hostId/rules/:ruleId/exclude", echo.WrapHandler(http.HandlerFunc(h.AddHostExclusion)))
	g.DELETE("/hosts/:hostId/rules/:ruleId/exclude", echo.WrapHandler(http.HandlerFunc(h.RemoveHostExclusion)))
}

func registerAccessListRoutes(v1 *echo.Group, h *handler.AccessListHandler) {
	g := v1.Group("/access-lists")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}

func registerRedirectHostRoutes(v1 *echo.Group, h *handler.RedirectHostHandler) {
	g := v1.Group("/redirect-hosts")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.POST("/sync", h.SyncAll)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}

func registerGeoRoutes(v1 *echo.Group, h *handler.GeoHandler) {
	v1.GET("/proxy-hosts/:id/geo", h.GetByProxyHost)
	v1.POST("/proxy-hosts/:id/geo", h.SetForProxyHost)
	v1.PUT("/proxy-hosts/:id/geo", h.UpdateForProxyHost)
	v1.DELETE("/proxy-hosts/:id/geo", h.DeleteForProxyHost)
	v1.GET("/geo/countries", h.GetCountryCodes)
}

func registerSecurityRoutes(v1 *echo.Group, h *handler.SecurityHandler) {
	// Rate limit (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/rate-limit", h.GetRateLimit)
	v1.PUT("/proxy-hosts/:proxyHostId/rate-limit", h.UpsertRateLimit)
	v1.DELETE("/proxy-hosts/:proxyHostId/rate-limit", h.DeleteRateLimit)

	// Fail2ban (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/fail2ban", h.GetFail2ban)
	v1.PUT("/proxy-hosts/:proxyHostId/fail2ban", h.UpsertFail2ban)
	v1.DELETE("/proxy-hosts/:proxyHostId/fail2ban", h.DeleteFail2ban)

	// Banned IPs
	bannedIPs := v1.Group("/banned-ips")
	bannedIPs.GET("", h.ListBannedIPs)
	bannedIPs.POST("", h.BanIP)
	bannedIPs.DELETE("/:id", h.UnbanIP)
	bannedIPs.DELETE("", h.UnbanIPByAddress)
	bannedIPs.GET("/history", h.GetIPBanHistory)
	bannedIPs.GET("/history/stats", h.GetIPBanHistoryStats)
	bannedIPs.GET("/history/ip/:ip", h.GetIPBanHistoryByIP)

	// Bot filter (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/bot-filter", h.GetBotFilter)
	v1.PUT("/proxy-hosts/:proxyHostId/bot-filter", h.UpsertBotFilter)
	v1.DELETE("/proxy-hosts/:proxyHostId/bot-filter", h.DeleteBotFilter)
	v1.GET("/bots/known", h.GetKnownBots)

	// URI block (per proxy host)
	v1.GET("/uri-blocks", h.ListAllURIBlocks)
	v1.POST("/uri-blocks/bulk-add-rule", h.BulkAddURIBlockRule)
	v1.GET("/proxy-hosts/:proxyHostId/uri-block", h.GetURIBlock)
	v1.PUT("/proxy-hosts/:proxyHostId/uri-block", h.UpsertURIBlock)
	v1.DELETE("/proxy-hosts/:proxyHostId/uri-block", h.DeleteURIBlock)
	v1.POST("/proxy-hosts/:proxyHostId/uri-block/rules", h.AddURIBlockRule)
	v1.DELETE("/proxy-hosts/:proxyHostId/uri-block/rules/:ruleId", h.RemoveURIBlockRule)

	// Global URI block
	v1.GET("/global-uri-block", h.GetGlobalURIBlock)
	v1.PUT("/global-uri-block", h.UpdateGlobalURIBlock)
	v1.POST("/global-uri-block/rules", h.AddGlobalURIBlockRule)
	v1.DELETE("/global-uri-block/rules/:ruleId", h.RemoveGlobalURIBlockRule)

	// Security headers (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/security-headers", h.GetSecurityHeaders)
	v1.PUT("/proxy-hosts/:proxyHostId/security-headers", h.UpsertSecurityHeaders)
	v1.DELETE("/proxy-hosts/:proxyHostId/security-headers", h.DeleteSecurityHeaders)
	v1.GET("/security-headers/presets", h.GetSecurityHeaderPresets)
	v1.POST("/proxy-hosts/:proxyHostId/security-headers/preset/:preset", h.ApplySecurityHeaderPreset)

	// Upstream (per proxy host)
	v1.GET("/proxy-hosts/:proxyHostId/upstream", h.GetUpstream)
	v1.PUT("/proxy-hosts/:proxyHostId/upstream", h.UpsertUpstream)
	v1.DELETE("/proxy-hosts/:proxyHostId/upstream", h.DeleteUpstream)
	v1.GET("/upstreams/:id/health", h.GetUpstreamHealth)
}

func registerSettingsRoutes(v1 *echo.Group, h *handler.SettingsHandler) {
	settings := v1.Group("/settings")
	settings.GET("", h.GetGlobalSettings)
	settings.PUT("", h.UpdateGlobalSettings)
	settings.POST("/reset", h.ResetGlobalSettings)
	settings.GET("/presets", h.GetSettingsPresets)
	settings.POST("/preset/:preset", h.ApplySettingsPreset)

	dashboard := v1.Group("/dashboard")
	dashboard.GET("", h.GetDashboard)
	dashboard.GET("/health", h.GetSystemHealth)
	dashboard.GET("/health/history", h.GetSystemHealthHistory)
	dashboard.GET("/stats/hourly", h.GetHourlyStats)
	dashboard.GET("/containers", h.GetDockerStats)
	dashboard.GET("/geoip-stats", h.GetGeoIPStats)

	v1.GET("/docker/containers", h.ListDockerContainers)

	backups := v1.Group("/backups")
	backups.GET("", h.ListBackups)
	backups.POST("", h.CreateBackup)
	backups.POST("/upload-restore", h.UploadAndRestoreBackup)
	backups.GET("/stats", h.GetBackupStats)
	backups.GET("/:id", h.GetBackup)
	backups.GET("/:id/download", h.DownloadBackup)
	backups.DELETE("/:id", h.DeleteBackup)
	backups.POST("/:id/restore", h.RestoreBackup)
}

func registerSystemLogRoutes(v1 *echo.Group, h *handler.SystemLogHandler) {
	g := v1.Group("/system-logs")
	g.GET("", h.List)
	g.GET("/stats", h.GetStats)
	g.POST("/cleanup", h.Cleanup)
	g.GET("/sources", h.GetSources)
	g.GET("/levels", h.GetLevels)
}

func registerSystemSettingsRoutes(v1 *echo.Group, h *handler.SystemSettingsHandler) {
	g := v1.Group("/system-settings")
	g.GET("", h.GetSystemSettings)
	g.PUT("", h.UpdateSystemSettings)
	g.GET("/geoip/status", h.GetGeoIPStatus)
	g.POST("/geoip/update", h.UpdateGeoIPDatabases)
	g.GET("/geoip/history", h.GetGeoIPHistory)
	g.POST("/acme/test", h.TestACME)

	g.GET("/log-files", h.ListLogFiles)
	g.GET("/log-files/:filename/download", h.DownloadLogFile)
	g.GET("/log-files/:filename/view", h.ViewLogFile)
	g.DELETE("/log-files/:filename", h.DeleteLogFile)
	g.POST("/log-files/rotate", h.TriggerLogRotation)

	g.GET("/logs", h.GetSystemLogConfig)
	g.PUT("/logs", h.UpdateSystemLogConfig)
}

func registerAuditLogRoutes(v1 *echo.Group, h *handler.AuditLogHandler) {
	g := v1.Group("/audit-logs")
	g.GET("", h.ListAuditLogs)
	g.GET("/actions", h.GetActions)
	g.GET("/resource-types", h.GetResourceTypes)
	g.GET("/api-tokens", h.ListAPITokenUsage)
}

func registerChallengeConfigRoutes(v1 *echo.Group, h *handler.ChallengeHandler) {
	challengeConfig := v1.Group("/challenge-config")
	challengeConfig.GET("", h.GetGlobalConfig)
	challengeConfig.PUT("", h.UpdateGlobalConfig)
	challengeConfig.GET("/stats", h.GetStats)

	v1.GET("/proxy-hosts/:id/challenge", h.GetProxyHostConfig)
	v1.PUT("/proxy-hosts/:id/challenge", h.UpdateProxyHostConfig)
	v1.DELETE("/proxy-hosts/:id/challenge", h.DeleteProxyHostConfig)
}

func registerCloudProviderRoutes(v1 *echo.Group, h *handler.CloudProviderHandler) {
	g := v1.Group("/cloud-providers")
	g.GET("", h.ListProviders)
	g.GET("/by-region", h.ListProvidersByRegion)
	g.GET("/:slug", h.GetProvider)
	g.POST("", h.CreateProvider)
	g.PUT("/:slug", h.UpdateProvider)
	g.DELETE("/:slug", h.DeleteProvider)

	v1.GET("/proxy-hosts/:proxyHostId/blocked-cloud-providers", h.GetBlockedProviders)
	v1.PUT("/proxy-hosts/:proxyHostId/blocked-cloud-providers", h.SetBlockedProviders)
}

func registerFilterSubscriptionRoutes(v1 *echo.Group, h *handler.FilterSubscriptionHandler) {
	g := v1.Group("/filter-subscriptions")
	g.GET("/catalog", h.GetCatalog)
	g.POST("/catalog/subscribe", h.SubscribeFromCatalog)
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.GetByID)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.POST("/:id/refresh", h.Refresh)
	g.GET("/:id/exclusions", h.ListExclusions)
	g.POST("/:id/exclusions/:hostId", h.AddExclusion)
	g.DELETE("/:id/exclusions/:hostId", h.RemoveExclusion)
	g.GET("/:id/entry-exclusions", h.ListEntryExclusions)
	g.POST("/:id/entry-exclusions", h.AddEntryExclusion)
	g.DELETE("/:id/entry-exclusions", h.RemoveEntryExclusion)
}

func registerTestRoutes(v1 *echo.Group, c *Container) {
	test := v1.Group("/test")

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
