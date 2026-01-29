package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/handler"
	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/scheduler"
	"nginx-proxy-guard/internal/service"
	"nginx-proxy-guard/pkg/cache"
)

func main() {
	cfg := config.Load()

	// Initialize database
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to database")

	// Run database migrations
	if err := db.RunMigrations(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize Redis cache (Valkey)
	redisCache, err := cache.NewRedisClient(cfg.RedisURL)
	if err != nil {
		log.Printf("Warning: Failed to initialize Redis cache: %v", err)
		// Continue without cache - graceful degradation
	} else {
		defer redisCache.Close()
		log.Println("Redis cache client initialized")
	}

	// Initialize nginx manager
	nginxManager := nginx.NewManager(
		cfg.NginxConfigPath,
		cfg.NginxCertsPath,
	)

	// Initialize repositories
	proxyHostRepo := repository.NewProxyHostRepository(db)
	dnsProviderRepo := repository.NewDNSProviderRepository(db)
	certificateRepo := repository.NewCertificateRepository(db)
	logRepo := repository.NewLogRepository(db)
	wafRepo := repository.NewWAFRepository(db)
	accessListRepo := repository.NewAccessListRepository(db)
	redirectHostRepo := repository.NewRedirectHostRepository(db)
	geoRepo := repository.NewGeoRepository(db)
	rateLimitRepo := repository.NewRateLimitRepository(db.DB)
	ipBanHistoryRepo := repository.NewIPBanHistoryRepository(db.DB)
	botFilterRepo := repository.NewBotFilterRepository(db.DB)
	securityHeadersRepo := repository.NewSecurityHeadersRepository(db.DB)
	upstreamRepo := repository.NewUpstreamRepository(db.DB)
	globalSettingsRepo := repository.NewGlobalSettingsRepository(db.DB)
	dashboardRepo := repository.NewDashboardRepository(db.DB)
	backupRepo := repository.NewBackupRepository(db.DB)
	systemLogRepo := repository.NewSystemLogRepository(db.DB)
	authRepo := repository.NewAuthRepository(db.DB)
	systemSettingsRepo := repository.NewSystemSettingsRepository(db.DB)
	apiTokenRepo := repository.NewAPITokenRepository(db.DB)
	auditLogRepo := repository.NewAuditLogRepository(db.DB)
	challengeRepo := repository.NewChallengeRepository(db.DB)
	cloudProviderRepo := repository.NewCloudProviderRepository(db.DB)
	uriBlockRepo := repository.NewURIBlockRepository(db)
	geoIPHistoryRepo := repository.NewGeoIPHistoryRepository(db.DB)
	exploitBlockRuleRepo := repository.NewExploitBlockRuleRepository(db.DB)

	// Wire up Valkey cache to repositories (if available)
	if redisCache != nil {
		proxyHostRepo.SetCache(redisCache)
		globalSettingsRepo.SetCache(redisCache)
		systemSettingsRepo.SetCache(redisCache)
		exploitBlockRuleRepo.SetCache(redisCache)
		log.Println("Valkey cache wired to repositories")
	}

	// Initialize services
	proxyHostService := service.NewProxyHostService(
		proxyHostRepo, wafRepo, accessListRepo, geoRepo,
		rateLimitRepo, securityHeadersRepo, botFilterRepo, upstreamRepo,
		systemSettingsRepo, cloudProviderRepo, globalSettingsRepo, uriBlockRepo,
		exploitBlockRuleRepo, certificateRepo, nginxManager,
	)
	dnsProviderService := service.NewDNSProviderService(dnsProviderRepo)
	certificateService := service.NewCertificateService(
		certificateRepo,
		dnsProviderRepo,
		systemSettingsRepo,
		cfg.NginxCertsPath,
		cfg.ACMEEmail,
		redisCache,
	)

	// Set up certificate ready callback to regenerate nginx configs
	// when a certificate is issued or renewed
	certificateService.SetCertificateReadyCallback(func(ctx context.Context, certificateID string) error {
		log.Printf("Certificate %s is ready, regenerating nginx configs for affected proxy hosts", certificateID)
		return proxyHostService.RegenerateConfigsForCertificate(ctx, certificateID)
	})

	// Create startup context with timeout to prevent hanging
	startupCtx, startupCancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer startupCancel()

	// Sync all proxy host configs on startup to apply any template changes
	log.Println("[Startup] Syncing all proxy host configs...")
	if err := proxyHostService.SyncAllConfigs(startupCtx); err != nil {
		log.Printf("[Startup] Warning: failed to sync proxy host configs: %v", err)
	} else {
		log.Println("[Startup] Proxy host configs synced successfully")
	}

	// Sync all redirect host configs on startup
	log.Println("[Startup] Syncing all redirect host configs...")
	redirectHosts, _, err := redirectHostRepo.List(startupCtx, 1, config.MaxWAFRulesLimit)
	if err != nil {
		log.Printf("[Startup] Warning: failed to list redirect hosts: %v", err)
	} else if err := nginxManager.GenerateAllRedirectConfigs(startupCtx, redirectHosts); err != nil {
		log.Printf("[Startup] Warning: failed to sync redirect host configs: %v", err)
	} else {
		log.Println("[Startup] Redirect host configs synced successfully")
	}

	// Regenerate default server config on startup
	// Read from global_settings (used by /settings/global UI)
	log.Println("[Startup] Regenerating default server config...")
	directIPAction := "allow" // Default
	if settings, err := globalSettingsRepo.Get(startupCtx); err == nil && settings != nil {
		directIPAction = settings.DirectIPAccessAction
	}
	if err := nginxManager.GenerateDefaultServerConfig(startupCtx, directIPAction); err != nil {
		log.Printf("[Startup] Warning: failed to regenerate default server config: %v", err)
	} else {
		log.Printf("[Startup] Default server config regenerated successfully (action: %s)\n", directIPAction)
	}

	// Initialize nginx reloader with debounce (for URI block etc.)
	nginxReloader := service.NewNginxReloader(nginxManager, config.NginxReloaderDebounce)

	// Initialize audit service
	auditService := service.NewAuditService(auditLogRepo)

	// Initialize challenge service
	challengeService := service.NewChallengeService(challengeRepo)

	// Initialize auth service
	authService := service.NewAuthServiceWithCache(authRepo, cfg.JWTSecret, redisCache)

	// Initialize Docker stats service
	dockerStatsService := service.NewDockerStatsService()

	// Initialize Docker Log Collector
	dockerLogCollector := service.NewDockerLogCollector(systemLogRepo, systemSettingsRepo)

	// Initialize handlers
	proxyHostHandler := handler.NewProxyHostHandler(proxyHostService, auditService)
	dnsProviderHandler := handler.NewDNSProviderHandler(dnsProviderService)
	certificateHandler := handler.NewCertificateHandler(certificateService, auditService)
	logHandler := handler.NewLogHandler(logRepo)
	wafTestHandler := handler.NewWAFTestHandler()
	wafHandler := handler.NewWAFHandler(wafRepo, proxyHostRepo, nginxManager)
	exploitBlockRuleHandler := handler.NewExploitBlockRuleHandler(exploitBlockRuleRepo, proxyHostRepo, proxyHostService)
	accessListHandler := handler.NewAccessListHandler(accessListRepo)
	redirectHostHandler := handler.NewRedirectHostHandler(redirectHostRepo, nginxManager, auditService)
	geoHandler := handler.NewGeoHandler(geoRepo, proxyHostRepo, nginxManager, accessListRepo, rateLimitRepo, securityHeadersRepo, botFilterRepo, upstreamRepo)
	securityHandler := handler.NewSecurityHandler(rateLimitRepo, botFilterRepo, securityHeadersRepo, upstreamRepo, proxyHostRepo, proxyHostService, auditService, redisCache, ipBanHistoryRepo, uriBlockRepo, nginxReloader)
	settingsHandler := handler.NewSettingsHandler(globalSettingsRepo, dashboardRepo, backupRepo, proxyHostRepo, redirectHostRepo, certificateRepo, wafRepo, nginxManager, cfg.BackupPath, auditService, dockerStatsService, proxyHostService, redisCache)
	systemLogHandler := handler.NewSystemLogHandler(systemLogRepo)
	authHandler := handler.NewAuthHandler(authService, auditService)
	// Initialize GeoIP service for log enrichment (moved up for scheduler)
	geoIPService := service.NewGeoIPServiceWithCache(redisCache)
	defer geoIPService.Close()

	// Initialize Cloud Provider service for auto-seeding and IP range updates
	cloudProviderService := service.NewCloudProviderService(cloudProviderRepo)
	// Set up callback to regenerate nginx configs when cloud provider IP ranges are updated
	cloudProviderService.SetIPRangesUpdatedCallback(func(ctx context.Context, updatedProviders []string) error {
		log.Printf("[CloudProvider] IP ranges updated for %v, regenerating affected nginx configs", updatedProviders)
		return proxyHostService.RegenerateConfigsForCloudProviders(ctx, updatedProviders)
	})
	cloudProviderService.Start()
	defer cloudProviderService.Stop()

	// Initialize GeoIP scheduler for automatic updates
	geoIPScheduler := service.NewGeoIPScheduler(systemSettingsRepo, geoIPHistoryRepo, geoIPService)
	geoIPScheduler.SetCloudProviderService(cloudProviderService) // Wire for seeding on GeoIP update
	geoIPScheduler.Start()
	defer geoIPScheduler.Stop()

	systemSettingsHandler := handler.NewSystemSettingsHandler(systemSettingsRepo, geoIPHistoryRepo, nginxManager, auditService, dockerLogCollector, geoIPScheduler, cloudProviderService)
	apiTokenHandler := handler.NewAPITokenHandler(apiTokenRepo, auditLogRepo)
	auditLogHandler := handler.NewAuditLogHandler(auditLogRepo, apiTokenRepo)
	challengeHandler := handler.NewChallengeHandler(challengeService, auditService)
	cloudProviderHandler := handler.NewCloudProviderHandler(cloudProviderRepo, proxyHostService, auditService)

	// Initialize log collector (with Redis buffer if available)
	var logCollector *service.LogCollector
	if cfg.LogCollection {
		logCollector = service.NewLogCollector(logRepo, cfg.NginxContainer, geoIPService, redisCache)
	}

	// Initialize WAF Auto-Ban service
	wafAutoBanService := service.NewWAFAutoBanService(db.DB, systemSettingsRepo, rateLimitRepo, proxyHostRepo, proxyHostService, ipBanHistoryRepo)
	if logCollector != nil {
		logCollector.SetWAFAutoBanService(wafAutoBanService)
	}

	// Initialize Fail2ban service
	fail2banService := service.NewFail2banService(db.DB, rateLimitRepo, proxyHostRepo, proxyHostService, redisCache, ipBanHistoryRepo)
	if logCollector != nil {
		logCollector.SetFail2banService(fail2banService)
		logCollector.SetProxyHostRepo(proxyHostRepo)
	}

	// Initialize renewal scheduler (check every 6 hours, renew 30 days before expiry)
	renewalScheduler := scheduler.NewRenewalScheduler(
		certificateRepo,
		certificateService,
		6*time.Hour,
		30,
	)
	renewalScheduler.Start()

	// Initialize partition scheduler (creates monthly partitions for logs/stats)
	partitionScheduler := scheduler.NewPartitionScheduler(db.DB, systemSettingsRepo, systemLogRepo)
	partitionScheduler.Start()

	// Initialize log rotate scheduler (rotates raw nginx logs daily)
	logRotateScheduler := scheduler.NewLogRotateScheduler()
	logRotateScheduler.Start()

	// Initialize backup scheduler (auto backups based on cron schedule)
	backupScheduler := scheduler.NewBackupScheduler(backupRepo, systemSettingsRepo, cfg.BackupPath)
	backupScheduler.Start()

	// Start log collector (use context for graceful shutdown)
	ctx, cancel := context.WithCancel(context.Background())
	if logCollector != nil {
		go logCollector.Start(ctx)
	}

	// Start WAF Auto-Ban service
	go wafAutoBanService.Start(ctx)

	// Start Fail2ban service
	go fail2banService.Start(ctx)

	// Start stats collector for dashboard
	nginxStatusURL := os.Getenv("NGINX_STATUS_URL")
	if nginxStatusURL == "" {
		nginxStatusURL = "http://nginx:8080/nginx_status"
	}
	accessLogPath := os.Getenv("NGINX_ACCESS_LOG")
	if accessLogPath == "" {
		accessLogPath = "/var/log/nginx/access.log"
	}
	statsCollector := service.NewStatsCollector(
		db.DB,
		nginxStatusURL,
		accessLogPath,
	)
	go statsCollector.Start(ctx)

	// Start Docker log collector for system logs
	if os.Getenv("ENABLE_DOCKER_LOGS") != "false" {
		go dockerLogCollector.Start(ctx)
	}

	// Initialize Echo
	e := echo.New()
	e.HideBanner = true

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// CORS configuration - use environment variable or default to same-origin only
	corsOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	var allowedOrigins []string
	if corsOrigins != "" {
		// Parse comma-separated origins from environment variable
		for _, origin := range strings.Split(corsOrigins, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" && origin != "*" { // Reject wildcard for security
				allowedOrigins = append(allowedOrigins, origin)
			}
		}
	}
	// If no valid origins configured, allow common development origins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:5173", "http://localhost:81"}
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	// Security headers middleware
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            config.HSTSMaxAge,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://www.google.com https://www.gstatic.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https://validator.swagger.io; connect-src 'self' https://unpkg.com; frame-src https://challenges.cloudflare.com https://www.google.com",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	// Rate limiting middleware - configurable via environment
	rateLimitEnabled := os.Getenv("RATE_LIMIT_ENABLED") != "false"
	if rateLimitEnabled {
		// Default: 100 requests per second per IP
		rateLimit := 100.0
		if rl := os.Getenv("RATE_LIMIT_RPS"); rl != "" {
			if parsed, err := strconv.ParseFloat(rl, 64); err == nil && parsed > 0 {
				rateLimit = parsed
			}
		}
		e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(rateLimit))))
	}

	// Health check (uses db and cache for actual health check)
	startTime := time.Now()
	e.GET("/health", func(c echo.Context) error {
		isHealthy := true
		dbStatus := config.StatusOK
		if err := db.Health(); err != nil {
			dbStatus = config.StatusError
			isHealthy = false
		}
		cacheStatus := config.StatusDisabled
		if redisCache != nil {
			if redisCache.IsReady() {
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

		return c.JSON(httpStatus, map[string]interface{}{
			"status":    status,
			"version":   config.AppVersion,
			"database":  dbStatus,
			"cache":     cacheStatus,
			"uptime":    time.Since(startTime).String(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Swagger API Documentation
	swaggerHandler := handler.NewSwaggerHandler()
	e.GET("/api/docs", swaggerHandler.ServeUI)
	e.GET("/api/docs/swagger.yaml", swaggerHandler.ServeSpec)

	// API v1 routes with rate limiting
	v1 := e.Group("/api/v1")
	// Apply rate limiting to all API routes (100 requests per minute per IP)
	v1.Use(authMiddleware.APIRateLimit(redisCache, authMiddleware.DefaultAPIRateLimitConfig()))

	// Auth routes (public)
	auth := v1.Group("/auth")
	{
		auth.POST("/login", authHandler.Login)
		auth.POST("/logout", authHandler.Logout)
		auth.GET("/status", authHandler.GetStatus)
		auth.POST("/verify-2fa", authHandler.Verify2FA)
	}

	// Challenge routes (public - for GeoIP blocked users)
	challenge := v1.Group("/challenge")
	{
		challenge.GET("/page", challengeHandler.GetChallengePage)       // Get challenge HTML page
		challenge.POST("/verify", challengeHandler.VerifyCaptcha)       // Verify CAPTCHA and get bypass token
		challenge.GET("/validate", challengeHandler.ValidateToken)      // For nginx auth_request
		challenge.GET("/favicon.ico", handler.ServeFavicon)             // Serve favicon for challenge pages
	}

	// Public UI settings (no auth required) - for welcome page, 403 page, etc.
	v1.GET("/public/ui-settings", systemSettingsHandler.GetPublicUISettings)

	// Protected routes
	protected := v1.Group("")
	protected.Use(authMiddleware.AuthMiddleware(authService))
	{
		// Auth management (requires authentication)
		protected.GET("/auth/me", authHandler.GetCurrentUser)
		protected.POST("/auth/change-credentials", authHandler.ChangeCredentials)
		protected.POST("/auth/change-password", authHandler.ChangePassword)
		protected.POST("/auth/change-username", authHandler.ChangeUsername)
		protected.GET("/auth/account", authHandler.GetAccountInfo)
		protected.POST("/auth/2fa/setup", authHandler.Setup2FA)
		protected.POST("/auth/2fa/enable", authHandler.Enable2FA)
		protected.POST("/auth/2fa/disable", authHandler.Disable2FA)
		protected.GET("/auth/language", authHandler.GetLanguage)
		protected.PUT("/auth/language", authHandler.SetLanguage)
		protected.GET("/auth/font", authHandler.GetFontFamily)
		protected.PUT("/auth/font", authHandler.SetFontFamily)

		// Status endpoint
		protected.GET("/status", func(c echo.Context) error {
			dbStatus := config.StatusOK
			if err := db.Health(); err != nil {
				dbStatus = config.StatusError
			}

			nginxStatus := config.StatusOK
			if err := nginxManager.TestConfig(c.Request().Context()); err != nil {
				nginxStatus = config.StatusError
			}

			return c.JSON(http.StatusOK, map[string]string{
				"api":      config.StatusOK,
				"database": dbStatus,
				"nginx":    nginxStatus,
			})
		})
	}

	// All other routes require authentication (JWT or API Token)
	v1.Use(authMiddleware.APITokenAuth(apiTokenRepo, auditLogRepo)) // Check API token first
	v1.Use(authMiddleware.AuthMiddleware(authService))              // Then JWT
	{
		// API Token management routes
		apiTokens := v1.Group("/api-tokens")
		{
			apiTokens.GET("", apiTokenHandler.ListTokens)
			apiTokens.POST("", apiTokenHandler.CreateToken)
			apiTokens.GET("/permissions", apiTokenHandler.GetPermissions)
			apiTokens.GET("/:id", apiTokenHandler.GetToken)
			apiTokens.PUT("/:id", apiTokenHandler.UpdateToken)
			apiTokens.POST("/:id/revoke", apiTokenHandler.RevokeToken)
			apiTokens.DELETE("/:id", apiTokenHandler.DeleteToken)
			apiTokens.GET("/:id/usage", apiTokenHandler.GetTokenUsage)
		}

		// Proxy Host routes
		proxyHosts := v1.Group("/proxy-hosts")
		{
			proxyHosts.GET("", proxyHostHandler.List)
			proxyHosts.POST("", proxyHostHandler.Create)
			proxyHosts.GET("/by-domain/:domain", proxyHostHandler.GetByDomain)
			proxyHosts.POST("/sync", proxyHostHandler.SyncAll)
			proxyHosts.GET("/:id", proxyHostHandler.GetByID)
			proxyHosts.PUT("/:id", proxyHostHandler.Update)
			proxyHosts.DELETE("/:id", proxyHostHandler.Delete)
			proxyHosts.POST("/:id/test", proxyHostHandler.TestHost)
		}

		// DNS Provider routes
		dnsProviders := v1.Group("/dns-providers")
		{
			dnsProviders.GET("", dnsProviderHandler.List)
			dnsProviders.POST("", dnsProviderHandler.Create)
			dnsProviders.POST("/test", dnsProviderHandler.Test)
			dnsProviders.GET("/default", dnsProviderHandler.GetDefault)
			dnsProviders.GET("/:id", dnsProviderHandler.Get)
			dnsProviders.PUT("/:id", dnsProviderHandler.Update)
			dnsProviders.DELETE("/:id", dnsProviderHandler.Delete)
		}

		// Certificate routes
		certificates := v1.Group("/certificates")
		{
			certificates.GET("", certificateHandler.List)
			certificates.POST("", certificateHandler.Create)
			certificates.POST("/upload", certificateHandler.Upload)
			certificates.GET("/expiring", certificateHandler.GetExpiring)
			certificates.GET("/history", certificateHandler.ListHistory)
			certificates.GET("/:id", certificateHandler.Get)
			certificates.DELETE("/:id", certificateHandler.Delete)
			certificates.POST("/:id/renew", certificateHandler.Renew)
			certificates.GET("/:id/logs", certificateHandler.GetLogs)
			certificates.GET("/:id/download", certificateHandler.Download)
		}

		// Log routes
		logs := v1.Group("/logs")
		{
			logs.GET("", echo.WrapHandler(http.HandlerFunc(logHandler.List)))
			logs.POST("", echo.WrapHandler(http.HandlerFunc(logHandler.Create)))
			logs.GET("/stats", echo.WrapHandler(http.HandlerFunc(logHandler.GetStats)))
			logs.GET("/settings", echo.WrapHandler(http.HandlerFunc(logHandler.GetSettings)))
			logs.PUT("/settings", echo.WrapHandler(http.HandlerFunc(logHandler.UpdateSettings)))
			logs.POST("/cleanup", echo.WrapHandler(http.HandlerFunc(logHandler.Cleanup)))

			// Autocomplete endpoints for filters
			logs.GET("/autocomplete/hosts", echo.WrapHandler(http.HandlerFunc(logHandler.GetDistinctHosts)))
			logs.GET("/autocomplete/ips", echo.WrapHandler(http.HandlerFunc(logHandler.GetDistinctIPs)))
			logs.GET("/autocomplete/user-agents", echo.WrapHandler(http.HandlerFunc(logHandler.GetDistinctUserAgents)))
			logs.GET("/autocomplete/countries", echo.WrapHandler(http.HandlerFunc(logHandler.GetDistinctCountries)))
			logs.GET("/autocomplete/uris", echo.WrapHandler(http.HandlerFunc(logHandler.GetDistinctURIs)))
			logs.GET("/autocomplete/methods", echo.WrapHandler(http.HandlerFunc(logHandler.GetDistinctMethods)))
		}

		// WAF Test routes
		wafTest := v1.Group("/waf-test")
		{
			wafTest.GET("/patterns", echo.WrapHandler(http.HandlerFunc(wafTestHandler.ListPatterns)))
			wafTest.POST("/test", echo.WrapHandler(http.HandlerFunc(wafTestHandler.Test)))
			wafTest.POST("/test-all", echo.WrapHandler(http.HandlerFunc(wafTestHandler.TestAll)))
		}

		// WAF Management routes
		waf := v1.Group("/waf")
		{
			// Get all OWASP CRS rules (optionally filtered by proxy_host_id)
			waf.GET("/rules", echo.WrapHandler(http.HandlerFunc(wafHandler.GetRules)))

			// Get WAF config for all proxy hosts
			waf.GET("/hosts", echo.WrapHandler(http.HandlerFunc(wafHandler.GetHostConfigs)))

			// Get WAF config for a specific proxy host
			waf.GET("/hosts/:id/config", echo.WrapHandler(http.HandlerFunc(wafHandler.GetHostConfig)))

			// Get policy change history for a proxy host
			waf.GET("/hosts/:id/history", echo.WrapHandler(http.HandlerFunc(wafHandler.GetPolicyHistory)))

			// Disable a rule for a proxy host
			waf.POST("/hosts/:id/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(wafHandler.DisableRule)))

			// Disable a rule by host domain name (used from log viewer)
			waf.POST("/rules/disable-by-host", echo.WrapHandler(http.HandlerFunc(wafHandler.DisableRuleByHost)))

			// Enable a rule for a proxy host (remove exclusion)
			waf.DELETE("/hosts/:id/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(wafHandler.EnableRule)))

			// Global WAF rule management
			waf.GET("/global/rules", echo.WrapHandler(http.HandlerFunc(wafHandler.GetGlobalRules)))
			waf.GET("/global/exclusions", echo.WrapHandler(http.HandlerFunc(wafHandler.GetGlobalExclusions)))
			waf.GET("/global/history", echo.WrapHandler(http.HandlerFunc(wafHandler.GetGlobalPolicyHistory)))
			waf.POST("/global/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(wafHandler.DisableGlobalRule)))
			waf.DELETE("/global/rules/:ruleId/disable", echo.WrapHandler(http.HandlerFunc(wafHandler.EnableGlobalRule)))
		}

		// Exploit Block Rules routes (database-managed blocking rules)
		exploitRules := v1.Group("/exploit-rules")
		{
			// List all rules grouped by category
			exploitRules.GET("", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.ListRules)))

			// Get a single rule
			exploitRules.GET("/:id", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.GetRule)))

			// Create a custom rule
			exploitRules.POST("", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.CreateRule)))

			// Update a rule
			exploitRules.PUT("/:id", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.UpdateRule)))

			// Delete a custom rule (system rules cannot be deleted)
			exploitRules.DELETE("/:id", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.DeleteRule)))

			// Toggle rule enabled status
			exploitRules.POST("/:id/toggle", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.ToggleRule)))

			// Global exclusions
			exploitRules.POST("/:id/global-exclude", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.AddGlobalExclusion)))
			exploitRules.DELETE("/:id/global-exclude", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.RemoveGlobalExclusion)))

			// List hosts with exploit blocking enabled
			exploitRules.GET("/hosts", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.ListHostsWithExploitBlocking)))

			// Get rules with exclusion status for a specific host
			exploitRules.GET("/hosts/:hostId/rules", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.GetHostRules)))

			// Host-specific exclusions
			exploitRules.POST("/hosts/:hostId/rules/:ruleId/exclude", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.AddHostExclusion)))
			exploitRules.DELETE("/hosts/:hostId/rules/:ruleId/exclude", echo.WrapHandler(http.HandlerFunc(exploitBlockRuleHandler.RemoveHostExclusion)))
		}

		// Access List routes
		accessLists := v1.Group("/access-lists")
		{
			accessLists.GET("", accessListHandler.List)
			accessLists.POST("", accessListHandler.Create)
			accessLists.GET("/:id", accessListHandler.Get)
			accessLists.PUT("/:id", accessListHandler.Update)
			accessLists.DELETE("/:id", accessListHandler.Delete)
		}

		// Redirect Host routes
		redirectHosts := v1.Group("/redirect-hosts")
		{
			redirectHosts.GET("", redirectHostHandler.List)
			redirectHosts.POST("", redirectHostHandler.Create)
			redirectHosts.POST("/sync", redirectHostHandler.SyncAll)
			redirectHosts.GET("/:id", redirectHostHandler.Get)
			redirectHosts.PUT("/:id", redirectHostHandler.Update)
			redirectHosts.DELETE("/:id", redirectHostHandler.Delete)
		}

		// Geo Restriction routes (per proxy host)
		v1.GET("/proxy-hosts/:id/geo", geoHandler.GetByProxyHost)
		v1.POST("/proxy-hosts/:id/geo", geoHandler.SetForProxyHost)
		v1.PUT("/proxy-hosts/:id/geo", geoHandler.UpdateForProxyHost)
		v1.DELETE("/proxy-hosts/:id/geo", geoHandler.DeleteForProxyHost)
		v1.GET("/geo/countries", geoHandler.GetCountryCodes)

		// Rate Limit routes (per proxy host)
		v1.GET("/proxy-hosts/:proxyHostId/rate-limit", securityHandler.GetRateLimit)
		v1.PUT("/proxy-hosts/:proxyHostId/rate-limit", securityHandler.UpsertRateLimit)
		v1.DELETE("/proxy-hosts/:proxyHostId/rate-limit", securityHandler.DeleteRateLimit)

		// Fail2ban routes (per proxy host)
		v1.GET("/proxy-hosts/:proxyHostId/fail2ban", securityHandler.GetFail2ban)
		v1.PUT("/proxy-hosts/:proxyHostId/fail2ban", securityHandler.UpsertFail2ban)
		v1.DELETE("/proxy-hosts/:proxyHostId/fail2ban", securityHandler.DeleteFail2ban)

		// Banned IPs routes
		bannedIPs := v1.Group("/banned-ips")
		{
			bannedIPs.GET("", securityHandler.ListBannedIPs)
			bannedIPs.POST("", securityHandler.BanIP)
			bannedIPs.DELETE("/:id", securityHandler.UnbanIP)
			bannedIPs.DELETE("", securityHandler.UnbanIPByAddress)

			// Ban history routes
			bannedIPs.GET("/history", securityHandler.GetIPBanHistory)
			bannedIPs.GET("/history/stats", securityHandler.GetIPBanHistoryStats)
			bannedIPs.GET("/history/ip/:ip", securityHandler.GetIPBanHistoryByIP)
		}

		// Bot Filter routes (per proxy host)
		v1.GET("/proxy-hosts/:proxyHostId/bot-filter", securityHandler.GetBotFilter)
		v1.PUT("/proxy-hosts/:proxyHostId/bot-filter", securityHandler.UpsertBotFilter)
		v1.DELETE("/proxy-hosts/:proxyHostId/bot-filter", securityHandler.DeleteBotFilter)
		v1.GET("/bots/known", securityHandler.GetKnownBots)

		// URI Block routes
		v1.GET("/uri-blocks", securityHandler.ListAllURIBlocks)
		v1.POST("/uri-blocks/bulk-add-rule", securityHandler.BulkAddURIBlockRule)
		v1.GET("/proxy-hosts/:proxyHostId/uri-block", securityHandler.GetURIBlock)
		v1.PUT("/proxy-hosts/:proxyHostId/uri-block", securityHandler.UpsertURIBlock)
		v1.DELETE("/proxy-hosts/:proxyHostId/uri-block", securityHandler.DeleteURIBlock)
		v1.POST("/proxy-hosts/:proxyHostId/uri-block/rules", securityHandler.AddURIBlockRule)
		v1.DELETE("/proxy-hosts/:proxyHostId/uri-block/rules/:ruleId", securityHandler.RemoveURIBlockRule)

		// Global URI Block routes
		v1.GET("/global-uri-block", securityHandler.GetGlobalURIBlock)
		v1.PUT("/global-uri-block", securityHandler.UpdateGlobalURIBlock)
		v1.POST("/global-uri-block/rules", securityHandler.AddGlobalURIBlockRule)
		v1.DELETE("/global-uri-block/rules/:ruleId", securityHandler.RemoveGlobalURIBlockRule)

		// Security Headers routes (per proxy host)
		v1.GET("/proxy-hosts/:proxyHostId/security-headers", securityHandler.GetSecurityHeaders)
		v1.PUT("/proxy-hosts/:proxyHostId/security-headers", securityHandler.UpsertSecurityHeaders)
		v1.DELETE("/proxy-hosts/:proxyHostId/security-headers", securityHandler.DeleteSecurityHeaders)
		v1.GET("/security-headers/presets", securityHandler.GetSecurityHeaderPresets)
		v1.POST("/proxy-hosts/:proxyHostId/security-headers/preset/:preset", securityHandler.ApplySecurityHeaderPreset)

		// Upstream / Health Check routes (per proxy host)
		v1.GET("/proxy-hosts/:proxyHostId/upstream", securityHandler.GetUpstream)
		v1.PUT("/proxy-hosts/:proxyHostId/upstream", securityHandler.UpsertUpstream)
		v1.DELETE("/proxy-hosts/:proxyHostId/upstream", securityHandler.DeleteUpstream)
		v1.GET("/upstreams/:id/health", securityHandler.GetUpstreamHealth)

		// Global Settings routes (Phase 7)
		settings := v1.Group("/settings")
		{
			settings.GET("", settingsHandler.GetGlobalSettings)
			settings.PUT("", settingsHandler.UpdateGlobalSettings)
			settings.POST("/reset", settingsHandler.ResetGlobalSettings)
			settings.GET("/presets", settingsHandler.GetSettingsPresets)
			settings.POST("/preset/:preset", settingsHandler.ApplySettingsPreset)
		}

		// Dashboard routes (Phase 7)
		dashboard := v1.Group("/dashboard")
		{
			dashboard.GET("", settingsHandler.GetDashboard)
			dashboard.GET("/health", settingsHandler.GetSystemHealth)
			dashboard.GET("/health/history", settingsHandler.GetSystemHealthHistory)
			dashboard.GET("/stats/hourly", settingsHandler.GetHourlyStats)
			dashboard.GET("/containers", settingsHandler.GetDockerStats)
			dashboard.GET("/geoip-stats", settingsHandler.GetGeoIPStats)
		}

		// Backup/Restore routes (Phase 7)
		backups := v1.Group("/backups")
		{
			backups.GET("", settingsHandler.ListBackups)
			backups.POST("", settingsHandler.CreateBackup)
			backups.POST("/upload-restore", settingsHandler.UploadAndRestoreBackup)
			backups.GET("/stats", settingsHandler.GetBackupStats)
			backups.GET("/:id", settingsHandler.GetBackup)
			backups.GET("/:id/download", settingsHandler.DownloadBackup)
			backups.DELETE("/:id", settingsHandler.DeleteBackup)
			backups.POST("/:id/restore", settingsHandler.RestoreBackup)
		}

		// System Logs routes (Phase 8)
		systemLogs := v1.Group("/system-logs")
		{
			systemLogs.GET("", systemLogHandler.List)
			systemLogs.GET("/stats", systemLogHandler.GetStats)
			systemLogs.POST("/cleanup", systemLogHandler.Cleanup)
			systemLogs.GET("/sources", systemLogHandler.GetSources)
			systemLogs.GET("/levels", systemLogHandler.GetLevels)
		}

		// System Settings routes (GeoIP, ACME, etc.)
		systemSettings := v1.Group("/system-settings")
		{
			systemSettings.GET("", systemSettingsHandler.GetSystemSettings)
			systemSettings.PUT("", systemSettingsHandler.UpdateSystemSettings)
			systemSettings.GET("/geoip/status", systemSettingsHandler.GetGeoIPStatus)
			systemSettings.POST("/geoip/update", systemSettingsHandler.UpdateGeoIPDatabases)
			systemSettings.GET("/geoip/history", systemSettingsHandler.GetGeoIPHistory)
			systemSettings.POST("/acme/test", systemSettingsHandler.TestACME)

			// Log Files Management
			systemSettings.GET("/log-files", systemSettingsHandler.ListLogFiles)
			systemSettings.GET("/log-files/:filename/download", systemSettingsHandler.DownloadLogFile)
			systemSettings.GET("/log-files/:filename/view", systemSettingsHandler.ViewLogFile)
			systemSettings.DELETE("/log-files/:filename", systemSettingsHandler.DeleteLogFile)
			systemSettings.POST("/log-files/rotate", systemSettingsHandler.TriggerLogRotation)

			// System Log Configuration
			systemSettings.GET("/logs", systemSettingsHandler.GetSystemLogConfig)
			systemSettings.PUT("/logs", systemSettingsHandler.UpdateSystemLogConfig)
		}

		// Audit Logs routes
		auditLogs := v1.Group("/audit-logs")
		{
			auditLogs.GET("", auditLogHandler.ListAuditLogs)
			auditLogs.GET("/actions", auditLogHandler.GetActions)
			auditLogs.GET("/resource-types", auditLogHandler.GetResourceTypes)
			auditLogs.GET("/api-tokens", auditLogHandler.ListAPITokenUsage)
		}

		// CAPTCHA Challenge Config routes (for GeoIP)
		challengeConfig := v1.Group("/challenge-config")
		{
			challengeConfig.GET("", challengeHandler.GetGlobalConfig)             // Global config
			challengeConfig.PUT("", challengeHandler.UpdateGlobalConfig)          // Update global config
			challengeConfig.GET("/stats", challengeHandler.GetStats)              // Challenge statistics
		}
		// Per proxy host challenge config
		v1.GET("/proxy-hosts/:id/challenge", challengeHandler.GetProxyHostConfig)
		v1.PUT("/proxy-hosts/:id/challenge", challengeHandler.UpdateProxyHostConfig)
		v1.DELETE("/proxy-hosts/:id/challenge", challengeHandler.DeleteProxyHostConfig)

		// Cloud Provider blocking routes
		cloudProviders := v1.Group("/cloud-providers")
		{
			cloudProviders.GET("", cloudProviderHandler.ListProviders)
			cloudProviders.GET("/by-region", cloudProviderHandler.ListProvidersByRegion)
			cloudProviders.GET("/:slug", cloudProviderHandler.GetProvider)
			cloudProviders.POST("", cloudProviderHandler.CreateProvider)
			cloudProviders.PUT("/:slug", cloudProviderHandler.UpdateProvider)
			cloudProviders.DELETE("/:slug", cloudProviderHandler.DeleteProvider)
		}
		// Per proxy host cloud provider blocking
		v1.GET("/proxy-hosts/:proxyHostId/blocked-cloud-providers", cloudProviderHandler.GetBlockedProviders)
		v1.PUT("/proxy-hosts/:proxyHostId/blocked-cloud-providers", cloudProviderHandler.SetBlockedProviders)

		// Test endpoints (Phase 1 + Phase 7)
		test := v1.Group("/test")
		{
			test.POST("/nginx-config", func(c echo.Context) error {
				if err := nginxManager.TestConfig(c.Request().Context()); err != nil {
					return c.JSON(http.StatusBadRequest, map[string]string{
						"status": "error",
						"error":  err.Error(),
					})
				}
				return c.JSON(http.StatusOK, map[string]string{
					"status":  "ok",
					"message": "Nginx configuration is valid",
				})
			})

			test.POST("/proxy-host/:id", func(c echo.Context) error {
				id := c.Param("id")
				host, err := proxyHostService.GetByID(c.Request().Context(), id)
				if err != nil {
					return c.JSON(http.StatusInternalServerError, map[string]string{
						"status": "error",
						"error":  err.Error(),
					})
				}
				if host == nil {
					return c.JSON(http.StatusNotFound, map[string]string{
						"status": "error",
						"error":  "Proxy host not found",
					})
				}

				// Test connectivity to upstream
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
					return c.JSON(http.StatusOK, map[string]interface{}{
						"status":   config.StatusError,
						"error":    "Failed to create request",
						"host":     host,
						"upstream": upstreamURL,
					})
				}
				resp, err := client.Do(req)
				if err != nil {
					return c.JSON(http.StatusOK, map[string]interface{}{
						"status":   config.StatusError,
						"error":    "Connection failed",
						"host":     host,
						"upstream": upstreamURL,
					})
				}
				defer resp.Body.Close()

				return c.JSON(http.StatusOK, map[string]interface{}{
					"status":      config.StatusOK,
					"host":        host,
					"upstream":    upstreamURL,
					"status_code": resp.StatusCode,
				})
			})

			// Phase 7 test endpoints
			test.GET("/system/self-check", settingsHandler.SelfCheck)
			test.GET("/backup-restore", settingsHandler.TestBackupRestore)
			test.GET("/dashboard/queries", settingsHandler.TestDashboardQueries)
		}
	}

	// Start server
	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	// Setup graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down...")
		cancel() // Stop log collector and stats collector
		if logCollector != nil {
			logCollector.Stop()
		}
		statsCollector.Stop()
		dockerLogCollector.Stop()
		renewalScheduler.Stop()
		partitionScheduler.Stop()
		e.Close()
	}()

	log.Printf("Starting server on port %s", port)
	if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
