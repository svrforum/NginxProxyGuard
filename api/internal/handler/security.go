package handler

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
	"nginx-proxy-guard/pkg/cache"
)

type SecurityHandler struct {
	rateLimitRepo    *repository.RateLimitRepository
	botFilterRepo    *repository.BotFilterRepository
	secHeadersRepo   *repository.SecurityHeadersRepository
	upstreamRepo     *repository.UpstreamRepository
	proxyHostRepo    *repository.ProxyHostRepository
	proxyHostService *service.ProxyHostService
	audit            *service.AuditService
	redisCache       *cache.RedisClient
	historyRepo      *repository.IPBanHistoryRepository
	uriBlockRepo     *repository.URIBlockRepository
	nginxReloader    *service.NginxReloader
}

func NewSecurityHandler(
	rateLimitRepo *repository.RateLimitRepository,
	botFilterRepo *repository.BotFilterRepository,
	secHeadersRepo *repository.SecurityHeadersRepository,
	upstreamRepo *repository.UpstreamRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	proxyHostService *service.ProxyHostService,
	audit *service.AuditService,
	redisCache *cache.RedisClient,
	historyRepo *repository.IPBanHistoryRepository,
	uriBlockRepo *repository.URIBlockRepository,
	nginxReloader *service.NginxReloader,
) *SecurityHandler {
	return &SecurityHandler{
		rateLimitRepo:    rateLimitRepo,
		botFilterRepo:    botFilterRepo,
		secHeadersRepo:   secHeadersRepo,
		upstreamRepo:     upstreamRepo,
		proxyHostRepo:    proxyHostRepo,
		proxyHostService: proxyHostService,
		audit:            audit,
		redisCache:       redisCache,
		historyRepo:      historyRepo,
		uriBlockRepo:     uriBlockRepo,
		nginxReloader:    nginxReloader,
	}
}

// Rate Limit handlers

func (h *SecurityHandler) GetRateLimit(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	rateLimit, err := h.rateLimitRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get rate limit", err)
	}

	if rateLimit == nil {
		rateLimit = &model.RateLimit{
			ProxyHostID:       proxyHostID,
			Enabled:           false,
			RequestsPerSecond: config.DefaultRPS,
			BurstSize:         config.DefaultBurstSize,
			ZoneSize:          config.DefaultZoneSize,
			LimitBy:           "ip",
			LimitResponse:     config.DefaultLimitResponse,
		}
	}

	return c.JSON(http.StatusOK, rateLimit)
}

func (h *SecurityHandler) UpsertRateLimit(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateRateLimitRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	rateLimit, err := h.rateLimitRepo.Upsert(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert rate limit", err)
	}

	// Get host info for audit and nginx config regeneration
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	// Regenerate nginx config to apply rate limit changes
	if host != nil && host.Enabled && h.proxyHostService != nil {
		if _, err := h.proxyHostService.Update(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for rate limit", err)
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "rate_limit", hostName, rateLimit.Enabled, nil)

	return c.JSON(http.StatusOK, rateLimit)
}

func (h *SecurityHandler) DeleteRateLimit(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host info for audit and nginx config regeneration
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	if err := h.rateLimitRepo.Delete(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete rate limit", err)
	}

	// Regenerate nginx config to remove rate limit
	if host != nil && host.Enabled && h.proxyHostService != nil {
		if _, err := h.proxyHostService.Update(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for rate limit removal", err)
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "rate_limit", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

// Fail2ban handlers

func (h *SecurityHandler) GetFail2ban(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	config, err := h.rateLimitRepo.GetFail2banByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get fail2ban config", err)
	}

	if config == nil {
		config = &model.Fail2banConfig{
			ProxyHostID: proxyHostID,
			Enabled:     false,
			MaxRetries:  5,
			FindTime:    600,
			BanTime:     3600,
			FailCodes:   "401,403",
			Action:      "block",
		}
	}

	return c.JSON(http.StatusOK, config)
}

func (h *SecurityHandler) UpsertFail2ban(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateFail2banRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	config, err := h.rateLimitRepo.UpsertFail2ban(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert fail2ban config", err)
	}

	// Audit log
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFail2banUpdate(auditCtx, hostName, config.Enabled, nil)

	return c.JSON(http.StatusOK, config)
}

func (h *SecurityHandler) DeleteFail2ban(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host info for audit
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	if err := h.rateLimitRepo.DeleteFail2ban(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete fail2ban config", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFail2banUpdate(auditCtx, hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

// Banned IP handlers

func (h *SecurityHandler) ListBannedIPs(c echo.Context) error {
	proxyHostID := c.QueryParam("proxy_host_id")
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	var proxyHostIDPtr *string
	if proxyHostID != "" {
		proxyHostIDPtr = &proxyHostID
	}

	result, err := h.rateLimitRepo.ListBannedIPs(c.Request().Context(), proxyHostIDPtr, page, perPage)
	if err != nil {
		return databaseError(c, "list banned IPs", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SecurityHandler) BanIP(c echo.Context) error {
	var req struct {
		ProxyHostID *string `json:"proxy_host_id,omitempty"`
		IPAddress   string  `json:"ip_address"`
		Reason      string  `json:"reason,omitempty"`
		BanTime     int     `json:"ban_time,omitempty"`
	}

	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.IPAddress == "" {
		return badRequestError(c, "ip_address is required")
	}

	bannedIP, err := h.rateLimitRepo.BanIP(c.Request().Context(), req.ProxyHostID, req.IPAddress, req.Reason, req.BanTime)
	if err != nil {
		return databaseError(c, "ban IP", err)
	}

	// Add to Redis cache for fast lookup
	if h.redisCache != nil && h.redisCache.IsReady() {
		hostID := ""
		if req.ProxyHostID != nil {
			hostID = *req.ProxyHostID
		}
		var ttl time.Duration
		if req.BanTime > 0 {
			ttl = time.Duration(req.BanTime) * time.Second
		}
		h.redisCache.AddBannedIP(c.Request().Context(), req.IPAddress, hostID, ttl)
	}

	// Record ban history
	if h.historyRepo != nil {
		domainName := ""
		if req.ProxyHostID != nil {
			host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), *req.ProxyHostID)
			if host != nil && len(host.DomainNames) > 0 {
				domainName = host.DomainNames[0]
			}
		}

		// Get user info from context
		var userID *string
		var userEmail string
		if uid, ok := c.Get("user_id").(string); ok && uid != "" {
			userID = &uid
		}
		if email, ok := c.Get("username").(string); ok {
			userEmail = email
		}

		historyEvent := &model.IPBanHistory{
			EventType:   model.BanEventTypeBan,
			IPAddress:   req.IPAddress,
			ProxyHostID: req.ProxyHostID,
			DomainName:  domainName,
			Reason:      req.Reason,
			Source:      model.BanSourceManual,
			BanDuration: &req.BanTime,
			ExpiresAt:   bannedIP.ExpiresAt,
			IsPermanent: bannedIP.IsPermanent,
			IsAuto:      false,
			UserID:      userID,
			UserEmail:   userEmail,
		}
		if err := h.historyRepo.RecordBanEvent(c.Request().Context(), historyEvent); err != nil {
			c.Logger().Errorf("Failed to record ban history: %v", err)
		}
	}

	// Regenerate nginx config to apply banned IP (in background for speed)
	// FIXED: Use debounced reload instead of updating all hosts individually
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
		defer cancel()

		if h.proxyHostService != nil {
			if req.ProxyHostID != nil {
				// Regenerate specific host config without immediate reload
				if _, err := h.proxyHostService.UpdateWithoutReload(ctx, *req.ProxyHostID, nil); err != nil {
					log.Printf("[BanIP] Failed to regenerate config for host: %v", err)
					return
				}
			} else {
				// For global ban, regenerate all enabled hosts without reload
				hosts, _, err := h.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
				if err == nil && hosts != nil {
					for _, host := range hosts {
						if host.Enabled {
							if _, err := h.proxyHostService.UpdateWithoutReload(ctx, host.ID, nil); err != nil {
								log.Printf("[BanIP] Failed to regenerate config for host %s: %v", host.ID, err)
							}
						}
					}
				}
			}
			// Request single debounced reload after all configs are generated
			if h.nginxReloader != nil {
				h.nginxReloader.RequestReload(ctx)
			}
		}
	}()

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogIPBanned(auditCtx, req.IPAddress, req.Reason, req.BanTime)

	return c.JSON(http.StatusCreated, bannedIP)
}

func (h *SecurityHandler) UnbanIP(c echo.Context) error {
	id := c.Param("id")

	// Get banned IP info before deleting (for history and cache removal)
	bannedIP, _ := h.rateLimitRepo.GetBannedIPByID(c.Request().Context(), id)

	if err := h.rateLimitRepo.UnbanIP(c.Request().Context(), id); err != nil {
		return databaseError(c, "unban IP", err)
	}

	// Remove from Redis cache
	if h.redisCache != nil && bannedIP != nil {
		hostID := ""
		if bannedIP.ProxyHostID != nil {
			hostID = *bannedIP.ProxyHostID
		}
		if err := h.redisCache.RemoveBannedIP(c.Request().Context(), bannedIP.IPAddress, hostID); err != nil {
			c.Logger().Errorf("Failed to remove banned IP from cache: %v", err)
		}
	}

	// Record unban history
	if h.historyRepo != nil && bannedIP != nil {
		var userID *string
		var userEmail string
		if uid, ok := c.Get("user_id").(string); ok && uid != "" {
			userID = &uid
		}
		if email, ok := c.Get("username").(string); ok {
			userEmail = email
		}

		historyEvent := &model.IPBanHistory{
			EventType:   model.BanEventTypeUnban,
			IPAddress:   bannedIP.IPAddress,
			ProxyHostID: bannedIP.ProxyHostID,
			Reason:      "Manual unban",
			Source:      model.BanSourceManual,
			IsAuto:      false,
			UserID:      userID,
			UserEmail:   userEmail,
		}
		if err := h.historyRepo.RecordBanEvent(c.Request().Context(), historyEvent); err != nil {
			c.Logger().Errorf("Failed to record unban history: %v", err)
		}
	}

	// Regenerate all enabled host configs in background for speed
	// Pass nil to UpdateWithoutReload to regenerate config without DB update
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
		defer cancel()

		if h.proxyHostService != nil && h.proxyHostRepo != nil {
			hosts, _, err := h.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
			if err == nil && hosts != nil {
				// Regenerate all host configs sequentially WITHOUT reload
				for _, host := range hosts {
					if host.Enabled {
						if _, err := h.proxyHostService.UpdateWithoutReload(ctx, host.ID, nil); err != nil {
							log.Printf("[UnbanIP] Failed to regenerate config for host %s: %v", host.ID, err)
						}
					}
				}
				// Request single debounced reload after all configs are updated
				if h.nginxReloader != nil {
					h.nginxReloader.RequestReload(ctx)
				}
			}
		}
	}()

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogIPUnbanned(auditCtx, id)

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) UnbanIPByAddress(c echo.Context) error {
	ip := c.QueryParam("ip")
	if ip == "" {
		return badRequestError(c, "ip parameter is required")
	}

	// Record unban history before deleting
	if h.historyRepo != nil {
		var userID *string
		var userEmail string
		if uid, ok := c.Get("user_id").(string); ok && uid != "" {
			userID = &uid
		}
		if email, ok := c.Get("username").(string); ok {
			userEmail = email
		}

		historyEvent := &model.IPBanHistory{
			EventType: model.BanEventTypeUnban,
			IPAddress: ip,
			Reason:    "Manual unban by IP address",
			Source:    model.BanSourceManual,
			IsAuto:    false,
			UserID:    userID,
			UserEmail: userEmail,
		}
		if err := h.historyRepo.RecordBanEvent(c.Request().Context(), historyEvent); err != nil {
			c.Logger().Errorf("Failed to record unban history by address: %v", err)
		}
	}

	if err := h.rateLimitRepo.UnbanIPByAddress(c.Request().Context(), ip); err != nil {
		return databaseError(c, "unban IP by address", err)
	}

	// Remove from Redis cache (both global and all host-specific)
	if h.redisCache != nil {
		// Remove from global ban list
		if err := h.redisCache.RemoveBannedIP(c.Request().Context(), ip, ""); err != nil {
			c.Logger().Errorf("Failed to remove banned IP from global cache: %v", err)
		}
		// Also try to remove from all host-specific caches
		if h.proxyHostRepo != nil {
			hosts, _, err := h.proxyHostRepo.List(c.Request().Context(), 1, config.MaxWAFRulesLimit, "", "", "")
			if err == nil && hosts != nil {
				for _, host := range hosts {
					h.redisCache.RemoveBannedIP(c.Request().Context(), ip, host.ID)
				}
			}
		}
	}

	// Regenerate all enabled host configs in background with debounced reload
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
		defer cancel()

		if h.proxyHostService != nil && h.proxyHostRepo != nil {
			hosts, _, err := h.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
			if err == nil && hosts != nil {
				// Regenerate all host configs sequentially WITHOUT reload
				for _, host := range hosts {
					if host.Enabled {
						if _, err := h.proxyHostService.UpdateWithoutReload(ctx, host.ID, nil); err != nil {
							log.Printf("[UnbanIPByAddress] Failed to regenerate config for host %s: %v", host.ID, err)
						}
					}
				}
				// Request single debounced reload after all configs are updated
				if h.nginxReloader != nil {
					h.nginxReloader.RequestReload(ctx)
				}
			}
		}
	}()

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogIPUnbanned(auditCtx, ip)

	return c.NoContent(http.StatusNoContent)
}

// Bot Filter handlers

func (h *SecurityHandler) GetBotFilter(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	filter, err := h.botFilterRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get bot filter", err)
	}

	if filter == nil {
		filter = &model.BotFilter{
			ProxyHostID:        proxyHostID,
			Enabled:            false,
			BlockBadBots:       true,
			BlockAIBots:        false,
			AllowSearchEngines: true,
		}
	}

	return c.JSON(http.StatusOK, filter)
}

func (h *SecurityHandler) UpsertBotFilter(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	skipReload := c.QueryParam("skip_reload") == "true"

	var req model.CreateBotFilterRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	filter, err := h.botFilterRepo.Upsert(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert bot filter", err)
	}

	// Get host info for audit and nginx config regeneration
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	// Regenerate nginx config to apply bot filter changes (skip if requested)
	if !skipReload && host != nil && host.Enabled && h.proxyHostService != nil {
		// Trigger a dummy update to regenerate nginx config with bot filter settings
		if _, err := h.proxyHostService.Update(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for bot filter", err)
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "bot_filter", hostName, filter.Enabled, nil)

	return c.JSON(http.StatusOK, filter)
}

func (h *SecurityHandler) DeleteBotFilter(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host info for audit
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	if err := h.botFilterRepo.Delete(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete bot filter", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "bot_filter", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) GetKnownBots(c echo.Context) error {
	response := map[string]interface{}{
		"bad_bots":           model.KnownBadBots,
		"ai_bots":            model.AIBots,
		"search_engine_bots": model.SearchEngineBots,
	}

	return c.JSON(http.StatusOK, response)
}

// Security Headers handlers

func (h *SecurityHandler) GetSecurityHeaders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	headers, err := h.secHeadersRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get security headers", err)
	}

	if headers == nil {
		headers = &model.SecurityHeaders{
			ProxyHostID:           proxyHostID,
			Enabled:               false,
			HSTSEnabled:           true,
			HSTSMaxAge:            31536000,
			HSTSIncludeSubdomains: true,
			HSTSPreload:           false,
			XFrameOptions:         "SAMEORIGIN",
			XContentTypeOptions:   true,
			XXSSProtection:        true,
			ReferrerPolicy:        "strict-origin-when-cross-origin",
		}
	}

	return c.JSON(http.StatusOK, headers)
}

func (h *SecurityHandler) UpsertSecurityHeaders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateSecurityHeadersRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	headers, err := h.secHeadersRepo.Upsert(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert security headers", err)
	}

	// Audit log
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "security_headers", hostName, headers.Enabled, nil)

	return c.JSON(http.StatusOK, headers)
}

func (h *SecurityHandler) DeleteSecurityHeaders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host info for audit
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	if err := h.secHeadersRepo.Delete(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete security headers", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "security_headers", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) GetSecurityHeaderPresets(c echo.Context) error {
	return c.JSON(http.StatusOK, model.SecurityHeaderPresets)
}

func (h *SecurityHandler) ApplySecurityHeaderPreset(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	preset := c.Param("preset")

	presetConfig, ok := model.SecurityHeaderPresets[preset]
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid preset"})
	}

	req := &model.CreateSecurityHeadersRequest{
		Enabled:               &presetConfig.Enabled,
		HSTSEnabled:           &presetConfig.HSTSEnabled,
		HSTSMaxAge:            presetConfig.HSTSMaxAge,
		HSTSIncludeSubdomains: &presetConfig.HSTSIncludeSubdomains,
		HSTSPreload:           &presetConfig.HSTSPreload,
		XFrameOptions:         presetConfig.XFrameOptions,
		XContentTypeOptions:   &presetConfig.XContentTypeOptions,
		XXSSProtection:        &presetConfig.XXSSProtection,
		ReferrerPolicy:        presetConfig.ReferrerPolicy,
		ContentSecurityPolicy: presetConfig.ContentSecurityPolicy,
	}

	headers, err := h.secHeadersRepo.Upsert(c.Request().Context(), proxyHostID, req)
	if err != nil {
		return databaseError(c, "apply security header preset", err)
	}

	// Audit log
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "security_headers", hostName, headers.Enabled, map[string]interface{}{
		"preset": preset,
	})

	return c.JSON(http.StatusOK, headers)
}

// Upstream handlers

func (h *SecurityHandler) GetUpstream(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	upstream, err := h.upstreamRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get upstream", err)
	}

	if upstream == nil {
		upstream = &model.Upstream{
			ProxyHostID:               proxyHostID,
			LoadBalance:               "round_robin",
			HealthCheckEnabled:        false,
			HealthCheckInterval:       30,
			HealthCheckTimeout:        5,
			HealthCheckPath:           "/",
			HealthCheckExpectedStatus: 200,
			Keepalive:                 32,
			IsHealthy:                 true,
			Servers:                   []model.UpstreamServer{},
		}
	}

	return c.JSON(http.StatusOK, upstream)
}

func (h *SecurityHandler) UpsertUpstream(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateUpstreamRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	upstream, err := h.upstreamRepo.Upsert(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert upstream", err)
	}

	// Audit log
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogUpstreamUpdate(auditCtx, hostName, map[string]interface{}{
		"load_balance": upstream.LoadBalance,
		"health_check": upstream.HealthCheckEnabled,
		"server_count": len(upstream.Servers),
	})

	return c.JSON(http.StatusOK, upstream)
}

func (h *SecurityHandler) DeleteUpstream(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host info for audit
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	if err := h.upstreamRepo.Delete(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete upstream", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogUpstreamUpdate(auditCtx, hostName, map[string]interface{}{
		"action": "deleted",
	})

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) GetUpstreamHealth(c echo.Context) error {
	id := c.Param("id")

	upstream, err := h.upstreamRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get upstream health", err)
	}

	if upstream == nil {
		return notFoundError(c, "Upstream")
	}

	healthyCount := 0
	unhealthyCount := 0
	serverStatuses := make([]model.ServerHealthStatus, len(upstream.Servers))

	for i, s := range upstream.Servers {
		if s.IsHealthy && !s.IsDown {
			healthyCount++
		} else {
			unhealthyCount++
		}

		serverStatuses[i] = model.ServerHealthStatus{
			Address:     s.Address,
			Port:        s.Port,
			IsHealthy:   s.IsHealthy,
			IsBackup:    s.IsBackup,
			IsDown:      s.IsDown,
			LastCheckAt: s.LastCheckAt,
			LastError:   s.LastError,
		}
	}

	response := model.UpstreamHealthStatus{
		UpstreamID:     upstream.ID,
		Name:           upstream.Name,
		IsHealthy:      upstream.IsHealthy,
		HealthyCount:   healthyCount,
		UnhealthyCount: unhealthyCount,
		LastCheckAt:    upstream.LastCheckAt,
		Servers:        serverStatuses,
	}

	return c.JSON(http.StatusOK, response)
}

// IP Ban History handlers

func (h *SecurityHandler) GetIPBanHistory(c echo.Context) error {
	if h.historyRepo == nil {
		return internalError(c, "history repository not initialized", nil)
	}

	// Parse filter parameters
	filter := &model.IPBanHistoryFilter{
		IPAddress:   c.QueryParam("ip_address"),
		EventType:   c.QueryParam("event_type"),
		Source:      c.QueryParam("source"),
		ProxyHostID: c.QueryParam("proxy_host_id"),
	}

	// Parse pagination
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	filter.Page = page
	filter.PerPage = perPage

	// Parse date filters
	if startDate := c.QueryParam("start_date"); startDate != "" {
		if t, err := time.Parse(time.RFC3339, startDate); err == nil {
			filter.StartDate = &t
		}
	}
	if endDate := c.QueryParam("end_date"); endDate != "" {
		if t, err := time.Parse(time.RFC3339, endDate); err == nil {
			filter.EndDate = &t
		}
	}

	result, err := h.historyRepo.List(c.Request().Context(), filter)
	if err != nil {
		return databaseError(c, "list IP ban history", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SecurityHandler) GetIPBanHistoryByIP(c echo.Context) error {
	if h.historyRepo == nil {
		return internalError(c, "history repository not initialized", nil)
	}

	ip := c.Param("ip")
	if ip == "" {
		return badRequestError(c, "IP address is required")
	}

	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}

	result, err := h.historyRepo.GetByIP(c.Request().Context(), ip, page, perPage)
	if err != nil {
		return databaseError(c, "get IP ban history", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SecurityHandler) GetIPBanHistoryStats(c echo.Context) error {
	if h.historyRepo == nil {
		return internalError(c, "history repository not initialized", nil)
	}

	stats, err := h.historyRepo.GetStats(c.Request().Context())
	if err != nil {
		return databaseError(c, "get IP ban history stats", err)
	}

	return c.JSON(http.StatusOK, stats)
}

// URI Block handlers

func (h *SecurityHandler) GetURIBlock(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	uriBlock, err := h.uriBlockRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get URI block", err)
	}

	if uriBlock == nil {
		uriBlock = &model.URIBlock{
			ProxyHostID:     proxyHostID,
			Enabled:         false,
			Rules:           []model.URIBlockRule{},
			ExceptionIPs:    []string{},
			AllowPrivateIPs: true,
		}
	}

	return c.JSON(http.StatusOK, uriBlock)
}

func (h *SecurityHandler) UpsertURIBlock(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	skipReload := c.QueryParam("skip_reload") == "true"

	var req model.CreateURIBlockRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	uriBlock, err := h.uriBlockRepo.Upsert(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert URI block", err)
	}

	// Get host info for audit and nginx config regeneration
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	// Update cache
	h.cacheURIBlock(c.Request().Context(), proxyHostID, uriBlock)

	// Regenerate nginx config with debounced reload (skip if requested)
	if !skipReload && host != nil && host.Enabled && h.proxyHostService != nil {
		// Generate config first
		if _, err := h.proxyHostService.UpdateWithoutReload(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for URI block", err)
		}
		// Request debounced reload
		if h.nginxReloader != nil {
			h.nginxReloader.RequestReload(c.Request().Context())
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, uriBlock.Enabled, nil)

	return c.JSON(http.StatusOK, uriBlock)
}

func (h *SecurityHandler) DeleteURIBlock(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host info for audit
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	if err := h.uriBlockRepo.Delete(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete URI block", err)
	}

	// Clear cache
	if h.redisCache != nil {
		h.redisCache.DeleteURIBlock(c.Request().Context(), proxyHostID)
	}

	// Regenerate nginx config with debounced reload
	if host != nil && host.Enabled && h.proxyHostService != nil {
		if _, err := h.proxyHostService.UpdateWithoutReload(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for URI block removal", err)
		}
		if h.nginxReloader != nil {
			h.nginxReloader.RequestReload(c.Request().Context())
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) AddURIBlockRule(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.AddURIBlockRuleRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Pattern == "" {
		return badRequestError(c, "pattern is required")
	}
	if req.MatchType == "" {
		req.MatchType = model.URIMatchPrefix
	}

	uriBlock, err := h.uriBlockRepo.AddRule(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "add URI block rule", err)
	}

	// Get host info for audit and nginx config regeneration
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	// Update cache
	h.cacheURIBlock(c.Request().Context(), proxyHostID, uriBlock)

	// Regenerate nginx config with debounced reload
	if host != nil && host.Enabled && h.proxyHostService != nil {
		if _, err := h.proxyHostService.UpdateWithoutReload(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for URI block rule", err)
		}
		if h.nginxReloader != nil {
			h.nginxReloader.RequestReload(c.Request().Context())
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, true, map[string]interface{}{
		"action":     "add_rule",
		"pattern":    req.Pattern,
		"match_type": req.MatchType,
	})

	return c.JSON(http.StatusCreated, uriBlock)
}

func (h *SecurityHandler) RemoveURIBlockRule(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	ruleID := c.Param("ruleId")

	if ruleID == "" {
		return badRequestError(c, "rule ID is required")
	}

	if err := h.uriBlockRepo.RemoveRule(c.Request().Context(), proxyHostID, ruleID); err != nil {
		return databaseError(c, "remove URI block rule", err)
	}

	// Get host info for audit and nginx config regeneration
	host, _ := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	hostName := proxyHostID
	if host != nil && len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	// Update cache (re-fetch to get current state)
	if uriBlock, err := h.uriBlockRepo.GetByProxyHostID(c.Request().Context(), proxyHostID); err == nil && uriBlock != nil {
		h.cacheURIBlock(c.Request().Context(), proxyHostID, uriBlock)
	} else if h.redisCache != nil {
		// If no rules left, clear cache
		h.redisCache.DeleteURIBlock(c.Request().Context(), proxyHostID)
	}

	// Regenerate nginx config with debounced reload
	if host != nil && host.Enabled && h.proxyHostService != nil {
		if _, err := h.proxyHostService.UpdateWithoutReload(c.Request().Context(), proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return internalError(c, "regenerate nginx config for URI block rule removal", err)
		}
		if h.nginxReloader != nil {
			h.nginxReloader.RequestReload(c.Request().Context())
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, true, map[string]interface{}{
		"action":  "remove_rule",
		"rule_id": ruleID,
	})

	return c.NoContent(http.StatusNoContent)
}

// BulkAddURIBlockRule adds a rule to multiple or all hosts
func (h *SecurityHandler) BulkAddURIBlockRule(c echo.Context) error {
	var req struct {
		Pattern     string   `json:"pattern"`
		MatchType   string   `json:"match_type"`
		Description string   `json:"description"`
		HostIDs     []string `json:"host_ids"` // If empty, applies to all enabled hosts
	}
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Pattern == "" {
		return badRequestError(c, "pattern is required")
	}
	if req.MatchType == "" {
		req.MatchType = string(model.URIMatchExact)
	}

	ctx := c.Request().Context()
	var targetHostIDs []string

	if len(req.HostIDs) > 0 {
		// Use specified host IDs
		targetHostIDs = req.HostIDs
	} else {
		// Get all enabled hosts
		allHosts, err := h.proxyHostRepo.GetAllEnabled(ctx)
		if err != nil {
			return databaseError(c, "get enabled hosts", err)
		}
		for _, host := range allHosts {
			targetHostIDs = append(targetHostIDs, host.ID)
		}
	}

	if len(targetHostIDs) == 0 {
		return badRequestError(c, "No target hosts found")
	}

	// Add rule to each host
	addedCount := 0
	var errors []string
	auditCtx := service.ContextWithAudit(ctx, c)

	for _, hostID := range targetHostIDs {
		enabled := true
		ruleReq := &model.AddURIBlockRuleRequest{
			Pattern:     req.Pattern,
			MatchType:   model.URIMatchType(req.MatchType),
			Description: req.Description,
			Enabled:     &enabled,
		}

		uriBlock, err := h.uriBlockRepo.AddRule(ctx, hostID, ruleReq)
		if err != nil {
			errors = append(errors, hostID+": "+err.Error())
			continue
		}

		// Update cache
		h.cacheURIBlock(ctx, hostID, uriBlock)

		// Regenerate nginx config (without reload - we'll reload once at the end)
		host, _ := h.proxyHostRepo.GetByID(ctx, hostID)
		if host != nil && host.Enabled && h.proxyHostService != nil {
			h.proxyHostService.UpdateWithoutReload(ctx, hostID, &model.UpdateProxyHostRequest{})
		}

		// Audit log for each host
		hostName := hostID
		if host != nil && len(host.DomainNames) > 0 {
			hostName = host.DomainNames[0]
		}
		h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, true, map[string]interface{}{
			"action":     "add_rule",
			"pattern":    req.Pattern,
			"match_type": req.MatchType,
			"bulk":       true,
		})

		addedCount++
	}

	// Request single debounced reload after all configs are generated
	if h.nginxReloader != nil {
		h.nginxReloader.RequestReload(ctx)
	}

	response := map[string]interface{}{
		"added_count":  addedCount,
		"total_hosts":  len(targetHostIDs),
		"pattern":      req.Pattern,
		"match_type":   req.MatchType,
	}
	if len(errors) > 0 {
		response["errors"] = errors
	}

	return c.JSON(http.StatusOK, response)
}

// cacheURIBlock updates the URI block cache in Redis
func (h *SecurityHandler) cacheURIBlock(ctx context.Context, proxyHostID string, uriBlock *model.URIBlock) {
	if h.redisCache == nil || uriBlock == nil {
		return
	}

	// Convert to cache entry
	patterns := make([]cache.URIBlockPattern, 0, len(uriBlock.Rules))
	for _, rule := range uriBlock.Rules {
		if rule.Enabled {
			patterns = append(patterns, cache.URIBlockPattern{
				Pattern:   rule.Pattern,
				MatchType: string(rule.MatchType),
				Enabled:   rule.Enabled,
			})
		}
	}

	entry := &cache.URIBlockEntry{
		HostID:          proxyHostID,
		Enabled:         uriBlock.Enabled,
		AllowPrivateIPs: uriBlock.AllowPrivateIPs,
		ExceptionIPs:    uriBlock.ExceptionIPs,
		Patterns:        patterns,
	}

	h.redisCache.SetURIBlock(ctx, proxyHostID, entry)
}

// ListAllURIBlocks returns all URI blocks across all hosts
func (h *SecurityHandler) ListAllURIBlocks(c echo.Context) error {
	blocks, err := h.uriBlockRepo.ListAll(c.Request().Context())
	if err != nil {
		return databaseError(c, "list all URI blocks", err)
	}
	return c.JSON(http.StatusOK, blocks)
}

// ============================================================================
// Global URI Block Handlers
// ============================================================================

// GetGlobalURIBlock returns the global URI block settings
func (h *SecurityHandler) GetGlobalURIBlock(c echo.Context) error {
	block, err := h.uriBlockRepo.GetGlobalURIBlock(c.Request().Context())
	if err != nil {
		return databaseError(c, "get global URI block", err)
	}

	// Return empty config if not found
	if block == nil {
		return c.JSON(http.StatusOK, model.GlobalURIBlock{
			Enabled:         false,
			Rules:           []model.URIBlockRule{},
			ExceptionIPs:    []string{},
			AllowPrivateIPs: true,
		})
	}

	return c.JSON(http.StatusOK, block)
}

// UpdateGlobalURIBlock updates the global URI block settings
func (h *SecurityHandler) UpdateGlobalURIBlock(c echo.Context) error {
	var req model.CreateGlobalURIBlockRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	ctx := c.Request().Context()

	block, err := h.uriBlockRepo.UpsertGlobalURIBlock(ctx, &req)
	if err != nil {
		return databaseError(c, "update global URI block", err)
	}

	// Log audit
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", block.Enabled, map[string]interface{}{
		"rules_count": len(block.Rules),
	})

	// Sync all proxy host configs to apply global rules (synchronous for immediate feedback)
	if err := h.syncAllProxyHostsForGlobalSync(); err != nil {
		// Log the error but don't fail the request since DB save succeeded
		// The config will be synced on next proxy host update
		c.Logger().Errorf("Failed to sync proxy host configs: %v", err)
	}

	return c.JSON(http.StatusOK, block)
}

// AddGlobalURIBlockRule adds a single rule to the global URI block
func (h *SecurityHandler) AddGlobalURIBlockRule(c echo.Context) error {
	var req model.AddURIBlockRuleRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Pattern == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Pattern is required"})
	}

	if req.MatchType == "" {
		req.MatchType = model.URIMatchPrefix
	}

	ctx := c.Request().Context()

	block, err := h.uriBlockRepo.AddGlobalRule(ctx, &req)
	if err != nil {
		return databaseError(c, "add global URI block rule", err)
	}

	// Log audit
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", true, map[string]interface{}{
		"action":     "add_rule",
		"pattern":    req.Pattern,
		"match_type": req.MatchType,
	})

	// Sync all proxy host configs
	go h.syncAllProxyHostsForGlobal()

	return c.JSON(http.StatusOK, block)
}

// RemoveGlobalURIBlockRule removes a single rule from the global URI block
func (h *SecurityHandler) RemoveGlobalURIBlockRule(c echo.Context) error {
	ruleID := c.Param("ruleId")
	if ruleID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Rule ID is required"})
	}

	ctx := c.Request().Context()

	// Get the rule info before deletion for audit log
	existing, _ := h.uriBlockRepo.GetGlobalURIBlock(ctx)
	var removedPattern string
	if existing != nil {
		for _, rule := range existing.Rules {
			if rule.ID == ruleID {
				removedPattern = rule.Pattern
				break
			}
		}
	}

	if err := h.uriBlockRepo.RemoveGlobalRule(ctx, ruleID); err != nil {
		return databaseError(c, "remove global URI block rule", err)
	}

	// Log audit
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", true, map[string]interface{}{
		"action":  "remove_rule",
		"rule_id": ruleID,
		"pattern": removedPattern,
	})

	// Sync all proxy host configs
	go h.syncAllProxyHostsForGlobal()

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// syncAllProxyHostsForGlobal syncs all proxy host nginx configs (for global rule changes)
func (h *SecurityHandler) syncAllProxyHostsForGlobal() {
	// Use a background context since the HTTP request may have completed
	ctx := context.Background()
	if h.proxyHostService != nil {
		_ = h.proxyHostService.SyncAllConfigs(ctx)
	}
}

// syncAllProxyHostsForGlobalSync syncs all proxy host configs synchronously and returns error
func (h *SecurityHandler) syncAllProxyHostsForGlobalSync() error {
	ctx := context.Background()
	if h.proxyHostService != nil {
		return h.proxyHostService.SyncAllConfigs(ctx)
	}
	return nil
}
