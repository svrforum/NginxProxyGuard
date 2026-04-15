package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// SecurityService handles business logic for security features:
// rate limiting, banned IPs, bot filters, security headers, upstreams, URI blocks.
type SecurityService struct {
	rateLimitRepo    *repository.RateLimitRepository
	botFilterRepo    *repository.BotFilterRepository
	secHeadersRepo   *repository.SecurityHeadersRepository
	upstreamRepo     *repository.UpstreamRepository
	proxyHostRepo    *repository.ProxyHostRepository
	proxyHostService *ProxyHostService
	historyRepo      *repository.IPBanHistoryRepository
	uriBlockRepo     *repository.URIBlockRepository
	redisCache       *cache.RedisClient
	nginxReloader    *NginxReloader
}

func NewSecurityService(
	rateLimitRepo *repository.RateLimitRepository,
	botFilterRepo *repository.BotFilterRepository,
	secHeadersRepo *repository.SecurityHeadersRepository,
	upstreamRepo *repository.UpstreamRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	proxyHostService *ProxyHostService,
	historyRepo *repository.IPBanHistoryRepository,
	uriBlockRepo *repository.URIBlockRepository,
	redisCache *cache.RedisClient,
	nginxReloader *NginxReloader,
) *SecurityService {
	return &SecurityService{
		rateLimitRepo:    rateLimitRepo,
		botFilterRepo:    botFilterRepo,
		secHeadersRepo:   secHeadersRepo,
		upstreamRepo:     upstreamRepo,
		proxyHostRepo:    proxyHostRepo,
		proxyHostService: proxyHostService,
		historyRepo:      historyRepo,
		uriBlockRepo:     uriBlockRepo,
		redisCache:       redisCache,
		nginxReloader:    nginxReloader,
	}
}

// ---- Rate Limit ----

func (s *SecurityService) GetRateLimit(ctx context.Context, proxyHostID string) (*model.RateLimit, error) {
	rateLimit, err := s.rateLimitRepo.GetByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit: %w", err)
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
	return rateLimit, nil
}

func (s *SecurityService) UpsertRateLimit(ctx context.Context, proxyHostID string, req *model.CreateRateLimitRequest) (*model.RateLimit, error) {
	rateLimit, err := s.rateLimitRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert rate limit: %w", err)
	}

	// Regenerate nginx config to apply rate limit changes
	host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)
	if host != nil && host.Enabled && s.proxyHostService != nil {
		if _, err := s.proxyHostService.Update(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return nil, fmt.Errorf("failed to regenerate nginx config for rate limit: %w", err)
		}
	}

	return rateLimit, nil
}

func (s *SecurityService) DeleteRateLimit(ctx context.Context, proxyHostID string) error {
	host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)

	if err := s.rateLimitRepo.Delete(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete rate limit: %w", err)
	}

	// Regenerate nginx config to remove rate limit
	if host != nil && host.Enabled && s.proxyHostService != nil {
		if _, err := s.proxyHostService.Update(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return fmt.Errorf("failed to regenerate nginx config for rate limit removal: %w", err)
		}
	}

	return nil
}

// GetHostName returns the first domain name of a proxy host, or the ID if not found.
func (s *SecurityService) GetHostName(ctx context.Context, proxyHostID string) string {
	host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)
	if host != nil && len(host.DomainNames) > 0 {
		return host.DomainNames[0]
	}
	return proxyHostID
}

// ---- Fail2ban ----

func (s *SecurityService) GetFail2ban(ctx context.Context, proxyHostID string) (*model.Fail2banConfig, error) {
	cfg, err := s.rateLimitRepo.GetFail2banByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get fail2ban config: %w", err)
	}
	if cfg == nil {
		cfg = &model.Fail2banConfig{
			ProxyHostID: proxyHostID,
			Enabled:     false,
			MaxRetries:  5,
			FindTime:    600,
			BanTime:     3600,
			FailCodes:   "401,403",
			Action:      "block",
		}
	}
	return cfg, nil
}

func (s *SecurityService) UpsertFail2ban(ctx context.Context, proxyHostID string, req *model.CreateFail2banRequest) (*model.Fail2banConfig, error) {
	cfg, err := s.rateLimitRepo.UpsertFail2ban(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert fail2ban config: %w", err)
	}
	return cfg, nil
}

func (s *SecurityService) DeleteFail2ban(ctx context.Context, proxyHostID string) error {
	if err := s.rateLimitRepo.DeleteFail2ban(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete fail2ban config: %w", err)
	}
	return nil
}

// ---- Upstream ----

func (s *SecurityService) GetUpstream(ctx context.Context, proxyHostID string) (*model.Upstream, error) {
	upstream, err := s.upstreamRepo.GetByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream: %w", err)
	}
	if upstream == nil {
		upstream = &model.Upstream{
			ProxyHostID:               proxyHostID,
			Scheme:                    "http",
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
	return upstream, nil
}

func (s *SecurityService) UpsertUpstream(ctx context.Context, proxyHostID string, req *model.CreateUpstreamRequest) (*model.Upstream, error) {
	// Validate load balance method
	if req.LoadBalance != "" {
		valid := false
		for _, m := range model.ValidLoadBalanceMethods {
			if req.LoadBalance == m {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid load_balance method: %s", req.LoadBalance)
		}
	}

	// Validate scheme (http or https only)
	if req.Scheme != "" && req.Scheme != "http" && req.Scheme != "https" {
		return nil, fmt.Errorf("invalid scheme: %s (must be http or https)", req.Scheme)
	}

	// Validate server addresses
	for i, srv := range req.Servers {
		if srv.Address == "" {
			return nil, fmt.Errorf("server %d: address is required", i+1)
		}
		if srv.Port < 0 || srv.Port > 65535 {
			return nil, fmt.Errorf("server %d: invalid port %d", i+1, srv.Port)
		}
	}

	upstream, err := s.upstreamRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert upstream: %w", err)
	}

	// Regenerate nginx config to apply upstream changes
	if s.proxyHostService != nil {
		if regenErr := s.proxyHostService.RegenerateConfigForHost(ctx, proxyHostID); regenErr != nil {
			log.Printf("[Upstream] Warning: failed to regenerate config for host %s: %v", proxyHostID, regenErr)
		}
	}

	return upstream, nil
}

func (s *SecurityService) DeleteUpstream(ctx context.Context, proxyHostID string) error {
	if err := s.upstreamRepo.Delete(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete upstream: %w", err)
	}

	// Regenerate nginx config to remove upstream block
	if s.proxyHostService != nil {
		if regenErr := s.proxyHostService.RegenerateConfigForHost(ctx, proxyHostID); regenErr != nil {
			log.Printf("[Upstream] Warning: failed to regenerate config after upstream delete for host %s: %v", proxyHostID, regenErr)
		}
	}

	return nil
}

func (s *SecurityService) GetUpstreamHealth(ctx context.Context, id string) (*model.UpstreamHealthStatus, error) {
	upstream, err := s.upstreamRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream health: %w", err)
	}
	if upstream == nil {
		return nil, nil
	}

	healthyCount := 0
	unhealthyCount := 0
	serverStatuses := make([]model.ServerHealthStatus, len(upstream.Servers))

	for i, srv := range upstream.Servers {
		if srv.IsHealthy && !srv.IsDown {
			healthyCount++
		} else {
			unhealthyCount++
		}
		serverStatuses[i] = model.ServerHealthStatus{
			Address:     srv.Address,
			Port:        srv.Port,
			IsHealthy:   srv.IsHealthy,
			IsBackup:    srv.IsBackup,
			IsDown:      srv.IsDown,
			LastCheckAt: srv.LastCheckAt,
			LastError:   srv.LastError,
		}
	}

	return &model.UpstreamHealthStatus{
		UpstreamID:     upstream.ID,
		Name:           upstream.Name,
		IsHealthy:      upstream.IsHealthy,
		HealthyCount:   healthyCount,
		UnhealthyCount: unhealthyCount,
		LastCheckAt:    upstream.LastCheckAt,
		Servers:        serverStatuses,
	}, nil
}

// ---- IP Ban History ----

func (s *SecurityService) GetIPBanHistory(ctx context.Context, filter *model.IPBanHistoryFilter) (*model.IPBanHistoryListResponse, error) {
	if s.historyRepo == nil {
		return nil, fmt.Errorf("history repository not initialized")
	}
	result, err := s.historyRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list IP ban history: %w", err)
	}
	return result, nil
}

func (s *SecurityService) GetIPBanHistoryByIP(ctx context.Context, ip string, page, perPage int) (*model.IPBanHistoryListResponse, error) {
	if s.historyRepo == nil {
		return nil, fmt.Errorf("history repository not initialized")
	}
	result, err := s.historyRepo.GetByIP(ctx, ip, page, perPage)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP ban history: %w", err)
	}
	return result, nil
}

func (s *SecurityService) GetIPBanHistoryStats(ctx context.Context) (*model.IPBanHistoryStats, error) {
	if s.historyRepo == nil {
		return nil, fmt.Errorf("history repository not initialized")
	}
	stats, err := s.historyRepo.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP ban history stats: %w", err)
	}
	return stats, nil
}

// ---- Banned IPs ----

func (s *SecurityService) ListBannedIPs(ctx context.Context, proxyHostID string, filterType string, page, perPage int) (*model.BannedIPListResponse, error) {
	var result *model.BannedIPListResponse
	var err error

	switch filterType {
	case "global":
		result, err = s.rateLimitRepo.ListGlobalBannedIPs(ctx, page, perPage)
	case "host":
		if proxyHostID != "" {
			result, err = s.rateLimitRepo.ListBannedIPs(ctx, &proxyHostID, page, perPage)
		} else {
			result, err = s.rateLimitRepo.ListHostBannedIPs(ctx, page, perPage)
		}
	default:
		var proxyHostIDPtr *string
		if proxyHostID != "" {
			proxyHostIDPtr = &proxyHostID
		}
		result, err = s.rateLimitRepo.ListBannedIPs(ctx, proxyHostIDPtr, page, perPage)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list banned IPs: %w", err)
	}
	return result, nil
}

// BanIPRequest holds the parameters for banning an IP.
type BanIPRequest struct {
	ProxyHostID *string
	IPAddress   string
	Reason      string
	BanTime     int
	UserID      *string
	UserEmail   string
}

func (s *SecurityService) BanIP(ctx context.Context, req *BanIPRequest) (*model.BannedIP, error) {
	bannedIP, err := s.rateLimitRepo.BanIP(ctx, req.ProxyHostID, req.IPAddress, req.Reason, req.BanTime)
	if err != nil {
		return nil, fmt.Errorf("failed to ban IP: %w", err)
	}

	// Add to Redis cache for fast lookup
	if s.redisCache != nil && s.redisCache.IsReady() {
		hostID := ""
		if req.ProxyHostID != nil {
			hostID = *req.ProxyHostID
		}
		var ttl time.Duration
		if req.BanTime > 0 {
			ttl = time.Duration(req.BanTime) * time.Second
		}
		s.redisCache.AddBannedIP(ctx, req.IPAddress, hostID, ttl)
	}

	// Record ban history
	if s.historyRepo != nil {
		domainName := ""
		if req.ProxyHostID != nil {
			host, _ := s.proxyHostRepo.GetByID(ctx, *req.ProxyHostID)
			if host != nil && len(host.DomainNames) > 0 {
				domainName = host.DomainNames[0]
			}
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
			UserID:      req.UserID,
			UserEmail:   req.UserEmail,
		}
		if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
			log.Printf("[SecurityService] Failed to record ban history: %v", err)
		}
	}

	// Regenerate nginx config to apply banned IP (in background for speed)
	go s.regenerateConfigsForBan(req.ProxyHostID)

	return bannedIP, nil
}

// regenerateConfigsForBan regenerates configs after an IP ban/unban.
func (s *SecurityService) regenerateConfigsForBan(proxyHostID *string) {
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()

	if s.proxyHostService == nil {
		return
	}

	if proxyHostID != nil {
		// Regenerate specific host config without immediate reload
		if _, err := s.proxyHostService.UpdateWithoutReload(ctx, *proxyHostID, nil); err != nil {
			log.Printf("[SecurityService] Failed to regenerate config for host: %v", err)
			return
		}
	} else {
		// For global ban, regenerate all enabled hosts without reload
		hosts, _, err := s.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
		if err == nil && hosts != nil {
			for _, host := range hosts {
				if host.Enabled {
					if _, err := s.proxyHostService.UpdateWithoutReload(ctx, host.ID, nil); err != nil {
						log.Printf("[SecurityService] Failed to regenerate config for host %s: %v", host.ID, err)
					}
				}
			}
		}
	}
	// Request single debounced reload after all configs are generated
	if s.nginxReloader != nil {
		s.nginxReloader.RequestReload(ctx)
	}
}

// regenerateAllConfigsForBan regenerates all host configs and requests a debounced reload.
func (s *SecurityService) regenerateAllConfigsForBan() {
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()

	if s.proxyHostService == nil || s.proxyHostRepo == nil {
		return
	}

	hosts, _, err := s.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
	if err == nil && hosts != nil {
		for _, host := range hosts {
			if host.Enabled {
				if _, err := s.proxyHostService.UpdateWithoutReload(ctx, host.ID, nil); err != nil {
					log.Printf("[SecurityService] Failed to regenerate config for host %s: %v", host.ID, err)
				}
			}
		}
		if s.nginxReloader != nil {
			s.nginxReloader.RequestReload(ctx)
		}
	}
}

func (s *SecurityService) UnbanIP(ctx context.Context, id string, userID *string, userEmail string) error {
	// Get banned IP info before deleting (for history and cache removal)
	bannedIP, _ := s.rateLimitRepo.GetBannedIPByID(ctx, id)

	if err := s.rateLimitRepo.UnbanIP(ctx, id); err != nil {
		return fmt.Errorf("failed to unban IP: %w", err)
	}

	// Remove from Redis cache
	if s.redisCache != nil && bannedIP != nil {
		hostID := ""
		if bannedIP.ProxyHostID != nil {
			hostID = *bannedIP.ProxyHostID
		}
		if err := s.redisCache.RemoveBannedIP(ctx, bannedIP.IPAddress, hostID); err != nil {
			log.Printf("[SecurityService] Failed to remove banned IP from cache: %v", err)
		}
	}

	// Record unban history
	if s.historyRepo != nil && bannedIP != nil {
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
		if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
			log.Printf("[SecurityService] Failed to record unban history: %v", err)
		}
	}

	// Regenerate all enabled host configs in background
	go s.regenerateAllConfigsForBan()

	return nil
}

func (s *SecurityService) UnbanIPByAddress(ctx context.Context, ip string, userID *string, userEmail string) error {
	// Record unban history before deleting
	if s.historyRepo != nil {
		historyEvent := &model.IPBanHistory{
			EventType: model.BanEventTypeUnban,
			IPAddress: ip,
			Reason:    "Manual unban by IP address",
			Source:    model.BanSourceManual,
			IsAuto:    false,
			UserID:    userID,
			UserEmail: userEmail,
		}
		if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
			log.Printf("[SecurityService] Failed to record unban history by address: %v", err)
		}
	}

	if err := s.rateLimitRepo.UnbanIPByAddress(ctx, ip); err != nil {
		return fmt.Errorf("failed to unban IP by address: %w", err)
	}

	// Remove from Redis cache (both global and all host-specific)
	if s.redisCache != nil {
		if err := s.redisCache.RemoveBannedIP(ctx, ip, ""); err != nil {
			log.Printf("[SecurityService] Failed to remove banned IP from global cache: %v", err)
		}
		if s.proxyHostRepo != nil {
			hosts, _, err := s.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
			if err == nil && hosts != nil {
				for _, host := range hosts {
					s.redisCache.RemoveBannedIP(ctx, ip, host.ID)
				}
			}
		}
	}

	// Regenerate all enabled host configs in background with debounced reload
	go s.regenerateAllConfigsForBan()

	return nil
}

// ---- Bot Filter ----

func (s *SecurityService) GetBotFilter(ctx context.Context, proxyHostID string) (*model.BotFilter, error) {
	filter, err := s.botFilterRepo.GetByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get bot filter: %w", err)
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
	return filter, nil
}

func (s *SecurityService) UpsertBotFilter(ctx context.Context, proxyHostID string, req *model.CreateBotFilterRequest, skipReload bool) (*model.BotFilter, error) {
	filter, err := s.botFilterRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert bot filter: %w", err)
	}

	// Regenerate nginx config to apply bot filter changes (skip if requested)
	if !skipReload {
		host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)
		if host != nil && host.Enabled && s.proxyHostService != nil {
			if _, err := s.proxyHostService.Update(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
				return nil, fmt.Errorf("failed to regenerate nginx config for bot filter: %w", err)
			}
		}
	}

	return filter, nil
}

func (s *SecurityService) DeleteBotFilter(ctx context.Context, proxyHostID string) error {
	if err := s.botFilterRepo.Delete(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete bot filter: %w", err)
	}
	return nil
}

// ---- Security Headers ----

func (s *SecurityService) GetSecurityHeaders(ctx context.Context, proxyHostID string) (*model.SecurityHeaders, error) {
	headers, err := s.secHeadersRepo.GetByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get security headers: %w", err)
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
	return headers, nil
}

func (s *SecurityService) UpsertSecurityHeaders(ctx context.Context, proxyHostID string, req *model.CreateSecurityHeadersRequest) (*model.SecurityHeaders, error) {
	headers, err := s.secHeadersRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert security headers: %w", err)
	}
	return headers, nil
}

func (s *SecurityService) DeleteSecurityHeaders(ctx context.Context, proxyHostID string) error {
	if err := s.secHeadersRepo.Delete(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete security headers: %w", err)
	}
	return nil
}

func (s *SecurityService) ApplySecurityHeaderPreset(ctx context.Context, proxyHostID string, preset string) (*model.SecurityHeaders, error) {
	presetConfig, ok := model.SecurityHeaderPresets[preset]
	if !ok {
		return nil, fmt.Errorf("invalid preset: %s", preset)
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

	headers, err := s.secHeadersRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to apply security header preset: %w", err)
	}
	return headers, nil
}

