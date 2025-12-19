package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

type NginxManager interface {
	GenerateConfig(ctx context.Context, host *model.ProxyHost) error
	GenerateConfigWithAccessControl(ctx context.Context, host *model.ProxyHost, accessList *model.AccessList, geoRestriction *model.GeoRestriction) error
	GenerateConfigFull(ctx context.Context, data nginx.ProxyHostConfigData) error
	RemoveConfig(ctx context.Context, host *model.ProxyHost) error
	TestConfig(ctx context.Context) error
	ReloadNginx(ctx context.Context) error
	GenerateAllConfigs(ctx context.Context, hosts []model.ProxyHost) error
	GenerateHostWAFConfig(ctx context.Context, host *model.ProxyHost, exclusions []model.WAFRuleExclusion) error
}

type ProxyHostService struct {
	repo                   *repository.ProxyHostRepository
	wafRepo                *repository.WAFRepository
	accessListRepo         *repository.AccessListRepository
	geoRepo                *repository.GeoRepository
	rateLimitRepo          *repository.RateLimitRepository
	securityHeadersRepo    *repository.SecurityHeadersRepository
	botFilterRepo          *repository.BotFilterRepository
	upstreamRepo           *repository.UpstreamRepository
	systemSettingsRepo     *repository.SystemSettingsRepository
	cloudProviderRepo      *repository.CloudProviderRepository
	globalSettingsRepo     *repository.GlobalSettingsRepository
	uriBlockRepo           *repository.URIBlockRepository
	exploitBlockRuleRepo   *repository.ExploitBlockRuleRepository
	nginx                  NginxManager
}

func NewProxyHostService(
	repo *repository.ProxyHostRepository,
	wafRepo *repository.WAFRepository,
	accessListRepo *repository.AccessListRepository,
	geoRepo *repository.GeoRepository,
	rateLimitRepo *repository.RateLimitRepository,
	securityHeadersRepo *repository.SecurityHeadersRepository,
	botFilterRepo *repository.BotFilterRepository,
	upstreamRepo *repository.UpstreamRepository,
	systemSettingsRepo *repository.SystemSettingsRepository,
	cloudProviderRepo *repository.CloudProviderRepository,
	globalSettingsRepo *repository.GlobalSettingsRepository,
	uriBlockRepo *repository.URIBlockRepository,
	exploitBlockRuleRepo *repository.ExploitBlockRuleRepository,
	nginx NginxManager,
) *ProxyHostService {
	return &ProxyHostService{
		repo:                   repo,
		wafRepo:                wafRepo,
		accessListRepo:         accessListRepo,
		geoRepo:                geoRepo,
		rateLimitRepo:          rateLimitRepo,
		securityHeadersRepo:    securityHeadersRepo,
		botFilterRepo:          botFilterRepo,
		upstreamRepo:           upstreamRepo,
		systemSettingsRepo:     systemSettingsRepo,
		cloudProviderRepo:      cloudProviderRepo,
		globalSettingsRepo:     globalSettingsRepo,
		uriBlockRepo:           uriBlockRepo,
		exploitBlockRuleRepo:   exploitBlockRuleRepo,
		nginx:                  nginx,
	}
}

// getMergedWAFExclusions gets host-specific exclusions and merges with global exclusions
func (s *ProxyHostService) getMergedWAFExclusions(ctx context.Context, hostID string) ([]model.WAFRuleExclusion, error) {
	// Get host-specific exclusions
	hostExclusions, err := s.wafRepo.GetExclusionsByProxyHost(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Get global exclusions
	globalExclusions, err := s.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		return nil, err
	}

	// Create a map of host exclusions to avoid duplicates
	hostExclusionMap := make(map[int]bool)
	for _, ex := range hostExclusions {
		hostExclusionMap[ex.RuleID] = true
	}

	// Merge: start with host exclusions
	merged := make([]model.WAFRuleExclusion, len(hostExclusions))
	copy(merged, hostExclusions)

	// Add global exclusions that are not already in host exclusions
	for _, gex := range globalExclusions {
		if !hostExclusionMap[gex.RuleID] {
			merged = append(merged, model.WAFRuleExclusion{
				ID:              gex.ID,
				ProxyHostID:     "global",
				RuleID:          gex.RuleID,
				RuleCategory:    gex.RuleCategory,
				RuleDescription: gex.RuleDescription,
				Reason:          gex.Reason + " (global)",
				DisabledBy:      gex.DisabledBy,
				CreatedAt:       gex.CreatedAt,
			})
		}
	}

	return merged, nil
}

// getAccessControlData fetches access list and geo restriction for a host
// Deprecated: Use getHostConfigData instead for Phase 6+ features
func (s *ProxyHostService) getAccessControlData(ctx context.Context, host *model.ProxyHost) (*model.AccessList, *model.GeoRestriction, error) {
	var accessList *model.AccessList
	var geoRestriction *model.GeoRestriction

	// Fetch access list if assigned
	if host.AccessListID != nil && *host.AccessListID != "" && s.accessListRepo != nil {
		al, err := s.accessListRepo.GetByID(ctx, *host.AccessListID)
		if err == nil && al != nil {
			accessList = al
		}
	}

	// Fetch geo restriction if exists
	// Load if enabled OR if has AllowedIPs (priority allow IPs are used for cloud blocking too)
	if s.geoRepo != nil {
		geo, err := s.geoRepo.GetByProxyHostID(ctx, host.ID)
		if err == nil && geo != nil && (geo.Enabled || len(geo.AllowedIPs) > 0) {
			geoRestriction = geo
		}
	}

	return accessList, geoRestriction, nil
}

// getHostConfigData fetches all Phase 6 configuration data for a host
func (s *ProxyHostService) getHostConfigData(ctx context.Context, host *model.ProxyHost) nginx.ProxyHostConfigData {
	data := nginx.ProxyHostConfigData{
		Host: host,
	}

	// Use goroutines to fetch all config data in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Fetch access list if assigned
	if host.AccessListID != nil && *host.AccessListID != "" && s.accessListRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			al, err := s.accessListRepo.GetByID(ctx, *host.AccessListID)
			if err == nil && al != nil {
				mu.Lock()
				data.AccessList = al
				mu.Unlock()
			}
		}()
	}

	// Fetch geo restriction if exists
	// Load if enabled OR if has AllowedIPs (priority allow IPs are used for cloud blocking too)
	if s.geoRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			geo, err := s.geoRepo.GetByProxyHostID(ctx, host.ID)
			if err == nil && geo != nil && (geo.Enabled || len(geo.AllowedIPs) > 0) {
				mu.Lock()
				data.GeoRestriction = geo
				mu.Unlock()
			}
		}()
	}

	// Fetch rate limit if exists
	if s.rateLimitRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl, err := s.rateLimitRepo.GetByProxyHostID(ctx, host.ID)
			if err == nil && rl != nil && rl.Enabled {
				mu.Lock()
				data.RateLimit = rl
				mu.Unlock()
			}
		}()
	}

	// Fetch security headers if exists
	if s.securityHeadersRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sh, err := s.securityHeadersRepo.GetByProxyHostID(ctx, host.ID)
			if err == nil && sh != nil && sh.Enabled {
				mu.Lock()
				data.SecurityHeaders = sh
				mu.Unlock()
			}
		}()
	}

	// Fetch bot filter if exists
	if s.botFilterRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bf, err := s.botFilterRepo.GetByProxyHostID(ctx, host.ID)
			if err == nil && bf != nil && bf.Enabled {
				mu.Lock()
				data.BotFilter = bf
				mu.Unlock()
			}
		}()
	}

	// Fetch upstream if exists
	if s.upstreamRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			up, err := s.upstreamRepo.GetByProxyHostID(ctx, host.ID)
			if err == nil && up != nil && len(up.Servers) > 0 {
				mu.Lock()
				data.Upstream = up
				mu.Unlock()
			}
		}()
	}

	// Fetch banned IPs for this host (including global bans with no proxy_host_id)
	if s.rateLimitRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var bannedIPs []model.BannedIP
			// Get host-specific bans
			bannedResp, err := s.rateLimitRepo.ListBannedIPs(ctx, &host.ID, 1, 1000)
			if err == nil && bannedResp != nil {
				bannedIPs = bannedResp.Data
			}
			// Also get global bans (proxy_host_id IS NULL)
			globalBannedResp, err := s.rateLimitRepo.ListGlobalBannedIPs(ctx, 1, 1000)
			if err == nil && globalBannedResp != nil {
				bannedIPs = append(bannedIPs, globalBannedResp.Data...)
			}
			mu.Lock()
			data.BannedIPs = bannedIPs
			mu.Unlock()
		}()
	}

	// Fetch blocked cloud provider IP ranges and challenge mode setting
	if s.cloudProviderRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			settings, err := s.cloudProviderRepo.GetCloudProviderBlockingSettings(ctx, host.ID)
			if err == nil && len(settings.BlockedProviders) > 0 {
				ipRanges, err := s.cloudProviderRepo.GetIPRangesForProviders(ctx, settings.BlockedProviders)
				if err == nil && len(ipRanges) > 0 {
					mu.Lock()
					data.BlockedCloudIPRanges = ipRanges
					data.CloudProviderChallengeMode = settings.ChallengeMode
					data.CloudProviderAllowSearchBots = settings.AllowSearchBots
					mu.Unlock()
				}
			}
		}()
	}

	// Fetch URI block settings (both global and per-host)
	if s.uriBlockRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Get global URI block rules
			globalUB, _ := s.uriBlockRepo.GetGlobalURIBlock(ctx)
			// Get host-specific URI block rules
			hostUB, _ := s.uriBlockRepo.GetByProxyHostID(ctx, host.ID)

			// Merge global and host-specific rules
			mergedUB := mergeURIBlocks(globalUB, hostUB)
			if mergedUB != nil && mergedUB.Enabled && len(mergedUB.Rules) > 0 {
				mu.Lock()
				data.URIBlock = mergedUB
				mu.Unlock()
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Fetch bot lists from system settings (for bot filter) - depends on BotFilter result
	if data.BotFilter != nil && data.BotFilter.Enabled {
		var settings *model.SystemSettings
		if s.systemSettingsRepo != nil {
			settings, _ = s.systemSettingsRepo.Get(ctx)
		}

		// Fetch each bot list based on filter settings, with fallback to model defaults
		if data.BotFilter.BlockSuspiciousClients {
			if settings != nil && settings.BotListSuspiciousClients != "" {
				data.SuspiciousClientsList = settings.BotListSuspiciousClients
			} else {
				data.SuspiciousClientsList = strings.Join(model.SuspiciousClients, "\n")
			}
		}
		if data.BotFilter.BlockBadBots {
			if settings != nil && settings.BotListBadBots != "" {
				data.BadBotsList = settings.BotListBadBots
			} else {
				data.BadBotsList = strings.Join(model.KnownBadBots, "\n")
			}
		}
		if data.BotFilter.BlockAIBots {
			if settings != nil && settings.BotListAIBots != "" {
				data.AIBotsList = settings.BotListAIBots
			} else {
				data.AIBotsList = strings.Join(model.AIBots, "\n")
			}
		}
		if data.BotFilter.AllowSearchEngines {
			if settings != nil && settings.BotListSearchEngines != "" {
				data.SearchEnginesList = settings.BotListSearchEngines
			} else {
				data.SearchEnginesList = strings.Join(model.SearchEngineBots, "\n")
			}
		}
	}

	// Fetch global settings for proxy timeouts, client body size, etc.
	if s.globalSettingsRepo != nil {
		gs, err := s.globalSettingsRepo.Get(ctx)
		if err == nil && gs != nil {
			data.GlobalSettings = gs
		}
	}

	// Fetch global block_exploits exceptions from system settings
	if host.BlockExploits && s.systemSettingsRepo != nil {
		settings, err := s.systemSettingsRepo.Get(ctx)
		if err == nil && settings != nil {
			data.GlobalBlockExploitsExceptions = settings.GlobalBlockExploitsExceptions
		}
	}

	// Fetch exploit block rules from database when block_exploits is enabled
	if host.BlockExploits && s.exploitBlockRuleRepo != nil {
		rules, err := s.exploitBlockRuleRepo.GetEnabledForHost(ctx, host.ID)
		if err == nil {
			data.ExploitBlockRules = rules
		}
	}

	return data
}

func (s *ProxyHostService) Create(ctx context.Context, req *model.CreateProxyHostRequest) (*model.ProxyHost, error) {
	// Set defaults
	if req.ForwardScheme == "" {
		req.ForwardScheme = "http"
	}
	if req.ForwardPort == 0 {
		req.ForwardPort = 80
	}

	// Filter out empty domain names
	var validDomains []string
	for _, d := range req.DomainNames {
		d = strings.TrimSpace(d)
		if d != "" {
			validDomains = append(validDomains, d)
		}
	}
	if len(validDomains) == 0 {
		return nil, fmt.Errorf("at least one valid domain name is required")
	}
	req.DomainNames = validDomains

	// Validate SSL settings: ssl_force_https requires ssl_enabled
	if req.SSLForceHTTPS && !req.SSLEnabled {
		req.SSLForceHTTPS = false // Auto-correct invalid state
	}

	// Validate advanced config for security
	if err := model.ValidateAdvancedConfig(req.AdvancedConfig); err != nil {
		return nil, fmt.Errorf("invalid advanced config: %w", err)
	}

	// Check for duplicate domains
	existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check domain existence: %w", err)
	}
	if len(existingDomains) > 0 {
		return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
	}

	// Create in database
	host, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy host: %w", err)
	}

	// Generate nginx config if enabled
	if host.Enabled {
		// Fetch all configuration data for this host
		configData := s.getHostConfigData(ctx, host)

		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return nil, fmt.Errorf("failed to generate nginx config: %w", err)
		}

		// Generate WAF config if WAF is enabled (new hosts may have global exclusions)
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get WAF exclusions: %w", err)
			}
			if err := s.nginx.GenerateHostWAFConfig(ctx, host, mergedExclusions); err != nil {
				return nil, fmt.Errorf("failed to generate WAF config: %w", err)
			}
		}

		if err := s.nginx.TestConfig(ctx); err != nil {
			// Rollback config on test failure
			_ = s.nginx.RemoveConfig(ctx, host)
			return nil, fmt.Errorf("nginx config test failed: %w", err)
		}

		if err := s.nginx.ReloadNginx(ctx); err != nil {
			return nil, fmt.Errorf("failed to reload nginx: %w", err)
		}
	}

	return host, nil
}

func (s *ProxyHostService) GetByID(ctx context.Context, id string) (*model.ProxyHost, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *ProxyHostService) GetByDomain(ctx context.Context, domain string) (*model.ProxyHost, error) {
	return s.repo.GetByDomain(ctx, domain)
}

func (s *ProxyHostService) List(ctx context.Context, page, perPage int) (*model.ProxyHostListResponse, error) {
	hosts, total, err := s.repo.List(ctx, page, perPage)
	if err != nil {
		return nil, err
	}

	totalPages := (total + perPage - 1) / perPage

	return &model.ProxyHostListResponse{
		Data:       hosts,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// UpdateWithoutReload generates nginx config without reloading (for use with debounced reloader)
func (s *ProxyHostService) UpdateWithoutReload(ctx context.Context, id string, req *model.UpdateProxyHostRequest) (*model.ProxyHost, error) {
	var host *model.ProxyHost
	var err error

	// If req is nil, we just want to regenerate config for the existing host
	if req != nil {
		// Validate SSL settings: ssl_force_https requires ssl_enabled
		if req.SSLForceHTTPS != nil && req.SSLEnabled != nil {
			if *req.SSLForceHTTPS && !*req.SSLEnabled {
				*req.SSLForceHTTPS = false
			}
		}

		// Validate advanced config for security if provided
		if req.AdvancedConfig != nil {
			if err := model.ValidateAdvancedConfig(*req.AdvancedConfig); err != nil {
				return nil, fmt.Errorf("invalid advanced config: %w", err)
			}
		}

		// Check for duplicate domains if domain_names is being updated
		if len(req.DomainNames) > 0 {
			var validDomains []string
			for _, d := range req.DomainNames {
				d = strings.TrimSpace(d)
				if d != "" {
					validDomains = append(validDomains, d)
				}
			}
			if len(validDomains) == 0 {
				return nil, fmt.Errorf("at least one valid domain name is required")
			}
			req.DomainNames = validDomains

			existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, id)
			if err != nil {
				return nil, fmt.Errorf("failed to check domain existence: %w", err)
			}
			if len(existingDomains) > 0 {
				return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
			}
		}

		host, err = s.repo.Update(ctx, id, req)
		if err != nil {
			return nil, fmt.Errorf("failed to update proxy host: %w", err)
		}
	} else {
		host, err = s.repo.GetByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to get proxy host: %w", err)
		}
	}

	if host == nil {
		return nil, nil
	}

	// Regenerate nginx config (without reload)
	if host.Enabled {
		configData := s.getHostConfigData(ctx, host)

		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return nil, fmt.Errorf("failed to generate nginx config: %w", err)
		}

		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("failed to get WAF exclusions: %w", err)
			}
			if err := s.nginx.GenerateHostWAFConfig(ctx, host, mergedExclusions); err != nil {
				return nil, fmt.Errorf("failed to generate WAF config: %w", err)
			}
		}
	} else {
		if err := s.nginx.RemoveConfig(ctx, host); err != nil {
			return nil, fmt.Errorf("failed to remove nginx config: %w", err)
		}
	}

	// Test config but don't reload
	if err := s.nginx.TestConfig(ctx); err != nil {
		return nil, fmt.Errorf("nginx config test failed: %w", err)
	}

	return host, nil
}

func (s *ProxyHostService) Update(ctx context.Context, id string, req *model.UpdateProxyHostRequest) (*model.ProxyHost, error) {
	var host *model.ProxyHost
	var err error

	// If req is nil, we just want to regenerate config for the existing host
	if req != nil {
		// Validate SSL settings: ssl_force_https requires ssl_enabled
		if req.SSLForceHTTPS != nil && req.SSLEnabled != nil {
			if *req.SSLForceHTTPS && !*req.SSLEnabled {
				*req.SSLForceHTTPS = false // Auto-correct invalid state
			}
		}

		// Validate advanced config for security if provided
		if req.AdvancedConfig != nil {
			if err := model.ValidateAdvancedConfig(*req.AdvancedConfig); err != nil {
				return nil, fmt.Errorf("invalid advanced config: %w", err)
			}
		}

		// Check for duplicate domains if domain_names is being updated
		if len(req.DomainNames) > 0 {
			// Filter out empty domain names
			var validDomains []string
			for _, d := range req.DomainNames {
				d = strings.TrimSpace(d)
				if d != "" {
					validDomains = append(validDomains, d)
				}
			}
			if len(validDomains) == 0 {
				return nil, fmt.Errorf("at least one valid domain name is required")
			}
			req.DomainNames = validDomains

			existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, id)
			if err != nil {
				return nil, fmt.Errorf("failed to check domain existence: %w", err)
			}
			if len(existingDomains) > 0 {
				return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
			}
		}

	    host, err = s.repo.Update(ctx, id, req)
	    if err != nil {
		    return nil, fmt.Errorf("failed to update proxy host: %w", err)
	    }
	} else {
		// Just fetch the host
		host, err = s.repo.GetByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to get proxy host: %w", err)
		}
	}

	if host == nil {
		return nil, nil
	}

	// Regenerate nginx config
	if host.Enabled {
		// Fetch all configuration data for this host
		configData := s.getHostConfigData(ctx, host)

		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return nil, fmt.Errorf("failed to generate nginx config: %w", err)
		}

		// Generate WAF config if WAF is enabled, including global + host exclusions
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("failed to get WAF exclusions: %w", err)
			}
			if err := s.nginx.GenerateHostWAFConfig(ctx, host, mergedExclusions); err != nil {
				return nil, fmt.Errorf("failed to generate WAF config: %w", err)
			}
		}
	} else {
		if err := s.nginx.RemoveConfig(ctx, host); err != nil {
			return nil, fmt.Errorf("failed to remove nginx config: %w", err)
		}
	}

	if err := s.nginx.TestConfig(ctx); err != nil {
		return nil, fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return nil, fmt.Errorf("failed to reload nginx: %w", err)
	}

	return host, nil
}

func (s *ProxyHostService) Delete(ctx context.Context, id string) error {
	// Get host first to know domain names for config file
	host, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get proxy host: %w", err)
	}
	if host == nil {
		return fmt.Errorf("proxy host not found")
	}

	// Remove nginx config first
	if err := s.nginx.RemoveConfig(ctx, host); err != nil {
		return fmt.Errorf("failed to remove nginx config: %w", err)
	}

	// Delete from database
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete proxy host: %w", err)
	}

	// Test and reload nginx
	if err := s.nginx.TestConfig(ctx); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

// RegenerateConfigsForCertificate regenerates nginx configs for all proxy hosts using the specified certificate
// This should be called when a certificate is issued or renewed
func (s *ProxyHostService) RegenerateConfigsForCertificate(ctx context.Context, certificateID string) error {
	hosts, err := s.repo.GetByCertificateID(ctx, certificateID)
	if err != nil {
		return fmt.Errorf("failed to get proxy hosts for certificate %s: %w", certificateID, err)
	}

	if len(hosts) == 0 {
		return nil // No proxy hosts use this certificate
	}

	// Regenerate configs for all affected hosts
	for _, host := range hosts {
		if !host.Enabled {
			continue
		}

		configData := s.getHostConfigData(ctx, &host)
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return fmt.Errorf("failed to generate config for host %s: %w", host.ID, err)
		}

		// Generate WAF config if WAF is enabled (includes global + host exclusions)
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				return fmt.Errorf("failed to get WAF exclusions for host %s: %w", host.ID, err)
			}
			if err := s.nginx.GenerateHostWAFConfig(ctx, &host, mergedExclusions); err != nil {
				return fmt.Errorf("failed to generate WAF config for host %s: %w", host.ID, err)
			}
		}
	}

	// Test and reload nginx
	if err := s.nginx.TestConfig(ctx); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

func (s *ProxyHostService) SyncAllConfigs(ctx context.Context) error {
	hosts, err := s.repo.GetAllEnabled(ctx)
	if err != nil {
		return fmt.Errorf("failed to get enabled hosts: %w", err)
	}

	// Generate configs for all hosts with full configuration data
	for _, host := range hosts {
		configData := s.getHostConfigData(ctx, &host)
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return fmt.Errorf("failed to generate config for host %s: %w", host.ID, err)
		}

		// Generate WAF config if WAF is enabled (includes global + host exclusions)
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				return fmt.Errorf("failed to get WAF exclusions for host %s: %w", host.ID, err)
			}
			if err := s.nginx.GenerateHostWAFConfig(ctx, &host, mergedExclusions); err != nil {
				return fmt.Errorf("failed to generate WAF config for host %s: %w", host.ID, err)
			}
		}
	}

	if err := s.nginx.TestConfig(ctx); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

// mergeURIBlocks merges global and host-specific URI block settings
// Global rules are applied first (higher priority), then host-specific rules
func mergeURIBlocks(global *model.GlobalURIBlock, host *model.URIBlock) *model.URIBlock {
	// If both are nil or disabled, return nil
	globalEnabled := global != nil && global.Enabled
	hostEnabled := host != nil && host.Enabled

	if !globalEnabled && !hostEnabled {
		return nil
	}

	// Create merged result
	result := &model.URIBlock{
		Enabled:         true,
		Rules:           []model.URIBlockRule{},
		ExceptionIPs:    []string{},
		AllowPrivateIPs: true, // Default to true
	}

	// If host has settings, use its ID and other properties
	if host != nil {
		result.ID = host.ID
		result.ProxyHostID = host.ProxyHostID
		result.CreatedAt = host.CreatedAt
		result.UpdatedAt = host.UpdatedAt
	}

	// Add global rules first (higher priority - checked first by nginx)
	if globalEnabled {
		for _, rule := range global.Rules {
			if rule.Enabled {
				result.Rules = append(result.Rules, rule)
			}
		}
		// Merge global exception IPs
		result.ExceptionIPs = append(result.ExceptionIPs, global.ExceptionIPs...)
		result.AllowPrivateIPs = global.AllowPrivateIPs
	}

	// Add host-specific rules
	if hostEnabled {
		for _, rule := range host.Rules {
			if rule.Enabled {
				// Check if rule already exists (by pattern and match type) to avoid duplicates
				exists := false
				for _, existing := range result.Rules {
					if existing.Pattern == rule.Pattern && existing.MatchType == rule.MatchType {
						exists = true
						break
					}
				}
				if !exists {
					result.Rules = append(result.Rules, rule)
				}
			}
		}
		// Merge host exception IPs (avoid duplicates)
		for _, ip := range host.ExceptionIPs {
			exists := false
			for _, existing := range result.ExceptionIPs {
				if existing == ip {
					exists = true
					break
				}
			}
			if !exists {
				result.ExceptionIPs = append(result.ExceptionIPs, ip)
			}
		}
		// Host-specific AllowPrivateIPs takes precedence if host settings exist
		if host.Enabled {
			result.AllowPrivateIPs = host.AllowPrivateIPs
		}
	}

	return result
}
