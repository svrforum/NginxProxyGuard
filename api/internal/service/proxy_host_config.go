package service

import (
	"context"
	"strings"
	"sync"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

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

// getPriorityAllowIPs returns the Priority Allow IPs for a host (used for WAF bypass)
func (s *ProxyHostService) getPriorityAllowIPs(ctx context.Context, hostID string) []string {
	if s.geoRepo == nil {
		return nil
	}
	geo, err := s.geoRepo.GetByProxyHostID(ctx, hostID)
	if err != nil || geo == nil {
		return nil
	}
	return geo.AllowedIPs
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
			// Deduplicate by IP address (same IP can exist in both host-specific and global bans)
			if len(bannedIPs) > 0 {
				seen := make(map[string]bool, len(bannedIPs))
				unique := make([]model.BannedIP, 0, len(bannedIPs))
				for _, ban := range bannedIPs {
					if !seen[ban.IPAddress] {
						seen[ban.IPAddress] = true
						unique = append(unique, ban)
					}
				}
				bannedIPs = unique
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

	// Check if this host should use shared filter subscription configs
	// The actual IP/UA entries are in shared include files (filter_sub_ips.conf, filter_sub_uas.conf)
	// generated by FilterSubscriptionService. We only need to determine if this host should use them.
	if s.filterSubscriptionRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enabledCount, err := s.filterSubscriptionRepo.CountEnabledSubscriptions(ctx)
			if err != nil || enabledCount == 0 {
				return
			}
			// Check if host is excluded from ALL subscriptions
			exclCount, err := s.filterSubscriptionRepo.CountExclusionsForHost(ctx, host.ID)
			if err != nil {
				return
			}
			if exclCount < enabledCount {
				mu.Lock()
				data.UseFilterSubscription = true
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

	// Fetch global trusted IPs and block_exploits exceptions from system settings
	if s.systemSettingsRepo != nil {
		settings, err := s.systemSettingsRepo.Get(ctx)
		if err == nil && settings != nil {
			if host.BlockExploits {
				data.GlobalBlockExploitsExceptions = settings.GlobalBlockExploitsExceptions
			}
			// Parse global trusted IPs for nginx ban bypass (with strict validation)
			if settings.GlobalTrustedIPs != "" {
				for _, line := range strings.Split(settings.GlobalTrustedIPs, "\n") {
					entry := strings.TrimSpace(line)
					if entry == "" || strings.HasPrefix(entry, "#") {
						continue
					}
					// Validate: must be a valid IP or CIDR (prevents nginx config injection)
					if isValidIPOrCIDR(entry) {
						data.GlobalTrustedIPs = append(data.GlobalTrustedIPs, entry)
					}
				}
			}
		}
	}

	// Filter out banned IPs that match any global trusted IP/CIDR.
	// This ensures trusted IPs are never blocked regardless of nginx geo ordering.
	if len(data.GlobalTrustedIPs) > 0 && len(data.BannedIPs) > 0 {
		data.BannedIPs = filterBannedByTrustedIPs(data.BannedIPs, data.GlobalTrustedIPs)
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
