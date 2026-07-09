package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// getMergedWAFExclusions gets host-specific exclusions and merges with global exclusions.
// The pure merge logic lives in mergeWAFExclusions (see waf_merge.go) so it can be unit tested
// without a database dependency.
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

	return mergeWAFExclusions(hostExclusions, globalExclusions), nil
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

// getHostConfigData fetches all Phase 6 configuration data for a host.
//
// FAIL-CLOSED: any repository error aborts with a non-nil error instead of
// silently rendering the config without that section. A transient DB error
// must never produce (and reload) a config that is missing access lists,
// banned IPs, geo/cloud/bot/URI blocking or rate limits — callers surface the
// error and nginx keeps running the previous known-good config. "Not found"
// (nil result, no error) is a legitimate state and simply skips the section.
func (s *ProxyHostService) getHostConfigData(ctx context.Context, host *model.ProxyHost) (nginx.ProxyHostConfigData, error) {
	data := nginx.ProxyHostConfigData{
		Host: host,
	}

	// Use goroutines to fetch all config data in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	var fetchErr error
	fail := func(what string, err error) {
		mu.Lock()
		if fetchErr == nil {
			fetchErr = fmt.Errorf("failed to load %s for host %s: %w", what, host.ID, err)
		}
		mu.Unlock()
	}

	// Fetch access list if assigned
	if host.AccessListID != nil && *host.AccessListID != "" && s.accessListRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			al, err := s.accessListRepo.GetByID(ctx, *host.AccessListID)
			if err != nil {
				fail("access list", err)
				return
			}
			if al != nil {
				mu.Lock()
				data.AccessList = al
				mu.Unlock()
			}
		}()
	}

	// Fetch auth provider if assigned (HTTP hosts only — auth_request is invalid in stream{}) (#179)
	if host.ProxyType != model.ProxyTypeStream && host.AuthProviderID != nil && *host.AuthProviderID != "" && s.authProviderRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ap, err := s.authProviderRepo.GetByID(ctx, *host.AuthProviderID)
			if err != nil {
				fail("auth provider", err)
				return
			}
			if ap != nil && ap.Enabled {
				mu.Lock()
				data.AuthProvider = ap
				mu.Unlock()
			}
		}()
	}

	// Fetch geo restriction and resolve it against the global default (#198).
	// resolveGeo collapses global + host into the single effective object the
	// template consumes (3-state: inherit/override/disable). It preserves the
	// host's AllowedIPs (priority-allow IPs used by cloud/bot sections) in every
	// state, so the pre-#198 "load if enabled OR has AllowedIPs" behavior is kept
	// while a global default now applies to inheriting hosts.
	if s.geoRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostGeo, err := s.geoRepo.GetByProxyHostID(ctx, host.ID)
			if err != nil {
				fail("geo restriction", err)
				return
			}
			var globalGeo *model.GlobalGeoRestriction
			if s.globalGeoRepo != nil {
				globalGeo, err = s.globalGeoRepo.GetGlobal(ctx)
				if err != nil {
					fail("global geo restriction", err)
					return
				}
			}
			if effective := resolveGeo(globalGeo, hostGeo); effective != nil {
				mu.Lock()
				data.GeoRestriction = effective
				mu.Unlock()
			}
		}()
	}

	// Fetch rate limit and resolve against the global default (#198 slice 5).
	// The nginx limit_req zone stays per-host; an inheriting host gets the
	// global values under its own zone name.
	if s.rateLimitRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostRL, err := s.rateLimitRepo.GetByProxyHostID(ctx, host.ID)
			if err != nil {
				fail("rate limit", err)
				return
			}
			var globalRL *model.GlobalRateLimit
			if s.globalRateLimitRepo != nil {
				globalRL, err = s.globalRateLimitRepo.GetGlobal(ctx)
				if err != nil {
					fail("global rate limit", err)
					return
				}
			}
			if effective := resolveRateLimit(globalRL, hostRL, host.ID); effective != nil {
				mu.Lock()
				data.RateLimit = effective
				mu.Unlock()
			}
		}()
	}

	// Fetch security headers and resolve against the global default (#198).
	if s.securityHeadersRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostSH, err := s.securityHeadersRepo.GetByProxyHostID(ctx, host.ID)
			if err != nil {
				fail("security headers", err)
				return
			}
			var globalSH *model.GlobalSecurityHeaders
			if s.globalSecHeadersRepo != nil {
				globalSH, err = s.globalSecHeadersRepo.GetGlobal(ctx)
				if err != nil {
					fail("global security headers", err)
					return
				}
			}
			if effective := resolveSecurityHeaders(globalSH, hostSH); effective != nil {
				mu.Lock()
				data.SecurityHeaders = effective
				mu.Unlock()
			}
		}()
	}

	// Fetch bot filter and resolve against the global default (#198).
	if s.botFilterRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostBF, err := s.botFilterRepo.GetByProxyHostID(ctx, host.ID)
			if err != nil {
				fail("bot filter", err)
				return
			}
			var globalBF *model.GlobalBotFilter
			if s.globalBotFilterRepo != nil {
				globalBF, err = s.globalBotFilterRepo.GetGlobal(ctx)
				if err != nil {
					fail("global bot filter", err)
					return
				}
			}
			if effective := resolveBotFilter(globalBF, hostBF); effective != nil {
				mu.Lock()
				data.BotFilter = effective
				mu.Unlock()
			}
		}()
	}

	// Fetch the global WAF default (#198 slice 6). Applied after wg.Wait so the
	// effective WAF fields (mode/paranoia/threshold/enabled) are resolved onto a
	// host copy the config/manager layer reads. WAF settings live on the host
	// struct, so resolveWAF returns a copy rather than a separate data field.
	var globalWAF *model.GlobalWAF
	if s.globalWAFRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := s.globalWAFRepo.GetGlobal(ctx)
			if err != nil {
				fail("global WAF", err)
				return
			}
			mu.Lock()
			globalWAF = g
			mu.Unlock()
		}()
	}

	// Fetch upstream if exists
	if s.upstreamRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			up, err := s.upstreamRepo.GetByProxyHostID(ctx, host.ID)
			if err != nil {
				fail("upstream", err)
				return
			}
			if up != nil && len(up.Servers) > 0 {
				mu.Lock()
				data.Upstream = up
				mu.Unlock()
			}
		}()
	}

	// Fetch banned IPs for this host (including global bans with no proxy_host_id).
	// Uses cached active-ban accessors: global bans in particular are identical
	// across all hosts and would otherwise cause N redundant queries during
	// SyncAllConfigs. Cache invalidation is wired into Ban/Unban methods.
	if s.rateLimitRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostBans, err := s.rateLimitRepo.GetActiveBansForHost(ctx, host.ID)
			if err != nil {
				fail("banned IPs", err)
				return
			}
			globalBans, err := s.rateLimitRepo.GetActiveGlobalBans(ctx)
			if err != nil {
				fail("global banned IPs", err)
				return
			}
			bannedIPs := append(hostBans, globalBans...)
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

	// Fetch blocked cloud provider IP ranges and resolve against the global
	// default (#198 slice 4). resolveCloudProviders collapses global + host into
	// the effective blocking settings (3-state: inherit/override/disable).
	if s.cloudProviderRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostSettings, err := s.cloudProviderRepo.GetCloudProviderBlockingSettings(ctx, host.ID)
			if err != nil {
				fail("cloud provider blocking settings", err)
				return
			}
			var global *model.GlobalCloudProviders
			if s.globalCloudRepo != nil {
				global, err = s.globalCloudRepo.GetGlobal(ctx)
				if err != nil {
					fail("global cloud provider blocking", err)
					return
				}
			}
			settings := resolveCloudProviders(global, hostSettings)
			if len(settings.BlockedProviders) > 0 {
				ipRanges, err := s.cloudProviderRepo.GetIPRangesForProviders(ctx, settings.BlockedProviders)
				if err != nil {
					fail("cloud provider IP ranges", err)
					return
				}
				if len(ipRanges) > 0 {
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
			globalUB, err := s.uriBlockRepo.GetGlobalURIBlock(ctx)
			if err != nil {
				fail("global URI block rules", err)
				return
			}
			// Get host-specific URI block rules
			hostUB, err := s.uriBlockRepo.GetByProxyHostID(ctx, host.ID)
			if err != nil {
				fail("URI block rules", err)
				return
			}

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
	// generated by FilterSubscriptionService. We also fetch the IP list for deduplication
	// against manual banned IPs to prevent nginx "duplicate network" errors.
	var filterSubIPs []string
	if s.filterSubscriptionRepo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enabledCount, err := s.filterSubscriptionRepo.CountEnabledSubscriptions(ctx)
			if err != nil {
				fail("filter subscriptions", err)
				return
			}
			if enabledCount == 0 {
				return
			}
			// Check if host is excluded from ALL subscriptions
			exclCount, err := s.filterSubscriptionRepo.CountExclusionsForHost(ctx, host.ID)
			if err != nil {
				fail("filter subscription exclusions", err)
				return
			}
			if exclCount < enabledCount {
				mu.Lock()
				data.UseFilterSubscription = true
				mu.Unlock()

				// Fetch filter subscription IPs for deduplication with manual banned IPs
				ips, err := s.filterSubscriptionRepo.GetAllEnabledEntriesByType(ctx, "ip")
				if err != nil {
					fail("filter subscription IP entries", err)
					return
				}
				cidrs, err := s.filterSubscriptionRepo.GetAllEnabledEntriesByType(ctx, "cidr")
				if err != nil {
					fail("filter subscription CIDR entries", err)
					return
				}
				mu.Lock()
				filterSubIPs = append(ips, cidrs...)
				mu.Unlock()
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if fetchErr != nil {
		return data, fetchErr
	}

	// Resolve WAF against the global default (#198 slice 6). For an inheriting
	// host (waf_use_global=true) this swaps data.Host for a copy carrying the
	// global mode/paranoia/threshold/enabled; every downstream WAF read
	// (GenerateHostWAFConfig, the WAFEnabled gate) uses data.Host, so this single
	// point covers both the per-host and bulk regeneration paths.
	data.Host = resolveWAF(globalWAF, host)

	// Remove banned IPs that already exist in filter subscription to prevent
	// nginx "duplicate network" errors in geo blocks (Issue #92)
	if data.UseFilterSubscription && len(filterSubIPs) > 0 && len(data.BannedIPs) > 0 {
		data.BannedIPs = filterBannedByFilterSubscription(data.BannedIPs, filterSubIPs)
	}

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
		if err != nil {
			return data, fmt.Errorf("failed to load global settings for host %s: %w", host.ID, err)
		}
		if gs != nil {
			data.GlobalSettings = gs
		}
	}

	// Fetch global trusted IPs and block_exploits exceptions from system settings
	if s.systemSettingsRepo != nil {
		settings, err := s.systemSettingsRepo.Get(ctx)
		if err != nil {
			return data, fmt.Errorf("failed to load system settings for host %s: %w", host.ID, err)
		}
		if settings != nil {
			if host.BlockExploits {
				data.GlobalBlockExploitsExceptions = settings.GlobalBlockExploitsExceptions
			}
			// Parse global trusted IPs for nginx ban bypass (with strict validation)
			data.GlobalTrustedIPs = ParseGlobalTrustedIPs(settings.GlobalTrustedIPs)
		}
	}

	// Filter out banned IPs that match any global trusted IP/CIDR.
	// This ensures trusted IPs are never blocked regardless of nginx geo ordering.
	if len(data.GlobalTrustedIPs) > 0 && len(data.BannedIPs) > 0 {
		data.BannedIPs = filterBannedByTrustedIPs(data.BannedIPs, data.GlobalTrustedIPs)
	}

	// Fetch exploit block rules + their URI-scoped exclusions when block_exploits is enabled.
	// The template renderer needs both: rules are what may trigger 403s, URI exclusions
	// are per-rule regex patterns that allow bypassing specific rules on specific paths.
	if host.BlockExploits && s.exploitBlockRuleRepo != nil {
		rules, err := s.exploitBlockRuleRepo.GetEnabledForHost(ctx, host.ID)
		if err != nil {
			// Fail-closed: rendering without the exploit rules would silently
			// drop all of them from the running config.
			return data, fmt.Errorf("failed to load exploit block rules for host %s: %w", host.ID, err)
		}
		uriExclusions, exErr := s.exploitBlockRuleRepo.GetURIExclusionsForHost(ctx, host.ID)
		if exErr != nil {
			// Graceful degradation: proceed with no URI-scoped exclusions rather than
			// failing the whole config regeneration. (Dropping exclusions only makes
			// the config stricter — the fail-closed direction.)
			uriExclusions = map[string][]string{}
		}
		rendered := make([]model.ExploitBlockRuleForRender, 0, len(rules))
		for _, r := range rules {
			rendered = append(rendered, model.ExploitBlockRuleForRender{
				ExploitBlockRule: r,
				URIExclusions:    uriExclusions[r.ID],
				IDSanitized:      strings.ReplaceAll(r.ID, "-", "_"),
			})
		}
		data.ExploitBlockRules = rendered
	}

	return data, nil
}
