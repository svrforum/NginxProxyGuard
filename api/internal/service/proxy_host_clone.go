package service

import (
	"context"
	"fmt"
	"log"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// boolPtr returns a pointer to a bool value
func boolPtr(b bool) *bool {
	return &b
}

// resolveCloneContainerBinding decides the cloned host's container binding:
//   - explicit container in request    -> use it (request drives name+network)
//   - forward_host overridden, no name  -> clear (drop the source's stale binding)
//   - neither                           -> copy from source
//
// Mirrors the create/edit form semantics so a cloned host never carries a
// container binding that contradicts a manually typed forward_host. (Issue #153)
func resolveCloneContainerBinding(srcName, srcNetwork, reqName, reqNetwork *string, reqHost string) (*string, *string) {
	if reqName != nil {
		return reqName, reqNetwork
	}
	if reqHost != "" {
		return nil, nil
	}
	return srcName, srcNetwork
}

// Clone creates a copy of an existing proxy host with new domain names
// It copies all related configurations including:
// - GeoRestriction, RateLimit, SecurityHeaders, BotFilter
// - Upstream (with servers), URIBlock (with rules)
// - WAF rule exclusions
func (s *ProxyHostService) Clone(ctx context.Context, sourceID string, req *model.CloneProxyHostRequest) (*model.ProxyHost, error) {
	// Get source host
	source, err := s.repo.GetByID(ctx, sourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get source proxy host: %w", err)
	}
	if source == nil {
		return nil, fmt.Errorf("source proxy host not found")
	}

	// Validate domain names
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

	// Check for duplicate domains
	existingDomains, err := s.repo.CheckDomainExists(ctx, validDomains, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check domain existence: %w", err)
	}
	if len(existingDomains) > 0 {
		return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
	}

	// Prepare certificate_id and SSL settings based on request
	var certificateID *string
	sslEnabled := false
	sslForceHTTPS := false
	createNewCert := req.CertProvider != "" // 'letsencrypt' or 'selfsigned'

	if req.CertificateID != nil && *req.CertificateID != "" {
		// User specified an existing certificate ID - enable SSL
		certificateID = req.CertificateID
		sslEnabled = true
		sslForceHTTPS = source.SSLForceHTTPS // Copy force HTTPS setting from source
		createNewCert = false                // Don't create new cert if existing one is specified
	}
	// If no certificate specified and not creating new cert, SSL remains disabled
	if source.IsStream() {
		certificateID = nil
		sslEnabled = false
		sslForceHTTPS = false
		createNewCert = false
	}

	// Use provided forward settings or copy from source
	forwardScheme := source.ForwardScheme
	forwardHost := source.ForwardHost
	forwardPort := source.ForwardPort
	streamListenHost := source.StreamListenHost
	streamListenPort := source.StreamListenPort
	streamProtocol := source.StreamProtocol

	if req.ForwardScheme != "" {
		forwardScheme = req.ForwardScheme
	}
	if req.ForwardHost != "" {
		forwardHost = req.ForwardHost
	}
	if req.ForwardPort > 0 {
		forwardPort = req.ForwardPort
	}
	if source.IsStream() {
		if req.StreamListenHost != "" {
			streamListenHost = req.StreamListenHost
		}
		if req.StreamListenPort > 0 {
			streamListenPort = req.StreamListenPort
		}
		if req.StreamProtocol != "" {
			streamProtocol = req.StreamProtocol
			forwardScheme = req.StreamProtocol
		}
	}

	cloneContainerName, cloneContainerNetwork := resolveCloneContainerBinding(
		source.ForwardContainerName, source.ForwardContainerNetwork,
		req.ForwardContainerName, req.ForwardContainerNetwork, req.ForwardHost,
	)

	// Create the new proxy host with copied settings
	createReq := &model.CreateProxyHostRequest{
		ProxyType:                 source.ProxyType,
		DomainNames:               validDomains,
		ForwardScheme:             forwardScheme,
		ForwardHost:               forwardHost,
		ForwardContainerName:      cloneContainerName,
		ForwardContainerNetwork:   cloneContainerNetwork,
		ForwardPort:               forwardPort,
		StreamListenHost:          streamListenHost,
		StreamListenPort:          streamListenPort,
		StreamProtocol:            streamProtocol,
		StreamSSLPreread:          source.StreamSSLPreread,
		StreamAcceptProxyProtocol: source.StreamAcceptProxyProtocol,
		StreamSendProxyProtocol:   source.StreamSendProxyProtocol,
		StreamProxyConnectTimeout: source.StreamProxyConnectTimeout,
		StreamProxyTimeout:        source.StreamProxyTimeout,
		SSLEnabled:                sslEnabled,
		SSLForceHTTPS:             sslForceHTTPS,
		SSLHTTP2:                  source.SSLHTTP2,
		SSLHTTP3:                  source.SSLHTTP3,
		CertificateID:             certificateID,
		AllowWebsocketUpgrade:     source.AllowWebsocketUpgrade,
		CacheEnabled:              source.CacheEnabled,
		CacheStaticOnly:           source.CacheStaticOnly,
		CacheTTL:                  source.CacheTTL,
		BlockExploits:             source.BlockExploits,
		BlockExploitsExceptions:   source.BlockExploitsExceptions,
		WAFEnabled:                source.WAFEnabled,
		WAFMode:                   source.WAFMode,
		WAFParanoiaLevel:          source.WAFParanoiaLevel,
		WAFAnomalyThreshold:       source.WAFAnomalyThreshold,
		AccessListID:              source.AccessListID,
		AdvancedConfig:            source.AdvancedConfig,
		ProxyConnectTimeout:       source.ProxyConnectTimeout,
		ProxySendTimeout:          source.ProxySendTimeout,
		ProxyReadTimeout:          source.ProxyReadTimeout,
		ProxyBuffering:            source.ProxyBuffering,
		ProxyRequestBuffering:     source.ProxyRequestBuffering,
		ClientMaxBodySize:         source.ClientMaxBodySize,
		ProxyMaxTempFileSize:      source.ProxyMaxTempFileSize,
		Enabled:                   source.Enabled,
	}

	// Create the new host
	newHost, err := s.Create(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloned proxy host: %w", err)
	}

	// Request new certificate if requested
	// Request new certificate if provider is specified
	if createNewCert && s.certService != nil {
		// Determine provider type
		provider := model.CertProviderLetsEncrypt
		if req.CertProvider == "selfsigned" {
			provider = model.CertProviderSelfSigned
		}

		certReq := &model.CreateCertificateRequest{
			DomainNames:   validDomains,
			Provider:      provider,
			AutoRenew:     provider == model.CertProviderLetsEncrypt,
			DNSProviderID: req.DNSProviderID,
		}
		cert, certErr := s.certService.Create(ctx, certReq)
		if certErr != nil {
			log.Printf("[Clone] Failed to create certificate request: %v", certErr)
			// Don't fail the clone, just log the error
			// The host will be created without SSL, user can request certificate later
		} else {
			log.Printf("[Clone] Certificate request created: %s (provider: %s) for domains %v", cert.ID, provider, validDomains)
			// Update the host with the new certificate ID
			// The certificate is pending/issued, SSL will be enabled when cert is ready
			updateReq := &model.UpdateProxyHostRequest{
				CertificateID: &cert.ID,
				SSLEnabled:    boolPtr(true),
				SSLForceHTTPS: &source.SSLForceHTTPS,
			}
			if _, updateErr := s.repo.Update(ctx, newHost.ID, updateReq); updateErr != nil {
				log.Printf("[Clone] Failed to update host with certificate: %v", updateErr)
			}
		}
	}

	// Clone related configurations
	if err := s.cloneRelatedConfigs(ctx, sourceID, newHost.ID); err != nil {
		// Rollback: delete the newly created host
		log.Printf("[WARN] Failed to clone related configs, rolling back: %v", err)
		if delErr := s.Delete(ctx, newHost.ID); delErr != nil {
			log.Printf("[ERROR] Rollback failed: could not delete cloned host %s: %v", newHost.ID, delErr)
		}
		return nil, fmt.Errorf("failed to clone related configurations: %w", err)
	}

	// Regenerate nginx config to include cloned settings
	if newHost.Enabled {
		if _, err := s.Update(ctx, newHost.ID, nil); err != nil {
			log.Printf("[WARN] Failed to regenerate nginx config for cloned host: %v", err)
		}
	}

	// Return fresh host data
	return s.GetByID(ctx, newHost.ID)
}

// cloneRelatedConfigs copies all related configurations from source to target host
func (s *ProxyHostService) cloneRelatedConfigs(ctx context.Context, sourceID, targetID string) error {
	// Clone GeoRestriction
	if s.geoRepo != nil {
		geo, err := s.geoRepo.GetByProxyHostID(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get geo restriction: %v", err)
		} else if geo != nil {
			geoReq := &model.CreateGeoRestrictionRequest{
				Mode:            geo.Mode,
				Countries:       geo.Countries,
				AllowedIPs:      geo.AllowedIPs,
				AllowPrivateIPs: &geo.AllowPrivateIPs,
				AllowSearchBots: &geo.AllowSearchBots,
				Enabled:         &geo.Enabled,
				ChallengeMode:   &geo.ChallengeMode,
			}
			if _, err := s.geoRepo.Upsert(ctx, targetID, geoReq); err != nil {
				log.Printf("[Clone] Failed to clone geo restriction: %v", err)
			}
		}
	}

	// Clone RateLimit
	if s.rateLimitRepo != nil {
		rl, err := s.rateLimitRepo.GetByProxyHostID(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get rate limit: %v", err)
		} else if rl != nil {
			rlReq := &model.CreateRateLimitRequest{
				Enabled:           &rl.Enabled,
				RequestsPerSecond: rl.RequestsPerSecond,
				BurstSize:         rl.BurstSize,
				ZoneSize:          rl.ZoneSize,
				LimitBy:           rl.LimitBy,
				LimitResponse:     rl.LimitResponse,
				WhitelistIPs:      rl.WhitelistIPs,
			}
			if _, err := s.rateLimitRepo.Upsert(ctx, targetID, rlReq); err != nil {
				log.Printf("[Clone] Failed to clone rate limit: %v", err)
			}
		}
	}

	// Clone SecurityHeaders
	if s.securityHeadersRepo != nil {
		sh, err := s.securityHeadersRepo.GetByProxyHostID(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get security headers: %v", err)
		} else if sh != nil {
			shReq := &model.CreateSecurityHeadersRequest{
				Enabled:               &sh.Enabled,
				HSTSEnabled:           &sh.HSTSEnabled,
				HSTSMaxAge:            sh.HSTSMaxAge,
				HSTSIncludeSubdomains: &sh.HSTSIncludeSubdomains,
				HSTSPreload:           &sh.HSTSPreload,
				XFrameOptions:         sh.XFrameOptions,
				XContentTypeOptions:   &sh.XContentTypeOptions,
				XXSSProtection:        &sh.XXSSProtection,
				ReferrerPolicy:        sh.ReferrerPolicy,
				ContentSecurityPolicy: sh.ContentSecurityPolicy,
				PermissionsPolicy:     sh.PermissionsPolicy,
				CustomHeaders:         sh.CustomHeaders,
			}
			if _, err := s.securityHeadersRepo.Upsert(ctx, targetID, shReq); err != nil {
				log.Printf("[Clone] Failed to clone security headers: %v", err)
			}
		}
	}

	// Clone BotFilter
	if s.botFilterRepo != nil {
		bf, err := s.botFilterRepo.GetByProxyHostID(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get bot filter: %v", err)
		} else if bf != nil {
			bfReq := &model.CreateBotFilterRequest{
				Enabled:                &bf.Enabled,
				BlockBadBots:           &bf.BlockBadBots,
				BlockAIBots:            &bf.BlockAIBots,
				AllowSearchEngines:     &bf.AllowSearchEngines,
				BlockSuspiciousClients: &bf.BlockSuspiciousClients,
				CustomBlockedAgents:    bf.CustomBlockedAgents,
				CustomAllowedAgents:    bf.CustomAllowedAgents,
				ChallengeSuspicious:    &bf.ChallengeSuspicious,
			}
			if _, err := s.botFilterRepo.Upsert(ctx, targetID, bfReq); err != nil {
				log.Printf("[Clone] Failed to clone bot filter: %v", err)
			}
		}
	}

	// Clone Upstream
	if s.upstreamRepo != nil {
		up, err := s.upstreamRepo.GetByProxyHostID(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get upstream: %v", err)
		} else if up != nil && len(up.Servers) > 0 {
			servers := make([]model.CreateUpstreamServerRequest, len(up.Servers))
			for i, srv := range up.Servers {
				servers[i] = model.CreateUpstreamServerRequest{
					Address:     srv.Address,
					Port:        srv.Port,
					Weight:      srv.Weight,
					MaxFails:    srv.MaxFails,
					FailTimeout: srv.FailTimeout,
					IsBackup:    srv.IsBackup,
					IsDown:      srv.IsDown,
				}
			}
			upReq := &model.CreateUpstreamRequest{
				Name:                      up.Name,
				Servers:                   servers,
				LoadBalance:               up.LoadBalance,
				HealthCheckEnabled:        &up.HealthCheckEnabled,
				HealthCheckInterval:       up.HealthCheckInterval,
				HealthCheckTimeout:        up.HealthCheckTimeout,
				HealthCheckPath:           up.HealthCheckPath,
				HealthCheckExpectedStatus: up.HealthCheckExpectedStatus,
				Keepalive:                 up.Keepalive,
			}
			if _, err := s.upstreamRepo.Upsert(ctx, targetID, upReq); err != nil {
				log.Printf("[Clone] Failed to clone upstream: %v", err)
			}
		}
	}

	// Clone URIBlock
	if s.uriBlockRepo != nil {
		ub, err := s.uriBlockRepo.GetByProxyHostID(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get URI block: %v", err)
		} else if ub != nil && len(ub.Rules) > 0 {
			ubReq := &model.CreateURIBlockRequest{
				Enabled:         &ub.Enabled,
				Rules:           ub.Rules,
				ExceptionIPs:    ub.ExceptionIPs,
				AllowPrivateIPs: &ub.AllowPrivateIPs,
			}
			if _, err := s.uriBlockRepo.Upsert(ctx, targetID, ubReq); err != nil {
				log.Printf("[Clone] Failed to clone URI block: %v", err)
			}
		}
	}

	// Clone WAF Rule Exclusions
	if s.wafRepo != nil {
		exclusions, err := s.wafRepo.GetExclusionsByProxyHost(ctx, sourceID)
		if err != nil {
			log.Printf("[Clone] Failed to get WAF exclusions: %v", err)
		} else {
			for _, ex := range exclusions {
				exReq := &model.CreateWAFRuleExclusionRequest{
					RuleID:          ex.RuleID,
					RuleCategory:    ex.RuleCategory,
					RuleDescription: ex.RuleDescription,
					Reason:          ex.Reason + " (cloned)",
				}
				if _, err := s.wafRepo.CreateExclusion(ctx, targetID, exReq); err != nil {
					log.Printf("[Clone] Failed to clone WAF exclusion for rule %d: %v", ex.RuleID, err)
				}
			}
		}
	}

	return nil
}
