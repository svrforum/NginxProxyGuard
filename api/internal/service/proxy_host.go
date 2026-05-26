package service

import (
	"context"
	"fmt"
	"log"
	"strings"

	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

type NginxManager interface {
	GenerateConfig(ctx context.Context, host *model.ProxyHost) error
	GenerateConfigWithAccessControl(ctx context.Context, host *model.ProxyHost, accessList *model.AccessList, geoRestriction *model.GeoRestriction) error
	GenerateConfigFull(ctx context.Context, data nginx.ProxyHostConfigData) error
	RemoveConfig(ctx context.Context, host *model.ProxyHost) error
	RemoveConfigByFilename(ctx context.Context, filename string) error
	RemoveHostWAFConfig(ctx context.Context, hostID string) error
	TestConfig(ctx context.Context) error
	ReloadNginx(ctx context.Context) error
	GenerateAllConfigs(ctx context.Context, hosts []model.ProxyHost) error
	GenerateHostWAFConfig(ctx context.Context, host *model.ProxyHost, exclusions []model.WAFRuleExclusion, allowedIPs []string) error
	// Atomic operations with global locking
	GenerateConfigAndReload(ctx context.Context, data nginx.ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion) error
	GenerateConfigAndReloadWithCleanup(ctx context.Context, data nginx.ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion, oldConfigFilename string) error
	RemoveConfigAndReload(ctx context.Context, host *model.ProxyHost) error
	// Filter subscription shared config generation
	GenerateFilterSubscriptionConfigs(ctx context.Context, ips []string, uas []string) error
}

// CertificateCreator is an interface for creating certificates (used to avoid circular dependency)
type CertificateCreator interface {
	Create(ctx context.Context, req *model.CreateCertificateRequest) (*model.Certificate, error)
}

// ContainerResolver resolves a docker container name to its current IP. (#150)
type ContainerResolver interface {
	ResolveContainerIP(ctx context.Context, name string) (string, error)
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
	certRepo               *repository.CertificateRepository
	systemLogRepo          *repository.SystemLogRepository
	filterSubscriptionRepo *repository.FilterSubscriptionRepository
	nginx                  NginxManager
	certService            CertificateCreator // Optional: for creating certificates during clone
	containerResolver      ContainerResolver  // Optional: resolves docker container name → IP (#150)
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
	certRepo *repository.CertificateRepository,
	systemLogRepo *repository.SystemLogRepository,
	nginx NginxManager,
) *ProxyHostService {
	return &ProxyHostService{
		repo:                 repo,
		wafRepo:              wafRepo,
		accessListRepo:       accessListRepo,
		geoRepo:              geoRepo,
		rateLimitRepo:        rateLimitRepo,
		securityHeadersRepo:  securityHeadersRepo,
		botFilterRepo:        botFilterRepo,
		upstreamRepo:         upstreamRepo,
		systemSettingsRepo:   systemSettingsRepo,
		cloudProviderRepo:    cloudProviderRepo,
		globalSettingsRepo:   globalSettingsRepo,
		uriBlockRepo:         uriBlockRepo,
		exploitBlockRuleRepo: exploitBlockRuleRepo,
		certRepo:             certRepo,
		systemLogRepo:        systemLogRepo,
		nginx:                nginx,
	}
}

// SetCertificateService sets the certificate service for creating certificates during clone operations
func (s *ProxyHostService) SetCertificateService(certService CertificateCreator) {
	s.certService = certService
}

func (s *ProxyHostService) SetFilterSubscriptionRepo(repo *repository.FilterSubscriptionRepository) {
	s.filterSubscriptionRepo = repo
}

// SetContainerResolver injects the docker container → IP resolver. (#150)
func (s *ProxyHostService) SetContainerResolver(r ContainerResolver) {
	s.containerResolver = r
}

// applyContainerTarget resolves a container-name target to its current IP.
// For non-container targets (nil/empty name) it returns forwardHost unchanged.
// Resolution failure returns an "invalid ..." error so the handler maps it to 400. (#150)
func (s *ProxyHostService) applyContainerTarget(ctx context.Context, containerName *string, forwardHost string) (string, error) {
	if containerName == nil || *containerName == "" {
		return forwardHost, nil
	}
	if s.containerResolver == nil {
		return "", fmt.Errorf("invalid: container targets unavailable (no docker access)")
	}
	ip, err := s.containerResolver.ResolveContainerIP(ctx, *containerName)
	if err != nil {
		return "", fmt.Errorf("invalid forward container %q: %w", *containerName, err)
	}
	return ip, nil
}

func normalizeCreateProxyHostRequest(req *model.CreateProxyHostRequest) error {
	req.ProxyType = model.NormalizeProxyType(req.ProxyType)
	if req.ProxyType == model.ProxyTypeStream {
		req.StreamProtocol = model.NormalizeStreamProtocol(req.StreamProtocol)
		streamListenHost, err := normalizeStreamListenHost(req.StreamListenHost)
		if err != nil {
			return err
		}
		req.StreamListenHost = streamListenHost
		req.ForwardScheme = req.StreamProtocol
		req.SSLEnabled = false
		req.SSLForceHTTPS = false
		req.SSLHTTP2 = false
		req.SSLHTTP3 = false
		req.CertificateID = nil
		req.AllowWebsocketUpgrade = false
		req.CacheEnabled = false
		req.BlockExploits = false
		req.WAFEnabled = false
		req.AccessListID = nil
		if req.StreamProtocol == model.StreamProtocolUDP {
			req.StreamSSLPreread = false
			req.StreamAcceptProxyProtocol = false
			req.StreamSendProxyProtocol = false
		}
		if req.StreamListenPort < 1 || req.StreamListenPort > 65535 {
			return fmt.Errorf("stream_listen_port is required and must be between 1 and 65535")
		}
		if req.ForwardPort < 1 || req.ForwardPort > 65535 {
			return fmt.Errorf("forward_port is required and must be between 1 and 65535")
		}
		if req.StreamProxyConnectTimeout < 0 || req.StreamProxyTimeout < 0 {
			return fmt.Errorf("stream timeouts must be zero or positive")
		}
		return nil
	}

	req.ProxyType = model.ProxyTypeHTTP
	if req.ForwardScheme == "" {
		req.ForwardScheme = "http"
	}
	if req.ForwardPort == 0 {
		req.ForwardPort = 80
	}
	return nil
}

func normalizeStreamListenHost(host string) (string, error) {
	if !model.ValidateStreamListenHost(host) {
		return "", fmt.Errorf("invalid stream_listen_host %q: use an empty value, '*', or a local IP address; upstream hostnames belong in forward_host", strings.TrimSpace(host))
	}
	return model.NormalizeStreamListenHost(host), nil
}

func applyUpdateCandidate(existing *model.ProxyHost, req *model.UpdateProxyHostRequest) model.ProxyHost {
	candidate := *existing
	if req.ProxyType != "" {
		candidate.ProxyType = req.ProxyType
	}
	if len(req.DomainNames) > 0 {
		candidate.DomainNames = req.DomainNames
	}
	if req.ForwardScheme != "" {
		candidate.ForwardScheme = req.ForwardScheme
	}
	if req.ForwardHost != "" {
		candidate.ForwardHost = req.ForwardHost
	}
	if req.ForwardPort > 0 {
		candidate.ForwardPort = req.ForwardPort
	}
	if req.StreamListenHost != nil {
		candidate.StreamListenHost = *req.StreamListenHost
	}
	if req.StreamListenPort != nil {
		candidate.StreamListenPort = *req.StreamListenPort
	}
	if req.StreamProtocol != nil {
		candidate.StreamProtocol = *req.StreamProtocol
	}
	if req.StreamSSLPreread != nil {
		candidate.StreamSSLPreread = *req.StreamSSLPreread
	}
	if req.StreamAcceptProxyProtocol != nil {
		candidate.StreamAcceptProxyProtocol = *req.StreamAcceptProxyProtocol
	}
	if req.StreamSendProxyProtocol != nil {
		candidate.StreamSendProxyProtocol = *req.StreamSendProxyProtocol
	}
	if req.StreamProxyConnectTimeout != nil {
		candidate.StreamProxyConnectTimeout = *req.StreamProxyConnectTimeout
	}
	if req.StreamProxyTimeout != nil {
		candidate.StreamProxyTimeout = *req.StreamProxyTimeout
	}
	return candidate
}

func normalizeUpdateProxyHostRequest(existing *model.ProxyHost, req *model.UpdateProxyHostRequest) (*model.ProxyHost, error) {
	candidate := applyUpdateCandidate(existing, req)
	candidate.ProxyType = model.NormalizeProxyType(candidate.ProxyType)
	if req.ProxyType != "" {
		req.ProxyType = candidate.ProxyType
	}

	if candidate.ProxyType == model.ProxyTypeStream {
		candidate.StreamProtocol = model.NormalizeStreamProtocol(candidate.StreamProtocol)
		streamProtocol := candidate.StreamProtocol
		req.StreamProtocol = &streamProtocol
		streamListenHost, err := normalizeStreamListenHost(candidate.StreamListenHost)
		if err != nil {
			return nil, err
		}
		candidate.StreamListenHost = streamListenHost
		req.StreamListenHost = &streamListenHost
		req.ForwardScheme = streamProtocol

		falseValue := false
		req.SSLEnabled = &falseValue
		req.SSLForceHTTPS = &falseValue
		req.SSLHTTP2 = &falseValue
		req.SSLHTTP3 = &falseValue
		req.CertificateID = stringPtr("")
		req.AllowWebsocketUpgrade = &falseValue
		req.CacheEnabled = &falseValue
		req.BlockExploits = &falseValue
		req.WAFEnabled = &falseValue
		req.AccessListID = stringPtr("")

		if candidate.StreamProtocol == model.StreamProtocolUDP {
			req.StreamSSLPreread = &falseValue
			req.StreamAcceptProxyProtocol = &falseValue
			req.StreamSendProxyProtocol = &falseValue
			candidate.StreamSSLPreread = false
			candidate.StreamAcceptProxyProtocol = false
			candidate.StreamSendProxyProtocol = false
		}
		if candidate.StreamListenPort < 1 || candidate.StreamListenPort > 65535 {
			return nil, fmt.Errorf("stream_listen_port is required and must be between 1 and 65535")
		}
		if candidate.ForwardPort < 1 || candidate.ForwardPort > 65535 {
			return nil, fmt.Errorf("forward_port is required and must be between 1 and 65535")
		}
		if candidate.StreamProxyConnectTimeout < 0 || candidate.StreamProxyTimeout < 0 {
			return nil, fmt.Errorf("stream timeouts must be zero or positive")
		}
	}

	return &candidate, nil
}

func stringPtr(value string) *string {
	return &value
}

func (s *ProxyHostService) prepareUpdateProxyHostRequest(ctx context.Context, id string, req *model.UpdateProxyHostRequest) (string, *model.ProxyHost, error) {
	existingHost, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get proxy host: %w", err)
	}
	if existingHost == nil {
		return "", nil, nil
	}

	oldConfigFilename := nginx.GetConfigFilename(existingHost)

	if len(req.DomainNames) > 0 {
		var validDomains []string
		for _, d := range req.DomainNames {
			d = strings.TrimSpace(d)
			if d != "" {
				validDomains = append(validDomains, d)
			}
		}
		if len(validDomains) == 0 {
			return "", nil, fmt.Errorf("at least one valid domain name is required")
		}
		req.DomainNames = validDomains
	}

	if req.AdvancedConfig != nil {
		if err := model.ValidateAdvancedConfig(*req.AdvancedConfig); err != nil {
			return "", nil, fmt.Errorf("invalid advanced config: %w", err)
		}
	}

	candidate, err := normalizeUpdateProxyHostRequest(existingHost, req)
	if err != nil {
		return "", nil, err
	}

	// Resolve container-name target to its current IP before persisting (#150).
	// Only fires when a non-empty container name is supplied; otherwise
	// forward_host is left untouched (existing behavior preserved).
	if req.ForwardContainerName != nil && *req.ForwardContainerName != "" {
		resolvedForwardHost, resolveErr := s.applyContainerTarget(ctx, req.ForwardContainerName, req.ForwardHost)
		if resolveErr != nil {
			return "", nil, resolveErr
		}
		req.ForwardHost = resolvedForwardHost
		candidate.ForwardHost = resolvedForwardHost
	}

	if candidate.ProxyType == model.ProxyTypeStream {
		conflicts, err := s.repo.CheckStreamListenConflicts(ctx, candidate.DomainNames, candidate.StreamListenHost, candidate.StreamListenPort, candidate.StreamProtocol, candidate.StreamSSLPreread, id)
		if err != nil {
			return "", nil, err
		}
		if len(conflicts) > 0 {
			return "", nil, fmt.Errorf("stream listener conflict: %v", conflicts)
		}
		return oldConfigFilename, candidate, nil
	}

	// Validate SSL settings: ssl_force_https requires ssl_enabled
	if req.SSLForceHTTPS != nil && req.SSLEnabled != nil {
		if *req.SSLForceHTTPS && !*req.SSLEnabled {
			*req.SSLForceHTTPS = false
		}
	}

	if len(req.DomainNames) > 0 {
		existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, id)
		if err != nil {
			return "", nil, fmt.Errorf("failed to check domain existence: %w", err)
		}
		if len(existingDomains) > 0 {
			return "", nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
		}
	}

	if req.CertificateID != nil && *req.CertificateID != "" && s.certRepo != nil {
		cert, err := s.certRepo.GetByID(ctx, *req.CertificateID)
		if err != nil {
			return "", nil, fmt.Errorf("failed to validate certificate_id: %w", err)
		}
		if cert == nil {
			return "", nil, fmt.Errorf("certificate not found: %s", *req.CertificateID)
		}
	}

	if req.AccessListID != nil && *req.AccessListID != "" && s.accessListRepo != nil {
		al, err := s.accessListRepo.GetByID(ctx, *req.AccessListID)
		if err != nil {
			return "", nil, fmt.Errorf("failed to validate access_list_id: %w", err)
		}
		if al == nil {
			return "", nil, fmt.Errorf("access list not found: %s", *req.AccessListID)
		}
	}

	return oldConfigFilename, candidate, nil
}

func (s *ProxyHostService) Create(ctx context.Context, req *model.CreateProxyHostRequest) (*model.ProxyHost, error) {
	if err := normalizeCreateProxyHostRequest(req); err != nil {
		return nil, err
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

	// Validate advanced config for security
	if err := model.ValidateAdvancedConfig(req.AdvancedConfig); err != nil {
		return nil, fmt.Errorf("invalid advanced config: %w", err)
	}

	if req.ProxyType == model.ProxyTypeStream {
		conflicts, err := s.repo.CheckStreamListenConflicts(ctx, req.DomainNames, req.StreamListenHost, req.StreamListenPort, req.StreamProtocol, req.StreamSSLPreread, "")
		if err != nil {
			return nil, err
		}
		if len(conflicts) > 0 {
			return nil, fmt.Errorf("stream listener conflict: %v", conflicts)
		}
	} else {
		// Validate SSL settings: ssl_force_https requires ssl_enabled
		if req.SSLForceHTTPS && !req.SSLEnabled {
			req.SSLForceHTTPS = false // Auto-correct invalid state
		}

		// Check for duplicate domains
		existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, "")
		if err != nil {
			return nil, fmt.Errorf("failed to check domain existence: %w", err)
		}
		if len(existingDomains) > 0 {
			return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
		}

		// Validate certificate_id exists if provided
		if req.CertificateID != nil && *req.CertificateID != "" && s.certRepo != nil {
			cert, err := s.certRepo.GetByID(ctx, *req.CertificateID)
			if err != nil {
				return nil, fmt.Errorf("failed to validate certificate_id: %w", err)
			}
			if cert == nil {
				return nil, fmt.Errorf("certificate not found: %s", *req.CertificateID)
			}
		}

		// Validate access_list_id exists if provided
		if req.AccessListID != nil && *req.AccessListID != "" && s.accessListRepo != nil {
			al, err := s.accessListRepo.GetByID(ctx, *req.AccessListID)
			if err != nil {
				return nil, fmt.Errorf("failed to validate access_list_id: %w", err)
			}
			if al == nil {
				return nil, fmt.Errorf("access list not found: %s", *req.AccessListID)
			}
		}
	}

	// Resolve container-name target to its current IP before persisting (#150).
	// Non-container requests leave forward_host unchanged.
	resolvedForwardHost, err := s.applyContainerTarget(ctx, req.ForwardContainerName, req.ForwardHost)
	if err != nil {
		return nil, err
	}
	req.ForwardHost = resolvedForwardHost

	// Create in database
	host, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy host: %w", err)
	}

	// Generate nginx config if enabled (atomic operation with global locking)
	if host.Enabled {
		configData := s.getHostConfigData(ctx, host)

		// Get WAF exclusions if WAF is enabled
		var wafExclusions []model.WAFRuleExclusion
		if host.WAFEnabled && !host.IsStream() {
			wafExclusions, err = s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				// Rollback: Delete DB record since config generation won't proceed
				if delErr := s.repo.Delete(ctx, host.ID); delErr != nil {
					log.Printf("[ERROR] Rollback failed: could not delete host %s after WAF exclusion error: %v", host.ID, delErr)
				}
				return nil, fmt.Errorf("failed to get WAF exclusions: %w", err)
			}
		}

		// Atomic: generate config + WAF config + test + reload (with global lock)
		if err := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); err != nil {
			// Rollback: Remove config and DB record on failure
			if removeErr := s.nginx.RemoveConfig(ctx, host); removeErr != nil {
				log.Printf("[ERROR] Rollback failed: could not remove nginx config for host %s: %v", host.ID, removeErr)
			}
			if delErr := s.repo.Delete(ctx, host.ID); delErr != nil {
				log.Printf("[ERROR] Rollback failed: could not delete host %s after config generation error: %v", host.ID, delErr)
			}
			return nil, fmt.Errorf("failed to generate nginx config: %w", err)
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

func (s *ProxyHostService) List(ctx context.Context, page, perPage int, search, sortBy, sortOrder string) (*model.ProxyHostListResponse, error) {
	hosts, total, err := s.repo.List(ctx, page, perPage, search, sortBy, sortOrder)
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
	var oldConfigFilename string // Track old config filename for cleanup when domain changes

	// If req is nil, we just want to regenerate config for the existing host
	if req != nil {
		oldConfigFilename, _, err = s.prepareUpdateProxyHostRequest(ctx, id, req)
		if err != nil {
			return nil, err
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
	newConfigFilename := ""
	if host.Enabled {
		newConfigFilename = nginx.GetConfigFilename(host)
		configData := s.getHostConfigData(ctx, host)

		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return nil, fmt.Errorf("failed to generate nginx config: %w", err)
		}

		// Generate or remove WAF config based on WAF enabled status
		if host.WAFEnabled && !host.IsStream() {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("failed to get WAF exclusions: %w", err)
			}
			allowedIPs := s.getPriorityAllowIPs(ctx, id)
			if err := s.nginx.GenerateHostWAFConfig(ctx, host, mergedExclusions, allowedIPs); err != nil {
				return nil, fmt.Errorf("failed to generate WAF config: %w", err)
			}
		} else {
			// Remove WAF config if WAF is disabled to prevent orphan files
			if err := s.nginx.RemoveHostWAFConfig(ctx, host.ID); err != nil {
				log.Printf("[WARN] Failed to remove WAF config for host %s: %v", host.ID, err)
				// Non-fatal: continue
			}
		}

		// Remove old config BEFORE nginx test (prevents zone duplication)
		// When domain changes, both old and new config files exist with same zone names
		// which causes limit_req_zone duplicate errors during nginx test
		if oldConfigFilename != "" && oldConfigFilename != newConfigFilename {
			if err := s.nginx.RemoveConfigByFilename(ctx, oldConfigFilename); err != nil {
				log.Printf("[WARN] Failed to remove old config file %s: %v", oldConfigFilename, err)
				// Non-fatal: continue with test
			}
		}
	} else {
		// Host is disabled - remove config
		// When domain changed, old config file has different name than current
		if oldConfigFilename != "" {
			// Domain was changed - remove old config file (different filename)
			if err := s.nginx.RemoveConfigByFilename(ctx, oldConfigFilename); err != nil {
				log.Printf("[WARN] Failed to remove old config file %s: %v", oldConfigFilename, err)
			}
		}
		// Also try to remove current config (may not exist if domain changed)
		if err := s.nginx.RemoveConfig(ctx, host); err != nil {
			// Only log if this is not the same file we just removed
			currentFilename := nginx.GetConfigFilename(host)
			if oldConfigFilename != currentFilename {
				log.Printf("[WARN] Failed to remove current config file: %v", err)
			}
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
	var oldConfigFilename string // Track old config filename for cleanup when domain changes

	// If req is nil, we just want to regenerate config for the existing host
	if req != nil {
		oldConfigFilename, _, err = s.prepareUpdateProxyHostRequest(ctx, id, req)
		if err != nil {
			return nil, err
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

	// Regenerate nginx config (atomic operation with global locking)
	if host.Enabled {
		newConfigFilename := nginx.GetConfigFilename(host)
		configData := s.getHostConfigData(ctx, host)

		// Get WAF exclusions if WAF is enabled
		var wafExclusions []model.WAFRuleExclusion
		if host.WAFEnabled && !host.IsStream() {
			wafExclusions, err = s.getMergedWAFExclusions(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("failed to get WAF exclusions: %w", err)
			}
		}

		// Atomic: generate config + WAF config + test + reload (with global lock)
		if oldConfigFilename != "" && oldConfigFilename != newConfigFilename {
			// Domain changed - use method that removes old config before nginx test
			// This prevents limit_req_zone duplicate errors when zone names stay same
			if err := s.nginx.GenerateConfigAndReloadWithCleanup(ctx, configData, wafExclusions, oldConfigFilename); err != nil {
				return nil, fmt.Errorf("failed to generate nginx config: %w", err)
			}
		} else {
			// No domain change - use standard method
			if err := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); err != nil {
				return nil, fmt.Errorf("failed to generate nginx config: %w", err)
			}
		}
	} else {
		// Host is disabled - remove config
		// When domain changed, old config file has different name than current
		if oldConfigFilename != "" {
			// Domain was changed - remove old config file first (different filename)
			if err := s.nginx.RemoveConfigByFilename(ctx, oldConfigFilename); err != nil {
				log.Printf("[WARN] Failed to remove old config file %s: %v", oldConfigFilename, err)
			}
		}
		// Atomic: remove current config + test + reload (with global lock)
		if err := s.nginx.RemoveConfigAndReload(ctx, host); err != nil {
			// Only fail if this is not just a "file not found" situation
			// (old config may have been the only one if domain changed)
			currentFilename := nginx.GetConfigFilename(host)
			if oldConfigFilename == "" || oldConfigFilename == currentFilename {
				return nil, fmt.Errorf("failed to remove nginx config: %w", err)
			}
			// Domain changed and old config was removed - just test and reload
			if testErr := s.nginx.TestConfig(ctx); testErr != nil {
				return nil, fmt.Errorf("nginx config test failed: %w", testErr)
			}
			if reloadErr := s.nginx.ReloadNginx(ctx); reloadErr != nil {
				return nil, fmt.Errorf("failed to reload nginx: %w", reloadErr)
			}
		}
	}

	// Clear config error on successful update
	_ = s.repo.UpdateConfigStatus(ctx, host.ID, "ok", "")
	metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(1)
	host.ConfigStatus = "ok"
	host.ConfigError = ""

	return host, nil
}

// UpdateDBOnly performs only DB update and domain change cleanup without nginx operations.
// Use this when a subsequent RegenerateConfigForHost call will handle nginx config/test/reload.
func (s *ProxyHostService) UpdateDBOnly(ctx context.Context, id string, req *model.UpdateProxyHostRequest) (*model.ProxyHost, error) {
	if req == nil {
		return s.repo.GetByID(ctx, id)
	}

	oldConfigFilename, _, err := s.prepareUpdateProxyHostRequest(ctx, id, req)
	if err != nil {
		return nil, err
	}

	host, err := s.repo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update proxy host: %w", err)
	}
	if host == nil {
		return nil, nil
	}

	// Clean up old config file if domain changed
	if oldConfigFilename != "" {
		newConfigFilename := nginx.GetConfigFilename(host)
		if oldConfigFilename != newConfigFilename {
			if err := s.nginx.RemoveConfigByFilename(ctx, oldConfigFilename); err != nil {
				log.Printf("[WARN] Failed to remove old config file %s: %v", oldConfigFilename, err)
			}
		}
	}

	return host, nil
}

func (s *ProxyHostService) ToggleFavorite(ctx context.Context, id string) (*model.ProxyHost, error) {
	return s.repo.ToggleFavorite(ctx, id)
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

	// Store config data in case we need to restore after DB failure
	var configData nginx.ProxyHostConfigData
	var wafExclusions []model.WAFRuleExclusion
	if host.Enabled {
		configData = s.getHostConfigData(ctx, host)
		if host.WAFEnabled && !host.IsStream() {
			wafExclusions, _ = s.getMergedWAFExclusions(ctx, host.ID)
		}
	}

	// Remove nginx config FIRST (atomic: remove config + test + reload with global lock)
	// This prevents orphan config files if DB deletion fails
	if err := s.nginx.RemoveConfigAndReload(ctx, host); err != nil {
		return fmt.Errorf("failed to remove nginx config: %w", err)
	}

	// Delete from database
	if err := s.repo.Delete(ctx, id); err != nil {
		// DB deletion failed after nginx config was removed
		// Try to restore nginx config to maintain consistency
		if host.Enabled {
			log.Printf("[WARN] DB deletion failed for host %s, attempting to restore nginx config: %v", id, err)
			if restoreErr := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); restoreErr != nil {
				log.Printf("[ERROR] Failed to restore nginx config for host %s after DB deletion failure: %v", id, restoreErr)
			}
		}
		return fmt.Errorf("failed to delete proxy host: %w", err)
	}

	return nil
}
