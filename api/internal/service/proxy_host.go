package service

import (
	"context"
	"fmt"
	"log"
	"strings"

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
	GenerateFilterSubscriptionConfigs(ips []string, uas []string) error
}

// CertificateCreator is an interface for creating certificates (used to avoid circular dependency)
type CertificateCreator interface {
	Create(ctx context.Context, req *model.CreateCertificateRequest) (*model.Certificate, error)
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
		certRepo:               certRepo,
		systemLogRepo:          systemLogRepo,
		nginx:                  nginx,
	}
}

// SetCertificateService sets the certificate service for creating certificates during clone operations
func (s *ProxyHostService) SetCertificateService(certService CertificateCreator) {
	s.certService = certService
}

func (s *ProxyHostService) SetFilterSubscriptionRepo(repo *repository.FilterSubscriptionRepository) {
	s.filterSubscriptionRepo = repo
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
		if host.WAFEnabled {
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

			// Get existing host to save old config filename before update
			// This is needed because config filename is based on the first domain name
			existingHost, getErr := s.repo.GetByID(ctx, id)
			if getErr == nil && existingHost != nil {
				oldConfigFilename = nginx.GetConfigFilename(existingHost)
			}

			existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, id)
			if err != nil {
				return nil, fmt.Errorf("failed to check domain existence: %w", err)
			}
			if len(existingDomains) > 0 {
				return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
			}
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
		if host.WAFEnabled {
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

			// Get existing host to save old config filename before update
			// This is needed because config filename is based on the first domain name
			existingHost, getErr := s.repo.GetByID(ctx, id)
			if getErr == nil && existingHost != nil {
				oldConfigFilename = nginx.GetConfigFilename(existingHost)
			}

			existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, id)
			if err != nil {
				return nil, fmt.Errorf("failed to check domain existence: %w", err)
			}
			if len(existingDomains) > 0 {
				return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
			}
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
		if host.WAFEnabled {
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

	// Validate SSL settings
	if req.SSLForceHTTPS != nil && req.SSLEnabled != nil {
		if *req.SSLForceHTTPS && !*req.SSLEnabled {
			*req.SSLForceHTTPS = false
		}
	}

	// Validate advanced config
	if req.AdvancedConfig != nil {
		if err := model.ValidateAdvancedConfig(*req.AdvancedConfig); err != nil {
			return nil, fmt.Errorf("invalid advanced config: %w", err)
		}
	}

	var oldConfigFilename string

	// Check for duplicate domains
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

		existingHost, getErr := s.repo.GetByID(ctx, id)
		if getErr == nil && existingHost != nil {
			oldConfigFilename = nginx.GetConfigFilename(existingHost)
		}

		existingDomains, err := s.repo.CheckDomainExists(ctx, req.DomainNames, id)
		if err != nil {
			return nil, fmt.Errorf("failed to check domain existence: %w", err)
		}
		if len(existingDomains) > 0 {
			return nil, fmt.Errorf("domain(s) already exist: %v", existingDomains)
		}
	}

	// Validate certificate_id
	if req.CertificateID != nil && *req.CertificateID != "" && s.certRepo != nil {
		cert, err := s.certRepo.GetByID(ctx, *req.CertificateID)
		if err != nil {
			return nil, fmt.Errorf("failed to validate certificate_id: %w", err)
		}
		if cert == nil {
			return nil, fmt.Errorf("certificate not found: %s", *req.CertificateID)
		}
	}

	// Validate access_list_id
	if req.AccessListID != nil && *req.AccessListID != "" && s.accessListRepo != nil {
		al, err := s.accessListRepo.GetByID(ctx, *req.AccessListID)
		if err != nil {
			return nil, fmt.Errorf("failed to validate access_list_id: %w", err)
		}
		if al == nil {
			return nil, fmt.Errorf("access list not found: %s", *req.AccessListID)
		}
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
		if host.WAFEnabled {
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
