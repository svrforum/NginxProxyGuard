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
	// Bulk atomic regeneration: one lock, snapshot + rollback on nginx -t failure
	RegenerateConfigsAtomic(ctx context.Context, renders []nginx.HostConfigRender, reload bool) error
	// Same, but additionally renders redirect host configs under the same lock
	// (certificate fan-out: redirect host configs embed certificate paths too)
	RegenerateConfigsAtomicWithRedirects(ctx context.Context, renders []nginx.HostConfigRender, redirectHosts []*model.RedirectHost, reload bool) error
	// Boot drift detection: remove on-disk host configs no enabled host
	// accounts for. fetchEnabled is invoked under the global nginx lock so the
	// expected-filename set reflects hosts created during the sync (TOCTOU).
	RemoveOrphanedHostConfigs(ctx context.Context, fetchEnabled func(context.Context) ([]model.ProxyHost, error)) []string
	// Filter subscription shared config generation
	GenerateFilterSubscriptionConfigs(ctx context.Context, ips []string, uas []string) error
}

// CertificateCreator is an interface for creating certificates (used to avoid circular dependency)
type CertificateCreator interface {
	Create(ctx context.Context, req *model.CreateCertificateRequest) (*model.Certificate, error)
}

// ContainerResolver resolves a docker container name to its current IP.
// When network is non-empty the resolution is pinned to that specific docker
// network (Issue #151) so multi-network containers don't drift to the wrong
// network's IP. An empty network preserves the legacy first-non-empty-IP
// behavior for callers that have no stored network yet. (#150, #151)
type ContainerResolver interface {
	ResolveContainerIP(ctx context.Context, name string, network string) (string, error)
}

// ddnsSyncer triggers an immediate DDNS sync for a host's managed records (#157 follow-up).
type ddnsSyncer interface {
	SyncByProxyHost(ctx context.Context, proxyHostID string)
}

type ProxyHostService struct {
	repo                   *repository.ProxyHostRepository
	wafRepo                *repository.WAFRepository
	accessListRepo         *repository.AccessListRepository
	authProviderRepo       *repository.AuthProviderRepository // ForwardAuth provider (#179)
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
	ddnsRepo               *repository.DDNSRepository        // managed DDNS record reconcile (#157)
	dnsProviderRepo        *repository.DNSProviderRepository // DDNS provider-type validation (#157)
	ddnsSyncer             ddnsSyncer                        // optional: immediate first sync after opt-in (#157 follow-up)
	nginx                  NginxManager
	certService            CertificateCreator         // Optional: for creating certificates during clone
	containerResolver      ContainerResolver          // Optional: resolves docker container name → IP (#150)
	redirectHostRepo       redirectHostsByCertificate // Optional: certificate fan-out to redirect hosts (wired in bootstrap)
}

func NewProxyHostService(
	repo *repository.ProxyHostRepository,
	wafRepo *repository.WAFRepository,
	accessListRepo *repository.AccessListRepository,
	authProviderRepo *repository.AuthProviderRepository,
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
	ddnsRepo *repository.DDNSRepository,
	dnsProviderRepo *repository.DNSProviderRepository,
	nginx NginxManager,
) *ProxyHostService {
	return &ProxyHostService{
		repo:                 repo,
		wafRepo:              wafRepo,
		accessListRepo:       accessListRepo,
		authProviderRepo:     authProviderRepo,
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
		ddnsRepo:             ddnsRepo,
		dnsProviderRepo:      dnsProviderRepo,
		nginx:                nginx,
	}
}

// SetCertificateService sets the certificate service for creating certificates during clone operations
func (s *ProxyHostService) SetCertificateService(certService CertificateCreator) {
	s.certService = certService
}

// SetDDNSSyncer wires the DDNS service for immediate first-sync after a host opts in. (#157 follow-up)
func (s *ProxyHostService) SetDDNSSyncer(d ddnsSyncer) { s.ddnsSyncer = d }

func (s *ProxyHostService) SetFilterSubscriptionRepo(repo *repository.FilterSubscriptionRepository) {
	s.filterSubscriptionRepo = repo
}

// SetContainerResolver injects the docker container → IP resolver. (#150)
func (s *ProxyHostService) SetContainerResolver(r ContainerResolver) {
	s.containerResolver = r
}

// applyContainerTarget resolves a container-name target to its current IP.
// For non-container targets (nil/empty name) it returns forwardHost unchanged.
// When containerNetwork is non-empty the resolution is pinned to that docker
// network (Issue #151); an empty/nil network falls back to the legacy
// first-non-empty-IP behavior. Resolution failure returns an "invalid ..."
// error so the handler maps it to 400. (#150, #151)
func (s *ProxyHostService) applyContainerTarget(ctx context.Context, containerName *string, containerNetwork *string, forwardHost string) (string, error) {
	if containerName == nil || *containerName == "" {
		return forwardHost, nil
	}
	if s.containerResolver == nil {
		return "", fmt.Errorf("invalid: container targets unavailable (no docker access)")
	}
	network := ""
	if containerNetwork != nil {
		network = *containerNetwork
	}
	ip, err := s.containerResolver.ResolveContainerIP(ctx, *containerName, network)
	if err != nil {
		if network != "" {
			return "", fmt.Errorf("invalid forward container %q (network %q): %w", *containerName, network, err)
		}
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
		// HTTP-only features never apply to stream.
		req.SSLForceHTTPS = false
		req.SSLHTTP2 = false
		req.SSLHTTP3 = false
		req.AllowWebsocketUpgrade = false
		req.CacheEnabled = false
		req.BlockExploits = false
		req.WAFEnabled = false
		req.AccessListID = nil

		if req.StreamProtocol == model.StreamProtocolUDP {
			// UDP supports neither passthrough nor TLS termination.
			req.StreamSSLPreread = false
			req.StreamAcceptProxyProtocol = false
			req.StreamSendProxyProtocol = false
			req.SSLEnabled = false
			req.CertificateID = nil
		} else if req.SSLEnabled {
			// TLS termination mode (mutually exclusive with passthrough).
			if req.StreamSSLPreread {
				return fmt.Errorf("invalid stream config: TLS termination and ssl_preread passthrough are mutually exclusive")
			}
			if req.CertificateID == nil || *req.CertificateID == "" {
				return fmt.Errorf("invalid stream config: TLS termination requires a certificate")
			}
		} else {
			// passthrough or plain — no certificate.
			req.CertificateID = nil
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
	if req.SSLEnabled != nil {
		candidate.SSLEnabled = *req.SSLEnabled
	}
	if req.CertificateID != nil {
		if *req.CertificateID == "" {
			candidate.CertificateID = nil
		} else {
			candidate.CertificateID = req.CertificateID
		}
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
	if req.DDNSEnabled != nil {
		candidate.DDNSEnabled = *req.DDNSEnabled
	}
	if req.DDNSProviderID != nil {
		if *req.DDNSProviderID == "" {
			candidate.DDNSProviderID = nil
		} else {
			candidate.DDNSProviderID = req.DDNSProviderID
		}
	}
	if req.AuthProviderID != nil {
		if *req.AuthProviderID == "" {
			candidate.AuthProviderID = nil
		} else {
			candidate.AuthProviderID = req.AuthProviderID
		}
	}
	if req.AuthBypassPaths != nil {
		candidate.AuthBypassPaths = req.AuthBypassPaths
	}
	return candidate
}

// validateAuthProviderConflict rejects a ForwardAuth assignment that would create a
// duplicate auth_request (geo challenge mode) or land on an uninjectable custom
// "location /" ("conflict:"-prefixed → HTTP 409), and validates that the per-host
// bypass paths are safe to template into a `location <path>` block ("invalid:"-prefixed
// → HTTP 400). Must be called from Create, Update AND UpdateDBOnly (UI saves via
// UpdateDBOnly). (#179)
func (s *ProxyHostService) validateAuthProviderConflict(ctx context.Context, hostID string, authProviderID *string, proxyType, advancedConfig string, bypassPaths []string) error {
	if authProviderID == nil || *authProviderID == "" || proxyType == model.ProxyTypeStream {
		return nil
	}
	if nginx.HasCustomLocationRootInConfig(advancedConfig) {
		return fmt.Errorf("conflict: auth provider cannot be combined with a custom \"location /\" block in advanced config")
	}
	if s.geoRepo != nil && hostID != "" {
		geo, err := s.geoRepo.GetByProxyHostID(ctx, hostID)
		if err == nil && geo != nil && geo.ChallengeMode {
			return fmt.Errorf("conflict: auth provider cannot be combined with geo challenge (CAPTCHA) mode on the same host")
		}
	}
	for _, p := range bypassPaths {
		if err := model.ValidateAuthBypassPath(p); err != nil {
			return err
		}
	}
	return nil
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
		req.SSLForceHTTPS = &falseValue
		req.SSLHTTP2 = &falseValue
		req.SSLHTTP3 = &falseValue
		req.AllowWebsocketUpgrade = &falseValue
		req.CacheEnabled = &falseValue
		req.BlockExploits = &falseValue
		req.WAFEnabled = &falseValue
		req.AccessListID = stringPtr("")
		candidate.SSLForceHTTPS, candidate.SSLHTTP2, candidate.SSLHTTP3 = false, false, false
		candidate.AllowWebsocketUpgrade, candidate.CacheEnabled, candidate.BlockExploits, candidate.WAFEnabled = false, false, false, false
		candidate.AccessListID = nil

		if candidate.StreamProtocol == model.StreamProtocolUDP {
			req.StreamSSLPreread = &falseValue
			req.StreamAcceptProxyProtocol = &falseValue
			req.StreamSendProxyProtocol = &falseValue
			candidate.StreamSSLPreread = false
			candidate.StreamAcceptProxyProtocol = false
			candidate.StreamSendProxyProtocol = false
			sslOff := false
			req.SSLEnabled = &sslOff
			req.CertificateID = stringPtr("")
			candidate.SSLEnabled = false
			candidate.CertificateID = nil
		} else if candidate.SSLEnabled {
			if candidate.StreamSSLPreread {
				return nil, fmt.Errorf("invalid stream config: TLS termination and ssl_preread passthrough are mutually exclusive")
			}
			if candidate.CertificateID == nil || *candidate.CertificateID == "" {
				return nil, fmt.Errorf("invalid stream config: TLS termination requires a certificate")
			}
			// leave req.SSLEnabled / req.CertificateID as the merged values
		} else {
			off := false
			req.SSLEnabled = &off
			req.CertificateID = stringPtr("")
			candidate.SSLEnabled = false
			candidate.CertificateID = nil
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

// validateDDNSOptIn enforces that DDNS auto-registration is only enabled with a
// provider whose type supports DDNS (cloudflare/duckdns/dynu). Returns an "invalid ..."
// error (mapped to 400 by the handler) when the opt-in is malformed. When DDNS is
// off this is a no-op. (#157)
func (s *ProxyHostService) validateDDNSOptIn(ctx context.Context, enabled bool, providerID *string) error {
	if !enabled {
		return nil
	}
	if providerID == nil || *providerID == "" {
		return fmt.Errorf("invalid: DDNS auto-registration requires a DNS provider")
	}
	if s.dnsProviderRepo == nil {
		return fmt.Errorf("invalid: DDNS provider validation unavailable")
	}
	provider, err := s.dnsProviderRepo.GetByID(ctx, *providerID)
	if err != nil {
		return fmt.Errorf("failed to validate ddns_provider_id: %w", err)
	}
	if provider == nil {
		return fmt.Errorf("invalid: DDNS provider not found: %s", *providerID)
	}
	if provider.ProviderType != model.DNSProviderCloudflare &&
		provider.ProviderType != model.DNSProviderDuckDNS &&
		provider.ProviderType != model.DNSProviderDynu {
		return fmt.Errorf("invalid: DDNS requires a Cloudflare, DuckDNS, or Dynu provider")
	}
	return nil
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

	// ForwardAuth conflict validation (geo challenge / custom location). Runs on the
	// shared update path so it covers Update AND UpdateDBOnly (UI saves via UpdateDBOnly). (#179)
	effAuthProviderID := existingHost.AuthProviderID
	if req.AuthProviderID != nil {
		effAuthProviderID = req.AuthProviderID
	}
	effAdvancedConfig := existingHost.AdvancedConfig
	if req.AdvancedConfig != nil {
		effAdvancedConfig = *req.AdvancedConfig
	}
	effProxyType := existingHost.ProxyType
	if req.ProxyType != "" {
		effProxyType = req.ProxyType
	}
	effBypassPaths := []string(existingHost.AuthBypassPaths)
	if req.AuthBypassPaths != nil {
		effBypassPaths = req.AuthBypassPaths
	}
	if err := s.validateAuthProviderConflict(ctx, id, effAuthProviderID, effProxyType, effAdvancedConfig, effBypassPaths); err != nil {
		return "", nil, err
	}

	candidate, err := normalizeUpdateProxyHostRequest(existingHost, req)
	if err != nil {
		return "", nil, err
	}

	// Resolve container-name target to its current IP before persisting (#150).
	// Only fires when a non-empty container name is supplied; otherwise
	// forward_host is left untouched (existing behavior preserved). When the
	// request carries a container network, resolution is pinned to it (#151).
	isContainerTarget := req.ForwardContainerName != nil && *req.ForwardContainerName != ""
	if isContainerTarget {
		resolvedForwardHost, resolveErr := s.applyContainerTarget(ctx, req.ForwardContainerName, req.ForwardContainerNetwork, req.ForwardHost)
		if resolveErr != nil {
			return "", nil, resolveErr
		}
		req.ForwardHost = resolvedForwardHost
		candidate.ForwardHost = resolvedForwardHost
	}

	// Enforce the SAME format validation that the Create path runs at the handler
	// layer. The Update path previously skipped this, letting unvalidated
	// domain_names / forward_host reach config generation and break out of the
	// generated server_name / proxy_pass directives (server_name / proxy_pass
	// injection). Applies to Update, UpdateWithoutReload and UpdateDBOnly
	// (skip_nginx) since all route through here.
	for _, domain := range candidate.DomainNames {
		validName := model.ValidateDomainName(domain)
		if candidate.ProxyType == model.ProxyTypeStream {
			validName = model.ValidateStreamName(domain)
		}
		if !validName {
			return "", nil, fmt.Errorf("invalid proxy name format: %s", domain)
		}
	}
	// Container-name targets resolve forward_host server-side, so the candidate
	// value is already a resolved IP; validating it here is still correct. Only
	// skip validation when no forward_host is set on a container target (the
	// resolver may legitimately leave it empty pre-resolution).
	if !(isContainerTarget && candidate.ForwardHost == "") {
		if !model.ValidateHostnameOrIP(candidate.ForwardHost) {
			return "", nil, fmt.Errorf("invalid forward_host format")
		}
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

	// Validate the merged DDNS opt-in: enabled requires a cloudflare/duckdns
	// provider, evaluated against the effective (merged) candidate so a request
	// that only toggles ddns_enabled is still validated against the stored
	// provider. (#157)
	if err := s.validateDDNSOptIn(ctx, candidate.DDNSEnabled, candidate.DDNSProviderID); err != nil {
		return "", nil, err
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

	// Validate DDNS opt-in: enabled requires a cloudflare/duckdns provider (#157).
	if err := s.validateDDNSOptIn(ctx, req.DDNSEnabled, req.DDNSProviderID); err != nil {
		return nil, err
	}

	// Resolve container-name target to its current IP before persisting (#150).
	// Non-container requests leave forward_host unchanged. When a container
	// network is supplied, resolution is pinned to it (#151).
	resolvedForwardHost, err := s.applyContainerTarget(ctx, req.ForwardContainerName, req.ForwardContainerNetwork, req.ForwardHost)
	if err != nil {
		return nil, err
	}
	req.ForwardHost = resolvedForwardHost

	// ForwardAuth conflict validation (custom location; geo challenge can't exist on a new host) (#179)
	if err := s.validateAuthProviderConflict(ctx, "", req.AuthProviderID, req.ProxyType, req.AdvancedConfig, req.AuthBypassPaths); err != nil {
		return nil, err
	}

	// Create in database
	host, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy host: %w", err)
	}

	// Generate nginx config if enabled (atomic operation with global locking)
	if host.Enabled {
		configData, err := s.getHostConfigData(ctx, host)
		if err != nil {
			// Rollback: Delete DB record since config generation won't proceed
			if delErr := s.repo.Delete(ctx, host.ID); delErr != nil {
				log.Printf("[ERROR] Rollback failed: could not delete host %s after config data error: %v", host.ID, delErr)
			}
			return nil, err
		}

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

	// Sync managed DDNS records to the host's domains (#157). Graceful: never
	// fails the create — the host has already been persisted + reloaded.
	s.reconcileHostDDNS(ctx, host, true)

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

	// Regenerate nginx config (without reload) via the bulk atomic primitive:
	// one lock acquisition, file snapshot first, nginx -t after the writes and
	// full rollback on failure — a failed -t must never leave an invalid file
	// on disk (it would wedge every subsequent nginx operation system-wide).
	if host.Enabled {
		render, err := s.buildHostRender(ctx, host)
		if err != nil {
			return nil, err
		}
		if oldConfigFilename != "" && oldConfigFilename != nginx.GetConfigFilename(host) {
			// Remove old config BEFORE nginx test (prevents limit_req_zone
			// duplication when the domain name / config filename changes)
			render.RemoveOldFilename = oldConfigFilename
		}
		if err := s.nginx.RegenerateConfigsAtomic(ctx, []nginx.HostConfigRender{render}, false); err != nil {
			// DB already updated; configs were rolled back — surface the error
			// state on the host so the UI shows it.
			_ = s.repo.UpdateConfigStatus(ctx, host.ID, "error", err.Error())
			metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(0)
			return nil, fmt.Errorf("nginx config test failed: %w", err)
		}
		// Clear any prior config error (e.g. a host that errored once must not
		// stay 'error' in the UI after a later successful skip_nginx save).
		_ = s.repo.UpdateConfigStatus(ctx, host.ID, "ok", "")
		metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(1)
	} else {
		// Host is disabled - remove config (old filename too when domain changed)
		render := nginx.HostConfigRender{
			Data:   nginx.ProxyHostConfigData{Host: host},
			Remove: true,
		}
		if oldConfigFilename != "" && oldConfigFilename != nginx.GetConfigFilename(host) {
			render.RemoveOldFilename = oldConfigFilename
		}
		if err := s.nginx.RegenerateConfigsAtomic(ctx, []nginx.HostConfigRender{render}, false); err != nil {
			return nil, fmt.Errorf("nginx config test failed: %w", err)
		}
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
		configData, err := s.getHostConfigData(ctx, host)
		if err != nil {
			return nil, err
		}

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
				// The DB row is already updated but nginx rejected (and rolled
				// back) the generated config — record that so the UI shows the
				// error badge instead of a silently-stale 'ok'.
				_ = s.repo.UpdateConfigStatus(ctx, host.ID, "error", err.Error())
				metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(0)
				return nil, fmt.Errorf("failed to generate nginx config: %w", err)
			}
		} else {
			// No domain change - use standard method
			if err := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); err != nil {
				_ = s.repo.UpdateConfigStatus(ctx, host.ID, "error", err.Error())
				metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(0)
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

	// Sync managed DDNS records to the host's (possibly changed) domains and
	// opt-in state (#157). Graceful: never fails the update.
	s.reconcileHostDDNS(ctx, host, true)

	return host, nil
}

// UpdateDBOnly performs only DB update and domain change cleanup without nginx operations.
// Use this when a subsequent RegenerateConfigForHost call will handle nginx config/test/reload.
//
// immediateDDNSSync is forwarded to reconcileHostDDNS: interactive UI saves pass true
// (sync the managed record immediately); bulk DDNS import passes false (let the scheduler sync).
func (s *ProxyHostService) UpdateDBOnly(ctx context.Context, id string, req *model.UpdateProxyHostRequest, immediateDDNSSync bool) (*model.ProxyHost, error) {
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

	// Sync managed DDNS records to the host's (possibly changed) domains and
	// opt-in state (#157). The UI saves via skip_nginx=true (this path), so the
	// reconcile must run here too — not only in Update. Graceful: never fails.
	s.reconcileHostDDNS(ctx, host, immediateDDNSSync)

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

	// Store config data in case we need to restore after DB failure.
	// Best-effort: this snapshot is only used to roll the config back if the
	// DB delete fails. When the lookup itself fails we proceed with the
	// delete but skip the (incomplete) restore — never write a config that is
	// missing security sections.
	var configData nginx.ProxyHostConfigData
	var configDataOK bool
	var wafExclusions []model.WAFRuleExclusion
	if host.Enabled {
		configData, err = s.getHostConfigData(ctx, host)
		if err != nil {
			log.Printf("[WARN] Failed to snapshot config data for host %s before delete (restore-on-failure disabled): %v", id, err)
		} else {
			configDataOK = true
		}
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
		if host.Enabled && configDataOK {
			log.Printf("[WARN] DB deletion failed for host %s, attempting to restore nginx config: %v", id, err)
			if restoreErr := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); restoreErr != nil {
				log.Printf("[ERROR] Failed to restore nginx config for host %s after DB deletion failure: %v", id, restoreErr)
			}
		} else if host.Enabled {
			log.Printf("[WARN] DB deletion failed for host %s and no config snapshot is available — run Sync All to restore the config: %v", id, err)
		}
		return fmt.Errorf("failed to delete proxy host: %w", err)
	}

	return nil
}

// ListContainerBackedHosts returns enabled proxy hosts whose forward target is a
// docker container name. Used by the container IP reconcile scheduler; hosts
// without forward_container_name are never returned (non-regression). (#150)
func (s *ProxyHostService) ListContainerBackedHosts(ctx context.Context) ([]*model.ProxyHost, error) {
	hosts, err := s.repo.GetEnabledContainerBacked(ctx)
	if err != nil {
		return nil, err
	}
	// Adapt the repo's []model.ProxyHost to the []*model.ProxyHost the scheduler iterates.
	out := make([]*model.ProxyHost, len(hosts))
	for i := range hosts {
		h := hosts[i]
		out[i] = &h
	}
	return out, nil
}

// UpdateForwardHostAndReload persists a new forward_host IP for a container-backed
// host and regenerates that host's nginx config through the EXISTING fail-safe
// path (Update → GenerateConfigAndReload → nginx -t → reload, rollback on test
// failure). It deliberately reuses Update rather than hand-rolling a reload so
// Core Principle 2 (fail-safe) holds; only forward_host is changed and
// forward_container_name is left untouched so no container re-resolution occurs. (#150)
func (s *ProxyHostService) UpdateForwardHostAndReload(ctx context.Context, id string, newIP string) error {
	_, err := s.Update(ctx, id, &model.UpdateProxyHostRequest{ForwardHost: newIP})
	return err
}
