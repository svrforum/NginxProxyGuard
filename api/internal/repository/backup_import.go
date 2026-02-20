package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

// ImportAllData imports all configuration data from backup
func (r *BackupRepository) ImportAllData(ctx context.Context, data *model.ExportData) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Clear existing data before import (in correct order for FK constraints)
	if err := r.clearExistingData(ctx, tx); err != nil {
		return fmt.Errorf("failed to clear existing data: %w", err)
	}

	// Create ID mappings for foreign key references
	certificateIDMap := make(map[string]string)    // old ID -> new ID
	accessListIDMap := make(map[string]string)     // old ID -> new ID
	dnsProviderIDMap := make(map[string]string)    // old ID -> new ID
	proxyHostIDMap := make(map[string]string)      // old ID -> new ID
	exploitRuleIDMap := make(map[string]string)    // old ID -> new ID

	// Import Global Settings (update existing)
	if data.GlobalSettings != nil {
		if err := r.importGlobalSettings(ctx, tx, data.GlobalSettings); err != nil {
			return fmt.Errorf("failed to import global settings: %w", err)
		}
	}

	// Import DNS Providers first (certificates depend on them)
	for _, dp := range data.DNSProviders {
		newID, err := r.importDNSProvider(ctx, tx, &dp)
		if err != nil {
			return fmt.Errorf("failed to import dns provider %s: %w", dp.Name, err)
		}
		dnsProviderIDMap[dp.ID] = newID
	}

	// Import Certificates (proxy hosts depend on them)
	for _, cert := range data.Certificates {
		// Remap DNS provider ID
		if cert.DNSProviderID != "" {
			if newID, ok := dnsProviderIDMap[cert.DNSProviderID]; ok {
				cert.DNSProviderID = newID
			}
		}
		newID, err := r.importCertificate(ctx, tx, &cert)
		if err != nil {
			return fmt.Errorf("failed to import certificate %v: %w", cert.DomainNames, err)
		}
		certificateIDMap[cert.ID] = newID
	}

	// Import Access Lists (proxy hosts depend on them)
	for _, al := range data.AccessLists {
		newID, err := r.importAccessList(ctx, tx, &al)
		if err != nil {
			return fmt.Errorf("failed to import access list %s: %w", al.AccessList.Name, err)
		}
		accessListIDMap[al.AccessList.ID] = newID
	}

	// Import Proxy Hosts with all related configurations
	for _, ph := range data.ProxyHosts {
		// Remap certificate ID
		if ph.ProxyHost.CertificateID != "" {
			if newID, ok := certificateIDMap[ph.ProxyHost.CertificateID]; ok {
				ph.ProxyHost.CertificateID = newID
			}
		}
		// Remap access list ID
		if ph.ProxyHost.AccessListID != "" {
			if newID, ok := accessListIDMap[ph.ProxyHost.AccessListID]; ok {
				ph.ProxyHost.AccessListID = newID
			}
		}

		newID, err := r.importProxyHost(ctx, tx, &ph)
		if err != nil {
			return fmt.Errorf("failed to import proxy host %v: %w", ph.ProxyHost.DomainNames, err)
		}
		proxyHostIDMap[ph.ProxyHost.ID] = newID
	}

	// Import Redirect Hosts
	for _, rh := range data.RedirectHosts {
		// Remap certificate ID
		if rh.RedirectHost.CertificateID != "" {
			if newID, ok := certificateIDMap[rh.RedirectHost.CertificateID]; ok {
				rh.RedirectHost.CertificateID = newID
			}
		}
		if err := r.importRedirectHost(ctx, tx, &rh); err != nil {
			return fmt.Errorf("failed to import redirect host %v: %w", rh.RedirectHost.DomainNames, err)
		}
	}

	// Import WAF Exclusions
	for _, we := range data.WAFExclusions {
		// Remap proxy host ID
		if newID, ok := proxyHostIDMap[we.ProxyHostID]; ok {
			we.ProxyHostID = newID
		}
		if err := r.importWAFExclusion(ctx, tx, &we); err != nil {
			return fmt.Errorf("failed to import waf exclusion for rule %d: %w", we.RuleID, err)
		}
	}

	// Import System Settings (update existing)
	if data.SystemSettings != nil {
		if err := r.importSystemSettings(ctx, tx, data.SystemSettings); err != nil {
			return fmt.Errorf("failed to import system settings: %w", err)
		}
	}

	// Import Banned IPs
	for _, bip := range data.BannedIPs {
		// Remap proxy host ID if present
		if bip.ProxyHostID != "" {
			if newID, ok := proxyHostIDMap[bip.ProxyHostID]; ok {
				bip.ProxyHostID = newID
			}
		}
		if err := r.importBannedIP(ctx, tx, &bip); err != nil {
			return fmt.Errorf("failed to import banned ip %s: %w", bip.IPAddress, err)
		}
	}

	// Import URI Blocks
	for _, ub := range data.URIBlocks {
		// Remap proxy host ID
		if newID, ok := proxyHostIDMap[ub.ProxyHostID]; ok {
			ub.ProxyHostID = newID
		}
		if err := r.importURIBlock(ctx, tx, &ub); err != nil {
			return fmt.Errorf("failed to import uri block for proxy host %s: %w", ub.ProxyHostID, err)
		}
	}

	// Import Global URI Block
	if data.GlobalURIBlock != nil {
		if err := r.importGlobalURIBlock(ctx, tx, data.GlobalURIBlock); err != nil {
			return fmt.Errorf("failed to import global uri block: %w", err)
		}
	}

	// Import Cloud Providers
	for _, cp := range data.CloudProviders {
		if err := r.importCloudProvider(ctx, tx, &cp); err != nil {
			return fmt.Errorf("failed to import cloud provider %s: %w", cp.Name, err)
		}
	}

	// Import Exploit Block Rules
	for _, rule := range data.ExploitBlockRules {
		newID, err := r.importExploitBlockRule(ctx, tx, &rule)
		if err != nil {
			return fmt.Errorf("failed to import exploit block rule %s: %w", rule.Name, err)
		}
		if newID != "" {
			exploitRuleIDMap[rule.ID] = newID
		}
	}

	// Import Global WAF Exclusions
	for _, we := range data.GlobalWAFExclusions {
		if err := r.importGlobalWAFExclusion(ctx, tx, &we); err != nil {
			return fmt.Errorf("failed to import global waf exclusion for rule %d: %w", we.RuleID, err)
		}
	}

	// Import Global Exploit Exclusions
	for _, ee := range data.GlobalExploitExclusions {
		// Remap rule ID
		if newID, ok := exploitRuleIDMap[ee.RuleID]; ok {
			ee.RuleID = newID
		} else {
			// Skip if rule doesn't exist
			continue
		}
		if err := r.importGlobalExploitExclusion(ctx, tx, &ee); err != nil {
			return fmt.Errorf("failed to import global exploit exclusion for rule %s: %w", ee.RuleID, err)
		}
	}

	// Import Host Exploit Exclusions
	for _, he := range data.HostExploitExclusions {
		// Remap proxy host ID
		if newID, ok := proxyHostIDMap[he.ProxyHostID]; ok {
			he.ProxyHostID = newID
		}
		// Remap rule ID
		if newID, ok := exploitRuleIDMap[he.RuleID]; ok {
			he.RuleID = newID
		} else {
			// Skip if rule doesn't exist (might be a deleted rule)
			continue
		}
		if err := r.importHostExploitExclusion(ctx, tx, &he); err != nil {
			return fmt.Errorf("failed to import host exploit exclusion: %w", err)
		}
	}

	// Import Global Challenge Config (CAPTCHA)
	if data.GlobalChallengeConfig != nil {
		if err := r.importGlobalChallengeConfig(ctx, tx, data.GlobalChallengeConfig); err != nil {
			return fmt.Errorf("failed to import global challenge config: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// clearExistingData removes existing configuration data in correct order for FK constraints
func (r *BackupRepository) clearExistingData(ctx context.Context, tx *sql.Tx) error {
	// Delete in order respecting foreign key constraints
	// 1. Delete proxy host related tables (they reference proxy_hosts)
	tables := []string{
		"waf_rule_exclusions",
		"host_exploit_rule_exclusions", // references proxy_hosts
		"challenge_configs",            // references proxy_hosts
		"upstream_servers",             // references upstreams
		"upstreams",
		"geo_restrictions",
		"security_headers",
		"bot_filters",
		"fail2ban_configs",
		"rate_limits",       // correct table name
		"uri_blocks",        // references proxy_hosts
		"banned_ips",        // references proxy_hosts
		"redirect_hosts",    // references certificates
		"proxy_hosts",       // references certificates and access_lists
		"access_list_items", // references access_lists
		"access_lists",
		"certificates",    // references dns_providers
		"dns_providers",
		"global_uri_blocks",            // standalone table
		"global_waf_rule_exclusions",   // standalone table
		"global_exploit_rule_exclusions", // standalone table
		"cloud_providers",              // standalone table
		"exploit_block_rules",          // standalone table (only non-builtin)
	}

	for _, table := range tables {
		var query string
		if table == "exploit_block_rules" {
			// Keep system rules, only delete user-defined rules
			query = "DELETE FROM exploit_block_rules WHERE is_system = false"
		} else {
			query = fmt.Sprintf("DELETE FROM %s", table)
		}
		_, err := tx.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to clear %s: %w", table, err)
		}
	}

	return nil
}

func (r *BackupRepository) importGlobalSettings(ctx context.Context, tx *sql.Tx, gs *model.GlobalSettingsExport) error {
	query := `
		UPDATE global_settings SET
			worker_processes = $1, worker_connections = $2, worker_rlimit_nofile = $3,
			multi_accept = $4, use_epoll = $5, sendfile = $6, tcp_nopush = $7, tcp_nodelay = $8,
			keepalive_timeout = $9, keepalive_requests = $10, types_hash_max_size = $11, server_tokens = $12,
			client_body_buffer_size = $13, client_header_buffer_size = $14, client_max_body_size = $15,
			large_client_header_buffers = $16, client_body_timeout = $17, client_header_timeout = $18,
			send_timeout = $19, proxy_connect_timeout = $20, proxy_send_timeout = $21, proxy_read_timeout = $22,
			gzip_enabled = $23, gzip_vary = $24, gzip_proxied = $25, gzip_comp_level = $26, gzip_buffers = $27,
			gzip_http_version = $28, gzip_min_length = $29, gzip_types = $30,
			ssl_protocols = $31, ssl_ciphers = $32, ssl_prefer_server_ciphers = $33, ssl_session_cache = $34,
			ssl_session_timeout = $35, ssl_session_tickets = $36, ssl_stapling = $37, ssl_stapling_verify = $38,
			access_log_enabled = $39, error_log_level = $40, resolver = $41, resolver_timeout = $42,
			custom_http_config = $43, custom_stream_config = $44, updated_at = NOW()
	`

	_, err := tx.ExecContext(ctx, query,
		gs.WorkerProcesses, gs.WorkerConnections, gs.WorkerRlimitNofile,
		gs.MultiAccept, gs.UseEpoll, gs.Sendfile, gs.TCPNopush, gs.TCPNodelay,
		gs.KeepaliveTimeout, gs.KeepaliveRequests, gs.TypesHashMaxSize, gs.ServerTokens,
		gs.ClientBodyBufferSize, gs.ClientHeaderBufferSize, gs.ClientMaxBodySize,
		gs.LargeClientHeaderBuffers, gs.ClientBodyTimeout, gs.ClientHeaderTimeout,
		gs.SendTimeout, gs.ProxyConnectTimeout, gs.ProxySendTimeout, gs.ProxyReadTimeout,
		gs.GzipEnabled, gs.GzipVary, gs.GzipProxied, gs.GzipCompLevel, gs.GzipBuffers,
		gs.GzipHTTPVersion, gs.GzipMinLength, gs.GzipTypes,
		gs.SSLProtocols, gs.SSLCiphers, gs.SSLPreferServerCiphers, gs.SSLSessionCache,
		gs.SSLSessionTimeout, gs.SSLSessionTickets, gs.SSLStapling, gs.SSLStaplingVerify,
		gs.AccessLogEnabled, gs.ErrorLogLevel, gs.Resolver, gs.ResolverTimeout,
		gs.CustomHTTPConfig, gs.CustomStreamConfig,
	)
	return err
}

func (r *BackupRepository) importDNSProvider(ctx context.Context, tx *sql.Tx, dp *model.DNSProviderExport) (string, error) {
	credentials, _ := json.Marshal(dp.Credentials)

	query := `
		INSERT INTO dns_providers (name, provider_type, credentials, is_default)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (is_default) WHERE is_default = true DO UPDATE
		SET name = EXCLUDED.name, provider_type = EXCLUDED.provider_type,
		    credentials = EXCLUDED.credentials, updated_at = NOW()
		RETURNING id
	`

	var newID string
	err := tx.QueryRowContext(ctx, query, dp.Name, dp.Type, credentials, dp.IsDefault).Scan(&newID)
	if err != nil {
		// Try without conflict handling
		query = `
			INSERT INTO dns_providers (name, provider_type, credentials, is_default)
			VALUES ($1, $2, $3, false)
			RETURNING id
		`
		err = tx.QueryRowContext(ctx, query, dp.Name, dp.Type, credentials).Scan(&newID)
	}
	return newID, err
}

func (r *BackupRepository) importCertificate(ctx context.Context, tx *sql.Tx, cert *model.CertificateExport) (string, error) {
	query := `
		INSERT INTO certificates (domain_names, expires_at, certificate_path, private_key_path, provider,
		                          dns_provider_id, status, auto_renew, certificate_pem, private_key_pem,
		                          issuer_certificate_pem)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`

	var dnsProviderID interface{}
	if cert.DNSProviderID != "" {
		dnsProviderID = cert.DNSProviderID
	}

	var newID string
	err := tx.QueryRowContext(ctx, query,
		pq.Array(cert.DomainNames), cert.ExpiresAt, cert.CertificatePath, cert.PrivateKeyPath, cert.Provider,
		dnsProviderID, cert.Status, cert.AutoRenew, cert.CertificatePEM, cert.PrivateKeyPEM,
		cert.IssuerCertificatePEM,
	).Scan(&newID)
	return newID, err
}

func (r *BackupRepository) importAccessList(ctx context.Context, tx *sql.Tx, al *model.AccessListExport) (string, error) {
	query := `
		INSERT INTO access_lists (name, description, satisfy_any, pass_auth)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`

	var newID string
	err := tx.QueryRowContext(ctx, query,
		al.AccessList.Name, al.AccessList.Description, al.AccessList.SatisfyAny, al.AccessList.PassAuth,
	).Scan(&newID)
	if err != nil {
		return "", err
	}

	// Import access list items
	for _, item := range al.AccessList.Items {
		itemQuery := `
			INSERT INTO access_list_items (access_list_id, directive, address, description, sort_order)
			VALUES ($1, $2, $3, $4, $5)
		`
		_, err = tx.ExecContext(ctx, itemQuery, newID, item.Directive, item.Address, item.Description, item.SortOrder)
		if err != nil {
			return "", err
		}
	}

	return newID, nil
}

func (r *BackupRepository) importProxyHost(ctx context.Context, tx *sql.Tx, ph *model.ProxyHostExport) (string, error) {
	customLocations, _ := json.Marshal(ph.ProxyHost.CustomLocations)
	meta, _ := json.Marshal(ph.ProxyHost.Meta)

	// Set default values for fields that may be missing from older backups
	cacheStaticOnly := ph.ProxyHost.CacheStaticOnly
	cacheTTL := ph.ProxyHost.CacheTTL
	if cacheTTL == "" {
		cacheTTL = "7d"
	}
	// waf_paranoia_level has CHECK constraint >= 1, default to 1 if missing from old backup
	wafParanoiaLevel := ph.ProxyHost.WAFParanoiaLevel
	if wafParanoiaLevel < 1 {
		wafParanoiaLevel = 1
	}
	// waf_anomaly_threshold has CHECK constraint >= 1, default to 5 if missing from old backup
	wafAnomalyThreshold := ph.ProxyHost.WAFAnomalyThreshold
	if wafAnomalyThreshold < 1 {
		wafAnomalyThreshold = 5
	}

	query := `
		INSERT INTO proxy_hosts (domain_names, forward_scheme, forward_host, forward_port,
		                         ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
		                         allow_websocket_upgrade, cache_enabled, cache_static_only, cache_ttl,
		                         block_exploits, block_exploits_exceptions,
		                         custom_locations, advanced_config, waf_enabled, waf_mode,
		                         waf_paranoia_level, waf_anomaly_threshold,
		                         access_list_id, enabled, is_favorite,
		                         rate_limit_enabled, fail2ban_enabled, bot_filter_enabled, security_headers_enabled,
		                         proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
		                         proxy_buffering, client_max_body_size, proxy_max_temp_file_size, meta)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
		        $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35)
		RETURNING id
	`

	var certID, accessListID interface{}
	if ph.ProxyHost.CertificateID != "" {
		certID = ph.ProxyHost.CertificateID
	}
	if ph.ProxyHost.AccessListID != "" {
		accessListID = ph.ProxyHost.AccessListID
	}

	var newID string
	err := tx.QueryRowContext(ctx, query,
		pq.Array(ph.ProxyHost.DomainNames), ph.ProxyHost.ForwardScheme, ph.ProxyHost.ForwardHost, ph.ProxyHost.ForwardPort,
		ph.ProxyHost.SSLEnabled, ph.ProxyHost.SSLForceHTTPS, ph.ProxyHost.SSLHTTP2, ph.ProxyHost.SSLHTTP3, certID,
		ph.ProxyHost.AllowWebsocketUpgrade, ph.ProxyHost.CacheEnabled, cacheStaticOnly, cacheTTL,
		ph.ProxyHost.BlockExploits, ph.ProxyHost.BlockExploitsExceptions,
		customLocations, ph.ProxyHost.AdvancedConfig, ph.ProxyHost.WAFEnabled, ph.ProxyHost.WAFMode,
		wafParanoiaLevel, wafAnomalyThreshold,
		accessListID, ph.ProxyHost.Enabled, ph.ProxyHost.IsFavorite,
		ph.ProxyHost.RateLimitEnabled, ph.ProxyHost.Fail2banEnabled, ph.ProxyHost.BotFilterEnabled, ph.ProxyHost.SecurityHeadersEnabled,
		ph.ProxyHost.ProxyConnectTimeout, ph.ProxyHost.ProxySendTimeout, ph.ProxyHost.ProxyReadTimeout,
		ph.ProxyHost.ProxyBuffering, ph.ProxyHost.ClientMaxBodySize, ph.ProxyHost.ProxyMaxTempFileSize, meta,
	).Scan(&newID)
	if err != nil {
		return "", err
	}

	// Import related configurations
	if ph.RateLimit != nil {
		if err := r.importRateLimit(ctx, tx, newID, ph.RateLimit); err != nil {
			return "", fmt.Errorf("failed to import rate limit: %w", err)
		}
	}

	if ph.Fail2ban != nil {
		if err := r.importFail2ban(ctx, tx, newID, ph.Fail2ban); err != nil {
			return "", fmt.Errorf("failed to import fail2ban: %w", err)
		}
	}

	if ph.BotFilter != nil {
		if err := r.importBotFilter(ctx, tx, newID, ph.BotFilter); err != nil {
			return "", fmt.Errorf("failed to import bot filter: %w", err)
		}
	}

	if ph.SecurityHeaders != nil {
		if err := r.importSecurityHeaders(ctx, tx, newID, ph.SecurityHeaders); err != nil {
			return "", fmt.Errorf("failed to import security headers: %w", err)
		}
	}

	if ph.GeoRestriction != nil {
		if err := r.importGeoRestriction(ctx, tx, newID, ph.GeoRestriction); err != nil {
			return "", fmt.Errorf("failed to import geo restriction: %w", err)
		}
	}

	if ph.Upstream != nil {
		if err := r.importUpstream(ctx, tx, newID, ph.Upstream); err != nil {
			return "", fmt.Errorf("failed to import upstream: %w", err)
		}
	}

	if ph.ChallengeConfig != nil {
		if err := r.importChallengeConfig(ctx, tx, newID, ph.ChallengeConfig); err != nil {
			return "", fmt.Errorf("failed to import challenge config: %w", err)
		}
	}

	return newID, nil
}

func (r *BackupRepository) importRateLimit(ctx context.Context, tx *sql.Tx, proxyHostID string, rl *model.RateLimitExport) error {
	query := `
		INSERT INTO rate_limits (proxy_host_id, enabled, requests_per_second, burst_size, zone_size,
		                         limit_by, limit_response, whitelist_ips)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, rl.Enabled, rl.RequestsPerSecond, rl.BurstSize,
		rl.ZoneSize, rl.LimitBy, rl.LimitResponse, rl.WhitelistIPs)
	return err
}

func (r *BackupRepository) importFail2ban(ctx context.Context, tx *sql.Tx, proxyHostID string, f *model.Fail2banExport) error {
	query := `
		INSERT INTO fail2ban_configs (proxy_host_id, enabled, max_retries, find_time, ban_time, fail_codes, action)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, f.Enabled, f.MaxRetries, f.FindTime, f.BanTime, f.FailCodes, f.Action)
	return err
}

func (r *BackupRepository) importBotFilter(ctx context.Context, tx *sql.Tx, proxyHostID string, bf *model.BotFilterExport) error {
	query := `
		INSERT INTO bot_filters (proxy_host_id, enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		                         custom_blocked_agents, custom_allowed_agents, challenge_suspicious)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, bf.Enabled, bf.BlockBadBots, bf.BlockAIBots,
		bf.AllowSearchEngines, bf.CustomBlockedAgents, bf.CustomAllowedAgents, bf.ChallengeSuspicious)
	return err
}

func (r *BackupRepository) importSecurityHeaders(ctx context.Context, tx *sql.Tx, proxyHostID string, sh *model.SecurityHeadersExport) error {
	customHeaders, _ := json.Marshal(sh.CustomHeaders)

	query := `
		INSERT INTO security_headers (proxy_host_id, enabled, hsts_enabled, hsts_max_age,
		                              hsts_include_subdomains, hsts_preload, x_frame_options,
		                              x_content_type_options, x_xss_protection, referrer_policy,
		                              content_security_policy, permissions_policy, custom_headers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, sh.Enabled, sh.HSTSEnabled, sh.HSTSMaxAge,
		sh.HSTSIncludeSubdomains, sh.HSTSPreload, sh.XFrameOptions, sh.XContentTypeOptions,
		sh.XXSSProtection, sh.ReferrerPolicy, sh.ContentSecurityPolicy, sh.PermissionsPolicy, customHeaders)
	return err
}

func (r *BackupRepository) importGeoRestriction(ctx context.Context, tx *sql.Tx, proxyHostID string, gr *model.GeoRestrictionExport) error {
	query := `
		INSERT INTO geo_restrictions (proxy_host_id, mode, countries, enabled, challenge_mode, allow_private_ips, allow_search_bots,
		                              allowed_ips, blocked_cloud_providers, challenge_cloud_providers, allow_search_bots_cloud_providers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			mode = EXCLUDED.mode,
			countries = EXCLUDED.countries,
			enabled = EXCLUDED.enabled,
			challenge_mode = EXCLUDED.challenge_mode,
			allow_private_ips = EXCLUDED.allow_private_ips,
			allow_search_bots = EXCLUDED.allow_search_bots,
			allowed_ips = EXCLUDED.allowed_ips,
			blocked_cloud_providers = EXCLUDED.blocked_cloud_providers,
			challenge_cloud_providers = EXCLUDED.challenge_cloud_providers,
			allow_search_bots_cloud_providers = EXCLUDED.allow_search_bots_cloud_providers,
			updated_at = NOW()
	`
	// Ensure arrays are not nil for postgres
	allowedIPs := gr.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}
	blockedCloudProviders := gr.BlockedCloudProviders
	if blockedCloudProviders == nil {
		blockedCloudProviders = []string{}
	}
	_, err := tx.ExecContext(ctx, query, proxyHostID, gr.Mode, pq.Array(gr.Countries), gr.Enabled,
		gr.ChallengeMode, gr.AllowPrivateIPs, gr.AllowSearchBots,
		pq.Array(allowedIPs), pq.Array(blockedCloudProviders),
		gr.ChallengeCloudProviders, gr.AllowSearchBotsCloudProviders)
	return err
}

func (r *BackupRepository) importUpstream(ctx context.Context, tx *sql.Tx, proxyHostID string, u *model.UpstreamExport) error {
	servers, _ := json.Marshal(u.Servers)

	query := `
		INSERT INTO upstreams (proxy_host_id, name, servers, load_balance, health_check_enabled,
		                       health_check_interval, health_check_timeout, health_check_path,
		                       health_check_expected_status, keepalive)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			name = EXCLUDED.name,
			servers = EXCLUDED.servers,
			load_balance = EXCLUDED.load_balance,
			health_check_enabled = EXCLUDED.health_check_enabled,
			health_check_interval = EXCLUDED.health_check_interval,
			health_check_timeout = EXCLUDED.health_check_timeout,
			health_check_path = EXCLUDED.health_check_path,
			health_check_expected_status = EXCLUDED.health_check_expected_status,
			keepalive = EXCLUDED.keepalive,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, u.Name, servers, u.LoadBalance,
		u.HealthCheckEnabled, u.HealthCheckInterval, u.HealthCheckTimeout, u.HealthCheckPath,
		u.HealthCheckExpectedStatus, u.Keepalive)
	return err
}

func (r *BackupRepository) importRedirectHost(ctx context.Context, tx *sql.Tx, rh *model.RedirectHostExport) error {
	meta, _ := json.Marshal(rh.RedirectHost.Meta)

	query := `
		INSERT INTO redirect_hosts (domain_names, forward_scheme, forward_domain_name, forward_path,
		                            preserve_path, redirect_code, ssl_enabled, certificate_id,
		                            ssl_force_https, enabled, block_exploits, meta)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	var certID interface{}
	if rh.RedirectHost.CertificateID != "" {
		certID = rh.RedirectHost.CertificateID
	}

	_, err := tx.ExecContext(ctx, query,
		pq.Array(rh.RedirectHost.DomainNames), rh.RedirectHost.ForwardScheme, rh.RedirectHost.ForwardDomainName, rh.RedirectHost.ForwardPath,
		rh.RedirectHost.PreservePath, rh.RedirectHost.RedirectCode, rh.RedirectHost.SSLEnabled, certID,
		rh.RedirectHost.SSLForceHTTPS, rh.RedirectHost.Enabled, rh.RedirectHost.BlockExploits, meta,
	)
	return err
}

func (r *BackupRepository) importWAFExclusion(ctx context.Context, tx *sql.Tx, we *model.WAFExclusionExport) error {
	query := `
		INSERT INTO waf_rule_exclusions (proxy_host_id, rule_id, rule_category, rule_description, reason, disabled_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (proxy_host_id, rule_id) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, we.ProxyHostID, we.RuleID, we.RuleCategory, we.RuleDescription, we.Reason, we.DisabledBy)
	return err
}

func (r *BackupRepository) importSystemSettings(ctx context.Context, tx *sql.Tx, ss *model.SystemSettingsExport) error {
	query := `
		UPDATE system_settings SET
			geoip_enabled = $1, geoip_auto_update = $2, geoip_update_interval = $3,
			maxmind_account_id = $4, maxmind_license_key = $5,
			acme_enabled = $6, acme_email = $7, acme_staging = $8, acme_auto_renew = $9, acme_renew_days_before = $10,
			notification_email = $11, notify_cert_expiry = $12, notify_cert_expiry_days = $13,
			notify_security_events = $14, notify_backup_complete = $15,
			log_retention_days = $16, stats_retention_days = $17, backup_retention_count = $18,
			auto_backup_enabled = $19, auto_backup_schedule = $20,
			access_log_retention_days = $21, waf_log_retention_days = $22, error_log_retention_days = $23,
			system_log_retention_days = $24, audit_log_retention_days = $25,
			raw_log_enabled = $26, raw_log_retention_days = $27, raw_log_max_size_mb = $28,
			raw_log_rotate_count = $29, raw_log_compress_rotated = $30,
			bot_filter_default_enabled = $31, bot_filter_default_block_bad_bots = $32,
			bot_filter_default_block_ai_bots = $33, bot_filter_default_allow_search_engines = $34,
			bot_filter_default_block_suspicious_clients = $35, bot_filter_default_challenge_suspicious = $36,
			bot_filter_default_custom_blocked_agents = $37,
			bot_list_bad_bots = $38, bot_list_ai_bots = $39, bot_list_search_engines = $40, bot_list_suspicious_clients = $41,
			waf_auto_ban_enabled = $42, waf_auto_ban_threshold = $43, waf_auto_ban_window = $44, waf_auto_ban_duration = $45,
			direct_ip_access_action = $46, system_logs_enabled = $47,
			updated_at = NOW()
	`

	_, err := tx.ExecContext(ctx, query,
		ss.GeoIPEnabled, ss.GeoIPAutoUpdate, ss.GeoIPUpdateInterval,
		ss.MaxmindAccountID, ss.MaxmindLicenseKey,
		ss.ACMEEnabled, ss.ACMEEmail, ss.ACMEStaging, ss.ACMEAutoRenew, ss.ACMERenewDaysBefore,
		ss.NotificationEmail, ss.NotifyCertExpiry, ss.NotifyCertExpiryDays,
		ss.NotifySecurityEvents, ss.NotifyBackupComplete,
		ss.LogRetentionDays, ss.StatsRetentionDays, ss.BackupRetentionCount,
		ss.AutoBackupEnabled, ss.AutoBackupSchedule,
		ss.AccessLogRetentionDays, ss.WAFLogRetentionDays, ss.ErrorLogRetentionDays,
		ss.SystemLogRetentionDays, ss.AuditLogRetentionDays,
		ss.RawLogEnabled, ss.RawLogRetentionDays, ss.RawLogMaxSizeMB,
		ss.RawLogRotateCount, ss.RawLogCompressRotated,
		ss.BotFilterDefaultEnabled, ss.BotFilterDefaultBlockBadBots,
		ss.BotFilterDefaultBlockAIBots, ss.BotFilterDefaultAllowSearchEngines,
		ss.BotFilterDefaultBlockSuspiciousClients, ss.BotFilterDefaultChallengeSuspicious,
		ss.BotFilterDefaultCustomBlockedAgents,
		ss.BotListBadBots, ss.BotListAIBots, ss.BotListSearchEngines, ss.BotListSuspiciousClients,
		ss.WAFAutoBanEnabled, ss.WAFAutoBanThreshold, ss.WAFAutoBanWindow, ss.WAFAutoBanDuration,
		ss.DirectIPAccessAction, ss.SystemLogsEnabled,
	)
	return err
}

func (r *BackupRepository) importBannedIP(ctx context.Context, tx *sql.Tx, bip *model.BannedIPExport) error {
	// Check if already exists (partial unique indexes require manual check)
	var exists bool
	var proxyHostID interface{}
	if bip.ProxyHostID != "" {
		proxyHostID = bip.ProxyHostID
		err := tx.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM banned_ips WHERE ip_address = $1 AND proxy_host_id = $2)",
			bip.IPAddress, proxyHostID).Scan(&exists)
		if err != nil {
			return err
		}
	} else {
		err := tx.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM banned_ips WHERE ip_address = $1 AND proxy_host_id IS NULL)",
			bip.IPAddress).Scan(&exists)
		if err != nil {
			return err
		}
	}

	if exists {
		return nil // Skip duplicate
	}

	query := `
		INSERT INTO banned_ips (proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, is_auto_banned)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := tx.ExecContext(ctx, query, proxyHostID, bip.IPAddress, bip.Reason, bip.FailCount,
		bip.BannedAt, bip.ExpiresAt, bip.IsPermanent, bip.IsAutoBanned)
	return err
}

func (r *BackupRepository) importURIBlock(ctx context.Context, tx *sql.Tx, ub *model.URIBlockExport) error {
	rulesJSON, _ := json.Marshal(ub.Rules)

	query := `
		INSERT INTO uri_blocks (proxy_host_id, enabled, rules, exception_ips, allow_private_ips)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			rules = EXCLUDED.rules,
			exception_ips = EXCLUDED.exception_ips,
			allow_private_ips = EXCLUDED.allow_private_ips,
			updated_at = NOW()
	`

	_, err := tx.ExecContext(ctx, query, ub.ProxyHostID, ub.Enabled, rulesJSON, pq.Array(ub.ExceptionIPs), ub.AllowPrivateIPs)
	return err
}

func (r *BackupRepository) importGlobalURIBlock(ctx context.Context, tx *sql.Tx, ub *model.GlobalURIBlockExport) error {
	rulesJSON, _ := json.Marshal(ub.Rules)

	// Delete existing and insert new
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_uri_blocks")

	query := `
		INSERT INTO global_uri_blocks (enabled, rules, exception_ips, allow_private_ips)
		VALUES ($1, $2, $3, $4)
	`

	_, err := tx.ExecContext(ctx, query, ub.Enabled, rulesJSON, pq.Array(ub.ExceptionIPs), ub.AllowPrivateIPs)
	return err
}

func (r *BackupRepository) importChallengeConfig(ctx context.Context, tx *sql.Tx, proxyHostID string, cc *model.ChallengeConfigExport) error {
	query := `
		INSERT INTO challenge_configs (proxy_host_id, enabled, challenge_type, site_key, secret_key,
		                               token_validity, min_score, apply_to, page_title, page_message, theme)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			challenge_type = EXCLUDED.challenge_type,
			site_key = EXCLUDED.site_key,
			secret_key = EXCLUDED.secret_key,
			token_validity = EXCLUDED.token_validity,
			min_score = EXCLUDED.min_score,
			apply_to = EXCLUDED.apply_to,
			page_title = EXCLUDED.page_title,
			page_message = EXCLUDED.page_message,
			theme = EXCLUDED.theme,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, cc.Enabled, cc.ChallengeType, cc.SiteKey, cc.SecretKey,
		cc.TokenValidity, cc.MinScore, cc.ApplyTo, cc.PageTitle, cc.PageMessage, cc.Theme)
	return err
}

func (r *BackupRepository) importCloudProvider(ctx context.Context, tx *sql.Tx, cp *model.CloudProviderExport) error {
	query := `
		INSERT INTO cloud_providers (name, slug, description, region, ip_ranges_url, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (slug) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			region = EXCLUDED.region,
			ip_ranges_url = EXCLUDED.ip_ranges_url,
			enabled = EXCLUDED.enabled,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query, cp.Name, cp.Slug, cp.Description, cp.Region, cp.IPRangesURL, cp.Enabled)
	return err
}

func (r *BackupRepository) importExploitBlockRule(ctx context.Context, tx *sql.Tx, rule *model.ExploitBlockRuleExport) (string, error) {
	// Skip system rules - they're already in the database
	if rule.IsBuiltin {
		// Just update enabled status for system rules and return the same ID
		query := `UPDATE exploit_block_rules SET enabled = $1, updated_at = NOW() WHERE id = $2 AND is_system = true`
		_, _ = tx.ExecContext(ctx, query, rule.Enabled, rule.ID)
		// For system rules, the ID remains the same
		return rule.ID, nil
	}

	query := `
		INSERT INTO exploit_block_rules (name, category, pattern, pattern_type, description, severity, enabled, is_system)
		VALUES ($1, $2, $3, $4, $5, $6, $7, false)
		ON CONFLICT (name, category) DO UPDATE SET
			pattern = EXCLUDED.pattern,
			pattern_type = EXCLUDED.pattern_type,
			description = EXCLUDED.description,
			severity = EXCLUDED.severity,
			enabled = EXCLUDED.enabled,
			updated_at = NOW()
		RETURNING id
	`
	var newID string
	err := tx.QueryRowContext(ctx, query, rule.Name, rule.Category, rule.Pattern, rule.PatternType,
		rule.Description, rule.Severity, rule.Enabled).Scan(&newID)
	return newID, err
}

func (r *BackupRepository) importGlobalWAFExclusion(ctx context.Context, tx *sql.Tx, we *model.GlobalWAFExclusionExport) error {
	query := `
		INSERT INTO global_waf_rule_exclusions (rule_id, rule_category, rule_description, reason, disabled_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (rule_id) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, we.RuleID, we.RuleCategory, we.RuleDescription, we.Reason, we.DisabledBy)
	return err
}

func (r *BackupRepository) importGlobalExploitExclusion(ctx context.Context, tx *sql.Tx, ee *model.GlobalExploitExclusionExport) error {
	query := `
		INSERT INTO global_exploit_rule_exclusions (rule_id, reason, disabled_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (rule_id) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, ee.RuleID, ee.Reason, ee.DisabledBy)
	return err
}

func (r *BackupRepository) importHostExploitExclusion(ctx context.Context, tx *sql.Tx, he *model.HostExploitExclusionExport) error {
	query := `
		INSERT INTO host_exploit_rule_exclusions (proxy_host_id, rule_id, reason, disabled_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (proxy_host_id, rule_id) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, he.ProxyHostID, he.RuleID, he.Reason, he.DisabledBy)
	return err
}

func (r *BackupRepository) importGlobalChallengeConfig(ctx context.Context, tx *sql.Tx, cc *model.ChallengeConfigExport) error {
	query := `
		INSERT INTO challenge_configs (
			proxy_host_id, enabled, challenge_type, site_key, secret_key,
			token_validity, min_score, apply_to, page_title, page_message, theme
		) VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := tx.ExecContext(ctx, query,
		cc.Enabled, cc.ChallengeType, cc.SiteKey, cc.SecretKey,
		cc.TokenValidity, cc.MinScore, cc.ApplyTo, cc.PageTitle, cc.PageMessage, cc.Theme,
	)
	return err
}
