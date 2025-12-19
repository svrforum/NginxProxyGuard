package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

// ExportAllData exports all configuration data for backup
func (r *BackupRepository) ExportAllData(ctx context.Context) (*model.ExportData, error) {
	export := &model.ExportData{
		Version:    "1.0",
		ExportedAt: time.Now(),
	}

	// Export Global Settings
	globalSettings, err := r.exportGlobalSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export global settings: %w", err)
	}
	export.GlobalSettings = globalSettings

	// Export System Settings
	systemSettings, err := r.exportSystemSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export system settings: %w", err)
	}
	export.SystemSettings = systemSettings

	// Export Proxy Hosts with all related configurations
	proxyHosts, err := r.exportProxyHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export proxy hosts: %w", err)
	}
	export.ProxyHosts = proxyHosts

	// Export Redirect Hosts
	redirectHosts, err := r.exportRedirectHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export redirect hosts: %w", err)
	}
	export.RedirectHosts = redirectHosts

	// Export Access Lists
	accessLists, err := r.exportAccessLists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export access lists: %w", err)
	}
	export.AccessLists = accessLists

	// Export DNS Providers (without sensitive credentials)
	dnsProviders, err := r.exportDNSProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export dns providers: %w", err)
	}
	export.DNSProviders = dnsProviders

	// Export Certificates
	certificates, err := r.exportCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export certificates: %w", err)
	}
	export.Certificates = certificates

	// Export WAF Rule Exclusions
	wafExclusions, err := r.exportWAFExclusions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export waf exclusions: %w", err)
	}
	export.WAFExclusions = wafExclusions

	// Export Banned IPs
	bannedIPs, err := r.exportBannedIPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export banned ips: %w", err)
	}
	export.BannedIPs = bannedIPs

	// Export URI Blocks (per proxy host)
	uriBlocks, err := r.exportURIBlocks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export uri blocks: %w", err)
	}
	export.URIBlocks = uriBlocks

	// Export Global URI Block
	globalURIBlock, err := r.exportGlobalURIBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export global uri block: %w", err)
	}
	export.GlobalURIBlock = globalURIBlock

	// Export Cloud Providers
	cloudProviders, err := r.exportCloudProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export cloud providers: %w", err)
	}
	export.CloudProviders = cloudProviders

	// Export Exploit Block Rules
	exploitRules, err := r.exportExploitBlockRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export exploit block rules: %w", err)
	}
	export.ExploitBlockRules = exploitRules

	// Export Global WAF Rule Exclusions
	globalWAFExclusions, err := r.exportGlobalWAFExclusions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export global waf exclusions: %w", err)
	}
	export.GlobalWAFExclusions = globalWAFExclusions

	// Export Global Exploit Rule Exclusions
	globalExploitExclusions, err := r.exportGlobalExploitExclusions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export global exploit exclusions: %w", err)
	}
	export.GlobalExploitExclusions = globalExploitExclusions

	// Export Host Exploit Rule Exclusions
	hostExploitExclusions, err := r.exportHostExploitExclusions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export host exploit exclusions: %w", err)
	}
	export.HostExploitExclusions = hostExploitExclusions

	return export, nil
}

func (r *BackupRepository) exportGlobalSettings(ctx context.Context) (*model.GlobalSettingsExport, error) {
	query := `
		SELECT worker_processes, worker_connections, worker_rlimit_nofile,
		       multi_accept, use_epoll, sendfile, tcp_nopush, tcp_nodelay,
		       keepalive_timeout, keepalive_requests, types_hash_max_size, server_tokens,
		       client_body_buffer_size, client_header_buffer_size, client_max_body_size,
		       large_client_header_buffers, client_body_timeout, client_header_timeout,
		       send_timeout, proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
		       gzip_enabled, gzip_vary, gzip_proxied, gzip_comp_level, gzip_buffers,
		       gzip_http_version, gzip_min_length, gzip_types,
		       ssl_protocols, ssl_ciphers, ssl_prefer_server_ciphers, ssl_session_cache,
		       ssl_session_timeout, ssl_session_tickets, ssl_stapling, ssl_stapling_verify,
		       access_log_enabled, error_log_level, resolver, resolver_timeout,
		       custom_http_config, custom_stream_config
		FROM global_settings LIMIT 1
	`

	var gs model.GlobalSettingsExport
	var resolver, resolverTimeout, customHttp, customStream sql.NullString
	var customInt sql.NullInt64

	err := r.db.QueryRowContext(ctx, query).Scan(
		&gs.WorkerProcesses, &gs.WorkerConnections, &customInt,
		&gs.MultiAccept, &gs.UseEpoll, &gs.Sendfile, &gs.TCPNopush, &gs.TCPNodelay,
		&gs.KeepaliveTimeout, &gs.KeepaliveRequests, &gs.TypesHashMaxSize, &gs.ServerTokens,
		&gs.ClientBodyBufferSize, &gs.ClientHeaderBufferSize, &gs.ClientMaxBodySize,
		&gs.LargeClientHeaderBuffers, &gs.ClientBodyTimeout, &gs.ClientHeaderTimeout,
		&gs.SendTimeout, &gs.ProxyConnectTimeout, &gs.ProxySendTimeout, &gs.ProxyReadTimeout,
		&gs.GzipEnabled, &gs.GzipVary, &gs.GzipProxied, &gs.GzipCompLevel, &gs.GzipBuffers,
		&gs.GzipHTTPVersion, &gs.GzipMinLength, &gs.GzipTypes,
		&gs.SSLProtocols, &gs.SSLCiphers, &gs.SSLPreferServerCiphers, &gs.SSLSessionCache,
		&gs.SSLSessionTimeout, &gs.SSLSessionTickets, &gs.SSLStapling, &gs.SSLStaplingVerify,
		&gs.AccessLogEnabled, &gs.ErrorLogLevel, &resolver, &resolverTimeout,
		&customHttp, &customStream,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if customInt.Valid {
		v := int(customInt.Int64)
		gs.WorkerRlimitNofile = &v
	}
	gs.Resolver = resolver.String
	gs.ResolverTimeout = resolverTimeout.String
	gs.CustomHTTPConfig = customHttp.String
	gs.CustomStreamConfig = customStream.String

	return &gs, nil
}

func (r *BackupRepository) exportProxyHosts(ctx context.Context) ([]model.ProxyHostExport, error) {
	query := `
		SELECT id, domain_names, forward_scheme, forward_host, forward_port,
		       ssl_enabled, ssl_force_https, ssl_http2, certificate_id,
		       allow_websocket_upgrade, cache_enabled,
		       COALESCE(cache_static_only, true) as cache_static_only,
		       COALESCE(cache_ttl, '7d') as cache_ttl,
		       block_exploits,
		       custom_locations, advanced_config, waf_enabled, waf_mode,
		       access_list_id, enabled, meta
		FROM proxy_hosts ORDER BY created_at
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.ProxyHostExport
	for rows.Next() {
		var ph model.ProxyHostData
		var customLocations, meta []byte
		var certID, accessListID sql.NullString
		var advancedConfig sql.NullString

		err := rows.Scan(
			&ph.ID, pq.Array(&ph.DomainNames), &ph.ForwardScheme, &ph.ForwardHost, &ph.ForwardPort,
			&ph.SSLEnabled, &ph.SSLForceHTTPS, &ph.SSLHTTP2, &certID,
			&ph.AllowWebsocketUpgrade, &ph.CacheEnabled, &ph.CacheStaticOnly, &ph.CacheTTL, &ph.BlockExploits,
			&customLocations, &advancedConfig, &ph.WAFEnabled, &ph.WAFMode,
			&accessListID, &ph.Enabled, &meta,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		json.Unmarshal(customLocations, &ph.CustomLocations)
		json.Unmarshal(meta, &ph.Meta)
		ph.CertificateID = certID.String
		ph.AccessListID = accessListID.String
		ph.AdvancedConfig = advancedConfig.String
		// Ensure domain names is not nil
		if ph.DomainNames == nil {
			ph.DomainNames = []string{}
		}

		export := model.ProxyHostExport{
			ProxyHost: ph,
		}

		// Get related configurations
		export.RateLimit, _ = r.getProxyHostRateLimit(ctx, ph.ID)
		export.Fail2ban, _ = r.getProxyHostFail2ban(ctx, ph.ID)
		export.BotFilter, _ = r.getProxyHostBotFilter(ctx, ph.ID)
		export.SecurityHeaders, _ = r.getProxyHostSecurityHeaders(ctx, ph.ID)
		export.GeoRestriction, _ = r.getProxyHostGeoRestriction(ctx, ph.ID)
		export.Upstream, _ = r.getProxyHostUpstream(ctx, ph.ID)
		export.ChallengeConfig, _ = r.getProxyHostChallengeConfig(ctx, ph.ID)

		exports = append(exports, export)
	}

	return exports, nil
}

func (r *BackupRepository) getProxyHostRateLimit(ctx context.Context, proxyHostID string) (*model.RateLimitExport, error) {
	query := `
		SELECT enabled, requests_per_second, burst_size, zone_size, limit_by, limit_response, whitelist_ips
		FROM rate_limits WHERE proxy_host_id = $1
	`
	var rl model.RateLimitExport
	var whitelistIPs sql.NullString
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&rl.Enabled, &rl.RequestsPerSecond, &rl.BurstSize, &rl.ZoneSize,
		&rl.LimitBy, &rl.LimitResponse, &whitelistIPs,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rl.WhitelistIPs = whitelistIPs.String
	return &rl, nil
}

func (r *BackupRepository) getProxyHostFail2ban(ctx context.Context, proxyHostID string) (*model.Fail2banExport, error) {
	query := `
		SELECT enabled, max_retries, find_time, ban_time, fail_codes, action
		FROM fail2ban_configs WHERE proxy_host_id = $1
	`
	var f model.Fail2banExport
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&f.Enabled, &f.MaxRetries, &f.FindTime, &f.BanTime, &f.FailCodes, &f.Action,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &f, err
}

func (r *BackupRepository) getProxyHostBotFilter(ctx context.Context, proxyHostID string) (*model.BotFilterExport, error) {
	query := `
		SELECT enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		       custom_blocked_agents, custom_allowed_agents, challenge_suspicious
		FROM bot_filters WHERE proxy_host_id = $1
	`
	var bf model.BotFilterExport
	var blockedAgents, allowedAgents sql.NullString
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&bf.Enabled, &bf.BlockBadBots, &bf.BlockAIBots, &bf.AllowSearchEngines,
		&blockedAgents, &allowedAgents, &bf.ChallengeSuspicious,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bf.CustomBlockedAgents = blockedAgents.String
	bf.CustomAllowedAgents = allowedAgents.String
	return &bf, nil
}

func (r *BackupRepository) getProxyHostSecurityHeaders(ctx context.Context, proxyHostID string) (*model.SecurityHeadersExport, error) {
	query := `
		SELECT enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		       x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		       content_security_policy, permissions_policy, custom_headers
		FROM security_headers WHERE proxy_host_id = $1
	`
	var sh model.SecurityHeadersExport
	var csp, pp sql.NullString
	var customHeaders []byte
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&sh.Enabled, &sh.HSTSEnabled, &sh.HSTSMaxAge, &sh.HSTSIncludeSubdomains, &sh.HSTSPreload,
		&sh.XFrameOptions, &sh.XContentTypeOptions, &sh.XXSSProtection, &sh.ReferrerPolicy,
		&csp, &pp, &customHeaders,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sh.ContentSecurityPolicy = csp.String
	sh.PermissionsPolicy = pp.String
	if customHeaders != nil {
		json.Unmarshal(customHeaders, &sh.CustomHeaders)
	}
	return &sh, nil
}

func (r *BackupRepository) getProxyHostGeoRestriction(ctx context.Context, proxyHostID string) (*model.GeoRestrictionExport, error) {
	query := `
		SELECT mode, countries, enabled
		FROM geo_restrictions WHERE proxy_host_id = $1
	`
	var gr model.GeoRestrictionExport
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(&gr.Mode, pq.Array(&gr.Countries), &gr.Enabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if gr.Countries == nil {
		gr.Countries = []string{}
	}
	return &gr, nil
}

func (r *BackupRepository) getProxyHostUpstream(ctx context.Context, proxyHostID string) (*model.UpstreamExport, error) {
	query := `
		SELECT name, servers, load_balance, health_check_enabled, health_check_interval,
		       health_check_timeout, health_check_path, health_check_expected_status, keepalive
		FROM upstreams WHERE proxy_host_id = $1
	`
	var u model.UpstreamExport
	var servers []byte
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&u.Name, &servers, &u.LoadBalance, &u.HealthCheckEnabled, &u.HealthCheckInterval,
		&u.HealthCheckTimeout, &u.HealthCheckPath, &u.HealthCheckExpectedStatus, &u.Keepalive,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(servers, &u.Servers)
	return &u, nil
}

func (r *BackupRepository) exportRedirectHosts(ctx context.Context) ([]model.RedirectHostExport, error) {
	query := `
		SELECT id, domain_names, forward_scheme, forward_domain_name, forward_path,
		       preserve_path, redirect_code, ssl_enabled, certificate_id, ssl_force_https,
		       enabled, block_exploits, meta
		FROM redirect_hosts ORDER BY created_at
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.RedirectHostExport
	for rows.Next() {
		var rh model.RedirectHostData
		var meta []byte
		var certID sql.NullString
		var forwardPath sql.NullString

		err := rows.Scan(
			&rh.ID, pq.Array(&rh.DomainNames), &rh.ForwardScheme, &rh.ForwardDomainName, &forwardPath,
			&rh.PreservePath, &rh.RedirectCode, &rh.SSLEnabled, &certID, &rh.SSLForceHTTPS,
			&rh.Enabled, &rh.BlockExploits, &meta,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(meta, &rh.Meta)
		rh.CertificateID = certID.String
		rh.ForwardPath = forwardPath.String
		if rh.DomainNames == nil {
			rh.DomainNames = []string{}
		}

		exports = append(exports, model.RedirectHostExport{RedirectHost: rh})
	}

	return exports, nil
}

func (r *BackupRepository) exportAccessLists(ctx context.Context) ([]model.AccessListExport, error) {
	query := `SELECT id, name, description, satisfy_any, pass_auth FROM access_lists ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.AccessListExport
	for rows.Next() {
		var al model.AccessListData
		var desc sql.NullString

		err := rows.Scan(&al.ID, &al.Name, &desc, &al.SatisfyAny, &al.PassAuth)
		if err != nil {
			return nil, err
		}
		al.Description = desc.String

		// Get access list items
		items, _ := r.getAccessListItems(ctx, al.ID)
		al.Items = items

		exports = append(exports, model.AccessListExport{AccessList: al})
	}

	return exports, nil
}

func (r *BackupRepository) getAccessListItems(ctx context.Context, accessListID string) ([]model.AccessListItemData, error) {
	query := `
		SELECT directive, address, description, sort_order
		FROM access_list_items WHERE access_list_id = $1 ORDER BY sort_order
	`

	rows, err := r.db.QueryContext(ctx, query, accessListID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.AccessListItemData
	for rows.Next() {
		var item model.AccessListItemData
		var desc sql.NullString
		err := rows.Scan(&item.Directive, &item.Address, &desc, &item.SortOrder)
		if err != nil {
			return nil, err
		}
		item.Description = desc.String
		items = append(items, item)
	}

	return items, nil
}

func (r *BackupRepository) exportDNSProviders(ctx context.Context) ([]model.DNSProviderExport, error) {
	// Note: credentials are exported for full backup functionality
	query := `SELECT id, name, provider_type, credentials, is_default FROM dns_providers ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.DNSProviderExport
	for rows.Next() {
		var dp model.DNSProviderExport
		var credentials []byte
		err := rows.Scan(&dp.ID, &dp.Name, &dp.Type, &credentials, &dp.IsDefault)
		if err != nil {
			return nil, err
		}
		json.Unmarshal(credentials, &dp.Credentials)
		exports = append(exports, dp)
	}

	return exports, nil
}

func (r *BackupRepository) exportCertificates(ctx context.Context) ([]model.CertificateExport, error) {
	query := `
		SELECT id, domain_names, expires_at, certificate_path, private_key_path, provider,
		       dns_provider_id, status, auto_renew, certificate_pem, private_key_pem, issuer_certificate_pem
		FROM certificates ORDER BY created_at
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.CertificateExport
	for rows.Next() {
		var cert model.CertificateExport
		var expiresAt sql.NullTime
		var certPath, keyPath, provider, dnsProviderID sql.NullString
		var certPEM, keyPEM, issuerPEM sql.NullString

		err := rows.Scan(
			&cert.ID, pq.Array(&cert.DomainNames), &expiresAt, &certPath, &keyPath, &provider,
			&dnsProviderID, &cert.Status, &cert.AutoRenew, &certPEM, &keyPEM, &issuerPEM,
		)
		if err != nil {
			return nil, err
		}

		if expiresAt.Valid {
			cert.ExpiresAt = &expiresAt.Time
		}
		cert.CertificatePath = certPath.String
		cert.PrivateKeyPath = keyPath.String
		cert.Provider = provider.String
		cert.DNSProviderID = dnsProviderID.String
		cert.CertificatePEM = certPEM.String
		cert.PrivateKeyPEM = keyPEM.String
		cert.IssuerCertificatePEM = issuerPEM.String
		if cert.DomainNames == nil {
			cert.DomainNames = []string{}
		}

		exports = append(exports, cert)
	}

	return exports, nil
}

func (r *BackupRepository) exportWAFExclusions(ctx context.Context) ([]model.WAFExclusionExport, error) {
	query := `
		SELECT proxy_host_id, rule_id, rule_category, rule_description, reason, disabled_by
		FROM waf_rule_exclusions ORDER BY proxy_host_id, rule_id
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.WAFExclusionExport
	for rows.Next() {
		var we model.WAFExclusionExport
		var category, desc, reason, disabledBy sql.NullString

		err := rows.Scan(&we.ProxyHostID, &we.RuleID, &category, &desc, &reason, &disabledBy)
		if err != nil {
			return nil, err
		}

		we.RuleCategory = category.String
		we.RuleDescription = desc.String
		we.Reason = reason.String
		we.DisabledBy = disabledBy.String

		exports = append(exports, we)
	}

	return exports, nil
}

func (r *BackupRepository) exportSystemSettings(ctx context.Context) (*model.SystemSettingsExport, error) {
	query := `
		SELECT geoip_enabled, geoip_auto_update, geoip_update_interval,
		       acme_enabled, acme_email, acme_staging, acme_auto_renew, acme_renew_days_before,
		       notification_email, notify_cert_expiry, notify_cert_expiry_days,
		       notify_security_events, notify_backup_complete,
		       log_retention_days, stats_retention_days, backup_retention_count,
		       auto_backup_enabled, auto_backup_schedule,
		       access_log_retention_days, waf_log_retention_days, error_log_retention_days,
		       system_log_retention_days, audit_log_retention_days,
		       raw_log_enabled, raw_log_retention_days, raw_log_max_size_mb,
		       raw_log_rotate_count, raw_log_compress_rotated,
		       bot_filter_default_enabled, bot_filter_default_block_bad_bots,
		       bot_filter_default_block_ai_bots, bot_filter_default_allow_search_engines,
		       bot_filter_default_block_suspicious_clients, bot_filter_default_challenge_suspicious,
		       bot_filter_default_custom_blocked_agents,
		       bot_list_bad_bots, bot_list_ai_bots, bot_list_search_engines, bot_list_suspicious_clients,
		       waf_auto_ban_enabled, waf_auto_ban_threshold, waf_auto_ban_window, waf_auto_ban_duration,
		       direct_ip_access_action, system_logs_enabled
		FROM system_settings LIMIT 1
	`

	var ss model.SystemSettingsExport
	var acmeEmail, notificationEmail sql.NullString
	var geoipUpdateInterval, autoBackupSchedule, directIPAccessAction sql.NullString
	var botFilterDefaultCustomBlockedAgents sql.NullString
	var botListBadBots, botListAIBots, botListSearchEngines, botListSuspiciousClients sql.NullString

	err := r.db.QueryRowContext(ctx, query).Scan(
		&ss.GeoIPEnabled, &ss.GeoIPAutoUpdate, &geoipUpdateInterval,
		&ss.ACMEEnabled, &acmeEmail, &ss.ACMEStaging, &ss.ACMEAutoRenew, &ss.ACMERenewDaysBefore,
		&notificationEmail, &ss.NotifyCertExpiry, &ss.NotifyCertExpiryDays,
		&ss.NotifySecurityEvents, &ss.NotifyBackupComplete,
		&ss.LogRetentionDays, &ss.StatsRetentionDays, &ss.BackupRetentionCount,
		&ss.AutoBackupEnabled, &autoBackupSchedule,
		&ss.AccessLogRetentionDays, &ss.WAFLogRetentionDays, &ss.ErrorLogRetentionDays,
		&ss.SystemLogRetentionDays, &ss.AuditLogRetentionDays,
		&ss.RawLogEnabled, &ss.RawLogRetentionDays, &ss.RawLogMaxSizeMB,
		&ss.RawLogRotateCount, &ss.RawLogCompressRotated,
		&ss.BotFilterDefaultEnabled, &ss.BotFilterDefaultBlockBadBots,
		&ss.BotFilterDefaultBlockAIBots, &ss.BotFilterDefaultAllowSearchEngines,
		&ss.BotFilterDefaultBlockSuspiciousClients, &ss.BotFilterDefaultChallengeSuspicious,
		&botFilterDefaultCustomBlockedAgents,
		&botListBadBots, &botListAIBots, &botListSearchEngines, &botListSuspiciousClients,
		&ss.WAFAutoBanEnabled, &ss.WAFAutoBanThreshold, &ss.WAFAutoBanWindow, &ss.WAFAutoBanDuration,
		&directIPAccessAction, &ss.SystemLogsEnabled,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ss.GeoIPUpdateInterval = geoipUpdateInterval.String
	ss.ACMEEmail = acmeEmail.String
	ss.NotificationEmail = notificationEmail.String
	ss.AutoBackupSchedule = autoBackupSchedule.String
	ss.DirectIPAccessAction = directIPAccessAction.String
	ss.BotFilterDefaultCustomBlockedAgents = botFilterDefaultCustomBlockedAgents.String
	ss.BotListBadBots = botListBadBots.String
	ss.BotListAIBots = botListAIBots.String
	ss.BotListSearchEngines = botListSearchEngines.String
	ss.BotListSuspiciousClients = botListSuspiciousClients.String

	return &ss, nil
}

func (r *BackupRepository) exportBannedIPs(ctx context.Context) ([]model.BannedIPExport, error) {
	query := `
		SELECT proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, is_auto_banned
		FROM banned_ips ORDER BY banned_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.BannedIPExport
	for rows.Next() {
		var b model.BannedIPExport
		var proxyHostID, reason sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(&proxyHostID, &b.IPAddress, &reason, &b.FailCount, &b.BannedAt, &expiresAt, &b.IsPermanent, &b.IsAutoBanned)
		if err != nil {
			return nil, err
		}

		b.ProxyHostID = proxyHostID.String
		b.Reason = reason.String
		if expiresAt.Valid {
			b.ExpiresAt = &expiresAt.Time
		}

		exports = append(exports, b)
	}

	return exports, nil
}

func (r *BackupRepository) exportURIBlocks(ctx context.Context) ([]model.URIBlockExport, error) {
	query := `
		SELECT proxy_host_id, enabled, rules, COALESCE(exception_ips, '{}'), COALESCE(allow_private_ips, true)
		FROM uri_blocks ORDER BY proxy_host_id
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.URIBlockExport
	for rows.Next() {
		var ub model.URIBlockExport
		var rulesJSON []byte
		var exceptionIPs pq.StringArray

		err := rows.Scan(&ub.ProxyHostID, &ub.Enabled, &rulesJSON, &exceptionIPs, &ub.AllowPrivateIPs)
		if err != nil {
			return nil, err
		}

		// Parse rules JSON
		if len(rulesJSON) > 0 {
			json.Unmarshal(rulesJSON, &ub.Rules)
		}
		if ub.Rules == nil {
			ub.Rules = []interface{}{}
		}

		ub.ExceptionIPs = []string(exceptionIPs)
		if ub.ExceptionIPs == nil {
			ub.ExceptionIPs = []string{}
		}

		exports = append(exports, ub)
	}

	return exports, nil
}

func (r *BackupRepository) exportGlobalURIBlock(ctx context.Context) (*model.GlobalURIBlockExport, error) {
	query := `
		SELECT enabled, rules, COALESCE(exception_ips, '{}'), COALESCE(allow_private_ips, true)
		FROM global_uri_blocks LIMIT 1
	`

	var ub model.GlobalURIBlockExport
	var rulesJSON []byte
	var exceptionIPs pq.StringArray

	err := r.db.QueryRowContext(ctx, query).Scan(&ub.Enabled, &rulesJSON, &exceptionIPs, &ub.AllowPrivateIPs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Parse rules JSON
	if len(rulesJSON) > 0 {
		json.Unmarshal(rulesJSON, &ub.Rules)
	}
	if ub.Rules == nil {
		ub.Rules = []interface{}{}
	}

	ub.ExceptionIPs = []string(exceptionIPs)
	if ub.ExceptionIPs == nil {
		ub.ExceptionIPs = []string{}
	}

	return &ub, nil
}

func (r *BackupRepository) getProxyHostChallengeConfig(ctx context.Context, proxyHostID string) (*model.ChallengeConfigExport, error) {
	query := `
		SELECT enabled, challenge_type, site_key, secret_key, token_validity,
		       min_score, apply_to, page_title, page_message, theme
		FROM challenge_configs WHERE proxy_host_id = $1
	`
	var cc model.ChallengeConfigExport
	var siteKey, secretKey sql.NullString
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&cc.Enabled, &cc.ChallengeType, &siteKey, &secretKey, &cc.TokenValidity,
		&cc.MinScore, &cc.ApplyTo, &cc.PageTitle, &cc.PageMessage, &cc.Theme,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cc.SiteKey = siteKey.String
	cc.SecretKey = secretKey.String
	return &cc, nil
}

func (r *BackupRepository) exportCloudProviders(ctx context.Context) ([]model.CloudProviderExport, error) {
	query := `
		SELECT id, name, slug, description, region, ip_ranges_url, enabled
		FROM cloud_providers ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.CloudProviderExport
	for rows.Next() {
		var cp model.CloudProviderExport
		var desc, region, ipURL sql.NullString

		err := rows.Scan(&cp.ID, &cp.Name, &cp.Slug, &desc, &region, &ipURL, &cp.Enabled)
		if err != nil {
			return nil, err
		}

		cp.Description = desc.String
		cp.Region = region.String
		cp.IPRangesURL = ipURL.String
		exports = append(exports, cp)
	}

	return exports, nil
}

func (r *BackupRepository) exportExploitBlockRules(ctx context.Context) ([]model.ExploitBlockRuleExport, error) {
	query := `
		SELECT id, name, category, pattern, pattern_type, description, severity, enabled, is_system
		FROM exploit_block_rules ORDER BY category, name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.ExploitBlockRuleExport
	for rows.Next() {
		var rule model.ExploitBlockRuleExport
		var desc sql.NullString

		err := rows.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Pattern, &rule.PatternType,
			&desc, &rule.Severity, &rule.Enabled, &rule.IsBuiltin)
		if err != nil {
			return nil, err
		}

		rule.Description = desc.String
		exports = append(exports, rule)
	}

	return exports, nil
}

func (r *BackupRepository) exportGlobalWAFExclusions(ctx context.Context) ([]model.GlobalWAFExclusionExport, error) {
	query := `
		SELECT rule_id, rule_category, rule_description, reason, disabled_by
		FROM global_waf_rule_exclusions ORDER BY rule_id
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.GlobalWAFExclusionExport
	for rows.Next() {
		var we model.GlobalWAFExclusionExport
		var category, desc, reason, disabledBy sql.NullString

		err := rows.Scan(&we.RuleID, &category, &desc, &reason, &disabledBy)
		if err != nil {
			return nil, err
		}

		we.RuleCategory = category.String
		we.RuleDescription = desc.String
		we.Reason = reason.String
		we.DisabledBy = disabledBy.String
		exports = append(exports, we)
	}

	return exports, nil
}

func (r *BackupRepository) exportGlobalExploitExclusions(ctx context.Context) ([]model.GlobalExploitExclusionExport, error) {
	query := `
		SELECT rule_id, reason, disabled_by
		FROM global_exploit_rule_exclusions ORDER BY rule_id
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.GlobalExploitExclusionExport
	for rows.Next() {
		var ee model.GlobalExploitExclusionExport
		var reason, disabledBy sql.NullString

		err := rows.Scan(&ee.RuleID, &reason, &disabledBy)
		if err != nil {
			return nil, err
		}

		ee.Reason = reason.String
		ee.DisabledBy = disabledBy.String
		exports = append(exports, ee)
	}

	return exports, nil
}

func (r *BackupRepository) exportHostExploitExclusions(ctx context.Context) ([]model.HostExploitExclusionExport, error) {
	query := `
		SELECT proxy_host_id, rule_id, reason, disabled_by
		FROM host_exploit_rule_exclusions ORDER BY proxy_host_id, rule_id
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.HostExploitExclusionExport
	for rows.Next() {
		var he model.HostExploitExclusionExport
		var reason, disabledBy sql.NullString

		err := rows.Scan(&he.ProxyHostID, &he.RuleID, &reason, &disabledBy)
		if err != nil {
			return nil, err
		}

		he.Reason = reason.String
		he.DisabledBy = disabledBy.String
		exports = append(exports, he)
	}

	return exports, nil
}
