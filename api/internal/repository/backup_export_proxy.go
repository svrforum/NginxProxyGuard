package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

func (r *BackupRepository) exportProxyHosts(ctx context.Context) ([]model.ProxyHostExport, error) {
	query := `
		SELECT id, domain_names, forward_scheme, forward_host, forward_port,
		       ssl_enabled, ssl_force_https, ssl_http2, COALESCE(ssl_http3, false) as ssl_http3, certificate_id,
		       allow_websocket_upgrade, cache_enabled,
		       COALESCE(cache_static_only, true) as cache_static_only,
		       COALESCE(cache_ttl, '7d') as cache_ttl,
		       block_exploits, COALESCE(block_exploits_exceptions, '') as block_exploits_exceptions,
		       custom_locations, advanced_config, waf_enabled, waf_mode,
		       COALESCE(waf_paranoia_level, 1) as waf_paranoia_level,
		       COALESCE(waf_anomaly_threshold, 5) as waf_anomaly_threshold,
		       access_list_id, enabled, COALESCE(is_favorite, false) as is_favorite,
		       COALESCE(rate_limit_enabled, false) as rate_limit_enabled,
		       COALESCE(fail2ban_enabled, false) as fail2ban_enabled,
		       COALESCE(bot_filter_enabled, false) as bot_filter_enabled,
		       COALESCE(security_headers_enabled, false) as security_headers_enabled,
		       COALESCE(proxy_connect_timeout, 0) as proxy_connect_timeout,
		       COALESCE(proxy_send_timeout, 0) as proxy_send_timeout,
		       COALESCE(proxy_read_timeout, 0) as proxy_read_timeout,
		       COALESCE(proxy_buffering, '') as proxy_buffering,
		       COALESCE(proxy_request_buffering, '') as proxy_request_buffering,
		       COALESCE(client_max_body_size, '') as client_max_body_size,
		       COALESCE(proxy_max_temp_file_size, '') as proxy_max_temp_file_size,
		       meta
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
			&ph.SSLEnabled, &ph.SSLForceHTTPS, &ph.SSLHTTP2, &ph.SSLHTTP3, &certID,
			&ph.AllowWebsocketUpgrade, &ph.CacheEnabled, &ph.CacheStaticOnly, &ph.CacheTTL,
			&ph.BlockExploits, &ph.BlockExploitsExceptions,
			&customLocations, &advancedConfig, &ph.WAFEnabled, &ph.WAFMode,
			&ph.WAFParanoiaLevel, &ph.WAFAnomalyThreshold,
			&accessListID, &ph.Enabled, &ph.IsFavorite,
			&ph.RateLimitEnabled, &ph.Fail2banEnabled, &ph.BotFilterEnabled, &ph.SecurityHeadersEnabled,
			&ph.ProxyConnectTimeout, &ph.ProxySendTimeout, &ph.ProxyReadTimeout,
			&ph.ProxyBuffering, &ph.ProxyRequestBuffering, &ph.ClientMaxBodySize, &ph.ProxyMaxTempFileSize,
			&meta,
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
		       COALESCE(block_suspicious_clients, FALSE) as block_suspicious_clients,
		       custom_blocked_agents, custom_allowed_agents, challenge_suspicious
		FROM bot_filters WHERE proxy_host_id = $1
	`
	var bf model.BotFilterExport
	var blockedAgents, allowedAgents sql.NullString
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&bf.Enabled, &bf.BlockBadBots, &bf.BlockAIBots, &bf.AllowSearchEngines,
		&bf.BlockSuspiciousClients, &blockedAgents, &allowedAgents, &bf.ChallengeSuspicious,
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
		SELECT mode, countries, enabled, challenge_mode, allow_private_ips, allow_search_bots,
		       COALESCE(allowed_ips, '{}'), COALESCE(blocked_cloud_providers, '{}'),
		       COALESCE(challenge_cloud_providers, false), COALESCE(allow_search_bots_cloud_providers, false)
		FROM geo_restrictions WHERE proxy_host_id = $1
	`
	var gr model.GeoRestrictionExport
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&gr.Mode, pq.Array(&gr.Countries), &gr.Enabled,
		&gr.ChallengeMode, &gr.AllowPrivateIPs, &gr.AllowSearchBots,
		pq.Array(&gr.AllowedIPs), pq.Array(&gr.BlockedCloudProviders),
		&gr.ChallengeCloudProviders, &gr.AllowSearchBotsCloudProviders,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if gr.Countries == nil {
		gr.Countries = []string{}
	}
	if gr.AllowedIPs == nil {
		gr.AllowedIPs = []string{}
	}
	if gr.BlockedCloudProviders == nil {
		gr.BlockedCloudProviders = []string{}
	}
	return &gr, nil
}

func (r *BackupRepository) getProxyHostUpstream(ctx context.Context, proxyHostID string) (*model.UpstreamExport, error) {
	query := `
		SELECT name, scheme, servers, load_balance, health_check_enabled, health_check_interval,
		       health_check_timeout, health_check_path, health_check_expected_status, keepalive
		FROM upstreams WHERE proxy_host_id = $1
	`
	var u model.UpstreamExport
	var servers []byte
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&u.Name, &u.Scheme, &servers, &u.LoadBalance, &u.HealthCheckEnabled, &u.HealthCheckInterval,
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
