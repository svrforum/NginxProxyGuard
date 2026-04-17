package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

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
		                         proxy_buffering, proxy_request_buffering, client_max_body_size, proxy_max_temp_file_size, meta)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
		        $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)
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
		ph.ProxyHost.ProxyBuffering, ph.ProxyHost.ProxyRequestBuffering, ph.ProxyHost.ClientMaxBodySize, ph.ProxyHost.ProxyMaxTempFileSize, meta,
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
		                         block_suspicious_clients, custom_blocked_agents, custom_allowed_agents, challenge_suspicious)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, bf.Enabled, bf.BlockBadBots, bf.BlockAIBots,
		bf.AllowSearchEngines, bf.BlockSuspiciousClients, bf.CustomBlockedAgents, bf.CustomAllowedAgents, bf.ChallengeSuspicious)
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

	// Older backups (pre-2.9.0) have no scheme field — default to "http" to preserve behavior.
	scheme := model.NormalizeUpstreamScheme(u.Scheme)

	query := `
		INSERT INTO upstreams (proxy_host_id, name, scheme, servers, load_balance, health_check_enabled,
		                       health_check_interval, health_check_timeout, health_check_path,
		                       health_check_expected_status, keepalive)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			name = EXCLUDED.name,
			scheme = EXCLUDED.scheme,
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
	_, err := tx.ExecContext(ctx, query, proxyHostID, u.Name, scheme, servers, u.LoadBalance,
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
