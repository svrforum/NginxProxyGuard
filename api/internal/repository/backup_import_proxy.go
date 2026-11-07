package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

func (r *BackupRepository) importDNSProvider(ctx context.Context, tx *sql.Tx, dp *model.DNSProviderExport) (string, error) {
	credentials, _ := json.Marshal(dp.Credentials)

	// Note: no in-tx INSERT retry here — any statement error aborts the whole
	// import transaction in Postgres, so a fallback statement could only fail
	// with "current transaction is aborted". Duplicate defaults are demoted to
	// is_default=false by the caller (ImportAllData) before insert; the ON
	// CONFLICT clause remains as defense in case a default row pre-exists.
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
	return newID, err
}

// importDDNSRecord imports a single DDNS record (#154). dns_provider_id must
// already be remapped to the freshly-imported provider ID by the caller.
func (r *BackupRepository) importDDNSRecord(ctx context.Context, tx *sql.Tx, rec *model.DDNSRecordExport) error {
	// Backwards-compat defaults for older backups missing these columns.
	if rec.RecordType == "" {
		rec.RecordType = "A"
	}
	if rec.TTL < 1 {
		rec.TTL = 1
	}

	var lastSyncedAt interface{}
	if rec.LastSyncedAt != nil {
		lastSyncedAt = *rec.LastSyncedAt
	}

	// proxy_host_id is remapped (or cleared) by the caller (#157). nil = manual record.
	var proxyHostID interface{}
	if rec.ProxyHostID != nil && *rec.ProxyHostID != "" {
		proxyHostID = *rec.ProxyHostID
	}

	query := `
		INSERT INTO ddns_records (hostname, dns_provider_id, record_type, proxied, ttl, enabled,
		                          last_ip, last_synced_at, last_status, last_error, proxy_host_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (hostname, dns_provider_id) DO NOTHING
	`

	_, err := tx.ExecContext(ctx, query,
		rec.Hostname, rec.DNSProviderID, rec.RecordType, rec.Proxied, rec.TTL, rec.Enabled,
		rec.LastIP, lastSyncedAt, rec.LastStatus, rec.LastError, proxyHostID,
	)
	return err
}

func (r *BackupRepository) importCertificate(ctx context.Context, tx *sql.Tx, cert *model.CertificateExport) (string, error) {
	query := `
		INSERT INTO certificates (domain_names, expires_at, certificate_path, private_key_path, provider,
		                          dns_provider_id, status, auto_renew, certificate_pem, private_key_pem,
		                          issuer_certificate_pem, key_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`

	var dnsProviderID interface{}
	if cert.DNSProviderID != "" {
		dnsProviderID = cert.DNSProviderID
	}
	// A backup from before 2.67.0 has no key type: those were RSA 2048, and so
	// is a value this version does not know.
	keyType, err := model.NormalizeCertKeyType(cert.KeyType)
	if err != nil {
		keyType = model.CertKeyTypeRSA2048
	}

	var newID string
	err = tx.QueryRowContext(ctx, query,
		pq.Array(cert.DomainNames), cert.ExpiresAt, cert.CertificatePath, cert.PrivateKeyPath, cert.Provider,
		dnsProviderID, cert.Status, cert.AutoRenew, cert.CertificatePEM, cert.PrivateKeyPEM,
		cert.IssuerCertificatePEM, keyType,
	).Scan(&newID)
	return newID, err
}

// backupTagsOrEmpty normalises tags from a backup. A backup taken before tags
// existed has no key and decodes to nil; that must restore as an empty list,
// not fail. Tags that do not pass the current rule are dropped for that host
// with a log line — a restore never aborts over a label.
func backupTagsOrEmpty(raw []string) []string {
	tags, err := model.NormalizeTags(raw)
	if err != nil {
		log.Printf("[Backup] ignoring unreadable tags %v: %v", raw, err)
		return []string{}
	}
	return tags
}

func (r *BackupRepository) importProxyHost(ctx context.Context, tx *sql.Tx, ph *model.ProxyHostExport) (string, []string, error) {
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
	proxyType := model.NormalizeProxyType(ph.ProxyHost.ProxyType)
	streamProtocol := model.NormalizeStreamProtocol(ph.ProxyHost.StreamProtocol)
	forwardScheme := ph.ProxyHost.ForwardScheme
	sslEnabled := ph.ProxyHost.SSLEnabled
	sslForceHTTPS := ph.ProxyHost.SSLForceHTTPS
	sslHTTP2 := ph.ProxyHost.SSLHTTP2
	sslHTTP3 := ph.ProxyHost.SSLHTTP3
	wafEnabled := ph.ProxyHost.WAFEnabled
	blockExploits := ph.ProxyHost.BlockExploits
	allowWebsocketUpgrade := ph.ProxyHost.AllowWebsocketUpgrade
	if proxyType == model.ProxyTypeStream {
		forwardScheme = streamProtocol
		sslEnabled = false
		sslForceHTTPS = false
		sslHTTP2 = false
		sslHTTP3 = false
		wafEnabled = false
		blockExploits = false
		allowWebsocketUpgrade = false
	}

	query := `
		INSERT INTO proxy_hosts (proxy_type, domain_names, forward_scheme, forward_host, forward_port,
		                         stream_listen_host, stream_listen_port, stream_protocol, stream_ssl_preread,
		                         stream_accept_proxy_protocol, stream_send_proxy_protocol,
		                         stream_proxy_connect_timeout, stream_proxy_timeout,
		                         ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
		                         allow_websocket_upgrade, cache_enabled, cache_static_only, cache_ttl,
		                         block_exploits, block_exploits_exceptions,
		                         custom_locations, advanced_config, waf_enabled, waf_mode,
		                         waf_paranoia_level, waf_anomaly_threshold,
		                         access_list_id, enabled, is_favorite,
		                         rate_limit_enabled, fail2ban_enabled, bot_filter_enabled, security_headers_enabled,
		                         proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
		                         proxy_buffering, proxy_request_buffering, client_max_body_size, proxy_max_temp_file_size, meta,
		                         forward_container_name, forward_container_network,
		                         ddns_enabled, ddns_provider_id, ddns_proxied,
		                         auth_provider_id, auth_bypass_paths, waf_use_global, tags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
		        $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36,
		        $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54)
		RETURNING id
	`

	var certID, accessListID, ddnsProviderID, authProviderID interface{}
	if ph.ProxyHost.CertificateID != "" {
		certID = ph.ProxyHost.CertificateID
	}
	if ph.ProxyHost.AccessListID != "" {
		accessListID = ph.ProxyHost.AccessListID
	}
	if ph.ProxyHost.DDNSProviderID != "" {
		ddnsProviderID = ph.ProxyHost.DDNSProviderID
	}
	if ph.ProxyHost.AuthProviderID != "" {
		authProviderID = ph.ProxyHost.AuthProviderID
	}

	var newID string
	err := tx.QueryRowContext(ctx, query,
		proxyType, pq.Array(ph.ProxyHost.DomainNames), forwardScheme, ph.ProxyHost.ForwardHost, ph.ProxyHost.ForwardPort,
		ph.ProxyHost.StreamListenHost, ph.ProxyHost.StreamListenPort, streamProtocol, ph.ProxyHost.StreamSSLPreread,
		ph.ProxyHost.StreamAcceptProxyProtocol, ph.ProxyHost.StreamSendProxyProtocol,
		ph.ProxyHost.StreamProxyConnectTimeout, ph.ProxyHost.StreamProxyTimeout,
		sslEnabled, sslForceHTTPS, sslHTTP2, sslHTTP3, certID,
		allowWebsocketUpgrade, ph.ProxyHost.CacheEnabled, cacheStaticOnly, cacheTTL,
		blockExploits, ph.ProxyHost.BlockExploitsExceptions,
		customLocations, ph.ProxyHost.AdvancedConfig, wafEnabled, ph.ProxyHost.WAFMode,
		wafParanoiaLevel, wafAnomalyThreshold,
		accessListID, ph.ProxyHost.Enabled, ph.ProxyHost.IsFavorite,
		ph.ProxyHost.RateLimitEnabled, ph.ProxyHost.Fail2banEnabled, ph.ProxyHost.BotFilterEnabled, ph.ProxyHost.SecurityHeadersEnabled,
		ph.ProxyHost.ProxyConnectTimeout, ph.ProxyHost.ProxySendTimeout, ph.ProxyHost.ProxyReadTimeout,
		ph.ProxyHost.ProxyBuffering, ph.ProxyHost.ProxyRequestBuffering, ph.ProxyHost.ClientMaxBodySize, ph.ProxyHost.ProxyMaxTempFileSize, meta,
		ph.ProxyHost.ForwardContainerName, ph.ProxyHost.ForwardContainerNetwork,
		ph.ProxyHost.DDNSEnabled, ddnsProviderID, ph.ProxyHost.DDNSProxied,
		authProviderID, pq.Array(ph.ProxyHost.AuthBypassPaths),
		ph.ProxyHost.WAFUseGlobal,
		pq.Array(backupTagsOrEmpty(ph.ProxyHost.Tags)),
	).Scan(&newID)
	if err != nil {
		return "", nil, err
	}

	// Import related configurations. names collects the domain names of
	// the host's exception lists (#320).
	var names []string
	if ph.RateLimit != nil {
		rlNames, err := r.importRateLimit(ctx, tx, newID, ph.RateLimit)
		if err != nil {
			return "", nil, fmt.Errorf("failed to import rate limit: %w", err)
		}
		names = append(names, rlNames...)
	}

	if ph.Fail2ban != nil {
		if err := r.importFail2ban(ctx, tx, newID, ph.Fail2ban); err != nil {
			return "", nil, fmt.Errorf("failed to import fail2ban: %w", err)
		}
	}

	if ph.BotFilter != nil {
		if err := r.importBotFilter(ctx, tx, newID, ph.BotFilter); err != nil {
			return "", nil, fmt.Errorf("failed to import bot filter: %w", err)
		}
	}

	if ph.SecurityHeaders != nil {
		if err := r.importSecurityHeaders(ctx, tx, newID, ph.SecurityHeaders); err != nil {
			return "", nil, fmt.Errorf("failed to import security headers: %w", err)
		}
	}

	if ph.GeoRestriction != nil {
		geoNames, err := r.importGeoRestriction(ctx, tx, newID, ph.GeoRestriction)
		if err != nil {
			return "", nil, fmt.Errorf("failed to import geo restriction: %w", err)
		}
		names = append(names, geoNames...)
	}

	if ph.Upstream != nil {
		if err := r.importUpstream(ctx, tx, newID, ph.Upstream); err != nil {
			return "", nil, fmt.Errorf("failed to import upstream: %w", err)
		}
	}

	if ph.ChallengeConfig != nil {
		if err := r.importChallengeConfig(ctx, tx, newID, ph.ChallengeConfig); err != nil {
			return "", nil, fmt.Errorf("failed to import challenge config: %w", err)
		}
	}

	return newID, names, nil
}

// importRateLimit restores a host's rate limit and returns the domain names
// of its exceptions (#320).
func (r *BackupRepository) importRateLimit(ctx context.Context, tx *sql.Tx, proxyHostID string, rl *model.RateLimitExport) ([]string, error) {
	query := `
		INSERT INTO rate_limits (proxy_host_id, enabled, requests_per_second, burst_size, zone_size,
		                         limit_by, limit_response, whitelist_ips, disable_global, whitelist_hostnames)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	names := restorableDNSNames("the rate limit exceptions of proxy host "+proxyHostID, rl.WhitelistHostnames)
	_, err := tx.ExecContext(ctx, query, proxyHostID, rl.Enabled, rl.RequestsPerSecond, rl.BurstSize,
		rl.ZoneSize, rl.LimitBy, rl.LimitResponse, rl.WhitelistIPs, rl.DisableGlobal, pq.Array(names))
	if err != nil {
		return nil, err
	}
	return names, nil
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
		                         block_suspicious_clients, custom_blocked_agents, custom_allowed_agents, challenge_suspicious, disable_global)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, bf.Enabled, bf.BlockBadBots, bf.BlockAIBots,
		bf.AllowSearchEngines, bf.BlockSuspiciousClients, bf.CustomBlockedAgents, bf.CustomAllowedAgents, bf.ChallengeSuspicious, bf.DisableGlobal)
	return err
}

func (r *BackupRepository) importSecurityHeaders(ctx context.Context, tx *sql.Tx, proxyHostID string, sh *model.SecurityHeadersExport) error {
	customHeaders, _ := json.Marshal(sh.CustomHeaders)

	// Each value goes into an add_header directive of the host's config.
	if reset := model.ResetUnusableSecurityHeaderValues(&sh.XFrameOptions, &sh.ReferrerPolicy, &sh.ContentSecurityPolicy, &sh.PermissionsPolicy); len(reset) > 0 {
		log.Printf("[Backup] Security headers of proxy host %s: %s could not be used as saved and were restored with their defaults", proxyHostID, strings.Join(reset, ", "))
	}

	query := `
		INSERT INTO security_headers (proxy_host_id, enabled, hsts_enabled, hsts_max_age,
		                              hsts_include_subdomains, hsts_preload, x_frame_options,
		                              x_content_type_options, x_xss_protection, referrer_policy,
		                              content_security_policy, permissions_policy, custom_headers, disable_global)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := tx.ExecContext(ctx, query, proxyHostID, sh.Enabled, sh.HSTSEnabled, sh.HSTSMaxAge,
		sh.HSTSIncludeSubdomains, sh.HSTSPreload, sh.XFrameOptions, sh.XContentTypeOptions,
		sh.XXSSProtection, sh.ReferrerPolicy, sh.ContentSecurityPolicy, sh.PermissionsPolicy, customHeaders, sh.DisableGlobal)
	return err
}

// importGeoRestriction restores a host's geo restriction and returns the
// domain names of its priority allow list (#320).
func (r *BackupRepository) importGeoRestriction(ctx context.Context, tx *sql.Tx, proxyHostID string, gr *model.GeoRestrictionExport) ([]string, error) {
	query := `
		INSERT INTO geo_restrictions (proxy_host_id, mode, countries, enabled, challenge_mode, allow_private_ips, allow_search_bots,
		                              allowed_ips, blocked_cloud_providers, challenge_cloud_providers, allow_search_bots_cloud_providers, disable_global, cloud_disable_global,
		                              allowed_hostnames)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
			disable_global = EXCLUDED.disable_global,
			cloud_disable_global = EXCLUDED.cloud_disable_global,
			allowed_hostnames = EXCLUDED.allowed_hostnames,
			updated_at = NOW()
	`
	// Countries and priority allow entries are written into the host's
	// config; keep the ones the API would accept.
	countries, allowedIPs, dropped := model.UsableGeoLists(gr.Countries, gr.AllowedIPs)
	if len(dropped) > 0 {
		log.Printf("[Backup] Geo restriction of proxy host %s: skipped %d entr(ies) that are not a country code or an IP address/CIDR range (first: %.60q)", proxyHostID, len(dropped), dropped[0])
	}
	// Ensure arrays are not nil for postgres
	if allowedIPs == nil {
		allowedIPs = []string{}
	}
	blockedCloudProviders := gr.BlockedCloudProviders
	if blockedCloudProviders == nil {
		blockedCloudProviders = []string{}
	}
	names := restorableDNSNames("the priority allow list of proxy host "+proxyHostID, gr.AllowedHostnames)
	_, err := tx.ExecContext(ctx, query, proxyHostID, gr.Mode, pq.Array(countries), gr.Enabled,
		gr.ChallengeMode, gr.AllowPrivateIPs, gr.AllowSearchBots,
		pq.Array(allowedIPs), pq.Array(blockedCloudProviders),
		gr.ChallengeCloudProviders, gr.AllowSearchBotsCloudProviders, gr.DisableGlobal, gr.CloudDisableGlobal,
		pq.Array(names))
	if err != nil {
		return nil, err
	}
	return names, nil
}

func (r *BackupRepository) importUpstream(ctx context.Context, tx *sql.Tx, proxyHostID string, u *model.UpstreamExport) error {
	servers, _ := json.Marshal(u.Servers)

	// Older backups (pre-2.9.0) have no scheme field — default to "http" to preserve behavior.
	scheme := model.NormalizeUpstreamScheme(u.Scheme)

	// A backup from before 2.67.0 can hold two upstreams with one name (a
	// clone copied it, #362), and nginx refuses that for every host. nginx
	// compares upstream names case-insensitively. As in the upgrade repair, an
	// enabled host keeps the name over a disabled one, and otherwise the one
	// restored first keeps it; the other takes the name derived from its
	// host's whole id.
	derived := func(hostID string) string { return "upstream_" + strings.ReplaceAll(hostID, "-", "") }
	name := u.Name
	if name == "" {
		name = derived(proxyHostID)
	} else {
		var holder string
		var holderEnabled, enabled bool
		err := tx.QueryRowContext(ctx, `
			SELECT u.proxy_host_id, h.enabled, me.enabled
			  FROM upstreams u
			  JOIN proxy_hosts h ON h.id = u.proxy_host_id
			  JOIN proxy_hosts me ON me.id = $2::uuid
			 WHERE lower(u.name) = lower($1) AND u.proxy_host_id <> $2::uuid
			 LIMIT 1`,
			name, proxyHostID,
		).Scan(&holder, &holderEnabled, &enabled)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return fmt.Errorf("check upstream name: %w", err)
		case enabled && !holderEnabled:
			if _, err := tx.ExecContext(ctx,
				`UPDATE upstreams SET name = $1, updated_at = NOW() WHERE proxy_host_id = $2::uuid`,
				derived(holder), holder,
			); err != nil {
				return fmt.Errorf("rename the disabled host's upstream: %w", err)
			}
		default:
			name = derived(proxyHostID)
		}
	}

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
	_, err := tx.ExecContext(ctx, query, proxyHostID, name, scheme, servers, u.LoadBalance,
		u.HealthCheckEnabled, u.HealthCheckInterval, u.HealthCheckTimeout, u.HealthCheckPath,
		u.HealthCheckExpectedStatus, u.Keepalive)
	return err
}

func (r *BackupRepository) importRedirectHost(ctx context.Context, tx *sql.Tx, rh *model.RedirectHostExport) error {
	if err := model.ValidateRedirectHost(&model.RedirectHost{
		DomainNames:       rh.RedirectHost.DomainNames,
		ForwardScheme:     rh.RedirectHost.ForwardScheme,
		ForwardDomainName: rh.RedirectHost.ForwardDomainName,
		ForwardPath:       rh.RedirectHost.ForwardPath,
		RedirectCode:      rh.RedirectHost.RedirectCode,
	}); err != nil {
		// Old releases allowed unrestricted values here. Do not make an otherwise
		// usable full backup impossible to restore; omit only the unsafe redirect
		// row and make the loss highly visible to the operator.
		log.Printf("[ERROR] [Backup] SKIPPING unsafe redirect host during restore (domains=%q): %v",
			rh.RedirectHost.DomainNames, err)
		return nil
	}

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

// importHostLogRules restores a host's log rules (#347) as the API saves them
// (restorableHostLogRules). Rules that skip nothing are not written.
func (r *BackupRepository) importHostLogRules(ctx context.Context, tx *sql.Tx, e *model.HostLogRulesExport) error {
	rules := restorableHostLogRules(e)
	if rules.IsEmpty() {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO proxy_host_log_rules (proxy_host_id, skip_all, skip_statuses, skip_methods, skip_paths)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			skip_all = EXCLUDED.skip_all,
			skip_statuses = EXCLUDED.skip_statuses,
			skip_methods = EXCLUDED.skip_methods,
			skip_paths = EXCLUDED.skip_paths,
			updated_at = NOW()`,
		e.ProxyHostID, rules.SkipAll, pq.Array(rules.SkipStatuses), pq.Array(rules.SkipMethods), pq.Array(rules.SkipPaths))
	return err
}

// restorableHostLogRules returns a backup's log rules with each entry as the
// API saves it (model.NormalizeHostLogRules), each once and at most
// model.MaxHostLogRuleEntries of each kind. An entry the API refuses, which
// only a hand-edited file holds, is left out and logged.
func restorableHostLogRules(e *model.HostLogRulesExport) model.HostLogRules {
	keep := func(field string, entries []string, normalize func(string) (string, bool)) []string {
		out := []string{}
		for _, entry := range entries {
			value, ok := normalize(strings.TrimSpace(entry))
			if !ok {
				log.Printf("[Backup] Skipped %s entry %.80q of the log rules of proxy host %s: it is not valid. Add it again if it is still needed.", field, entry, e.ProxyHostID)
				continue
			}
			if !slices.Contains(out, value) {
				out = append(out, value)
			}
		}
		if len(out) > model.MaxHostLogRuleEntries {
			log.Printf("[Backup] Kept the first %d %s entries of the log rules of proxy host %s, the most a list takes.", model.MaxHostLogRuleEntries, field, e.ProxyHostID)
			out = out[:model.MaxHostLogRuleEntries]
		}
		return out
	}
	return model.HostLogRules{
		ProxyHostID:  e.ProxyHostID,
		SkipAll:      e.SkipAll,
		SkipStatuses: keep("skip_statuses", e.SkipStatuses, model.NormalizeLogRuleStatus),
		SkipMethods:  keep("skip_methods", e.SkipMethods, model.NormalizeLogRuleMethod),
		SkipPaths:    keep("skip_paths", e.SkipPaths, model.NormalizeLogRulePath),
	}
}
