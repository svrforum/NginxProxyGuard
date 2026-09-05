package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

// importAuthProvider imports a ForwardAuth provider, returning the new ID (#179)
func (r *BackupRepository) importAuthProvider(ctx context.Context, tx *sql.Tx, ap *model.AuthProviderExport) (string, error) {
	cfgJSON, err := json.Marshal(ap.AuthProvider.Config)
	if err != nil {
		return "", err
	}
	timeout := ap.AuthProvider.TimeoutMs
	if timeout <= 0 {
		timeout = 5000 // older/zero-value backups
	}
	var newID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO auth_providers (name, type, provider_url, config, timeout_ms, enabled,
			container_name, container_network, container_port, container_scheme)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`, ap.AuthProvider.Name, ap.AuthProvider.Type, ap.AuthProvider.ProviderURL, cfgJSON, timeout, ap.AuthProvider.Enabled,
		ap.AuthProvider.ContainerName, ap.AuthProvider.ContainerNetwork, ap.AuthProvider.ContainerPort, ap.AuthProvider.ContainerScheme).Scan(&newID)
	if err != nil {
		return "", err
	}
	return newID, nil
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

func (r *BackupRepository) importWAFExclusion(ctx context.Context, tx *sql.Tx, we *model.WAFExclusionExport) error {
	query := `
		INSERT INTO waf_rule_exclusions (proxy_host_id, rule_id, rule_category, rule_description, reason, disabled_by,
			scope_type, scope_value)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (proxy_host_id, rule_id, scope_type, scope_value) DO NOTHING
	`
	// Validate rather than trust the file. scope_value is rendered verbatim into
	// a ModSecurity directive and the column carries no CHECK, so restore was the
	// one write path that could put an arbitrary string there. ValidateScope also
	// maps an absent scope to host — a backup written before scoped exclusions
	// existed carries none, and host is what those exclusions were. (#286)
	scope := model.WAFRuleExclusion{ScopeType: we.ScopeType, ScopeValue: we.ScopeValue}
	if err := scope.ValidateScope(); err != nil {
		// Two things must not happen here. Failing the restore is one:
		// ImportAllData runs after clearExistingData in a single transaction, so
		// returning an error rolls back proxy hosts, certificates — everything,
		// over one exclusion row. Widening the row to a host-wide exclusion is
		// the other: that would switch a CRS rule off for the entire host on the
		// strength of a value we could not parse. So the row is dropped and
		// logged — the rule keeps protecting, and the operator can re-create the
		// exemption from a message that names it.
		//
		// Note this branch is for corrupt input only: a backup predating scoped
		// exclusions carries no scope and normalises to host, and a legacy uri
		// scope of "/" normalises too. (#286)
		log.Printf("[Backup] Skipped WAF exclusion for rule %d: unusable scope (%v). The rule stays enabled on that host; re-create the exemption if it is still needed.", we.RuleID, err)
		return nil
	}
	_, err := tx.ExecContext(ctx, query, we.ProxyHostID, we.RuleID, we.RuleCategory, we.RuleDescription, we.Reason, we.DisabledBy,
		scope.ScopeType, scope.ScopeValue)
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

// importGlobalGeo restores the singleton global geo default (#198). Delete-then-
// insert so the singleton stays unique.
func (r *BackupRepository) importGlobalGeo(ctx context.Context, tx *sql.Tx, g *model.GlobalGeoRestrictionExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_geo_restrictions")

	mode := g.Mode
	if mode != "whitelist" && mode != "blacklist" {
		mode = "blacklist"
	}
	query := `
		INSERT INTO global_geo_restrictions (enabled, mode, countries, allowed_ips, allow_private_ips, allow_search_bots, challenge_mode)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := tx.ExecContext(ctx, query, g.Enabled, mode, pq.Array(g.Countries), pq.Array(g.AllowedIPs), g.AllowPrivateIPs, g.AllowSearchBots, g.ChallengeMode)
	return err
}

// importGlobalBotFilter restores the singleton global bot-filter default (#198).
// Delete-then-insert so the singleton stays unique.
func (r *BackupRepository) importGlobalBotFilter(ctx context.Context, tx *sql.Tx, g *model.GlobalBotFilterExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_bot_filters")

	query := `
		INSERT INTO global_bot_filters (enabled, block_bad_bots, block_ai_bots, allow_search_engines, block_suspicious_clients, custom_blocked_agents, custom_allowed_agents, challenge_suspicious)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := tx.ExecContext(ctx, query, g.Enabled, g.BlockBadBots, g.BlockAIBots, g.AllowSearchEngines, g.BlockSuspiciousClients, g.CustomBlockedAgents, g.CustomAllowedAgents, g.ChallengeSuspicious)
	return err
}

// importGlobalSecurityHeaders restores the singleton global security-headers
// default (#198). Delete-then-insert so the singleton stays unique.
func (r *BackupRepository) importGlobalSecurityHeaders(ctx context.Context, tx *sql.Tx, g *model.GlobalSecurityHeadersExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_security_headers")

	customHeaders, _ := json.Marshal(g.CustomHeaders)
	if len(g.CustomHeaders) == 0 {
		customHeaders = []byte("{}")
	}
	query := `
		INSERT INTO global_security_headers (enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		                                     x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		                                     content_security_policy, permissions_policy, custom_headers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := tx.ExecContext(ctx, query, g.Enabled, g.HSTSEnabled, g.HSTSMaxAge, g.HSTSIncludeSubdomains, g.HSTSPreload,
		g.XFrameOptions, g.XContentTypeOptions, g.XXSSProtection, g.ReferrerPolicy,
		g.ContentSecurityPolicy, g.PermissionsPolicy, customHeaders)
	return err
}

// importGlobalCloudProviders restores the singleton global cloud-provider
// default (#198 slice 4). Delete-then-insert so the singleton stays unique.
func (r *BackupRepository) importGlobalCloudProviders(ctx context.Context, tx *sql.Tx, g *model.GlobalCloudProvidersExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_cloud_providers")

	providers := g.BlockedProviders
	if providers == nil {
		providers = []string{}
	}
	query := `
		INSERT INTO global_cloud_providers (blocked_providers, challenge_mode, allow_search_bots)
		VALUES ($1, $2, $3)
	`
	_, err := tx.ExecContext(ctx, query, pq.Array(providers), g.ChallengeMode, g.AllowSearchBots)
	return err
}

// importGlobalRateLimit restores the singleton global rate-limit default
// (#198 slice 5). Delete-then-insert so the singleton stays unique.
func (r *BackupRepository) importGlobalRateLimit(ctx context.Context, tx *sql.Tx, g *model.GlobalRateLimitExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_rate_limits")

	whitelist := sql.NullString{String: g.WhitelistIPs, Valid: g.WhitelistIPs != ""}
	query := `
		INSERT INTO global_rate_limits (enabled, requests_per_second, burst_size, zone_size, limit_by, limit_response, whitelist_ips)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := tx.ExecContext(ctx, query, g.Enabled, g.RequestsPerSecond, g.BurstSize, g.ZoneSize, g.LimitBy, g.LimitResponse, whitelist)
	return err
}

// importGlobalFail2ban restores the singleton global jail (#275).
// Delete-then-insert so the singleton stays unique. Values are coerced rather
// than trusted: this row decides whether addresses get banned on every host, so
// a hand-edited backup must not be able to arm it with nonsense.
func (r *BackupRepository) importGlobalFail2ban(ctx context.Context, tx *sql.Tx, g *model.GlobalFail2banExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_fail2ban")

	failCodes := g.FailCodes
	if err := model.ValidateFail2banRequest(&model.CreateFail2banRequest{FailCodes: failCodes}); err != nil || failCodes == "" {
		failCodes = "400,444"
	}
	action := g.Action
	if err := model.ValidateFail2banRequest(&model.CreateFail2banRequest{Action: action}); err != nil || action == "" {
		action = "log"
	}
	maxRetries := g.MaxRetries
	if maxRetries < 1 {
		maxRetries = 5
	}
	findTime := g.FindTime
	if findTime < 1 {
		findTime = 600
	}
	banTime := g.BanTime
	if banTime < 0 {
		banTime = 3600
	}

	// The API refuses to ENABLE this jail while Trusted Proxies are
	// unconfigured, because without them the address it would ban is the CDN
	// edge. A restore must not be a way around that check: system_settings is
	// imported earlier in this same transaction, so the post-restore state is
	// already visible here. A backup that carries an armed jail but no trusted
	// proxies is imported disarmed rather than rejected — losing a setting is
	// recoverable, banning every visitor is not.
	enabled := g.Enabled
	if enabled {
		var trustedCount int
		err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM system_settings
			WHERE COALESCE(NULLIF(trusted_proxy_cidrs, ''), NULL) IS NOT NULL
			   OR COALESCE(trusted_proxy_preset, 'none') <> 'none'
		`).Scan(&trustedCount)
		if err != nil || trustedCount == 0 {
			enabled = false
			log.Printf("[Backup] global fail2ban restored DISABLED: the backup had it enabled but this instance has no trusted proxies configured, and the jail bans on every host")
		}
	}

	query := `
		INSERT INTO global_fail2ban (enabled, max_retries, find_time, ban_time, fail_codes, action)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query, enabled, maxRetries, findTime, banTime, failCodes, action)
	return err
}

// importGlobalWAF restores the singleton global WAF default (#198 slice 6).
// Delete-then-insert so the singleton stays unique. Clamps paranoia/threshold to
// the column CHECK ranges so a malformed or zero-value backup cannot fail import.
func (r *BackupRepository) importGlobalWAF(ctx context.Context, tx *sql.Tx, g *model.GlobalWAFExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM global_waf")

	mode := g.Mode
	if mode == "" {
		mode = "detection"
	}
	paranoia := g.ParanoiaLevel
	if paranoia < 1 || paranoia > 4 {
		paranoia = 1
	}
	threshold := g.AnomalyThreshold
	if threshold < 1 || threshold > 100 {
		threshold = 5
	}
	query := `
		INSERT INTO global_waf (enabled, mode, paranoia_level, anomaly_threshold)
		VALUES ($1, $2, $3, $4)
	`
	_, err := tx.ExecContext(ctx, query, g.Enabled, mode, paranoia, threshold)
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
		// Just update enabled status for system rules and keep the same ID.
		// Built-in IDs are hardcoded and seeded by the migrations, so a backup
		// taken on a NEWER version can name a built-in this install does not
		// have. Returning its ID anyway put a dangling entry in the caller's
		// rule map and the following exclusion INSERT then failed the FK,
		// killing the whole restore — so report "not found" (empty ID) when the
		// UPDATE matched nothing, which makes the caller skip its exclusions.
		query := `UPDATE exploit_block_rules SET enabled = $1, updated_at = NOW() WHERE id = $2 AND is_system = true`
		res, err := tx.ExecContext(ctx, query, rule.Enabled, rule.ID)
		if err != nil {
			return "", err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return "", err
		}
		if affected == 0 {
			log.Printf("[Backup Import] built-in exploit rule %q (%s) does not exist on this version — skipping it and any exclusions referencing it", rule.Name, rule.ID)
			return "", nil
		}
		// For system rules, the ID remains the same
		return rule.ID, nil
	}

	// Plain INSERT, no upsert: ImportAllData runs clearExistingData in this same
	// transaction, and that does `DELETE FROM exploit_block_rules WHERE
	// is_system = false`, so no user rule can survive to conflict with. An
	// ON CONFLICT (name, category) clause used to sit here and there is no
	// unique index behind those columns, so Postgres rejected it at plan time
	// (42P10) — every restore carrying a user-created rule failed (#259).
	query := `
		INSERT INTO exploit_block_rules (name, category, pattern, pattern_type, description, severity, enabled, is_system)
		VALUES ($1, $2, $3, $4, $5, $6, $7, false)
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

// importGlobalExploitExclusion imports a single global exploit rule exclusion.
// Pre-v2.13.2 backups lack the uri_pattern field; ee.URIPattern will be nil,
// which inserts NULL — preserving the legacy full-exclusion semantic.
func (r *BackupRepository) importGlobalExploitExclusion(ctx context.Context, tx *sql.Tx, ee *model.GlobalExploitExclusionExport) error {
	query := `
		INSERT INTO global_exploit_rule_exclusions (rule_id, uri_pattern, reason, disabled_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (rule_id, COALESCE(uri_pattern, '')) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, ee.RuleID, ee.URIPattern, ee.Reason, ee.DisabledBy)
	return err
}

// importHostExploitExclusion imports a single host-level exploit rule exclusion.
// Pre-v2.13.2 backups lack the uri_pattern field; he.URIPattern will be nil,
// which inserts NULL — preserving the legacy full-exclusion semantic.
func (r *BackupRepository) importHostExploitExclusion(ctx context.Context, tx *sql.Tx, he *model.HostExploitExclusionExport) error {
	query := `
		INSERT INTO host_exploit_rule_exclusions (proxy_host_id, rule_id, uri_pattern, reason, disabled_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (proxy_host_id, rule_id, COALESCE(uri_pattern, '')) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, he.ProxyHostID, he.RuleID, he.URIPattern, he.Reason, he.DisabledBy)
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
