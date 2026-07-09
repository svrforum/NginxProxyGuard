package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

// exportAuthProviders exports ForwardAuth providers (#179)
func (r *BackupRepository) exportAuthProviders(ctx context.Context) ([]model.AuthProviderExport, error) {
	query := `SELECT id, name, type, provider_url, config, timeout_ms, enabled,
		container_name, container_network, container_port, container_scheme
		FROM auth_providers ORDER BY created_at`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.AuthProviderExport
	for rows.Next() {
		var ap model.AuthProviderData
		var cfgRaw []byte
		var cName, cNetwork, cScheme sql.NullString
		var cPort sql.NullInt64
		if err := rows.Scan(&ap.ID, &ap.Name, &ap.Type, &ap.ProviderURL, &cfgRaw, &ap.TimeoutMs, &ap.Enabled,
			&cName, &cNetwork, &cPort, &cScheme); err != nil {
			return nil, err
		}
		if len(cfgRaw) > 0 {
			_ = json.Unmarshal(cfgRaw, &ap.Config)
		}
		if cName.Valid && cName.String != "" {
			v := cName.String
			ap.ContainerName = &v
		}
		if cNetwork.Valid && cNetwork.String != "" {
			v := cNetwork.String
			ap.ContainerNetwork = &v
		}
		if cScheme.Valid && cScheme.String != "" {
			v := cScheme.String
			ap.ContainerScheme = &v
		}
		if cPort.Valid {
			v := int(cPort.Int64)
			ap.ContainerPort = &v
		}
		exports = append(exports, model.AuthProviderExport{AuthProvider: ap})
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

// exportGlobalGeo exports the singleton global geo default (#198). Returns nil
// when no row exists (older installs / never configured).
func (r *BackupRepository) exportGlobalGeo(ctx context.Context) (*model.GlobalGeoRestrictionExport, error) {
	query := `
		SELECT enabled, mode, countries, COALESCE(allowed_ips, '{}'), allow_private_ips, allow_search_bots, challenge_mode
		FROM global_geo_restrictions LIMIT 1
	`
	var g model.GlobalGeoRestrictionExport
	err := r.db.QueryRowContext(ctx, query).Scan(
		&g.Enabled, &g.Mode, pq.Array(&g.Countries), pq.Array(&g.AllowedIPs), &g.AllowPrivateIPs, &g.AllowSearchBots, &g.ChallengeMode,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if g.Countries == nil {
		g.Countries = []string{}
	}
	if g.AllowedIPs == nil {
		g.AllowedIPs = []string{}
	}
	return &g, nil
}

// exportGlobalBotFilter exports the singleton global bot-filter default (#198).
// Returns nil when no row exists (older installs / never configured).
func (r *BackupRepository) exportGlobalBotFilter(ctx context.Context) (*model.GlobalBotFilterExport, error) {
	query := `
		SELECT enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		       COALESCE(block_suspicious_clients, FALSE), custom_blocked_agents, custom_allowed_agents, challenge_suspicious
		FROM global_bot_filters LIMIT 1
	`
	var g model.GlobalBotFilterExport
	var blockedAgents, allowedAgents sql.NullString
	err := r.db.QueryRowContext(ctx, query).Scan(
		&g.Enabled, &g.BlockBadBots, &g.BlockAIBots, &g.AllowSearchEngines,
		&g.BlockSuspiciousClients, &blockedAgents, &allowedAgents, &g.ChallengeSuspicious,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g.CustomBlockedAgents = blockedAgents.String
	g.CustomAllowedAgents = allowedAgents.String
	return &g, nil
}

// exportGlobalSecurityHeaders exports the singleton global security-headers
// default (#198). Returns nil when no row exists.
func (r *BackupRepository) exportGlobalSecurityHeaders(ctx context.Context) (*model.GlobalSecurityHeadersExport, error) {
	query := `
		SELECT enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		       x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		       content_security_policy, permissions_policy, custom_headers
		FROM global_security_headers LIMIT 1
	`
	var g model.GlobalSecurityHeadersExport
	var csp, pp sql.NullString
	var customHeaders []byte
	err := r.db.QueryRowContext(ctx, query).Scan(
		&g.Enabled, &g.HSTSEnabled, &g.HSTSMaxAge, &g.HSTSIncludeSubdomains, &g.HSTSPreload,
		&g.XFrameOptions, &g.XContentTypeOptions, &g.XXSSProtection, &g.ReferrerPolicy,
		&csp, &pp, &customHeaders,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g.ContentSecurityPolicy = csp.String
	g.PermissionsPolicy = pp.String
	if len(customHeaders) > 0 {
		json.Unmarshal(customHeaders, &g.CustomHeaders)
	}
	return &g, nil
}

// exportGlobalCloudProviders exports the singleton global cloud-provider default
// (#198 slice 4). Returns nil when no row exists.
func (r *BackupRepository) exportGlobalCloudProviders(ctx context.Context) (*model.GlobalCloudProvidersExport, error) {
	query := `
		SELECT COALESCE(blocked_providers, '{}'), challenge_mode, allow_search_bots
		FROM global_cloud_providers LIMIT 1
	`
	var g model.GlobalCloudProvidersExport
	err := r.db.QueryRowContext(ctx, query).Scan(pq.Array(&g.BlockedProviders), &g.ChallengeMode, &g.AllowSearchBots)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if g.BlockedProviders == nil {
		g.BlockedProviders = []string{}
	}
	return &g, nil
}

// exportGlobalRateLimit exports the singleton global rate-limit default
// (#198 slice 5). Returns nil when no row exists.
func (r *BackupRepository) exportGlobalRateLimit(ctx context.Context) (*model.GlobalRateLimitExport, error) {
	query := `
		SELECT enabled, requests_per_second, burst_size, zone_size, limit_by, limit_response, whitelist_ips
		FROM global_rate_limits LIMIT 1
	`
	var g model.GlobalRateLimitExport
	var whitelistIPs sql.NullString
	err := r.db.QueryRowContext(ctx, query).Scan(
		&g.Enabled, &g.RequestsPerSecond, &g.BurstSize, &g.ZoneSize,
		&g.LimitBy, &g.LimitResponse, &whitelistIPs,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g.WhitelistIPs = whitelistIPs.String
	return &g, nil
}

// exportGlobalWAF exports the singleton global WAF default (#198 slice 6).
// Returns nil when no row exists.
func (r *BackupRepository) exportGlobalWAF(ctx context.Context) (*model.GlobalWAFExport, error) {
	query := `
		SELECT enabled, mode, paranoia_level, anomaly_threshold
		FROM global_waf LIMIT 1
	`
	var g model.GlobalWAFExport
	err := r.db.QueryRowContext(ctx, query).Scan(&g.Enabled, &g.Mode, &g.ParanoiaLevel, &g.AnomalyThreshold)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
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
		SELECT rule_id, uri_pattern, reason, disabled_by
		FROM global_exploit_rule_exclusions ORDER BY rule_id, uri_pattern
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.GlobalExploitExclusionExport
	for rows.Next() {
		var ee model.GlobalExploitExclusionExport
		var uriPattern, reason, disabledBy sql.NullString

		err := rows.Scan(&ee.RuleID, &uriPattern, &reason, &disabledBy)
		if err != nil {
			return nil, err
		}

		ee.URIPattern = nullStringToPtr(uriPattern)
		ee.Reason = reason.String
		ee.DisabledBy = disabledBy.String
		exports = append(exports, ee)
	}

	return exports, nil
}

func (r *BackupRepository) exportHostExploitExclusions(ctx context.Context) ([]model.HostExploitExclusionExport, error) {
	query := `
		SELECT proxy_host_id, rule_id, uri_pattern, reason, disabled_by
		FROM host_exploit_rule_exclusions ORDER BY proxy_host_id, rule_id, uri_pattern
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exports []model.HostExploitExclusionExport
	for rows.Next() {
		var he model.HostExploitExclusionExport
		var uriPattern, reason, disabledBy sql.NullString

		err := rows.Scan(&he.ProxyHostID, &he.RuleID, &uriPattern, &reason, &disabledBy)
		if err != nil {
			return nil, err
		}

		he.URIPattern = nullStringToPtr(uriPattern)
		he.Reason = reason.String
		he.DisabledBy = disabledBy.String
		exports = append(exports, he)
	}

	return exports, nil
}

func (r *BackupRepository) exportGlobalChallengeConfig(ctx context.Context) (*model.ChallengeConfigExport, error) {
	query := `
		SELECT enabled, challenge_type, site_key, secret_key, token_validity,
		       min_score, apply_to, page_title, page_message, theme
		FROM challenge_configs WHERE proxy_host_id IS NULL
	`
	var cc model.ChallengeConfigExport
	var siteKey, secretKey sql.NullString
	err := r.db.QueryRowContext(ctx, query).Scan(
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
