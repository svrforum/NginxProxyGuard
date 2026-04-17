package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

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
