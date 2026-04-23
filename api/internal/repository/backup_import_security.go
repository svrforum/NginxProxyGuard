package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

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
		INSERT INTO waf_rule_exclusions (proxy_host_id, rule_id, rule_category, rule_description, reason, disabled_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (proxy_host_id, rule_id) DO NOTHING
	`
	_, err := tx.ExecContext(ctx, query, we.ProxyHostID, we.RuleID, we.RuleCategory, we.RuleDescription, we.Reason, we.DisabledBy)
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
