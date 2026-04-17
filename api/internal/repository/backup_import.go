package repository

import (
	"context"
	"database/sql"
	"fmt"

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

	// Import Filter Subscriptions
	for _, fs := range data.FilterSubscriptions {
		if err := r.importFilterSubscription(ctx, tx, &fs, proxyHostIDMap); err != nil {
			return fmt.Errorf("failed to import filter subscription %s: %w", fs.Name, err)
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
		"filter_subscription_entry_exclusions", // references filter_subscriptions
		"filter_subscription_host_exclusions", // references filter_subscriptions + proxy_hosts
		"filter_subscription_entries",         // references filter_subscriptions
		"filter_subscriptions",
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
