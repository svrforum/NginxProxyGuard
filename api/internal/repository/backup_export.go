package repository

import (
	"context"
	"fmt"
	"time"

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

	// Export Global Challenge Config (CAPTCHA)
	globalChallengeConfig, err := r.exportGlobalChallengeConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export global challenge config: %w", err)
	}
	export.GlobalChallengeConfig = globalChallengeConfig

	// Export Filter Subscriptions
	filterSubscriptions, err := r.exportFilterSubscriptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export filter subscriptions: %w", err)
	}
	export.FilterSubscriptions = filterSubscriptions

	return export, nil
}
