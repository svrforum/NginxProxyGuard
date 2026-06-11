package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// BuildConfigData builds the full nginx configuration data for a proxy host.
// This is useful for backup restore and other scenarios where the full config
// data including GeoRestriction, RateLimit, BotFilter etc. is needed.
// Fail-closed: returns an error when any security-relevant lookup fails.
func (s *ProxyHostService) BuildConfigData(ctx context.Context, host *model.ProxyHost) (nginx.ProxyHostConfigData, error) {
	return s.getHostConfigData(ctx, host)
}

// buildHostRender aggregates one host's config data + WAF inputs for a bulk
// atomic regeneration (nginx.RegenerateConfigsAtomic).
func (s *ProxyHostService) buildHostRender(ctx context.Context, host *model.ProxyHost) (nginx.HostConfigRender, error) {
	configData, err := s.getHostConfigData(ctx, host)
	if err != nil {
		return nginx.HostConfigRender{}, err
	}
	render := nginx.HostConfigRender{Data: configData}
	if host.WAFEnabled && !host.IsStream() {
		mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
		if err != nil {
			return render, fmt.Errorf("failed to get WAF exclusions for host %s: %w", host.ID, err)
		}
		render.WAFExclusions = mergedExclusions
		render.WAFAllowedIPs = s.getPriorityAllowIPs(ctx, host.ID)
	}
	return render, nil
}

// redirectHostsByCertificate is the narrow redirect-host repo dependency used
// by the certificate fan-out. Wired in bootstrap (SetRedirectHostRepo) to
// avoid widening the ProxyHostService constructor.
type redirectHostsByCertificate interface {
	GetByCertificateID(ctx context.Context, certificateID string) ([]model.RedirectHost, error)
}

// SetRedirectHostRepo wires the redirect-host lookup used when a renewed
// certificate is also (or only) referenced by redirect hosts.
func (s *ProxyHostService) SetRedirectHostRepo(repo redirectHostsByCertificate) {
	s.redirectHostRepo = repo
}

// RegenerateConfigsForCertificate regenerates nginx configs for all proxy and
// redirect hosts using the specified certificate.
// This should be called when a certificate is issued or renewed. Redirect
// hosts matter even when no proxy host uses the cert: their configs embed the
// cert file paths, and without a reload nginx keeps serving the old
// certificate from memory until an unrelated reload happens.
func (s *ProxyHostService) RegenerateConfigsForCertificate(ctx context.Context, certificateID string) error {
	hosts, err := s.repo.GetByCertificateID(ctx, certificateID)
	if err != nil {
		return fmt.Errorf("failed to get proxy hosts for certificate %s: %w", certificateID, err)
	}

	var redirectHosts []*model.RedirectHost
	if s.redirectHostRepo != nil {
		rhosts, err := s.redirectHostRepo.GetByCertificateID(ctx, certificateID)
		if err != nil {
			return fmt.Errorf("failed to get redirect hosts for certificate %s: %w", certificateID, err)
		}
		for i := range rhosts {
			if rhosts[i].Enabled {
				redirectHosts = append(redirectHosts, &rhosts[i])
			}
		}
	}

	if len(hosts) == 0 && len(redirectHosts) == 0 {
		return nil // Nothing references this certificate
	}

	var renders []nginx.HostConfigRender
	for i := range hosts {
		if !hosts[i].Enabled {
			continue
		}
		render, err := s.buildHostRender(ctx, &hosts[i])
		if err != nil {
			// Skip this host rather than abort the whole renewal fan-out: a
			// transient DB error on one host must not stop nginx from picking
			// up the renewed cert for every other host. The skipped host's
			// existing config still references the same cert file paths, so
			// reloading the others is strictly better than reloading none.
			log.Printf("[Certificate] Skipping host %s during cert %s fan-out: %v", hosts[i].ID, certificateID, err)
			continue
		}
		renders = append(renders, render)
	}

	// Single lock acquisition: write all + test + reload, rollback on failure
	return s.nginx.RegenerateConfigsAtomicWithRedirects(ctx, renders, redirectHosts, true)
}

// RegenerateConfigsForAccessList regenerates nginx configs for all proxy hosts
// referencing the specified access list. Access list rules are rendered
// statically into each dependent host config, so every item edit must fan out
// here — otherwise nginx silently keeps enforcing the stale allow/deny rules.
func (s *ProxyHostService) RegenerateConfigsForAccessList(ctx context.Context, accessListID string) error {
	hosts, err := s.repo.GetByAccessListID(ctx, accessListID)
	if err != nil {
		return fmt.Errorf("failed to get proxy hosts for access list %s: %w", accessListID, err)
	}
	if len(hosts) == 0 {
		return nil
	}

	var renders []nginx.HostConfigRender
	for i := range hosts {
		if !hosts[i].Enabled {
			continue
		}
		render, err := s.buildHostRender(ctx, &hosts[i])
		if err != nil {
			return err
		}
		renders = append(renders, render)
	}

	return s.nginx.RegenerateConfigsAtomic(ctx, renders, true)
}

// GetHostIDsByAccessList returns the IDs of proxy hosts referencing an access
// list. Used to capture the dependent set before the list is deleted.
func (s *ProxyHostService) GetHostIDsByAccessList(ctx context.Context, accessListID string) ([]string, error) {
	hosts, err := s.repo.GetByAccessListID(ctx, accessListID)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy hosts for access list %s: %w", accessListID, err)
	}
	ids := make([]string, 0, len(hosts))
	for i := range hosts {
		ids = append(ids, hosts[i].ID)
	}
	return ids, nil
}

// RegenerateConfigsForHostIDs regenerates nginx configs for the specified
// hosts (e.g. after an access list they referenced was deleted).
func (s *ProxyHostService) RegenerateConfigsForHostIDs(ctx context.Context, hostIDs []string) error {
	var renders []nginx.HostConfigRender
	for _, hostID := range hostIDs {
		host, err := s.repo.GetByID(ctx, hostID)
		if err != nil {
			return fmt.Errorf("failed to get proxy host %s: %w", hostID, err)
		}
		if host == nil || !host.Enabled {
			continue
		}
		render, err := s.buildHostRender(ctx, host)
		if err != nil {
			return err
		}
		renders = append(renders, render)
	}

	return s.nginx.RegenerateConfigsAtomic(ctx, renders, true)
}

// SyncHostResult represents the result of syncing a single host
type SyncHostResult struct {
	HostID      string   `json:"host_id"`
	DomainNames []string `json:"domain_names"`
	Success     bool     `json:"success"`
	Error       string   `json:"error,omitempty"`
}

// SyncAllResult represents the result of syncing all proxy host configs
type SyncAllResult struct {
	TotalHosts    int              `json:"total_hosts"`
	SuccessCount  int              `json:"success_count"`
	FailedCount   int              `json:"failed_count"`
	TestSuccess   bool             `json:"test_success"`
	TestError     string           `json:"test_error,omitempty"`
	ReloadSuccess bool             `json:"reload_success"`
	ReloadError   string           `json:"reload_error,omitempty"`
	Hosts         []SyncHostResult `json:"hosts"`
}

func (s *ProxyHostService) SyncAllConfigs(ctx context.Context) error {
	result, _ := s.SyncAllConfigsWithDetails(ctx)
	if result.FailedCount > 0 || !result.TestSuccess || !result.ReloadSuccess {
		if result.TestError != "" {
			return fmt.Errorf("nginx config test failed: %s", result.TestError)
		}
		if result.ReloadError != "" {
			return fmt.Errorf("nginx reload failed: %s", result.ReloadError)
		}
		for _, h := range result.Hosts {
			if !h.Success {
				return fmt.Errorf("failed to generate config for host %s: %s", h.DomainNames[0], h.Error)
			}
		}
	}
	return nil
}

func (s *ProxyHostService) SyncAllConfigsWithDetails(ctx context.Context) (*SyncAllResult, error) {
	result := &SyncAllResult{
		Hosts: []SyncHostResult{},
	}

	hosts, err := s.repo.GetAllEnabled(ctx)
	if err != nil {
		return result, fmt.Errorf("failed to get enabled hosts: %w", err)
	}

	result.TotalHosts = len(hosts)

	// Generate configs for all hosts with full configuration data
	for _, host := range hosts {
		hostResult := SyncHostResult{
			HostID:      host.ID,
			DomainNames: host.DomainNames,
			Success:     true,
		}

		configData, err := s.getHostConfigData(ctx, &host)
		if err != nil {
			hostResult.Success = false
			hostResult.Error = fmt.Sprintf("failed to load config data: %v", err)
			result.FailedCount++
			result.Hosts = append(result.Hosts, hostResult)
			continue
		}
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			hostResult.Success = false
			hostResult.Error = fmt.Sprintf("failed to generate config: %v", err)
			result.FailedCount++
			result.Hosts = append(result.Hosts, hostResult)
			continue
		}

		// Generate WAF config if WAF is enabled (includes global + host exclusions)
		if host.WAFEnabled && !host.IsStream() {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				hostResult.Success = false
				hostResult.Error = fmt.Sprintf("failed to get WAF exclusions: %v", err)
				result.FailedCount++
				result.Hosts = append(result.Hosts, hostResult)
				continue
			}
			allowedIPs := s.getPriorityAllowIPs(ctx, host.ID)
			if err := s.nginx.GenerateHostWAFConfig(ctx, &host, mergedExclusions, allowedIPs); err != nil {
				hostResult.Success = false
				hostResult.Error = fmt.Sprintf("failed to generate WAF config: %v", err)
				result.FailedCount++
				result.Hosts = append(result.Hosts, hostResult)
				continue
			}
		}

		result.SuccessCount++
		result.Hosts = append(result.Hosts, hostResult)
	}

	// Drift detection: configs may exist on disk for hosts that are deleted or
	// disabled in the DB (e.g. after a DB or volume restore). Remove them
	// before testing — nginx includes conf.d/*.conf wholesale, so leftovers
	// would keep serving traffic indefinitely. The enabled-host list is
	// re-queried under the nginx lock (not reusing the `hosts` snapshot above):
	// the per-host loop does many DB reads, so a host created meanwhile would
	// otherwise have its just-written config deleted as a false orphan.
	if removed := s.nginx.RemoveOrphanedHostConfigs(ctx, s.repo.GetAllEnabled); len(removed) > 0 {
		log.Printf("[SyncConfigs] Removed %d stale host config file(s): %s", len(removed), strings.Join(removed, ", "))
	}

	// Test nginx config — on failure, run the auto-recovery loop that
	// iteratively removes the config of hosts nginx reports as failing.
	// See runAutoRecovery (sync_auto_recovery.go) for the loop details.
	if err := s.nginx.TestConfig(ctx); err != nil {
		recovered, lastErr := runAutoRecovery(ctx, s.nginx, hosts, result, err)
		if !recovered {
			result.TestSuccess = false
			result.TestError = lastErr.Error()
			return result, nil
		}
	}
	result.TestSuccess = true

	// Reload nginx
	if err := s.nginx.ReloadNginx(ctx); err != nil {
		result.ReloadSuccess = false
		result.ReloadError = err.Error()
		return result, nil
	}
	result.ReloadSuccess = true

	// Update config_status for all hosts based on sync results
	s.updateConfigStatuses(ctx, result)

	return result, nil
}

// updateConfigStatuses updates DB config_status and writes system logs for failed hosts
func (s *ProxyHostService) updateConfigStatuses(ctx context.Context, result *SyncAllResult) {
	for _, h := range result.Hosts {
		if h.Success {
			if err := s.repo.UpdateConfigStatus(ctx, h.HostID, "ok", ""); err != nil {
				log.Printf("[SyncConfigs] Failed to update config status for host %s: %v", h.HostID, err)
			}
			metrics.NginxConfigStatus.WithLabelValues(h.HostID).Set(1)
		} else {
			if err := s.repo.UpdateConfigStatus(ctx, h.HostID, "error", h.Error); err != nil {
				log.Printf("[SyncConfigs] Failed to update config status for host %s: %v", h.HostID, err)
			}
			metrics.NginxConfigStatus.WithLabelValues(h.HostID).Set(0)
			// Write system log for failed host
			if s.systemLogRepo != nil {
				details, _ := json.Marshal(map[string]string{
					"host_id": h.HostID,
					"domains": strings.Join(h.DomainNames, ", "),
					"error":   h.Error,
				})
				_ = s.systemLogRepo.Create(ctx, &repository.SystemLog{
					Source:    repository.SourceInternal,
					Level:     repository.LevelWarn,
					Message:   fmt.Sprintf("Proxy host config error: %s (%s)", strings.Join(h.DomainNames, ", "), h.Error),
					Details:   details,
					Component: "proxy_host_sync",
				})
			}
		}
	}
}

// RegenerateConfigsForCloudProviders regenerates nginx configs for proxy hosts
// that have cloud provider blocking enabled for the specified providers
// If updatedProviders is nil or empty, regenerates for all hosts with any cloud provider blocking
func (s *ProxyHostService) RegenerateConfigsForCloudProviders(ctx context.Context, updatedProviders []string) error {
	// Get proxy host IDs with cloud provider blocking
	hostIDs, err := s.cloudProviderRepo.GetProxyHostIDsWithCloudProviderBlocking(ctx, updatedProviders)
	if err != nil {
		return fmt.Errorf("failed to get proxy hosts with cloud provider blocking: %w", err)
	}

	if len(hostIDs) == 0 {
		log.Println("[CloudProvider] No proxy hosts with cloud provider blocking found")
		return nil // No hosts to update
	}

	log.Printf("[CloudProvider] Regenerating configs for %d proxy hosts", len(hostIDs))

	var renders []nginx.HostConfigRender
	for _, hostID := range hostIDs {
		host, err := s.repo.GetByID(ctx, hostID)
		if err != nil {
			log.Printf("[CloudProvider] Error getting proxy host %s: %v", hostID, err)
			continue
		}
		if host == nil || !host.Enabled {
			continue
		}
		render, err := s.buildHostRender(ctx, host)
		if err != nil {
			return err
		}
		renders = append(renders, render)
	}

	// Single lock acquisition: write all + test + reload, rollback on failure
	if err := s.nginx.RegenerateConfigsAtomic(ctx, renders, true); err != nil {
		return err
	}

	log.Printf("[CloudProvider] Nginx configs regenerated and reloaded for %d hosts", len(renders))
	return nil
}

// RegenerateConfigsForExploitRules regenerates nginx configs for all proxy hosts
// that have block_exploits enabled. Called when exploit rules are modified.
func (s *ProxyHostService) RegenerateConfigsForExploitRules(ctx context.Context) error {
	// Get all hosts with block_exploits enabled
	hosts, _, err := s.repo.List(ctx, 1, 10000, "", "", "")
	if err != nil {
		return fmt.Errorf("failed to list proxy hosts: %w", err)
	}

	var hostsToUpdate []*model.ProxyHost
	for i := range hosts {
		if hosts[i].BlockExploits && !hosts[i].IsStream() {
			hostsToUpdate = append(hostsToUpdate, &hosts[i])
		}
	}

	if len(hostsToUpdate) == 0 {
		log.Printf("[ExploitRules] No hosts with block_exploits enabled, skipping regeneration")
		return nil
	}

	log.Printf("[ExploitRules] Regenerating nginx configs for %d hosts with block_exploits enabled", len(hostsToUpdate))

	var renders []nginx.HostConfigRender
	for _, host := range hostsToUpdate {
		render, err := s.buildHostRender(ctx, host)
		if err != nil {
			return err
		}
		renders = append(renders, render)
	}

	// Single lock acquisition: write all + test + reload, rollback on failure
	if err := s.nginx.RegenerateConfigsAtomic(ctx, renders, true); err != nil {
		return err
	}

	log.Printf("[ExploitRules] Nginx configs regenerated and reloaded for %d hosts", len(hostsToUpdate))
	return nil
}

// RegenerateConfigForHost regenerates nginx config for a single host by ID
// Handles both enabled hosts (generate config + test + reload) and
// disabled hosts (remove config + test + reload)
func (s *ProxyHostService) RegenerateConfigForHost(ctx context.Context, hostID string) error {
	host, err := s.repo.GetByID(ctx, hostID)
	if err != nil {
		return fmt.Errorf("failed to get proxy host %s: %w", hostID, err)
	}
	if host == nil {
		// Idempotent no-op: nothing to regenerate for an unknown/deleted host.
		// Callers like the geo DELETE handler delegate here after the row is
		// already gone — a missing host must return 204, not 500.
		return nil
	}

	if !host.Enabled {
		// Host is disabled - remove config and reload
		if err := s.nginx.RemoveConfigAndReload(ctx, host); err != nil {
			// Ignore "file not found" - config may already be removed
			if !strings.Contains(err.Error(), "no such file") {
				return fmt.Errorf("failed to remove config for disabled host %s: %w", hostID, err)
			}
			// Still need to test and reload even if file was already gone
			if testErr := s.nginx.TestConfig(ctx); testErr != nil {
				return fmt.Errorf("nginx config test failed: %w", testErr)
			}
			if reloadErr := s.nginx.ReloadNginx(ctx); reloadErr != nil {
				return fmt.Errorf("failed to reload nginx: %w", reloadErr)
			}
		}
		_ = s.repo.UpdateConfigStatus(ctx, host.ID, "ok", "")
		metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(1)
		log.Printf("[ProxyHost] Nginx config removed and reloaded for disabled host %s", hostID)
		return nil
	}

	configData, err := s.getHostConfigData(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to load config data for host %s: %w", hostID, err)
	}

	// Get WAF exclusions if WAF is enabled
	var wafExclusions []model.WAFRuleExclusion
	if host.WAFEnabled && !host.IsStream() {
		wafExclusions, err = s.getMergedWAFExclusions(ctx, hostID)
		if err != nil {
			return fmt.Errorf("failed to get WAF exclusions for host %s: %w", hostID, err)
		}
	}

	// Atomic: generate config + WAF config + test + reload (with global lock)
	if err := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); err != nil {
		_ = s.repo.UpdateConfigStatus(ctx, host.ID, "error", err.Error())
		metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(0)
		return fmt.Errorf("failed to generate config for host %s: %w", hostID, err)
	}

	_ = s.repo.UpdateConfigStatus(ctx, host.ID, "ok", "")
	metrics.NginxConfigStatus.WithLabelValues(host.ID).Set(1)
	log.Printf("[ProxyHost] Nginx config regenerated and reloaded for host %s", hostID)
	return nil
}
