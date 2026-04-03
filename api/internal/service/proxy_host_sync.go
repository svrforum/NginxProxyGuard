package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// BuildConfigData builds the full nginx configuration data for a proxy host.
// This is useful for backup restore and other scenarios where the full config
// data including GeoRestriction, RateLimit, BotFilter etc. is needed.
func (s *ProxyHostService) BuildConfigData(ctx context.Context, host *model.ProxyHost) nginx.ProxyHostConfigData {
	return s.getHostConfigData(ctx, host)
}

// RegenerateConfigsForCertificate regenerates nginx configs for all proxy hosts using the specified certificate
// This should be called when a certificate is issued or renewed
func (s *ProxyHostService) RegenerateConfigsForCertificate(ctx context.Context, certificateID string) error {
	hosts, err := s.repo.GetByCertificateID(ctx, certificateID)
	if err != nil {
		return fmt.Errorf("failed to get proxy hosts for certificate %s: %w", certificateID, err)
	}

	if len(hosts) == 0 {
		return nil // No proxy hosts use this certificate
	}

	// Regenerate configs for all affected hosts
	for _, host := range hosts {
		if !host.Enabled {
			continue
		}

		configData := s.getHostConfigData(ctx, &host)
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return fmt.Errorf("failed to generate config for host %s: %w", host.ID, err)
		}

		// Generate WAF config if WAF is enabled (includes global + host exclusions)
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				return fmt.Errorf("failed to get WAF exclusions for host %s: %w", host.ID, err)
			}
			allowedIPs := s.getPriorityAllowIPs(ctx, host.ID)
			if err := s.nginx.GenerateHostWAFConfig(ctx, &host, mergedExclusions, allowedIPs); err != nil {
				return fmt.Errorf("failed to generate WAF config for host %s: %w", host.ID, err)
			}
		}
	}

	// Test and reload nginx
	if err := s.nginx.TestConfig(ctx); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
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

		configData := s.getHostConfigData(ctx, &host)
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			hostResult.Success = false
			hostResult.Error = fmt.Sprintf("failed to generate config: %v", err)
			result.FailedCount++
			result.Hosts = append(result.Hosts, hostResult)
			continue
		}

		// Generate WAF config if WAF is enabled (includes global + host exclusions)
		if host.WAFEnabled {
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

	// Test nginx config — on failure, remove the failing host's config and retry
	if err := s.nginx.TestConfig(ctx); err != nil {
		testErr := err
		recovered := false

		// Try to recover by removing failing host configs one at a time
		for attempt := 0; attempt < 5; attempt++ {
			failingDomain := parseNginxErrorForHost(testErr.Error())
			if failingDomain == "" {
				break
			}
			hostIdx := findHostByDomain(result.Hosts, failingDomain)
			if hostIdx < 0 {
				break
			}
			// Mark the host as failed
			if result.Hosts[hostIdx].Success {
				result.Hosts[hostIdx].Success = false
				result.Hosts[hostIdx].Error = testErr.Error()
				result.SuccessCount--
				result.FailedCount++
			}
			// Remove the failing host's config and WAF config to recover nginx
			failingHost := findHostByID(hosts, result.Hosts[hostIdx].HostID)
			if failingHost != nil {
				log.Printf("[SyncConfigs] Removing failing config for %s to recover nginx", result.Hosts[hostIdx].DomainNames)
				_ = s.nginx.RemoveConfig(ctx, failingHost)
				_ = s.nginx.RemoveHostWAFConfig(ctx, failingHost.ID)
			}
			// Retry nginx test
			if retryErr := s.nginx.TestConfig(ctx); retryErr != nil {
				testErr = retryErr
				continue
			}
			recovered = true
			break
		}

		if !recovered {
			result.TestSuccess = false
			result.TestError = testErr.Error()
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
		} else {
			if err := s.repo.UpdateConfigStatus(ctx, h.HostID, "error", h.Error); err != nil {
				log.Printf("[SyncConfigs] Failed to update config status for host %s: %v", h.HostID, err)
			}
			// Write system log for failed host
			if s.systemLogRepo != nil {
				details, _ := json.Marshal(map[string]string{
					"host_id": h.HostID,
					"domains": strings.Join(h.DomainNames, ", "),
					"error":   h.Error,
				})
				_ = s.systemLogRepo.Create(ctx, &repository.SystemLog{
					Source:    repository.SourceInternal,
					Level:    repository.LevelWarn,
					Message:  fmt.Sprintf("Proxy host config error: %s (%s)", strings.Join(h.DomainNames, ", "), h.Error),
					Details:  details,
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

	// Regenerate configs for all affected hosts
	for _, hostID := range hostIDs {
		host, err := s.repo.GetByID(ctx, hostID)
		if err != nil {
			log.Printf("[CloudProvider] Error getting proxy host %s: %v", hostID, err)
			continue
		}
		if host == nil || !host.Enabled {
			continue
		}

		configData := s.getHostConfigData(ctx, host)
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return fmt.Errorf("failed to generate config for host %s: %w", hostID, err)
		}

		// Generate WAF config if WAF is enabled (includes global + host exclusions)
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, hostID)
			if err != nil {
				return fmt.Errorf("failed to get WAF exclusions for host %s: %w", hostID, err)
			}
			allowedIPs := s.getPriorityAllowIPs(ctx, hostID)
			if err := s.nginx.GenerateHostWAFConfig(ctx, host, mergedExclusions, allowedIPs); err != nil {
				return fmt.Errorf("failed to generate WAF config for host %s: %w", hostID, err)
			}
		}
	}

	// Test and reload nginx
	if err := s.nginx.TestConfig(ctx); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	log.Printf("[CloudProvider] Nginx configs regenerated and reloaded for %d hosts", len(hostIDs))
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
		if hosts[i].BlockExploits {
			hostsToUpdate = append(hostsToUpdate, &hosts[i])
		}
	}

	if len(hostsToUpdate) == 0 {
		log.Printf("[ExploitRules] No hosts with block_exploits enabled, skipping regeneration")
		return nil
	}

	log.Printf("[ExploitRules] Regenerating nginx configs for %d hosts with block_exploits enabled", len(hostsToUpdate))

	for _, host := range hostsToUpdate {
		configData := s.getHostConfigData(ctx, host)
		if err := s.nginx.GenerateConfigFull(ctx, configData); err != nil {
			return fmt.Errorf("failed to generate config for host %s: %w", host.ID, err)
		}

		// Also regenerate WAF config if enabled
		if host.WAFEnabled {
			mergedExclusions, err := s.getMergedWAFExclusions(ctx, host.ID)
			if err != nil {
				return fmt.Errorf("failed to get WAF exclusions for host %s: %w", host.ID, err)
			}
			allowedIPs := s.getPriorityAllowIPs(ctx, host.ID)
			if err := s.nginx.GenerateHostWAFConfig(ctx, host, mergedExclusions, allowedIPs); err != nil {
				return fmt.Errorf("failed to generate WAF config for host %s: %w", host.ID, err)
			}
		}
	}

	// Test and reload nginx
	if err := s.nginx.TestConfig(ctx); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	if err := s.nginx.ReloadNginx(ctx); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
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
		return fmt.Errorf("proxy host %s not found", hostID)
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
		log.Printf("[ProxyHost] Nginx config removed and reloaded for disabled host %s", hostID)
		return nil
	}

	configData := s.getHostConfigData(ctx, host)

	// Get WAF exclusions if WAF is enabled
	var wafExclusions []model.WAFRuleExclusion
	if host.WAFEnabled {
		wafExclusions, err = s.getMergedWAFExclusions(ctx, hostID)
		if err != nil {
			return fmt.Errorf("failed to get WAF exclusions for host %s: %w", hostID, err)
		}
	}

	// Atomic: generate config + WAF config + test + reload (with global lock)
	if err := s.nginx.GenerateConfigAndReload(ctx, configData, wafExclusions); err != nil {
		_ = s.repo.UpdateConfigStatus(ctx, host.ID, "error", err.Error())
		return fmt.Errorf("failed to generate config for host %s: %w", hostID, err)
	}

	_ = s.repo.UpdateConfigStatus(ctx, host.ID, "ok", "")
	log.Printf("[ProxyHost] Nginx config regenerated and reloaded for host %s", hostID)
	return nil
}
