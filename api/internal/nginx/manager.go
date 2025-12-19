package nginx

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// Manager handles nginx configuration generation and operations
type Manager struct {
	configPath     string
	certsPath      string
	modsecPath     string // Path to ModSecurity config directory
	nginxContainer string // Docker container name for nginx
	skipTest       bool   // Skip nginx test/reload (for development)
}

func NewManager(configPath, certsPath string) *Manager {
	nginxContainer := os.Getenv("NGINX_CONTAINER")
	if nginxContainer == "" {
		nginxContainer = "npg-proxy"
	}

	modsecPath := os.Getenv("MODSEC_PATH")
	if modsecPath == "" {
		modsecPath = "/etc/nginx/modsec"
	}

	skipTest := os.Getenv("NGINX_SKIP_TEST") == "true"

	return &Manager{
		configPath:     configPath,
		certsPath:      certsPath,
		modsecPath:     modsecPath,
		nginxContainer: nginxContainer,
		skipTest:       skipTest,
	}
}


func (m *Manager) GenerateConfig(ctx context.Context, host *model.ProxyHost) error {
	// Convenience wrapper that calls GenerateConfigFull with nil values
	return m.GenerateConfigFull(ctx, ProxyHostConfigData{Host: host})
}

// GenerateConfigWithAccessControl generates nginx config with access list and geo restriction support
// Deprecated: Use GenerateConfigFull instead for Phase 6+ features
func (m *Manager) GenerateConfigWithAccessControl(ctx context.Context, host *model.ProxyHost, accessList *model.AccessList, geoRestriction *model.GeoRestriction) error {
	return m.GenerateConfigFull(ctx, ProxyHostConfigData{
		Host:           host,
		AccessList:     accessList,
		GeoRestriction: geoRestriction,
	})
}

// GenerateConfigFull generates nginx config with all Phase 6 features support
func (m *Manager) GenerateConfigFull(ctx context.Context, data ProxyHostConfigData) error {
	// Note: WAF config is generated separately by the service layer
	// to properly include any rule exclusions

	// Get API host from environment or default
	apiHostValue := os.Getenv("API_HOST")
	if apiHostValue == "" {
		apiHostValue = "api:8080" // Docker internal hostname
	}

	funcMap := template.FuncMap{
		"join": strings.Join,
		"now": func() string {
			return "auto-generated"
		},
		"escapeNginxPattern": func(s string) string {
			// Normalize: first remove any existing escapes to handle already-escaped patterns
			s = strings.ReplaceAll(s, `\"`, `"`)
			// Then escape all double quotes for nginx double-quoted strings
			return strings.ReplaceAll(s, `"`, `\"`)
		},
		"certPath": func(h *model.ProxyHost) string {
			// Use certificate ID if available, otherwise fall back to proxy host ID
			if h.CertificateID != nil && *h.CertificateID != "" {
				return *h.CertificateID
			}
			return h.ID
		},
		"wafConfig": func(h *model.ProxyHost) string {
			// Return per-host WAF config file
			// Each host has its own WAF config with exclusions
			return fmt.Sprintf("host_%s.conf", h.ID)
		},
		"sanitizeID": func(id string) string {
			// Replace hyphens with underscores for nginx zone names
			return strings.ReplaceAll(id, "-", "_")
		},
		"toRegexPattern": func(s string) string {
			// Convert newline-separated patterns to pipe-separated regex pattern
			// Also trim whitespace, filter empty lines and comments
			lines := strings.Split(s, "\n")
			var patterns []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				// Skip empty lines and comment lines (starting with #)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// Limit line length to prevent ReDoS attacks
				if len(line) > 500 {
					line = line[:500]
				}
				// Escape all special regex characters for safety
				// Order matters: escape backslash first
				line = strings.ReplaceAll(line, "\\", "\\\\")
				line = strings.ReplaceAll(line, ".", "\\.")
				line = strings.ReplaceAll(line, "+", "\\+")
				line = strings.ReplaceAll(line, "?", "\\?")
				line = strings.ReplaceAll(line, "(", "\\(")
				line = strings.ReplaceAll(line, ")", "\\)")
				line = strings.ReplaceAll(line, "[", "\\[")
				line = strings.ReplaceAll(line, "]", "\\]")
				line = strings.ReplaceAll(line, "{", "\\{")
				line = strings.ReplaceAll(line, "}", "\\}")
				line = strings.ReplaceAll(line, "^", "\\^")
				line = strings.ReplaceAll(line, "$", "\\$")
				line = strings.ReplaceAll(line, "|", "\\|")
				// Convert * to .* for wildcard matching (after escaping other chars)
				line = strings.ReplaceAll(line, "*", ".*")
				// Escape spaces for nginx regex (spaces break nginx if conditions)
				line = strings.ReplaceAll(line, " ", "\\s")
				patterns = append(patterns, line)
			}
			// Limit total number of patterns to prevent complexity attacks
			if len(patterns) > 100 {
				patterns = patterns[:100]
			}
			return strings.Join(patterns, "|")
		},
		"apiHost": func() string {
			return apiHostValue
		},
		"len": func(s []string) int {
			return len(s)
		},
		"uriLocationDirective": func(matchType model.URIMatchType, pattern string) string {
			switch matchType {
			case model.URIMatchExact:
				return fmt.Sprintf("location = %s", pattern)
			case model.URIMatchPrefix:
				return fmt.Sprintf("location ^~ %s", pattern)
			case model.URIMatchRegex:
				return fmt.Sprintf("location ~* %s", pattern)
			default:
				return fmt.Sprintf("location ^~ %s", pattern)
			}
		},
		"hasURIBlockExceptionIPs": func(ub *model.URIBlock) bool {
			return ub != nil && (len(ub.ExceptionIPs) > 0 || ub.AllowPrivateIPs)
		},
		"escapeRegex": func(s string) string {
			// Escape special regex characters for nginx regex matching
			// Also handle CIDR notation for IP ranges
			s = strings.TrimSpace(s)
			if s == "" {
				return s
			}
			// Check if it's a CIDR range (e.g., 192.168.1.0/24)
			if strings.Contains(s, "/") {
				parts := strings.Split(s, "/")
				if len(parts) == 2 {
					ip := strings.ReplaceAll(parts[0], ".", "\\.")
					return ip + "/" + parts[1]
				}
			}
			// Escape dots for regular IP addresses
			return strings.ReplaceAll(s, ".", "\\.")
		},
		"isCIDR": isCIDR,
		"cidrToNginxPattern": cidrToNginxPattern,
		"splitExceptions": func(s string) []string {
			// Split newline-separated exception patterns into a slice
			// Used for block_exploits_exceptions
			if s == "" {
				return nil
			}
			lines := strings.Split(s, "\n")
			var patterns []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				patterns = append(patterns, line)
			}
			return patterns
		},
		"hasExceptions": func(s string) bool {
			// Check if there are any non-empty exception patterns
			if s == "" {
				return false
			}
			lines := strings.Split(s, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					return true
				}
			}
			return false
		},
		"mergeExceptions": func(global, host string) string {
			// Merge global and host-specific exception patterns
			// Returns combined newline-separated patterns
			var patterns []string
			seen := make(map[string]bool)

			// Add global patterns first
			if global != "" {
				for _, line := range strings.Split(global, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
						patterns = append(patterns, line)
						seen[line] = true
					}
				}
			}

			// Add host patterns (may override/add to global)
			if host != "" {
				for _, line := range strings.Split(host, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
						patterns = append(patterns, line)
						seen[line] = true
					}
				}
			}

			return strings.Join(patterns, "\n")
		},
		"hasMergedExceptions": func(global, host string) bool {
			// Check if there are any exceptions from either global or host
			if global != "" {
				for _, line := range strings.Split(global, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return true
					}
				}
			}
			if host != "" {
				for _, line := range strings.Split(host, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return true
					}
				}
			}
			return false
		},
		// Exploit rule helpers
		"filterRulesByPatternType": func(rules []model.ExploitBlockRule, patternType string) []model.ExploitBlockRule {
			var filtered []model.ExploitBlockRule
			for _, rule := range rules {
				if rule.PatternType == patternType {
					filtered = append(filtered, rule)
				}
			}
			return filtered
		},
		"hasExploitRules": func(rules []model.ExploitBlockRule) bool {
			return len(rules) > 0
		},
		"hasRulesOfType": func(rules []model.ExploitBlockRule, patternType string) bool {
			for _, rule := range rules {
				if rule.PatternType == patternType {
					return true
				}
			}
			return false
		},
	}

	// Check if SSL is enabled but certificate files don't exist
	// If so, temporarily disable SSL to generate a working config
	// This is a fallback for when certificate is being issued asynchronously
	sslTemporarilyDisabled := false
	if data.Host.SSLEnabled && data.Host.CertificateID != nil && *data.Host.CertificateID != "" {
		certPath := filepath.Join(m.certsPath, *data.Host.CertificateID, "fullchain.pem")
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			// Certificate files don't exist yet, disable SSL temporarily
			// Log a warning so this is visible in logs
			log.Printf("[WARN] SSL temporarily disabled for host %s (%s): certificate file not found at %s. Config will be HTTP-only until certificate is ready.",
				data.Host.ID, strings.Join(data.Host.DomainNames, ", "), certPath)
			data.Host.SSLEnabled = false
			data.Host.SSLForceHTTPS = false
			sslTemporarilyDisabled = true
		}
	}
	_ = sslTemporarilyDisabled // Will be used for adding comments to config in future

	// Generate cloud IPs include file if there are blocked cloud providers
	// This significantly reduces the main config file size
	if len(data.BlockedCloudIPRanges) > 0 {
		if err := m.GenerateCloudIPsInclude(data.Host.ID, data.BlockedCloudIPRanges); err != nil {
			return fmt.Errorf("failed to generate cloud IPs include: %w", err)
		}
	} else {
		// Remove the include file if no cloud IPs to block
		_ = m.RemoveCloudIPsInclude(data.Host.ID)
	}

	tmpl, err := template.New("proxy_host").Funcs(funcMap).Parse(proxyHostTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	configFile := filepath.Join(m.configPath, GetConfigFilename(data.Host))
	if err := os.WriteFile(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (m *Manager) RemoveConfig(ctx context.Context, host *model.ProxyHost) error {
	configFile := filepath.Join(m.configPath, GetConfigFilename(host))

	// Check if file exists before removing
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to remove
	}

	if err := os.Remove(configFile); err != nil {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	// Also remove the cloud IPs include file if it exists
	_ = m.RemoveCloudIPsInclude(host.ID)

	return nil
}

func (m *Manager) TestConfig(ctx context.Context) error {
	if m.skipTest {
		return nil
	}

	// Try docker exec first (for containerized environments)
	cmd := exec.CommandContext(ctx, "docker", "exec", m.nginxContainer, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to direct nginx command (for non-containerized environments)
		cmd = exec.CommandContext(ctx, "nginx", "-t")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx config test failed: %s", string(output))
		}
	}
	return nil
}

func (m *Manager) ReloadNginx(ctx context.Context) error {
	if m.skipTest {
		return nil
	}

	// Try docker exec first (for containerized environments)
	cmd := exec.CommandContext(ctx, "docker", "exec", m.nginxContainer, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to direct nginx command (for non-containerized environments)
		cmd = exec.CommandContext(ctx, "nginx", "-s", "reload")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx reload failed: %s", string(output))
		}
	}
	return nil
}

func (m *Manager) GenerateAllConfigs(ctx context.Context, hosts []model.ProxyHost) error {
	// Remove all existing proxy_host configs
	files, err := filepath.Glob(filepath.Join(m.configPath, "proxy_host_*.conf"))
	if err != nil {
		return fmt.Errorf("failed to list config files: %w", err)
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("failed to remove config file %s: %w", f, err)
		}
	}

	// Generate configs for all hosts
	for _, host := range hosts {
		if err := m.GenerateConfig(ctx, &host); err != nil {
			return fmt.Errorf("failed to generate config for host %s: %w", host.ID, err)
		}
	}

	return nil
}

func (m *Manager) GetConfigPath() string {
	return m.configPath
}

func (m *Manager) GetCertsPath() string {
	return m.certsPath
}

func (m *Manager) GetModsecPath() string {
	return m.modsecPath
}

// NOTE: The following functions have been moved to separate files:
// - GenerateHostWAFConfig, RemoveHostWAFConfig -> waf_config.go
// - GenerateRedirectConfig, RemoveRedirectConfig, GenerateAllRedirectConfigs -> redirect_config.go
// - GenerateDefaultServerConfig -> default_server_config.go
// - UpdateBannedIPs -> banned_ips.go
