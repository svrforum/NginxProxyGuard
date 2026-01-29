package nginx

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// globalNginxMutex ensures all nginx config operations (write/test/reload) are serialized globally
// This prevents race conditions where nginx reads partially-written config files
var globalNginxMutex sync.Mutex

// Manager handles nginx configuration generation and operations
type Manager struct {
	configPath     string
	certsPath      string
	modsecPath     string // Path to ModSecurity config directory
	nginxContainer string // Docker container name for nginx
	skipTest       bool   // Skip nginx test/reload (for development)
	httpPort       string // HTTP listen port (default: 80)
	httpsPort      string // HTTPS listen port (default: 443)
	apiURL         string // API URL for nginx to reach API (default: http://api:8080)
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

	// Custom listen ports for host network mode (e.g., Synology DSM)
	httpPort := os.Getenv("NGINX_HTTP_PORT")
	if httpPort == "" {
		httpPort = "80"
	}
	httpsPort := os.Getenv("NGINX_HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "443"
	}

	// API URL for nginx to reach API
	// In host network mode, nginx can't use Docker service names
	// Use API_HOST_PORT env var to determine the correct URL
	apiURL := "http://api:8080" // Default for bridge network mode
	apiHostPort := os.Getenv("API_HOST_PORT")
	if apiHostPort != "" {
		// Host network mode - use localhost with the exposed API port
		apiURL = "http://127.0.0.1:" + apiHostPort
	}

	return &Manager{
		configPath:     configPath,
		certsPath:      certsPath,
		modsecPath:     modsecPath,
		nginxContainer: nginxContainer,
		skipTest:       skipTest,
		httpPort:       httpPort,
		httpsPort:      httpsPort,
		apiURL:         apiURL,
	}
}

// GetHTTPPort returns the HTTP listen port
func (m *Manager) GetHTTPPort() string {
	return m.httpPort
}

// GetHTTPSPort returns the HTTPS listen port
func (m *Manager) GetHTTPSPort() string {
	return m.httpsPort
}

// writeFileAtomic writes data to a file atomically using temp file + fsync + rename
// This ensures nginx never reads partially-written config files
func (m *Manager) writeFileAtomic(filePath string, data []byte, perm os.FileMode) error {
	// Ensure parent directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create temp file in the same directory (required for atomic rename)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Cleanup temp file on error
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	// Write all data
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	// Fsync to ensure data is on disk
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	// Close file before rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	tmpFile = nil // Mark as closed for defer cleanup

	// Set correct permissions
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// executeWithLock runs a function with the global nginx mutex locked
// This ensures all config operations are serialized
func (m *Manager) executeWithLock(ctx context.Context, fn func() error) error {
	globalNginxMutex.Lock()
	defer globalNginxMutex.Unlock()
	
	return fn()
}

// testAndReloadNginx tests and reloads nginx configuration
// Must be called within executeWithLock
func (m *Manager) testAndReloadNginx(ctx context.Context) error {
	if m.skipTest {
		return nil
	}

	// Test configuration first
	if err := m.testConfigInternal(ctx); err != nil {
		return err
	}

	// Reload nginx
	return m.reloadNginxInternal(ctx)
}

// GenerateConfigAndReload generates proxy host config, WAF config, tests and reloads nginx
// This is a centralized operation that ensures all file writes complete before test/reload
func (m *Manager) GenerateConfigAndReload(ctx context.Context, data ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion) error {
	return m.executeWithLock(ctx, func() error {
		// Generate main proxy host config
		if err := m.GenerateConfigFull(ctx, data); err != nil {
			return fmt.Errorf("failed to generate proxy host config: %w", err)
		}

		// Generate or remove WAF config based on WAF enabled status
		if data.Host.WAFEnabled {
			if err := m.GenerateHostWAFConfig(ctx, data.Host, wafExclusions); err != nil {
				return fmt.Errorf("failed to generate WAF config: %w", err)
			}
		} else {
			// Remove WAF config if WAF is disabled to prevent orphan files
			if err := m.RemoveHostWAFConfig(ctx, data.Host.ID); err != nil {
				log.Printf("[WARN] Failed to remove WAF config for host %s: %v", data.Host.ID, err)
				// Non-fatal: continue with nginx reload
			}
		}

		// Test and reload nginx (all config files are complete now)
		if err := m.testAndReloadNginx(ctx); err != nil {
			return err
		}

		return nil
	})
}

// UpdateConfigAndReload updates existing proxy host config, WAF config, tests and reloads nginx
// This is an alias for GenerateConfigAndReload for semantic clarity
func (m *Manager) UpdateConfigAndReload(ctx context.Context, data ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion) error {
	return m.GenerateConfigAndReload(ctx, data, wafExclusions)
}

// GenerateConfigAndReloadWithCleanup generates config, removes old config, tests and reloads
// Use this when domain name changes (config filename changes but zone names stay same)
// This prevents limit_req_zone duplicate errors by removing the old config BEFORE nginx test
func (m *Manager) GenerateConfigAndReloadWithCleanup(ctx context.Context, data ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion, oldConfigFilename string) error {
	return m.executeWithLock(ctx, func() error {
		newConfigFilename := GetConfigFilename(data.Host)
		oldConfigFile := filepath.Join(m.configPath, oldConfigFilename)
		var oldConfigBackup []byte
		var oldConfigExists bool

		// 1. Backup old config for potential rollback
		if oldConfigFilename != "" && oldConfigFilename != newConfigFilename {
			if content, err := os.ReadFile(oldConfigFile); err == nil {
				oldConfigBackup = content
				oldConfigExists = true
			}
		}

		// 2. Generate new config
		if err := m.GenerateConfigFull(ctx, data); err != nil {
			return fmt.Errorf("failed to generate proxy host config: %w", err)
		}

		// 3. Generate or remove WAF config
		if data.Host.WAFEnabled {
			if err := m.GenerateHostWAFConfig(ctx, data.Host, wafExclusions); err != nil {
				return fmt.Errorf("failed to generate WAF config: %w", err)
			}
		} else {
			if err := m.RemoveHostWAFConfig(ctx, data.Host.ID); err != nil {
				log.Printf("[WARN] Failed to remove WAF config for host %s: %v", data.Host.ID, err)
			}
		}

		// 4. Remove old config BEFORE nginx test (prevents zone duplication)
		if oldConfigFilename != "" && oldConfigFilename != newConfigFilename {
			if err := os.Remove(oldConfigFile); err != nil && !os.IsNotExist(err) {
				log.Printf("[WARN] Failed to remove old config file %s: %v", oldConfigFilename, err)
			}
		}

		// 5. Test and reload nginx
		if err := m.testAndReloadNginx(ctx); err != nil {
			// Rollback: restore old config file if test fails
			if oldConfigExists && len(oldConfigBackup) > 0 {
				log.Printf("[WARN] Nginx test failed, attempting to restore old config: %s", oldConfigFilename)
				if writeErr := m.writeFileAtomic(oldConfigFile, oldConfigBackup, 0644); writeErr != nil {
					log.Printf("[ERROR] Failed to restore old config file %s: %v", oldConfigFilename, writeErr)
				}
				// Also remove the new (invalid) config file
				newConfigFile := filepath.Join(m.configPath, newConfigFilename)
				if removeErr := os.Remove(newConfigFile); removeErr != nil && !os.IsNotExist(removeErr) {
					log.Printf("[ERROR] Failed to remove invalid new config file %s: %v", newConfigFilename, removeErr)
				}
			}
			return err
		}

		return nil
	})
}

// RemoveConfigAndReload removes proxy host config, WAF config, tests and reloads nginx
func (m *Manager) RemoveConfigAndReload(ctx context.Context, host *model.ProxyHost) error {
	return m.executeWithLock(ctx, func() error {
		// Remove configs
		if err := m.RemoveConfig(ctx, host); err != nil {
			return err
		}

		// Test and reload nginx
		if err := m.testAndReloadNginx(ctx); err != nil {
			return err
		}

		return nil
	})
}

// testConfigInternal is the internal test function without locking
func (m *Manager) testConfigInternal(ctx context.Context) error {
	if m.skipTest {
		return nil
	}

	// Try docker exec first (for containerized environments)
	cmd := exec.CommandContext(ctx, "docker", "exec", m.nginxContainer, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		// If we got nginx output, return it
		if outputStr != "" {
			return fmt.Errorf("nginx config test failed: %s", outputStr)
		}
		// If output is empty, try to capture error details
		log.Printf("[TestConfig] docker exec failed with empty output, err: %v", err)
		// Fallback to direct nginx command (for non-containerized environments)
		cmd = exec.CommandContext(ctx, "nginx", "-t")
		output, err = cmd.CombinedOutput()
		if err != nil {
			fallbackOutput := strings.TrimSpace(string(output))
			if fallbackOutput != "" {
				return fmt.Errorf("nginx config test failed: %s", fallbackOutput)
			}
			return fmt.Errorf("nginx config test failed: %v", err)
		}
	}
	return nil
}

// reloadNginxInternal is the internal reload function without locking
func (m *Manager) reloadNginxInternal(ctx context.Context) error {
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

	// Set listen ports from manager config
	data.HTTPPort = m.httpPort
	data.HTTPSPort = m.httpsPort

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

	// Check if AdvancedConfig contains a custom location / block
	// If so, skip generating the default location / block to avoid duplicates
	if data.Host.AdvancedConfig != "" {
		// Check for location / { pattern (with flexible whitespace)
		locationPattern := regexp.MustCompile(`(?m)^\s*location\s+/\s*\{`)
		data.HasCustomLocationRoot = locationPattern.MatchString(data.Host.AdvancedConfig)

		// Check if AdvancedConfig contains ANY location directive
		// If so, we cannot inject it inside location / block (would cause nested location error)
		anyLocationPattern := regexp.MustCompile(`(?m)^\s*location\s+`)
		data.AdvancedConfigHasLocation = anyLocationPattern.MatchString(data.Host.AdvancedConfig)
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
	
	// Use atomic write to prevent nginx from reading partial config
	if err := m.writeFileAtomic(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (m *Manager) RemoveConfig(ctx context.Context, host *model.ProxyHost) error {
	configFile := filepath.Join(m.configPath, GetConfigFilename(host))

	// Check if file exists before removing
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Even if main config doesn't exist, try to remove WAF config to be safe
		_ = m.RemoveHostWAFConfig(ctx, host.ID)
		_ = m.RemoveCloudIPsInclude(host.ID)
		return nil
	}

	if err := os.Remove(configFile); err != nil {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	// Remove WAF config if it exists
	// We verify WAF status but try to remove file anyway to ensure cleanup
	if err := m.RemoveHostWAFConfig(ctx, host.ID); err != nil {
		log.Printf("[WARN] Failed to remove WAF config for host %s: %v", host.ID, err)
		// Don't return error here, as main config removal was successful
	}

	// Also remove the cloud IPs include file if it exists
	_ = m.RemoveCloudIPsInclude(host.ID)

	return nil
}

// RemoveConfigByFilename removes a config file by its filename
// This is used when the domain name changes, causing the config filename to change
func (m *Manager) RemoveConfigByFilename(ctx context.Context, filename string) error {
	configFile := filepath.Join(m.configPath, filename)

	// Check if file exists before removing
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to do
	}

	if err := os.Remove(configFile); err != nil {
		log.Printf("[WARN] Failed to remove old config file %s: %v", filename, err)
		return err
	}

	log.Printf("[INFO] Removed old config file: %s", filename)
	return nil
}

func (m *Manager) TestConfig(ctx context.Context) error {
	return m.executeWithLock(ctx, func() error {
		return m.testConfigInternal(ctx)
	})
}

func (m *Manager) ReloadNginx(ctx context.Context) error {
	return m.executeWithLock(ctx, func() error {
		return m.reloadNginxInternal(ctx)
	})
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
