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

	"nginx-proxy-guard/internal/config"
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
	apiURL         string // API URL for nginx to reach API (default: http://127.0.0.1:9080)
	dnsResolver    string // DNS resolver for nginx (default: 127.0.0.53 8.8.8.8)
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

	// API URL for nginx to reach API (host network mode)
	// nginx runs in host mode, so it reaches API via localhost
	apiHostPort := os.Getenv("API_HOST_PORT")
	if apiHostPort == "" {
		apiHostPort = "9080"
	}
	apiURL := "http://127.0.0.1:" + apiHostPort

	// DNS resolver for nginx (host network mode uses system resolver)
	dnsResolver := os.Getenv("DNS_RESOLVER")
	if dnsResolver == "" {
		dnsResolver = "127.0.0.53 8.8.8.8"
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
		dnsResolver:    dnsResolver,
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
	// Check if context is already cancelled before waiting for the lock
	if ctx.Err() != nil {
		return fmt.Errorf("nginx operation cancelled before acquiring lock: %w", ctx.Err())
	}

	globalNginxMutex.Lock()
	defer globalNginxMutex.Unlock()

	// Check again after acquiring the lock (may have waited a long time)
	if ctx.Err() != nil {
		return fmt.Errorf("nginx operation cancelled while waiting for lock: %w", ctx.Err())
	}

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
// On test failure, it rolls back to the previous config
func (m *Manager) GenerateConfigAndReload(ctx context.Context, data ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion) error {
	return m.executeWithLock(ctx, func() error {
		configFilename := GetConfigFilename(data.Host)
		configFile := filepath.Join(m.configPath, configFilename)
		wafConfigFile := filepath.Join(m.modsecPath, fmt.Sprintf("host_%s.conf", data.Host.ID))

		// 1. Backup existing configs for rollback
		var configBackup []byte
		var wafConfigBackup []byte
		configExists := false
		wafConfigExists := false

		if content, err := os.ReadFile(configFile); err == nil {
			configBackup = content
			configExists = true
		}
		if content, err := os.ReadFile(wafConfigFile); err == nil {
			wafConfigBackup = content
			wafConfigExists = true
		}

		// 2. Generate main proxy host config
		if err := m.GenerateConfigFull(ctx, data); err != nil {
			return fmt.Errorf("failed to generate proxy host config: %w", err)
		}

		// 3. Generate or remove WAF config based on WAF enabled status
		if data.Host.WAFEnabled {
			var allowedIPs []string
			if data.GeoRestriction != nil {
				allowedIPs = data.GeoRestriction.AllowedIPs
			}
			if err := m.GenerateHostWAFConfig(ctx, data.Host, wafExclusions, allowedIPs); err != nil {
				return fmt.Errorf("failed to generate WAF config: %w", err)
			}
		} else {
			if err := m.RemoveHostWAFConfig(ctx, data.Host.ID); err != nil {
				log.Printf("[WARN] Failed to remove WAF config for host %s: %v", data.Host.ID, err)
			}
		}

		// 4. Test and reload nginx (all config files are complete now)
		if err := m.testAndReloadNginx(ctx); err != nil {
			// Rollback: restore previous configs
			log.Printf("[WARN] Nginx test failed, rolling back config for host %s", data.Host.ID)
			if configExists && len(configBackup) > 0 {
				if writeErr := m.writeFileAtomic(configFile, configBackup, 0644); writeErr != nil {
					log.Printf("[ERROR] Failed to restore proxy host config %s: %v", configFilename, writeErr)
				}
			} else if !configExists {
				// Config didn't exist before (new host) - remove the invalid one
				if removeErr := os.Remove(configFile); removeErr != nil && !os.IsNotExist(removeErr) {
					log.Printf("[ERROR] Failed to remove invalid new config %s: %v", configFilename, removeErr)
				}
			}
			if wafConfigExists && len(wafConfigBackup) > 0 {
				if writeErr := m.writeFileAtomic(wafConfigFile, wafConfigBackup, 0644); writeErr != nil {
					log.Printf("[ERROR] Failed to restore WAF config for host %s: %v", data.Host.ID, writeErr)
				}
			} else if !wafConfigExists && data.Host.WAFEnabled {
				if removeErr := os.Remove(wafConfigFile); removeErr != nil && !os.IsNotExist(removeErr) {
					log.Printf("[ERROR] Failed to remove invalid WAF config for host %s: %v", data.Host.ID, removeErr)
				}
			}
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
			var allowedIPs []string
			if data.GeoRestriction != nil {
				allowedIPs = data.GeoRestriction.AllowedIPs
			}
			if err := m.GenerateHostWAFConfig(ctx, data.Host, wafExclusions, allowedIPs); err != nil {
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

	testCtx, cancel := context.WithTimeout(ctx, config.NginxTestTimeout)
	defer cancel()

	cmd := exec.CommandContext(testCtx, "docker", "exec", m.nginxContainer, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if testCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nginx config test timed out after %s", config.NginxTestTimeout)
		}
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" {
			return fmt.Errorf("nginx config test failed: %s", outputStr)
		}
		return fmt.Errorf("nginx config test failed: %v", err)
	}
	return nil
}

// reloadNginxInternal is the internal reload function without locking
func (m *Manager) reloadNginxInternal(ctx context.Context) error {
	if m.skipTest {
		return nil
	}

	reloadCtx, cancel := context.WithTimeout(ctx, config.NginxReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(reloadCtx, "docker", "exec", m.nginxContainer, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if reloadCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nginx reload timed out after %s", config.NginxReloadTimeout)
		}
		return fmt.Errorf("nginx reload failed: %s", string(output))
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

	// Get API host from environment or default (host network mode)
	apiHostValue := os.Getenv("API_HOST")
	if apiHostValue == "" {
		apiHostValue = "127.0.0.1:9080"
	}

	// Use centralized template functions and add proxy-host-specific ones
	funcMap := GetTemplateFuncMap(apiHostValue)
	funcMap["dnsResolver"] = func() string {
		return m.dnsResolver
	}

	// Check if SSL is enabled but certificate files don't exist
	// If so, temporarily disable SSL to generate a working config
	// This is a fallback for when certificate is being issued asynchronously
	sslTemporarilyDisabled := false
	if data.Host.SSLEnabled && (data.Host.CertificateID == nil || *data.Host.CertificateID == "") {
		// No certificate assigned - disable SSL to avoid referencing non-existent cert files
		log.Printf("[WARN] SSL temporarily disabled for host %s (%s): no certificate assigned. Config will be HTTP-only until a certificate is assigned.",
			data.Host.ID, strings.Join(data.Host.DomainNames, ", "))
		data.Host.SSLEnabled = false
		data.Host.SSLForceHTTPS = false
		sslTemporarilyDisabled = true
	}
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

		// Parse directive names from AdvancedConfig to avoid duplicates with template-generated directives
		// When AdvancedConfig is injected inside location / block, directives like proxy_connect_timeout
		// would conflict with the same directives already generated by the template
		data.AdvancedConfigDirectives = parseAdvancedConfigDirectives(data.Host.AdvancedConfig)
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

// parseAdvancedConfigDirectives extracts nginx directive names from AdvancedConfig text.
// This is used to skip template-generated directives that would conflict when AdvancedConfig
// is injected inside the same location block.
func parseAdvancedConfigDirectives(advancedConfig string) map[string]bool {
	directives := make(map[string]bool)
	directivePattern := regexp.MustCompile(`(?m)^\s*([a-z_]+)\s+`)
	for _, match := range directivePattern.FindAllStringSubmatch(advancedConfig, -1) {
		directives[match[1]] = true
	}
	return directives
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

// TestAndReload tests and reloads nginx with a single lock acquisition.
func (m *Manager) TestAndReload(ctx context.Context) error {
	return m.executeWithLock(ctx, func() error {
		return m.testAndReloadNginx(ctx)
	})
}

// GenerateHostWAFConfigAndReload atomically generates per-host WAF config, tests and reloads nginx.
// On test failure, it rolls back to the previous WAF config.
// This should be used instead of calling GenerateHostWAFConfig + TestConfig + ReloadNginx separately.
func (m *Manager) GenerateHostWAFConfigAndReload(ctx context.Context, host *model.ProxyHost, exclusions []model.WAFRuleExclusion, allowedIPs []string) error {
	return m.executeWithLock(ctx, func() error {
		wafConfigFile := filepath.Join(m.modsecPath, fmt.Sprintf("host_%s.conf", host.ID))

		// 1. Backup existing WAF config for rollback
		var wafConfigBackup []byte
		wafConfigExists := false
		if content, err := os.ReadFile(wafConfigFile); err == nil {
			wafConfigBackup = content
			wafConfigExists = true
		}

		// 2. Generate new WAF config
		if err := m.GenerateHostWAFConfig(ctx, host, exclusions, allowedIPs); err != nil {
			return fmt.Errorf("failed to generate WAF config: %w", err)
		}

		// 3. Test and reload nginx
		if err := m.testAndReloadNginx(ctx); err != nil {
			// Rollback: restore previous WAF config
			log.Printf("[WARN] Nginx test failed after WAF config update for host %s, rolling back", host.ID)
			if wafConfigExists && len(wafConfigBackup) > 0 {
				if writeErr := m.writeFileAtomic(wafConfigFile, wafConfigBackup, 0644); writeErr != nil {
					log.Printf("[ERROR] Failed to restore WAF config for host %s: %v", host.ID, writeErr)
				}
			} else if !wafConfigExists {
				if removeErr := os.Remove(wafConfigFile); removeErr != nil && !os.IsNotExist(removeErr) {
					log.Printf("[ERROR] Failed to remove invalid WAF config for host %s: %v", host.ID, removeErr)
				}
			}
			return err
		}

		return nil
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
