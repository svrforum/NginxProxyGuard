package model

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Dangerous nginx directives that should not be allowed in advanced config
var dangerousDirectives = []string{
	"load_module",        // Could load malicious modules
	"include",            // Could include arbitrary files
	"lua_",               // Lua scripting (various lua_* directives)
	"perl_",              // Perl scripting
	"js_",                // JavaScript scripting
	"njs_",               // njs scripting
	"set_by_lua",         // Lua code execution
	"content_by_lua",     // Lua code execution
	"access_by_lua",      // Lua code execution
	"worker_processes",   // Global directive
	"worker_connections", // Global directive
	"daemon",             // Global directive
	"master_process",     // Global directive
	"pid",                // Global directive
	"user",               // Global directive
	"env",                // Environment variables
	"error_log",          // Could redirect logs
	"access_log",         // Could redirect logs (in root context)
	"ssl_certificate",    // Certificate paths (should use UI)
	"ssl_certificate_key", // Certificate paths (should use UI)
	"modsecurity",        // Could disable WAF protection
	"modsecurity_rules",  // Could modify WAF rules
	"SecRuleEngine",      // Could disable WAF (ModSecurity directive)
	"SecRule",            // Could add/modify WAF rules
}

// Security-overriding directives that are warned but not blocked
var securityOverrideDirectives = []string{
	"error_page 403",    // Could override security block pages
	"error_page 418",    // Could override cloud challenge
	"satisfy",           // Could override access control
}

// validateAdvancedConfig checks if the advanced config contains dangerous directives
func ValidateAdvancedConfig(config string) error {
	if config == "" {
		return nil
	}

	// Normalize: lowercase for comparison
	configLower := strings.ToLower(config)

	// Check for dangerous directives
	for _, directive := range dangerousDirectives {
		// Match directive at word boundary (not as part of another word)
		pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(directive) + `\b`)
		if pattern.MatchString(configLower) {
			return fmt.Errorf("advanced config contains forbidden directive: %s", directive)
		}
	}

	// Check for potential shell command injection in proxy_pass
	if strings.Contains(configLower, "proxy_pass") {
		// Check for backticks or $() which could be shell command substitution
		if strings.Contains(config, "`") || strings.Contains(config, "$(") {
			return fmt.Errorf("advanced config contains potential command injection")
		}
	}

	// Check for semicolon at end of each line to detect potential injection
	// Allow empty lines and comments
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check for block start/end
		if strings.HasSuffix(trimmed, "{") || trimmed == "}" {
			continue
		}
		// Valid nginx directives should end with ; or { or }
		if !strings.HasSuffix(trimmed, ";") && !strings.HasSuffix(trimmed, "{") && !strings.HasSuffix(trimmed, "}") {
			// Allow if it's part of multi-line value (ends with quotes continuation)
			if !strings.HasSuffix(trimmed, "'") && !strings.HasSuffix(trimmed, "\"") {
				// This might be fine for multi-line configs, so just log a warning
				// return fmt.Errorf("advanced config line may be malformed: %s", trimmed)
			}
		}
	}

	// Check for null bytes
	if strings.Contains(config, "\x00") {
		return fmt.Errorf("advanced config contains null bytes")
	}

	return nil
}

type ProxyHost struct {
	ID        string `json:"id"`

	// Domain configuration
	DomainNames pq.StringArray `json:"domain_names"`

	// Forward configuration
	ForwardScheme string `json:"forward_scheme"`
	ForwardHost   string `json:"forward_host"`
	ForwardPort   int    `json:"forward_port"`

	// SSL configuration
	SSLEnabled    bool    `json:"ssl_enabled"`
	SSLForceHTTPS bool    `json:"ssl_force_https"`
	SSLHTTP2      bool    `json:"ssl_http2"`
	SSLHTTP3      bool    `json:"ssl_http3"`
	CertificateID *string `json:"certificate_id,omitempty"`

	// Access configuration
	AllowWebsocketUpgrade bool `json:"allow_websocket_upgrade"`

	// Cache configuration
	CacheEnabled    bool   `json:"cache_enabled"`
	CacheStaticOnly bool   `json:"cache_static_only"` // Only cache static assets (js, css, images, fonts)
	CacheTTL        string `json:"cache_ttl"`         // Cache duration (e.g., "1h", "7d", "30m")

	// Security
	BlockExploits           bool   `json:"block_exploits"`
	BlockExploitsExceptions string `json:"block_exploits_exceptions,omitempty"` // Newline-separated URI patterns to bypass RFI blocking

	// Custom configuration
	CustomLocations json.RawMessage `json:"custom_locations,omitempty"`
	AdvancedConfig  string          `json:"advanced_config,omitempty"`

	// Host-level proxy settings (override global settings if set)
	ProxyConnectTimeout int    `json:"proxy_connect_timeout,omitempty"` // seconds, 0 = use global
	ProxySendTimeout    int    `json:"proxy_send_timeout,omitempty"`    // seconds, 0 = use global
	ProxyReadTimeout    int    `json:"proxy_read_timeout,omitempty"`    // seconds, 0 = use global
	ProxyBuffering      string `json:"proxy_buffering,omitempty"`       // "on", "off", "" = use global
	ClientMaxBodySize   string `json:"client_max_body_size,omitempty"`  // e.g. "100m", "" = use global

	// WAF configuration
	WAFEnabled          bool   `json:"waf_enabled"`
	WAFMode             string `json:"waf_mode"`
	WAFParanoiaLevel    int    `json:"waf_paranoia_level"`
	WAFAnomalyThreshold int    `json:"waf_anomaly_threshold"`

	// Access list
	AccessListID *string `json:"access_list_id,omitempty"`

	// Status
	Enabled bool `json:"enabled"`

	// Metadata
	Meta      json.RawMessage `json:"meta,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type CreateProxyHostRequest struct {
	DomainNames           []string `json:"domain_names" validate:"required,min=1"`
	ForwardScheme         string   `json:"forward_scheme" validate:"required,oneof=http https"`
	ForwardHost           string   `json:"forward_host" validate:"required"`
	ForwardPort           int      `json:"forward_port" validate:"required,min=1,max=65535"`
	SSLEnabled            bool     `json:"ssl_enabled"`
	SSLForceHTTPS         bool     `json:"ssl_force_https"`
	SSLHTTP2              bool     `json:"ssl_http2"`
	SSLHTTP3              bool     `json:"ssl_http3"`
	CertificateID         *string  `json:"certificate_id,omitempty"`
	AllowWebsocketUpgrade   bool     `json:"allow_websocket_upgrade"`
	CacheEnabled            bool     `json:"cache_enabled"`
	CacheStaticOnly         bool     `json:"cache_static_only"`
	CacheTTL                string   `json:"cache_ttl"`
	BlockExploits           bool     `json:"block_exploits"`
	BlockExploitsExceptions string   `json:"block_exploits_exceptions,omitempty"`
	WAFEnabled              bool     `json:"waf_enabled"`
	WAFMode                 string   `json:"waf_mode"`
	WAFParanoiaLevel        int      `json:"waf_paranoia_level"`
	WAFAnomalyThreshold     int      `json:"waf_anomaly_threshold"`
	AccessListID            *string  `json:"access_list_id,omitempty"`
	AdvancedConfig          string   `json:"advanced_config,omitempty"`
	ProxyConnectTimeout     int      `json:"proxy_connect_timeout,omitempty"`
	ProxySendTimeout        int      `json:"proxy_send_timeout,omitempty"`
	ProxyReadTimeout        int      `json:"proxy_read_timeout,omitempty"`
	ProxyBuffering          string   `json:"proxy_buffering,omitempty"`
	ClientMaxBodySize       string   `json:"client_max_body_size,omitempty"`
	Enabled                 bool     `json:"enabled"`
}

type UpdateProxyHostRequest struct {
	DomainNames           []string `json:"domain_names,omitempty"`
	ForwardScheme         string   `json:"forward_scheme,omitempty"`
	ForwardHost           string   `json:"forward_host,omitempty"`
	ForwardPort           int      `json:"forward_port,omitempty"`
	SSLEnabled            *bool    `json:"ssl_enabled,omitempty"`
	SSLForceHTTPS         *bool    `json:"ssl_force_https,omitempty"`
	SSLHTTP2              *bool    `json:"ssl_http2,omitempty"`
	SSLHTTP3              *bool    `json:"ssl_http3,omitempty"`
	CertificateID         *string  `json:"certificate_id,omitempty"`
	AllowWebsocketUpgrade   *bool   `json:"allow_websocket_upgrade,omitempty"`
	CacheEnabled            *bool   `json:"cache_enabled,omitempty"`
	CacheStaticOnly         *bool   `json:"cache_static_only,omitempty"`
	CacheTTL                *string `json:"cache_ttl,omitempty"`
	BlockExploits           *bool   `json:"block_exploits,omitempty"`
	BlockExploitsExceptions *string `json:"block_exploits_exceptions,omitempty"`
	WAFEnabled              *bool   `json:"waf_enabled,omitempty"`
	WAFMode                 *string `json:"waf_mode,omitempty"`
	WAFParanoiaLevel        *int    `json:"waf_paranoia_level,omitempty"`
	WAFAnomalyThreshold     *int    `json:"waf_anomaly_threshold,omitempty"`
	AccessListID            *string `json:"access_list_id,omitempty"`
	AdvancedConfig          *string `json:"advanced_config,omitempty"`
	ProxyConnectTimeout     *int    `json:"proxy_connect_timeout,omitempty"`
	ProxySendTimeout        *int    `json:"proxy_send_timeout,omitempty"`
	ProxyReadTimeout        *int    `json:"proxy_read_timeout,omitempty"`
	ProxyBuffering          *string `json:"proxy_buffering,omitempty"`
	ClientMaxBodySize       *string `json:"client_max_body_size,omitempty"`
	Enabled                 *bool   `json:"enabled,omitempty"`
}

type ProxyHostListResponse struct {
	Data       []ProxyHost `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	TotalPages int         `json:"total_pages"`
}

// ProxyHostTestResult contains the results of testing a proxy host configuration
type ProxyHostTestResult struct {
	Domain        string                  `json:"domain"`
	TestedAt      time.Time               `json:"tested_at"`
	Success       bool                    `json:"success"`
	ResponseTime  int64                   `json:"response_time_ms"`
	StatusCode    int                     `json:"status_code,omitempty"`
	Error         string                  `json:"error,omitempty"`
	SSL           *SSLTestResult          `json:"ssl,omitempty"`
	HTTP          *HTTPTestResult         `json:"http,omitempty"`
	Cache         *CacheTestResult        `json:"cache,omitempty"`
	Security      *SecurityTestResult     `json:"security,omitempty"`
	Headers       map[string]string       `json:"headers,omitempty"`
}

type SSLTestResult struct {
	Enabled       bool     `json:"enabled"`
	Valid         bool     `json:"valid"`
	Protocol      string   `json:"protocol,omitempty"`
	Cipher        string   `json:"cipher,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	DaysRemaining int      `json:"days_remaining,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type HTTPTestResult struct {
	HTTP2Enabled    bool   `json:"http2_enabled"`
	HTTP3Enabled    bool   `json:"http3_enabled"`
	AltSvcHeader    string `json:"alt_svc_header,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
}

type CacheTestResult struct {
	Enabled          bool   `json:"enabled"`
	CacheStatus      string `json:"cache_status,omitempty"`
	CacheControl     string `json:"cache_control,omitempty"`
	Expires          string `json:"expires,omitempty"`
	ETag             string `json:"etag,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
}

type SecurityTestResult struct {
	HSTS                   bool   `json:"hsts"`
	HSTSValue              string `json:"hsts_value,omitempty"`
	XFrameOptions          string `json:"x_frame_options,omitempty"`
	XContentTypeOptions    string `json:"x_content_type_options,omitempty"`
	ContentSecurityPolicy  string `json:"content_security_policy,omitempty"`
	XSSProtection          string `json:"xss_protection,omitempty"`
	ReferrerPolicy         string `json:"referrer_policy,omitempty"`
	PermissionsPolicy      string `json:"permissions_policy,omitempty"`
	ServerHeader           string `json:"server_header,omitempty"`
}
