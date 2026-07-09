package model

import "time"

// SecurityHeaders represents security headers configuration for a proxy host
type SecurityHeaders struct {
	ID                    string            `json:"id"`
	ProxyHostID           string            `json:"proxy_host_id"`
	Enabled               bool              `json:"enabled"`
	HSTSEnabled           bool              `json:"hsts_enabled"`
	HSTSMaxAge            int               `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool              `json:"hsts_include_subdomains"`
	HSTSPreload           bool              `json:"hsts_preload"`
	XFrameOptions         string            `json:"x_frame_options"`
	XContentTypeOptions   bool              `json:"x_content_type_options"`
	XXSSProtection        bool              `json:"x_xss_protection"`
	ReferrerPolicy        string            `json:"referrer_policy"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	DisableGlobal         bool              `json:"disable_global"` // opt out of global security-headers default (#198)
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// CreateSecurityHeadersRequest is the request to create/update security headers config
type CreateSecurityHeadersRequest struct {
	Enabled               *bool             `json:"enabled,omitempty"`
	HSTSEnabled           *bool             `json:"hsts_enabled,omitempty"`
	HSTSMaxAge            int               `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubdomains *bool             `json:"hsts_include_subdomains,omitempty"`
	HSTSPreload           *bool             `json:"hsts_preload,omitempty"`
	XFrameOptions         string            `json:"x_frame_options,omitempty"`
	XContentTypeOptions   *bool             `json:"x_content_type_options,omitempty"`
	XXSSProtection        *bool             `json:"x_xss_protection,omitempty"`
	ReferrerPolicy        string            `json:"referrer_policy,omitempty"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	DisableGlobal         *bool             `json:"disable_global,omitempty"`
}

// GlobalSecurityHeaders is the singleton global security-headers default inherited
// by hosts that don't override or disable (#198).
type GlobalSecurityHeaders struct {
	ID                    string            `json:"id"`
	Enabled               bool              `json:"enabled"`
	HSTSEnabled           bool              `json:"hsts_enabled"`
	HSTSMaxAge            int               `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool              `json:"hsts_include_subdomains"`
	HSTSPreload           bool              `json:"hsts_preload"`
	XFrameOptions         string            `json:"x_frame_options"`
	XContentTypeOptions   bool              `json:"x_content_type_options"`
	XXSSProtection        bool              `json:"x_xss_protection"`
	ReferrerPolicy        string            `json:"referrer_policy"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// UpdateGlobalSecurityHeadersRequest is a partial update for the singleton.
type UpdateGlobalSecurityHeadersRequest struct {
	Enabled               *bool             `json:"enabled,omitempty"`
	HSTSEnabled           *bool             `json:"hsts_enabled,omitempty"`
	HSTSMaxAge            int               `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubdomains *bool             `json:"hsts_include_subdomains,omitempty"`
	HSTSPreload           *bool             `json:"hsts_preload,omitempty"`
	XFrameOptions         string            `json:"x_frame_options,omitempty"`
	XContentTypeOptions   *bool             `json:"x_content_type_options,omitempty"`
	XXSSProtection        *bool             `json:"x_xss_protection,omitempty"`
	ReferrerPolicy        string            `json:"referrer_policy,omitempty"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
}

// Common security header presets
var SecurityHeaderPresets = map[string]SecurityHeaders{
	"strict": {
		Enabled:               true,
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
		XFrameOptions:         "DENY",
		XContentTypeOptions:   true,
		XXSSProtection:        true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
	},
	"moderate": {
		Enabled:               true,
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           false,
		XFrameOptions:         "SAMEORIGIN",
		XContentTypeOptions:   true,
		XXSSProtection:        true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	},
	"relaxed": {
		Enabled:               true,
		HSTSEnabled:           true,
		HSTSMaxAge:            86400,
		HSTSIncludeSubdomains: false,
		HSTSPreload:           false,
		XFrameOptions:         "SAMEORIGIN",
		XContentTypeOptions:   true,
		XXSSProtection:        true,
		ReferrerPolicy:        "no-referrer-when-downgrade",
	},
}

// X-Frame-Options valid values
var ValidXFrameOptions = []string{
	"DENY",
	"SAMEORIGIN",
}

// Referrer-Policy valid values
var ValidReferrerPolicies = []string{
	"no-referrer",
	"no-referrer-when-downgrade",
	"origin",
	"origin-when-cross-origin",
	"same-origin",
	"strict-origin",
	"strict-origin-when-cross-origin",
	"unsafe-url",
}
