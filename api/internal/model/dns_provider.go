package model

import (
	"encoding/json"
	"time"
)

// DNS Provider types
const (
	DNSProviderCloudflare = "cloudflare"
	DNSProviderRoute53    = "route53"
	DNSProviderDuckDNS    = "duckdns"
	DNSProviderDynu       = "dynu"
	DNSProviderManual     = "manual"
)

// DNSProvider represents a DNS provider configuration for ACME DNS-01 challenges
type DNSProvider struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	ProviderType string          `json:"provider_type"` // cloudflare, route53, manual
	Credentials  json.RawMessage `json:"-"`             // Not exposed in API responses
	IsDefault    bool            `json:"is_default"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`

	// For API responses - masked credentials
	HasCredentials bool `json:"has_credentials"`
}

// CloudflareCredentials represents Cloudflare API credentials
type CloudflareCredentials struct {
	APIToken string `json:"api_token,omitempty"` // Recommended: API Token with Zone:DNS:Edit and Zone:Read
	APIKey   string `json:"api_key,omitempty"`   // Legacy: Global API Key
	Email    string `json:"email,omitempty"`     // Required if using API Key
}

// Route53Credentials represents AWS Route53 credentials
type Route53Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region,omitempty"`
	HostedZoneID    string `json:"hosted_zone_id,omitempty"`
}

// DuckDNSCredentials represents DuckDNS API credentials
type DuckDNSCredentials struct {
	Token string `json:"token"` // DuckDNS API token
}

// DynuCredentials represents Dynu API credentials
type DynuCredentials struct {
	APIKey string `json:"api_key"` // Dynu API key
}

// CreateDNSProviderRequest is the request body for creating a DNS provider
type CreateDNSProviderRequest struct {
	Name         string          `json:"name" validate:"required"`
	ProviderType string          `json:"provider_type" validate:"required,oneof=cloudflare route53 duckdns dynu manual"`
	Credentials  json.RawMessage `json:"credentials" validate:"required"`
	IsDefault    bool            `json:"is_default"`
}

// UpdateDNSProviderRequest is the request body for updating a DNS provider
type UpdateDNSProviderRequest struct {
	Name        *string          `json:"name,omitempty"`
	Credentials *json.RawMessage `json:"credentials,omitempty"`
	IsDefault   *bool            `json:"is_default,omitempty"`
}

// DNSProviderListResponse is the paginated list response
type DNSProviderListResponse struct {
	Data       []DNSProvider `json:"data"`
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	PerPage    int           `json:"per_page"`
	TotalPages int           `json:"total_pages"`
}

// MaskCredentials returns a provider with masked credential info
func (p *DNSProvider) MaskCredentials() DNSProvider {
	masked := *p
	masked.Credentials = nil
	masked.HasCredentials = len(p.Credentials) > 0 && string(p.Credentials) != "{}"
	return masked
}

// ValidateCredentials checks if the credentials are valid for the provider type
func (p *DNSProvider) ValidateCredentials() error {
	switch p.ProviderType {
	case DNSProviderCloudflare:
		var creds CloudflareCredentials
		if err := json.Unmarshal(p.Credentials, &creds); err != nil {
			return err
		}
		// Need either API Token or (API Key + Email)
		if creds.APIToken == "" && (creds.APIKey == "" || creds.Email == "") {
			return ErrInvalidCredentials
		}
	case DNSProviderRoute53:
		var creds Route53Credentials
		if err := json.Unmarshal(p.Credentials, &creds); err != nil {
			return err
		}
		if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			return ErrInvalidCredentials
		}
	case DNSProviderDuckDNS:
		var creds DuckDNSCredentials
		if err := json.Unmarshal(p.Credentials, &creds); err != nil {
			return err
		}
		if creds.Token == "" {
			return ErrInvalidCredentials
		}
	case DNSProviderDynu:
		var creds DynuCredentials
		if err := json.Unmarshal(p.Credentials, &creds); err != nil {
			return err
		}
		if creds.APIKey == "" {
			return ErrInvalidCredentials
		}
	case DNSProviderManual:
		// No credentials needed for manual DNS
	}
	return nil
}
