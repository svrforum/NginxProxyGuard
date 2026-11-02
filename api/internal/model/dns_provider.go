package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DNS Provider types
const (
	DNSProviderCloudflare = "cloudflare"
	DNSProviderRoute53    = "route53"
	DNSProviderDuckDNS    = "duckdns"
	DNSProviderDynu       = "dynu"
	DNSProviderManual     = "manual"
	DNSProviderIonos      = "ionos"
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
	// Route 53 only: the row authenticates with the host's AWS credentials,
	// so the edit form can open with that choice (#357).
	UseDefaultCredentials bool `json:"use_default_credentials,omitempty"`
}

// CloudflareCredentials represents Cloudflare API credentials
type CloudflareCredentials struct {
	APIToken string `json:"api_token,omitempty"` // Recommended: API Token with Zone:DNS:Edit and Zone:Read
	APIKey   string `json:"api_key,omitempty"`   // Legacy: Global API Key
	Email    string `json:"email,omitempty"`     // Required if using API Key
	ZoneID   string `json:"zone_id,omitempty"`   // Optional: Cloudflare Zone ID (bypasses SOA-based zone detection)
}

// Route53Credentials represents AWS Route53 credentials: an access key pair,
// or UseDefaultCredentials and no keys. With the flag, lego builds its AWS
// client without static credentials and the SDK's default credential chain
// supplies them — the environment, the shared config and credentials files,
// an ECS task role or an EC2 instance role read from the instance metadata
// service. That is how AWS recommends a host authenticate, without a
// permanent key. Missing keys alone do not mean that: the edit form sends
// blank key fields, and a row without keys would otherwise authenticate as
// whatever role the host has (#357).
type Route53Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region,omitempty"`
	HostedZoneID    string `json:"hosted_zone_id,omitempty"`
	// Authenticate with the AWS default credential chain; no keys allowed.
	UseDefaultCredentials bool `json:"use_default_credentials,omitempty"`
}

// UsesDefaultCredentialChain reports whether the row leaves authentication
// to the AWS SDK's default credential chain.
func (c Route53Credentials) UsesDefaultCredentialChain() bool {
	return c.UseDefaultCredentials
}

// Validate requires the access key pair, or use_default_credentials and no
// keys. lego refuses half a pair too, but only when a certificate is issued;
// here it is a 400 on create and update.
func (c Route53Credentials) Validate() error {
	if c.UseDefaultCredentials {
		if c.AccessKeyID != "" || c.SecretAccessKey != "" {
			return fmt.Errorf("%w: route53 takes no access key with use_default_credentials", ErrInvalidCredentials)
		}
		return nil
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return fmt.Errorf("%w: route53 needs access_key_id and secret_access_key, or use_default_credentials for the AWS default credential chain", ErrInvalidCredentials)
	}
	return nil
}

// DuckDNSCredentials represents DuckDNS API credentials
type DuckDNSCredentials struct {
	Token string `json:"token"` // DuckDNS API token
}

// DynuCredentials represents Dynu API credentials
type DynuCredentials struct {
	APIKey string `json:"api_key"` // Dynu API key
}

// IonosCredentials holds the credential pair IONOS hands out: an API
// key prefix, the public identifier, and the secret key that goes with
// it. lego carries them joined by a dot as one value in the X-Api-Key
// header of every request, so the halves are stored separately here and
// joined only where the provider is built.
type IonosCredentials struct {
	APIKeyPrefix string `json:"api_key_prefix" validate:"required"`
	APIKey       string `json:"api_key" validate:"required"`
}

// Normalized returns the pair as it is checked, stored and sent to IONOS:
// both halves trimmed, and the secret without a copy of the prefix in front.
// Pasting the whole key (prefix.secret) into the secret field is the easy
// mistake; lego would then send prefix.prefix.secret, which IONOS refuses
// only when a certificate is issued.
func (c IonosCredentials) Normalized() IonosCredentials {
	c.APIKeyPrefix = strings.TrimSpace(c.APIKeyPrefix)
	c.APIKey = strings.TrimSpace(c.APIKey)
	if c.APIKeyPrefix != "" {
		c.APIKey = strings.TrimPrefix(c.APIKey, c.APIKeyPrefix+".")
	}
	return c
}

// CreateDNSProviderRequest is the request body for creating a DNS provider
type CreateDNSProviderRequest struct {
	Name         string          `json:"name" validate:"required"`
	ProviderType string          `json:"provider_type" validate:"required,oneof=cloudflare route53 duckdns dynu manual ionos"`
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
	if p.ProviderType == DNSProviderRoute53 {
		var creds Route53Credentials
		if json.Unmarshal(p.Credentials, &creds) == nil {
			masked.UseDefaultCredentials = creds.UseDefaultCredentials
		}
	}
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
		if err := creds.Validate(); err != nil {
			return err
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
	case DNSProviderIonos:
		// IONOS hands the credential over as a pair: prefix and secret key.
		// A row that carries only one half cannot authenticate.
		var creds IonosCredentials
		if err := json.Unmarshal(p.Credentials, &creds); err != nil {
			return err
		}
		if creds.APIKeyPrefix == "" || creds.APIKey == "" {
			return ErrInvalidCredentials
		}
	case DNSProviderManual:
		// No credentials needed for manual DNS
	}
	return nil
}
