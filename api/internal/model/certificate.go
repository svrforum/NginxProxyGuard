package model

import (
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

// Certificate status constants
const (
	CertStatusPending  = "pending"
	CertStatusIssued   = "issued"
	CertStatusExpired  = "expired"
	CertStatusError    = "error"
	CertStatusRenewing = "renewing"
)

// Certificate provider types
const (
	CertProviderLetsEncrypt = "letsencrypt"
	CertProviderSelfSigned  = "selfsigned"
	CertProviderCustom      = "custom"
)

// Certificate represents an SSL certificate
type Certificate struct {
	ID                   string         `json:"id"`
	DomainNames          pq.StringArray `json:"domain_names"`
	DNSProviderID        *string        `json:"dns_provider_id,omitempty"`
	Status               string         `json:"status"`
	Provider             string         `json:"provider"` // letsencrypt, custom, etc.
	AutoRenew            bool           `json:"auto_renew"`
	ExpiresAt            *time.Time     `json:"expires_at,omitempty"`
	IssuedAt             *time.Time     `json:"issued_at,omitempty"`
	RenewalAttemptedAt   *time.Time     `json:"renewal_attempted_at,omitempty"`
	ErrorMessage         *string        `json:"error_message,omitempty"`
	CertificatePath      *string        `json:"certificate_path,omitempty"`
	PrivateKeyPath       *string        `json:"private_key_path,omitempty"`
	CertificatePEM       string         `json:"-"` // Not exposed in API
	PrivateKeyPEM        string         `json:"-"` // Not exposed in API
	IssuerCertificatePEM string         `json:"-"` // Not exposed in API
	AcmeAccount          json.RawMessage `json:"-"` // Not exposed in API
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`

	// Joined data
	DNSProvider *DNSProvider `json:"dns_provider,omitempty"`
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (c *Certificate) DaysUntilExpiry() int {
	if c.ExpiresAt == nil {
		return -1
	}
	return int(time.Until(*c.ExpiresAt).Hours() / 24)
}

// NeedsRenewal returns true if the certificate needs renewal (expires in 30 days or less)
func (c *Certificate) NeedsRenewal() bool {
	return c.DaysUntilExpiry() <= 30
}

// CreateCertificateRequest is the request body for creating a certificate
type CreateCertificateRequest struct {
	DomainNames   []string `json:"domain_names" validate:"required,min=1"`
	DNSProviderID *string  `json:"dns_provider_id,omitempty"` // Required for letsencrypt
	Provider      string   `json:"provider"`                   // letsencrypt, selfsigned, custom
	AutoRenew     bool     `json:"auto_renew"`
	// For self-signed certificates
	ValidityDays int `json:"validity_days,omitempty"` // Default 365 for self-signed
}

// CreateSelfSignedRequest is for generating self-signed certificates
type CreateSelfSignedRequest struct {
	DomainNames  []string `json:"domain_names" validate:"required,min=1"`
	ValidityDays int      `json:"validity_days"` // Default 365
	Organization string   `json:"organization,omitempty"`
	Country      string   `json:"country,omitempty"`
}

// UploadCertificateRequest is for uploading custom certificates
type UploadCertificateRequest struct {
	DomainNames    []string `json:"domain_names" validate:"required,min=1"`
	CertificatePEM string   `json:"certificate_pem" validate:"required"`
	PrivateKeyPEM  string   `json:"private_key_pem" validate:"required"`
	IssuerPEM      string   `json:"issuer_pem,omitempty"`
}

// CertificateListResponse is the paginated list response
type CertificateListResponse struct {
	Data       []CertificateWithDetails `json:"data"`
	Total      int                      `json:"total"`
	Page       int                      `json:"page"`
	PerPage    int                      `json:"per_page"`
	TotalPages int                      `json:"total_pages"`
}

// CertificateWithDetails includes additional computed fields
type CertificateWithDetails struct {
	Certificate
	DaysUntilExpiry int  `json:"days_until_expiry"`
	NeedsRenewal    bool `json:"needs_renewal"`
}

// ToWithDetails converts Certificate to CertificateWithDetails
func (c *Certificate) ToWithDetails() CertificateWithDetails {
	return CertificateWithDetails{
		Certificate:     *c,
		DaysUntilExpiry: c.DaysUntilExpiry(),
		NeedsRenewal:    c.NeedsRenewal(),
	}
}

// CertificateLog represents a log entry during certificate issuance
type CertificateLog struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // info, warn, error, success
	Message   string    `json:"message"`
	Step      string    `json:"step,omitempty"` // e.g., "validation", "challenge", "finalize"
}

// CertificateLogResponse is the response for certificate logs API
type CertificateLogResponse struct {
	CertificateID string           `json:"certificate_id"`
	Status        string           `json:"status"`
	Logs          []CertificateLog `json:"logs"`
	IsComplete    bool             `json:"is_complete"`
}

// CertificateHistory represents a historical record of certificate operations
type CertificateHistory struct {
	ID            string     `json:"id"`
	CertificateID string     `json:"certificate_id"`
	Action        string     `json:"action"` // issued, renewed, error, expired
	Status        string     `json:"status"` // success, error
	Message       string     `json:"message,omitempty"`
	DomainNames   pq.StringArray `json:"domain_names"`
	Provider      string     `json:"provider"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Logs          string     `json:"logs,omitempty"` // JSON array of CertificateLog
	CreatedAt     time.Time  `json:"created_at"`
}

// CertificateHistoryListResponse is the paginated list response for history
type CertificateHistoryListResponse struct {
	Data       []CertificateHistory `json:"data"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"per_page"`
	TotalPages int                  `json:"total_pages"`
}
