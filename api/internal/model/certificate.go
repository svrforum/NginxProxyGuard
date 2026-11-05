package model

import (
	"encoding/json"
	"fmt"
	"strings"
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

// Key types an ACME certificate can be issued with (#364). Every certificate
// issued before had an RSA 2048 key, and that stays the default.
const (
	CertKeyTypeRSA2048 = "rsa2048"
	CertKeyTypeEC256   = "ec256"
	CertKeyTypeEC384   = "ec384"
)

// NormalizeCertKeyType returns the key type a request or a backup names, ""
// meaning RSA 2048, or ErrInvalidInput for any other value.
func NormalizeCertKeyType(keyType string) (string, error) {
	switch k := strings.ToLower(strings.TrimSpace(keyType)); k {
	case "":
		return CertKeyTypeRSA2048, nil
	case CertKeyTypeRSA2048, CertKeyTypeEC256, CertKeyTypeEC384:
		return k, nil
	}
	return "", fmt.Errorf("%w: key_type must be rsa2048, ec256 or ec384", ErrInvalidInput)
}

// Certificate represents an SSL certificate.
//
// CertificatePEM, PrivateKeyPEM, IssuerCertificatePEM and AcmeAccount are key
// material and stay out of every JSON representation (`json:"-"`). That makes a
// marshalled Certificate a LOSSY copy, so it must never be round-tripped
// through a cache, a backup body or an API response and then written back: a
// struct that lost its key material used to overwrite the real one and destroy
// the certificate (#253). Reads that need the material come from
// CertificateRepository.GetByID; writes that carry it go through
// UpdateWithMaterial.
type Certificate struct {
	ID                   string         `json:"id"`
	DomainNames          pq.StringArray `json:"domain_names"`
	DNSProviderID        *string        `json:"dns_provider_id,omitempty"`
	Status               string         `json:"status"`
	Provider             string         `json:"provider"` // letsencrypt, custom, etc.
	AutoRenew            bool           `json:"auto_renew"`
	KeyType              string         `json:"key_type"` // ACME key type; see CertKeyTypeRSA2048
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
	KeyType       string   `json:"key_type,omitempty"`         // letsencrypt: rsa2048 (default), ec256, ec384
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

	// Hosts referencing this certificate — proxy and redirect both, because
	// the delete guard counts both. Always a list, never null, so the panel
	// can tell "nothing is using it" apart from "nobody looked" (#302).
	LinkedHosts []CertificateLinkedHost `json:"linked_hosts"`
}

// CertificateLinkedHost is one host that references a certificate. It is
// deliberately a flat display shape rather than an embedded host: what the
// panel shows is a name, whether it is live, and whether Cloudflare is in
// front of it — and a certificate page has no business carrying a host's
// forwarding rules or WAF settings.
type CertificateLinkedHost struct {
	// Kind is "proxy" or "redirect". Redirect hosts were the half the old
	// client-side grouping never asked for.
	Kind string `json:"kind"`

	// Domains is every name on the host, not just the first: the detail view
	// shows "+N more", and truncating here would quietly change what it says.
	Domains []string `json:"domains"`

	Enabled bool `json:"enabled"`

	// Target is where the host sends traffic, rendered per kind — an upstream
	// for a proxy host, a destination for a redirect. Pre-rendered because the
	// two are assembled from different columns and the panel should not have to
	// know which kind it is holding to print one line.
	Target string `json:"target"`

	CloudflareProxied bool `json:"cloudflare_proxied"`
}

// ToWithDetails converts Certificate to CertificateWithDetails
func (c *Certificate) ToWithDetails() CertificateWithDetails {
	return CertificateWithDetails{
		Certificate:     *c,
		DaysUntilExpiry: c.DaysUntilExpiry(),
		NeedsRenewal:    c.NeedsRenewal(),
		LinkedHosts:     []CertificateLinkedHost{},
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
