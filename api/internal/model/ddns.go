package model

import "time"

// DDNS record status values
const (
	DDNSStatusOK    = "ok"
	DDNSStatusError = "error"
)

// DDNSRecord is a hostname whose A record is kept pointed at the server's public IPv4.
type DDNSRecord struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	DNSProviderID string     `json:"dns_provider_id"`
	RecordType    string     `json:"record_type"` // 'A' (v1)
	Proxied       bool       `json:"proxied"`     // Cloudflare only
	TTL           int        `json:"ttl"`         // Cloudflare: 1 = auto
	Enabled       bool       `json:"enabled"`
	LastIP        string     `json:"last_ip"`
	LastSyncedAt  *time.Time `json:"last_synced_at,omitempty"`
	LastStatus    string     `json:"last_status"` // '', 'ok', 'error'
	LastError     string     `json:"last_error"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type CreateDDNSRecordRequest struct {
	Hostname      string `json:"hostname" validate:"required"`
	DNSProviderID string `json:"dns_provider_id" validate:"required"`
	Proxied       bool   `json:"proxied"`
	TTL           int    `json:"ttl"`
	Enabled       bool   `json:"enabled"`
}

type UpdateDDNSRecordRequest struct {
	Hostname      *string `json:"hostname,omitempty"`
	DNSProviderID *string `json:"dns_provider_id,omitempty"`
	Proxied       *bool   `json:"proxied,omitempty"`
	TTL           *int    `json:"ttl,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

type DDNSRecordListResponse struct {
	Data       []DDNSRecord `json:"data"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	TotalPages int          `json:"total_pages"`
}
