package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/lib/pq"
)

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	UserID     string                 `json:"user_id"`
	Username   string                 `json:"username"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
}

// Available API permissions
const (
	PermissionAll = "*"

	PermissionProxyRead   = "proxy:read"
	PermissionProxyWrite  = "proxy:write"
	PermissionProxyDelete = "proxy:delete"

	PermissionCertRead   = "certificate:read"
	PermissionCertWrite  = "certificate:write"
	PermissionCertDelete = "certificate:delete"

	PermissionWAFRead  = "waf:read"
	PermissionWAFWrite = "waf:write"

	PermissionLogsRead = "logs:read"

	PermissionSettingsRead  = "settings:read"
	PermissionSettingsWrite = "settings:write"

	PermissionBackupRead    = "backup:read"
	PermissionBackupCreate  = "backup:create"
	PermissionBackupRestore = "backup:restore"

	PermissionUserRead = "user:read"
)

// AllPermissions lists all available permissions
var AllPermissions = []string{
	PermissionProxyRead, PermissionProxyWrite, PermissionProxyDelete,
	PermissionCertRead, PermissionCertWrite, PermissionCertDelete,
	PermissionWAFRead, PermissionWAFWrite,
	PermissionLogsRead,
	PermissionSettingsRead, PermissionSettingsWrite,
	PermissionBackupRead, PermissionBackupCreate, PermissionBackupRestore,
	PermissionUserRead,
}

// PermissionGroups provides convenient permission groupings
var PermissionGroups = map[string][]string{
	"read_only": {
		PermissionProxyRead, PermissionCertRead, PermissionWAFRead,
		PermissionLogsRead, PermissionSettingsRead, PermissionBackupRead,
	},
	"operator": {
		PermissionProxyRead, PermissionProxyWrite,
		PermissionCertRead, PermissionCertWrite,
		PermissionWAFRead, PermissionWAFWrite,
		PermissionLogsRead,
		PermissionSettingsRead,
		PermissionBackupRead, PermissionBackupCreate,
	},
	"admin": {PermissionAll},
}

type APIToken struct {
	ID          string         `json:"id" db:"id"`
	UserID      string         `json:"user_id" db:"user_id"`
	Name        string         `json:"name" db:"name"`
	TokenHash   string         `json:"-" db:"token_hash"` // Never expose
	TokenPrefix string         `json:"token_prefix" db:"token_prefix"`
	Permissions pq.StringArray `json:"permissions" db:"permissions"`
	AllowedIPs  pq.StringArray `json:"allowed_ips,omitempty" db:"allowed_ips"`
	RateLimit   *int           `json:"rate_limit,omitempty" db:"rate_limit"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty" db:"expires_at"`
	LastUsedAt  *time.Time     `json:"last_used_at,omitempty" db:"last_used_at"`
	LastUsedIP  *string        `json:"last_used_ip,omitempty" db:"last_used_ip"`
	UseCount    int64          `json:"use_count" db:"use_count"`
	IsActive    bool           `json:"is_active" db:"is_active"`
	RevokedAt   *time.Time     `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedReason *string      `json:"revoked_reason,omitempty" db:"revoked_reason"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`

	// Joined fields
	Username string `json:"username,omitempty" db:"username"`
}

type APITokenResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	TokenPrefix string    `json:"token_prefix"`
	Permissions []string  `json:"permissions"`
	AllowedIPs  []string  `json:"allowed_ips,omitempty"`
	RateLimit   *int      `json:"rate_limit,omitempty"`
	ExpiresAt   *string   `json:"expires_at,omitempty"`
	LastUsedAt  *string   `json:"last_used_at,omitempty"`
	LastUsedIP  *string   `json:"last_used_ip,omitempty"`
	UseCount    int64     `json:"use_count"`
	IsActive    bool      `json:"is_active"`
	IsExpired   bool      `json:"is_expired"`
	CreatedAt   string    `json:"created_at"`
	Username    string    `json:"username,omitempty"`
}

// APITokenWithSecret is returned only when creating a new token
type APITokenWithSecret struct {
	APITokenResponse
	Token string `json:"token"` // Only returned once on creation
}

type CreateAPITokenRequest struct {
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	RateLimit   *int     `json:"rate_limit,omitempty"`
	ExpiresIn   *string  `json:"expires_in,omitempty"` // e.g., "30d", "1y", "never"
}

type UpdateAPITokenRequest struct {
	Name        *string  `json:"name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	RateLimit   *int     `json:"rate_limit,omitempty"`
	IsActive    *bool    `json:"is_active,omitempty"`
}

type RevokeAPITokenRequest struct {
	Reason string `json:"reason,omitempty"`
}

type APITokenUsage struct {
	ID              string    `json:"id" db:"id"`
	TokenID         string    `json:"token_id" db:"token_id"`
	Endpoint        string    `json:"endpoint" db:"endpoint"`
	Method          string    `json:"method" db:"method"`
	StatusCode      int       `json:"status_code" db:"status_code"`
	ClientIP        string    `json:"client_ip" db:"client_ip"`
	UserAgent       string    `json:"user_agent,omitempty" db:"user_agent"`
	RequestBodySize int64     `json:"request_body_size" db:"request_body_size"`
	ResponseTimeMs  int       `json:"response_time_ms" db:"response_time_ms"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// GenerateToken creates a new secure API token
// Returns: full token, token hash, token prefix
func GenerateToken() (token, hash, prefix string, err error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", "", err
	}

	// Create token with prefix "ng_" for easy identification
	token = "ng_" + hex.EncodeToString(bytes)

	// Hash the token for storage
	hashBytes := sha256.Sum256([]byte(token))
	hash = hex.EncodeToString(hashBytes[:])

	// Prefix for display (first 8 chars after "ng_")
	prefix = token[:11] // "ng_" + 8 chars

	return token, hash, prefix, nil
}

// HashToken creates a SHA-256 hash of a token
func HashToken(token string) string {
	hashBytes := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hashBytes[:])
}

// ToResponse converts APIToken to APITokenResponse
func (t *APIToken) ToResponse() APITokenResponse {
	resp := APITokenResponse{
		ID:          t.ID,
		Name:        t.Name,
		TokenPrefix: t.TokenPrefix,
		Permissions: t.Permissions,
		AllowedIPs:  t.AllowedIPs,
		RateLimit:   t.RateLimit,
		UseCount:    t.UseCount,
		IsActive:    t.IsActive,
		IsExpired:   t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()),
		CreatedAt:   t.CreatedAt.Format(time.RFC3339),
		Username:    t.Username,
	}

	if t.ExpiresAt != nil {
		s := t.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	if t.LastUsedAt != nil {
		s := t.LastUsedAt.Format(time.RFC3339)
		resp.LastUsedAt = &s
	}
	resp.LastUsedIP = t.LastUsedIP

	return resp
}

// HasPermission checks if the token has a specific permission
func (t *APIToken) HasPermission(required string) bool {
	for _, p := range t.Permissions {
		if p == PermissionAll || p == required {
			return true
		}
		// Check for wildcard patterns like "proxy:*"
		if len(p) > 2 && p[len(p)-2:] == ":*" {
			prefix := p[:len(p)-1]
			if len(required) >= len(prefix) && required[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// IsValid checks if the token is valid (active and not expired)
func (t *APIToken) IsValid() bool {
	if !t.IsActive {
		return false
	}
	if t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}

// IsIPAllowed checks if the given IP is allowed (supports both exact IPs and CIDR notation)
func (t *APIToken) IsIPAllowed(ip string) bool {
	if len(t.AllowedIPs) == 0 {
		return true // No restrictions
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false // Invalid IP
	}

	for _, allowed := range t.AllowedIPs {
		allowed = strings.TrimSpace(allowed)

		// Check if it's a CIDR notation
		if strings.Contains(allowed, "/") {
			_, network, err := net.ParseCIDR(allowed)
			if err == nil && network.Contains(clientIP) {
				return true
			}
		} else {
			// Exact IP match
			if allowed == ip {
				return true
			}
		}
	}
	return false
}
