package model

import "time"

// Role is a named permission set. Permissions hold the area:verb strings
// defined in permission.go; a role with IsSuperuser set carries no permission
// rows at all and bypasses the check instead, so areas added in a later release
// are covered without touching stored data. (#222)
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSuperuser bool      `json:"is_superuser"`
	IsBuiltin   bool      `json:"is_builtin"`
	Permissions []string  `json:"permissions"`
	UserCount   int       `json:"user_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateRoleRequest / UpdateRoleRequest are consumed by the management API in
// increment 2. They live here so the repository and service written in
// increment 1 already speak the final shape.
//
// Note: no struct validator is registered on the Echo instance, so `validate:`
// tags are inert in this codebase — these fields must be hand-checked in the
// handler.
type CreateRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type UpdateRoleRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
}

// Built-in role identifiers. Seeded by the migration; the UI renders the names
// through i18n rather than showing these slugs.
const (
	RoleAdministrator = "builtin.administrator"
	RoleOperator      = "builtin.operator"
	RoleViewer        = "builtin.viewer"
)

// UserSummary is the administrative view of an account. It never carries the
// password hash, TOTP secret or backup codes — those exist only on model.User
// and are already json:"-" there. (#222)
type UserSummary struct {
	ID       string  `json:"id"`
	Username string  `json:"username"`
	RoleID   *string `json:"role_id,omitempty"`
	RoleName string  `json:"role_name"`
	// LegacyRole is the users.role column ('admin'|'user'), kept in sync with the
	// role's is_superuser so `server reset-password` can still find administrators.
	LegacyRole         string     `json:"legacy_role"`
	IsSuperuser        bool       `json:"is_superuser"`
	TOTPEnabled        bool       `json:"totp_enabled"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	LoginCount         int        `json:"login_count"`
	CreatedAt          time.Time  `json:"created_at"`
	// APITokenCount is surfaced because deleting a user cascades their API
	// tokens; the confirmation shows the number so automation is not cut
	// silently. (#222 D8)
	APITokenCount int `json:"api_token_count"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	RoleID   string `json:"role_id"`
}

type AssignRoleRequest struct {
	RoleID string `json:"role_id"`
}

type SetUserPasswordRequest struct {
	Password string `json:"password"`
}

// UserTokenInfo is the API-token view inside a user's detail panel. The token
// hash never appears — only the prefix, which is what the tokens screen shows.
type UserTokenInfo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Permissions []string   `json:"permissions"`
	AllowedIPs  []string   `json:"allowed_ips,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  *string    `json:"last_used_ip,omitempty"`
	UseCount    int64      `json:"use_count"`
	IsActive    bool       `json:"is_active"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// UserDetail is what the admin panel shows when an account name is opened:
// the summary plus the sign-in history and the tokens issued under it.
//
// EffectivePermissions is the EXPANDED set actually enforced, not the role's
// stored rows — a role holding a legacy coarse scope reaches more than it lists,
// and an administrator holds everything without any rows at all. Showing the
// stored list would misrepresent what the account can do. (#222)
type UserDetail struct {
	UserSummary
	LastLoginIP          string          `json:"last_login_ip,omitempty"`
	TOTPVerifiedAt       *time.Time      `json:"totp_verified_at,omitempty"`
	UpdatedAt            time.Time       `json:"updated_at"`
	EffectivePermissions []string        `json:"effective_permissions"`
	RolePermissions      []string        `json:"role_permissions"`
	Tokens               []UserTokenInfo `json:"tokens"`
	ActiveSessions       int             `json:"active_sessions"`
}
