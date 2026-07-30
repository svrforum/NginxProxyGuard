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
