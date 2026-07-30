package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type RoleRepository struct {
	db *database.DB
}

func NewRoleRepository(db *database.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// TablesExist reports whether the RBAC schema is present.
//
// Migration failures are non-fatal by design (database/migration.go warns and
// continues so a bad statement cannot brick an install), which means the API can
// boot without these tables. Authorization then falls back to the pre-RBAC
// behavior — every authenticated session is an administrator — rather than
// denying everything and locking the operator out of their own server. (#222)
func (r *RoleRepository) TablesExist(ctx context.Context) bool {
	var present bool
	err := r.db.QueryRowContext(ctx, `
		SELECT to_regclass('public.roles') IS NOT NULL
		   AND to_regclass('public.role_permissions') IS NOT NULL`).Scan(&present)
	return err == nil && present
}

// GetEffectivePermissions returns the stored permission strings of a user's role
// and whether that role is a superuser. A user with no role yet (role_id NULL)
// gets no permissions — the migration assigns administrator to every existing
// account, so a NULL here means a row created outside that path.
//
// Callers must expand the result with model.ExpandPermissions before checking;
// the stored values are deliberately un-expanded (see permission.go).
func (r *RoleRepository) GetEffectivePermissions(ctx context.Context, userID string) (perms []string, isSuperuser bool, err error) {
	var superuser sql.NullBool
	err = r.db.QueryRowContext(ctx, `
		SELECT r.is_superuser
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1`, userID).Scan(&superuser)
	if err == sql.ErrNoRows {
		return nil, false, nil // no role assigned
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to load user role: %w", err)
	}
	if superuser.Bool {
		return nil, true, nil // permission rows are irrelevant for a superuser
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT rp.permission
		FROM role_permissions rp
		JOIN users u ON u.role_id = rp.role_id
		WHERE u.id = $1`, userID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to load role permissions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, false, fmt.Errorf("failed to scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, false, rows.Err()
}

// GetByID returns one role with its permissions.
func (r *RoleRepository) GetByID(ctx context.Context, id string) (*model.Role, error) {
	var role model.Role
	var description sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, COALESCE(description, ''), is_superuser, is_builtin, created_at, updated_at
		FROM roles WHERE id = $1`, id).Scan(
		&role.ID, &role.Name, &description, &role.IsSuperuser, &role.IsBuiltin,
		&role.CreatedAt, &role.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	role.Description = description.String

	perms, err := r.permissionsFor(ctx, id)
	if err != nil {
		return nil, err
	}
	role.Permissions = perms
	return &role, nil
}

// List returns every role with its permissions and how many users hold it. The
// count is what lets the UI explain a blocked delete (users_role_id_fkey is
// ON DELETE RESTRICT).
func (r *RoleRepository) List(ctx context.Context) ([]model.Role, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT r.id, r.name, COALESCE(r.description, ''), r.is_superuser, r.is_builtin,
		       r.created_at, r.updated_at, count(u.id)
		FROM roles r
		LEFT JOIN users u ON u.role_id = r.id
		GROUP BY r.id, r.name, r.description, r.is_superuser, r.is_builtin, r.created_at, r.updated_at
		ORDER BY r.is_builtin DESC, r.name`)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	var out []model.Role
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.IsSuperuser,
			&role.IsBuiltin, &role.CreatedAt, &role.UpdatedAt, &role.UserCount); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		perms, err := r.permissionsFor(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Permissions = perms
	}
	return out, nil
}

// CountSuperusers backs the last-administrator guard: demoting or deleting the
// only superuser must be refused, or nobody can administer the install again.
func (r *RoleRepository) CountSuperusers(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE r.is_superuser`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count superusers: %w", err)
	}
	return n, nil
}

func (r *RoleRepository) permissionsFor(ctx context.Context, roleID string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT permission FROM role_permissions WHERE role_id = $1 ORDER BY permission`, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to load role permissions: %w", err)
	}
	defer rows.Close()
	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// Create inserts a role and its permissions in one transaction, so a failure
// cannot leave a role with a half-written permission set.
func (r *RoleRepository) Create(ctx context.Context, req *model.CreateRoleRequest) (*model.Role, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO roles (name, description, is_superuser, is_builtin)
		VALUES ($1, $2, false, false)
		RETURNING id`, req.Name, req.Description).Scan(&id); err != nil {
		return nil, wrapRoleUniqueViolation(err)
	}
	if err := insertRolePermissions(ctx, tx, id, req.Permissions); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit role: %w", err)
	}
	return r.GetByID(ctx, id)
}

// Update applies a partial change. Permissions are replaced wholesale when
// provided, which is what the role editor sends.
func (r *RoleRepository) Update(ctx context.Context, id string, req *model.UpdateRoleRequest) (*model.Role, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if req.Name != nil {
		if _, err := tx.ExecContext(ctx,
			`UPDATE roles SET name = $2, updated_at = now() WHERE id = $1`, id, *req.Name); err != nil {
			return nil, wrapRoleUniqueViolation(err)
		}
	}
	if req.Description != nil {
		if _, err := tx.ExecContext(ctx,
			`UPDATE roles SET description = $2, updated_at = now() WHERE id = $1`, id, *req.Description); err != nil {
			return nil, fmt.Errorf("failed to update role description: %w", err)
		}
	}
	if req.Permissions != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id); err != nil {
			return nil, fmt.Errorf("failed to clear role permissions: %w", err)
		}
		if err := insertRolePermissions(ctx, tx, id, *req.Permissions); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE roles SET updated_at = now() WHERE id = $1`, id); err != nil {
			return nil, fmt.Errorf("failed to touch role: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit role update: %w", err)
	}
	return r.GetByID(ctx, id)
}

// Delete removes a role. users_role_id_fkey is ON DELETE RESTRICT, so a role
// that is still assigned fails here rather than silently stripping accounts of
// every permission; the service turns that into a 409 with the user count.
func (r *RoleRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountUsersWithRole reports how many accounts hold a role, for the message a
// blocked delete shows.
func (r *RoleRepository) CountUsersWithRole(ctx context.Context, roleID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role_id = $1`, roleID).Scan(&n)
	return n, err
}

func insertRolePermissions(ctx context.Context, tx *sql.Tx, roleID string, perms []string) error {
	for _, p := range perms {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)
			ON CONFLICT (role_id, permission) DO NOTHING`, roleID, p); err != nil {
			return fmt.Errorf("failed to add permission %s: %w", p, err)
		}
	}
	return nil
}

// wrapRoleUniqueViolation turns the unique-index error into something the
// handler can map to 409 — the codebase's existing pattern (see
// isDDNSUniqueViolation) rather than string-matching the message.
func wrapRoleUniqueViolation(err error) error {
	if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
		return fmt.Errorf("role name already exists")
	}
	return fmt.Errorf("failed to write role: %w", err)
}
