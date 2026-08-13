package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"nginx-proxy-guard/internal/model"
)

// Sentinel errors the handler maps to status codes. String matching is the
// existing convention in this codebase's handlers, but these give the callers a
// stable target for the guards that matter most.
var (
	ErrLastSuperuser  = errors.New("cannot remove the last administrator")
	ErrSelfMutation   = errors.New("cannot change your own role or delete your own account")
	ErrBuiltinRole    = errors.New("built-in roles cannot be modified or deleted")
	ErrRoleInUse      = errors.New("role is still assigned to users")
	ErrUnknownRole    = errors.New("role not found")
	ErrInvalidPerm    = errors.New("unknown permission")
	ErrInvalidRoleName = errors.New("invalid role name")
	ErrInvalidUsername = errors.New("invalid username")
)

type userAdminRepo interface {
	List(ctx context.Context) ([]model.UserSummary, error)
	GetSummary(ctx context.Context, userID string) (*model.UserSummary, error)
	GetDetail(ctx context.Context, userID string) (*model.UserDetail, error)
	Create(ctx context.Context, username, email, passwordHash, roleID string, isSuperuser bool) (string, error)
	AssignRole(ctx context.Context, userID, roleID string, isSuperuser bool) error
	SetPassword(ctx context.Context, userID, passwordHash string) error
	SetEmail(ctx context.Context, userID, email string) error
	Delete(ctx context.Context, userID string) error
	DeleteSessions(ctx context.Context, userID string) error
}

type roleAdminRepo interface {
	List(ctx context.Context) ([]model.Role, error)
	GetByID(ctx context.Context, id string) (*model.Role, error)
	Create(ctx context.Context, req *model.CreateRoleRequest) (*model.Role, error)
	Update(ctx context.Context, id string, req *model.UpdateRoleRequest) (*model.Role, error)
	Delete(ctx context.Context, id string) error
	CountSuperusers(ctx context.Context) (int, error)
	CountUsersWithRole(ctx context.Context, roleID string) (int, error)
}

// UserAdminService owns every invariant of identity administration. None of them
// belong in a handler: the UI must not be the thing standing between an operator
// and an install nobody can administer. (#222)
type UserAdminService struct {
	users userAdminRepo
	roles roleAdminRepo
}

func NewUserAdminService(users userAdminRepo, roles roleAdminRepo) *UserAdminService {
	return &UserAdminService{users: users, roles: roles}
}

// ─── Roles ──────────────────────────────────────────────────────────────

func (s *UserAdminService) ListRoles(ctx context.Context) ([]model.Role, error) {
	return s.roles.List(ctx)
}

func (s *UserAdminService) CreateRole(ctx context.Context, req *model.CreateRoleRequest) (*model.Role, error) {
	if err := validateRoleName(req.Name); err != nil {
		return nil, err
	}
	if err := validatePermissions(req.Permissions); err != nil {
		return nil, err
	}
	return s.roles.Create(ctx, req)
}

func (s *UserAdminService) UpdateRole(ctx context.Context, id string, req *model.UpdateRoleRequest) (*model.Role, error) {
	role, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrUnknownRole
	}
	if role.IsBuiltin {
		return nil, ErrBuiltinRole
	}
	if req.Name != nil {
		if err := validateRoleName(*req.Name); err != nil {
			return nil, err
		}
	}
	if req.Permissions != nil {
		if err := validatePermissions(*req.Permissions); err != nil {
			return nil, err
		}
	}
	return s.roles.Update(ctx, id, req)
}

func (s *UserAdminService) DeleteRole(ctx context.Context, id string) error {
	role, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrUnknownRole
	}
	if role.IsBuiltin {
		return ErrBuiltinRole
	}
	// Checked before the delete so the error can say how many accounts hold it;
	// the FK (ON DELETE RESTRICT) is the backstop if this races.
	n, err := s.roles.CountUsersWithRole(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %d user(s)", ErrRoleInUse, n)
	}
	return s.roles.Delete(ctx, id)
}

// ─── Users ──────────────────────────────────────────────────────────────

func (s *UserAdminService) ListUsers(ctx context.Context) ([]model.UserSummary, error) {
	return s.users.List(ctx)
}

func (s *UserAdminService) GetUser(ctx context.Context, id string) (*model.UserSummary, error) {
	return s.users.GetSummary(ctx, id)
}

// GetUserDetail returns an account with its sign-in history and tokens, plus both
// permission views: the role's stored rows and the EXPANDED set actually
// enforced. Showing only the stored rows would misrepresent an account whose role
// holds a legacy coarse scope, and an administrator whose reach comes from
// is_superuser rather than any row at all. (#222)
func (s *UserAdminService) GetUserDetail(ctx context.Context, id string) (*model.UserDetail, error) {
	d, err := s.users.GetDetail(ctx, id)
	if err != nil || d == nil {
		return nil, err
	}
	if d.RoleID != nil {
		role, err := s.roles.GetByID(ctx, *d.RoleID)
		if err != nil {
			return nil, err
		}
		if role != nil {
			d.RolePermissions = role.Permissions
			if role.IsSuperuser {
				d.EffectivePermissions = model.AllAreaPermissions
			} else {
				expanded := model.ExpandPermissions(role.Permissions)
				for _, p := range model.AllAreaPermissions {
					if expanded[p] {
						d.EffectivePermissions = append(d.EffectivePermissions, p)
					}
				}
			}
		}
	}
	return d, nil
}

// CreateUser provisions an account. The password must clear the same strength
// rule the self-service change uses, so this path cannot become the weakest one.
// New accounts start with must_change_password set.
func (s *UserAdminService) CreateUser(ctx context.Context, req *model.CreateUserRequest) (*model.UserSummary, error) {
	if len(req.Username) < 3 {
		return nil, fmt.Errorf("%w: must be at least 3 characters", ErrInvalidUsername)
	}
	if req.Username == "admin" {
		// The rule previously lived only in the UI (InitialSetup.tsx); with
		// multiple accounts it has to be enforced server-side.
		return nil, fmt.Errorf("%w: 'admin' is reserved", ErrInvalidUsername)
	}
	if !isStrongPassword(req.Password) {
		return nil, ErrWeakPassword
	}
	role, err := s.roles.GetByID(ctx, req.RoleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrUnknownRole
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	// An address is optional; without one the account gets the synthesised
	// <username>@localhost and simply cannot be linked from an IdP later
	// without an administrator setting one. (#240)
	var email string
	if strings.TrimSpace(req.Email) != "" {
		email, err = model.NormalizeEmail(req.Email)
		if err != nil {
			return nil, err
		}
	}
	id, err := s.users.Create(ctx, req.Username, email, string(hash), role.ID, role.IsSuperuser)
	if err != nil {
		return nil, err
	}
	return s.users.GetSummary(ctx, id)
}

// AssignRole moves an account to another role.
//
// Two guards: you cannot change your own role (an administrator locking
// themselves out mid-session), and the last superuser cannot be demoted.
func (s *UserAdminService) AssignRole(ctx context.Context, actingUserID, targetUserID, roleID string) (*model.UserSummary, error) {
	if actingUserID == targetUserID {
		return nil, ErrSelfMutation
	}
	target, err := s.users.GetSummary(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, sql.ErrNoRows
	}
	role, err := s.roles.GetByID(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrUnknownRole
	}
	if target.IsSuperuser && !role.IsSuperuser {
		if err := s.assertNotLastSuperuser(ctx); err != nil {
			return nil, err
		}
	}
	if err := s.users.AssignRole(ctx, targetUserID, role.ID, role.IsSuperuser); err != nil {
		return nil, err
	}
	// No session invalidation: permissions resolve per request, so the new role
	// applies to the target's very next call.
	return s.users.GetSummary(ctx, targetUserID)
}

// SetPassword resets another account's password and ends its sessions, because
// the point of an admin reset is that the current holder loses access.
func (s *UserAdminService) SetPassword(ctx context.Context, targetUserID, password string) error {
	if !isStrongPassword(password) {
		return ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	if err := s.users.SetPassword(ctx, targetUserID, string(hash)); err != nil {
		return err
	}
	return s.users.DeleteSessions(ctx, targetUserID)
}

// SetEmail changes the address an account is linked by when signing in through
// an identity provider (#240).
//
// Admin-only by design. SSO matches a verified provider email to a local
// account and then syncs the role from the provider's groups, so a user able to
// set their own address could claim an administrator's provider address before
// that administrator first signs in, and take the role with it. Assigning roles
// is already user:write, so gating the address the same way grants nothing new.
//
// Sessions are deliberately left alone: unlike a password change this does not
// invalidate the credential the account already signed in with.
func (s *UserAdminService) SetEmail(ctx context.Context, targetUserID, email string) error {
	normalized, err := model.NormalizeEmail(email)
	if err != nil {
		return err
	}
	return s.users.SetEmail(ctx, targetUserID, normalized)
}

// DeleteUser removes an account. Deleting cascades the account's API tokens and
// sessions (#222 D8) — the caller is expected to have shown the token count.
func (s *UserAdminService) DeleteUser(ctx context.Context, actingUserID, targetUserID string) error {
	if actingUserID == targetUserID {
		return ErrSelfMutation
	}
	target, err := s.users.GetSummary(ctx, targetUserID)
	if err != nil {
		return err
	}
	if target == nil {
		return sql.ErrNoRows
	}
	if target.IsSuperuser {
		if err := s.assertNotLastSuperuser(ctx); err != nil {
			return err
		}
	}
	return s.users.Delete(ctx, targetUserID)
}

// EndSessions is the "kick this account" action.
func (s *UserAdminService) EndSessions(ctx context.Context, targetUserID string) error {
	return s.users.DeleteSessions(ctx, targetUserID)
}

func (s *UserAdminService) assertNotLastSuperuser(ctx context.Context) error {
	n, err := s.roles.CountSuperusers(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastSuperuser
	}
	return nil
}

// ─── Validation ─────────────────────────────────────────────────────────

func validateRoleName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return fmt.Errorf("%w: must be 1-64 characters", ErrInvalidRoleName)
	}
	// The name is rendered in the UI and written into audit logs verbatim.
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: control characters are not allowed", ErrInvalidRoleName)
		}
	}
	// builtin.* is reserved so a custom role cannot shadow a seeded one and
	// inherit its i18n label.
	if len(name) >= 8 && name[:8] == "builtin." {
		return fmt.Errorf("%w: the builtin. prefix is reserved", ErrInvalidRoleName)
	}
	return nil
}

func validatePermissions(perms []string) error {
	valid := make(map[string]bool, len(model.AllAreaPermissions))
	for _, p := range model.AllAreaPermissions {
		valid[p] = true
	}
	for _, p := range perms {
		if !valid[p] {
			return fmt.Errorf("%w: %s", ErrInvalidPerm, p)
		}
	}
	return nil
}

// isStrongPassword mirrors the service-layer rule used by the self-service
// password change (auth.go). The handler additionally runs
// handler.ValidatePasswordStrength, which adds the character-class requirements,
// so the admin path is never the weakest entry point. Consolidating the three
// existing rules into one is increment 4.
func isStrongPassword(pw string) bool {
	return len(pw) >= 10
}
