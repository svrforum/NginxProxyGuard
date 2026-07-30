package service

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/model"
)

// roleReader is the narrow repository dependency (interface for testability).
type roleReader interface {
	TablesExist(ctx context.Context) bool
	GetEffectivePermissions(ctx context.Context, userID string) ([]string, bool, error)
}

// AuthzService answers "may this principal do X?" for both humans and API
// tokens. It is the single place authorization is decided, so route middleware
// and the handful of in-handler field checks cannot drift apart. (#222)
type AuthzService struct {
	roles roleReader
}

func NewAuthzService(roles roleReader) *AuthzService {
	return &AuthzService{roles: roles}
}

// CanUser reports whether a session user holds a permission.
//
// Permissions are resolved per request rather than snapshotted into the session,
// which is what makes a role change take effect immediately — there is no way to
// force-log-out a user today, so a stale snapshot would keep a demoted account
// privileged until its session expired.
func (s *AuthzService) CanUser(ctx context.Context, userID, permission string) bool {
	if s == nil || s.roles == nil {
		return true // not wired: keep pre-RBAC behavior
	}
	if !s.roles.TablesExist(ctx) {
		return true // schema absent — see repository.RoleRepository.TablesExist
	}
	perms, superuser, err := s.roles.GetEffectivePermissions(ctx, userID)
	if err != nil {
		log.Printf("[Authz] permission lookup failed for user %s: %v — denying %s", userID, err, permission)
		return false
	}
	if superuser {
		return true
	}
	return model.ExpandPermissions(perms)[permission]
}

// CanToken reports whether an API token holds a permission, capped by the role
// of the user who issued it.
//
// The cap is applied here at validation time rather than by rewriting stored
// token rows when a role changes: an intersection follows the role
// automatically, in both directions, and cannot leave a half-migrated token
// behind. Before RBAC a token holding "*" outlived any later restriction of its
// owner, which made token creation a privilege-escalation path. (#222 D3)
func (s *AuthzService) CanToken(ctx context.Context, token *model.APIToken, permission string) bool {
	if token == nil {
		return false
	}
	if !token.HasPermission(permission) {
		return false
	}
	if s == nil || s.roles == nil || !s.roles.TablesExist(ctx) {
		return true // pre-RBAC behavior: the token's own grant is final
	}
	// The owner's role is the ceiling.
	return s.CanUser(ctx, token.UserID, permission)
}

// EffectivePermissions returns the expanded permission list for a user plus
// whether they are a superuser. Consumed by the who-am-I endpoint so the UI can
// hide areas the user cannot reach (convenience only — the server stays the
// authority).
func (s *AuthzService) EffectivePermissions(ctx context.Context, userID string) ([]string, bool, error) {
	if s == nil || s.roles == nil || !s.roles.TablesExist(ctx) {
		return model.AllAreaPermissions, true, nil
	}
	perms, superuser, err := s.roles.GetEffectivePermissions(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	if superuser {
		return model.AllAreaPermissions, true, nil
	}
	expanded := model.ExpandPermissions(perms)
	out := make([]string, 0, len(expanded))
	for _, p := range model.AllAreaPermissions {
		if expanded[p] {
			out = append(out, p)
		}
	}
	return out, false, nil
}
