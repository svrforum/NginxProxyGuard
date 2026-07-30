package service

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// fakeRoleRepo lets the tests drive every branch without a database.
type fakeRoleRepo struct {
	tablesExist bool
	perms       []string
	superuser   bool
	err         error
}

func (f fakeRoleRepo) TablesExist(context.Context) bool { return f.tablesExist }
func (f fakeRoleRepo) GetEffectivePermissions(context.Context, string) ([]string, bool, error) {
	return f.perms, f.superuser, f.err
}

func TestAuthz_SuperuserPassesEverything(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true, superuser: true})
	for _, p := range []string{"proxy:write", "settings:write", "role:write", "audit:read"} {
		if !svc.CanUser(context.Background(), "u1", p) {
			t.Errorf("superuser must pass %q", p)
		}
	}
}

// The implication rules must reach through the service, not only in model tests:
// settings:read was the catch-all that used to gate the audit log.
func TestAuthz_ImplicationApplies(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true, perms: []string{model.PermissionSettingsRead}})
	if !svc.CanUser(context.Background(), "u1", "audit:read") {
		t.Error("settings:read must still reach audit:read")
	}
	if svc.CanUser(context.Background(), "u1", "settings:write") {
		t.Error("settings:read must not grant settings:write")
	}
}

func TestAuthz_ReadOnlyRoleCannotWrite(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true, perms: []string{"logs:read"}})
	if !svc.CanUser(context.Background(), "u1", "logs:read") {
		t.Error("logs:read must pass logs:read")
	}
	if svc.CanUser(context.Background(), "u1", "logs:write") {
		t.Error("logs:read must not pass logs:write")
	}
}

// Migration failures are non-fatal, so the API can run without the RBAC tables.
// Denying everything there would lock the operator out of their own server.
func TestAuthz_FailsOpenWithoutTables(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: false})
	for _, p := range []string{"proxy:write", "settings:write", "role:write"} {
		if !svc.CanUser(context.Background(), "u1", p) {
			t.Errorf("without RBAC tables everything must pass (pre-RBAC behavior); %q denied", p)
		}
	}
}

// Tables present but no role assigned is a broken row, not a reason to open up.
func TestAuthz_NoRoleAssignedDeniesAll(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true})
	if svc.CanUser(context.Background(), "u1", "proxy:read") {
		t.Error("a user with no role must be denied")
	}
}

// A repository error must not silently grant access.
func TestAuthz_RepoErrorDenies(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true, err: context.DeadlineExceeded})
	if svc.CanUser(context.Background(), "u1", "proxy:read") {
		t.Error("a lookup failure must deny, not grant")
	}
}

// D3: a token can never exceed its owner's role. A "*" token owned by a viewer
// is a viewer.
func TestAuthz_TokenIsCappedByOwnerRole(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true, perms: []string{"logs:read"}})
	token := &model.APIToken{UserID: "u1", Permissions: []string{model.PermissionAll}}

	if !svc.CanToken(context.Background(), token, "logs:read") {
		t.Error("token ∩ owner role must keep logs:read")
	}
	if svc.CanToken(context.Background(), token, "settings:write") {
		t.Error("a '*' token owned by a viewer must not reach settings:write")
	}
}

// The intersection cuts both ways: a narrow token under a superuser owner stays
// narrow.
func TestAuthz_TokenNarrowerThanOwner(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: true, superuser: true})
	token := &model.APIToken{UserID: "u1", Permissions: []string{"logs:read"}}

	if !svc.CanToken(context.Background(), token, "logs:read") {
		t.Error("token must keep its own grant")
	}
	if svc.CanToken(context.Background(), token, "proxy:write") {
		t.Error("a logs:read token must not inherit its superuser owner's reach")
	}
}

// Without the RBAC tables a token keeps exactly its own permissions — the
// pre-RBAC behavior.
func TestAuthz_TokenWithoutTablesUsesOwnPermissions(t *testing.T) {
	svc := NewAuthzService(fakeRoleRepo{tablesExist: false})
	token := &model.APIToken{UserID: "u1", Permissions: []string{"logs:read"}}

	if !svc.CanToken(context.Background(), token, "logs:read") {
		t.Error("token must keep logs:read")
	}
	if svc.CanToken(context.Background(), token, "proxy:write") {
		t.Error("token must not gain permissions it never had")
	}
}
