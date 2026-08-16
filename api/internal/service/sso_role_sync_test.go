package service

import (
	"context"
	"errors"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestResolveUserEnforcesRequiredGroupBeforeIdentityLookup(t *testing.T) {
	s := &SSOService{}
	provider := &model.SSOProvider{Slug: "corp", RequiredGroup: "npg-users"}
	claims := &model.SSOClaims{Subject: "linked-user", Groups: []string{}, GroupsStated: true}

	_, _, err := s.resolveUser(context.Background(), provider, claims)
	if !errors.Is(err, ErrSSONotAllowed) {
		t.Fatalf("resolveUser error = %v, want ErrSSONotAllowed", err)
	}
}

func TestRequiredGroupRefusalDistinguishesMissingClaim(t *testing.T) {
	reason, _ := requiredGroupRefusal(&model.SSOClaims{GroupsStated: false})
	if reason != "required_group_claim_missing" {
		t.Fatalf("missing claim reason = %q", reason)
	}
	reason, _ = requiredGroupRefusal(&model.SSOClaims{GroupsStated: true})
	if reason != "required_group" {
		t.Fatalf("stated empty claim reason = %q", reason)
	}
}

func TestRoleToSync(t *testing.T) {
	defaultRole := "role-viewer"
	provider := &model.SSOProvider{
		DefaultRoleID: &defaultRole,
		GroupRoleMappings: []model.GroupRoleMapping{
			{Group: "npg-admins", RoleID: "role-admin"},
		},
	}

	t.Run("matching group selects mapped role", func(t *testing.T) {
		roleID, enforce, err := roleToSync(provider, &model.SSOClaims{Groups: []string{"npg-admins"}})
		if err != nil || !enforce || roleID != "role-admin" {
			t.Fatalf("got role=%q enforce=%v err=%v", roleID, enforce, err)
		}
	})

	t.Run("removed group falls back to default role", func(t *testing.T) {
		roleID, enforce, err := roleToSync(provider, &model.SSOClaims{Groups: []string{"users"}})
		if err != nil || !enforce || roleID != defaultRole {
			t.Fatalf("got role=%q enforce=%v err=%v", roleID, enforce, err)
		}
	})

	t.Run("removed group without fallback preserves existing role", func(t *testing.T) {
		withoutDefault := *provider
		withoutDefault.DefaultRoleID = nil
		roleID, enforce, err := roleToSync(&withoutDefault, &model.SSOClaims{Groups: []string{"users"}})
		if err != nil || enforce || roleID != "" {
			t.Fatalf("got role=%q enforce=%v err=%v, want existing role preserved", roleID, enforce, err)
		}
	})

	t.Run("provider without mappings leaves local role authoritative", func(t *testing.T) {
		roleID, enforce, err := roleToSync(&model.SSOProvider{DefaultRoleID: &defaultRole}, &model.SSOClaims{})
		if err != nil || enforce || roleID != "" {
			t.Fatalf("got role=%q enforce=%v err=%v", roleID, enforce, err)
		}
	})
}
