package service

import (
	"context"
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// AuthProviderService manages reusable ForwardAuth providers and triggers a config
// regen of all referencing hosts when a provider changes. (#179)
type AuthProviderService struct {
	repo         *repository.AuthProviderRepository
	proxyHostSvc *ProxyHostService
}

func NewAuthProviderService(repo *repository.AuthProviderRepository, proxyHostSvc *ProxyHostService) *AuthProviderService {
	return &AuthProviderService{repo: repo, proxyHostSvc: proxyHostSvc}
}

// normalizeAuthProviderURL strips a trailing slash so template proxy_pass
// concatenation (ProviderURL + "/api/authz/auth-request") never doubles the slash.
func normalizeAuthProviderURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

func (s *AuthProviderService) Create(ctx context.Context, req *model.CreateAuthProviderRequest) (*model.AuthProvider, error) {
	req.ProviderURL = normalizeAuthProviderURL(req.ProviderURL)
	return s.repo.Create(ctx, req)
}

func (s *AuthProviderService) GetByID(ctx context.Context, id string) (*model.AuthProvider, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *AuthProviderService) List(ctx context.Context, page, perPage int) ([]model.AuthProvider, int, error) {
	return s.repo.List(ctx, page, perPage)
}

func (s *AuthProviderService) Update(ctx context.Context, id string, req *model.UpdateAuthProviderRequest) (*model.AuthProvider, error) {
	if req.ProviderURL != nil {
		u := normalizeAuthProviderURL(*req.ProviderURL)
		req.ProviderURL = &u
	}
	ap, err := s.repo.Update(ctx, id, req)
	if err != nil || ap == nil {
		return ap, err
	}
	// Regenerate every host referencing this provider so changed directives apply.
	if rerr := s.proxyHostSvc.RegenerateConfigsForAuthProvider(ctx, id); rerr != nil {
		return ap, rerr
	}
	return ap, nil
}

func (s *AuthProviderService) Delete(ctx context.Context, id string) error {
	// Capture the dependent hosts BEFORE delete — the FK is ON DELETE SET NULL, so
	// after delete GetByAuthProviderID returns nothing.
	hostIDs, _ := s.proxyHostSvc.GetHostIDsByAuthProvider(ctx, id)
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	// Rebuild the now-detached hosts so the auth_request directives are removed.
	return s.proxyHostSvc.RegenerateConfigsForHostIDs(ctx, hostIDs)
}
