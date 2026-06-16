package service

import (
	"context"
	"fmt"
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// AuthProviderService manages reusable ForwardAuth providers and triggers a config
// regen of all referencing hosts when a provider changes. (#179)
type AuthProviderService struct {
	repo              *repository.AuthProviderRepository
	proxyHostSvc      *ProxyHostService
	containerResolver ContainerResolver // Optional: resolves docker container name → IP (#181)
}

func NewAuthProviderService(repo *repository.AuthProviderRepository, proxyHostSvc *ProxyHostService) *AuthProviderService {
	return &AuthProviderService{repo: repo, proxyHostSvc: proxyHostSvc}
}

// SetContainerResolver injects the docker container → IP resolver, enabling
// container-backed verify endpoints (#181). Mirrors ProxyHostService.
func (s *AuthProviderService) SetContainerResolver(r ContainerResolver) {
	s.containerResolver = r
}

// normalizeAuthProviderURL strips a trailing slash so template proxy_pass
// concatenation (ProviderURL + "/api/authz/auth-request") never doubles the slash.
func normalizeAuthProviderURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

// buildProviderURL composes scheme://ip:port for a container-backed provider.
// Returns "" when the inputs are insufficient (no IP or no port).
func buildProviderURL(scheme *string, ip string, port *int) string {
	if ip == "" || port == nil || *port <= 0 {
		return ""
	}
	sch := "http"
	if scheme != nil && *scheme != "" {
		sch = *scheme
	}
	return fmt.Sprintf("%s://%s:%d", sch, ip, *port)
}

// resolveContainerURL resolves a container target to its current verify URL. Returns
// ("", nil) when no container is specified (caller keeps the manual provider_url).
// Resolution/validation failures are "invalid:"-prefixed → HTTP 400.
func (s *AuthProviderService) resolveContainerURL(ctx context.Context, name, network *string, port *int, scheme *string) (string, error) {
	if name == nil || *name == "" {
		return "", nil
	}
	if s.containerResolver == nil {
		return "", fmt.Errorf("invalid: container targets unavailable (no docker access)")
	}
	if port == nil || *port <= 0 {
		return "", fmt.Errorf("invalid: container_port is required for a container target")
	}
	net := ""
	if network != nil {
		net = *network
	}
	ip, err := s.containerResolver.ResolveContainerIP(ctx, *name, net)
	if err != nil {
		return "", fmt.Errorf("invalid auth provider container %q: %w", *name, err)
	}
	url := buildProviderURL(scheme, ip, port)
	if url == "" {
		return "", fmt.Errorf("invalid: could not resolve container %q to a usable address", *name)
	}
	return url, nil
}

func (s *AuthProviderService) Create(ctx context.Context, req *model.CreateAuthProviderRequest) (*model.AuthProvider, error) {
	if url, err := s.resolveContainerURL(ctx, req.ContainerName, req.ContainerNetwork, req.ContainerPort, req.ContainerScheme); err != nil {
		return nil, err
	} else if url != "" {
		req.ProviderURL = url
	}
	req.ProviderURL = normalizeAuthProviderURL(req.ProviderURL)
	if err := model.ValidateProviderURL(req.ProviderURL); err != nil {
		return nil, err
	}
	if req.Config != nil {
		if err := req.Config.Validate(req.Type); err != nil {
			return nil, err
		}
	}
	return s.repo.Create(ctx, req)
}

func (s *AuthProviderService) GetByID(ctx context.Context, id string) (*model.AuthProvider, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *AuthProviderService) List(ctx context.Context, page, perPage int) ([]model.AuthProvider, int, error) {
	return s.repo.List(ctx, page, perPage)
}

func (s *AuthProviderService) Update(ctx context.Context, id string, req *model.UpdateAuthProviderRequest) (*model.AuthProvider, error) {
	// Container target set → re-resolve and overwrite provider_url. An explicit
	// empty ContainerName clears the binding and keeps whatever manual URL was sent.
	if req.ContainerName != nil && *req.ContainerName != "" {
		url, err := s.resolveContainerURL(ctx, req.ContainerName, req.ContainerNetwork, req.ContainerPort, req.ContainerScheme)
		if err != nil {
			return nil, err
		}
		u := normalizeAuthProviderURL(url)
		req.ProviderURL = &u
	} else if req.ProviderURL != nil {
		u := normalizeAuthProviderURL(*req.ProviderURL)
		req.ProviderURL = &u
	}
	if req.ProviderURL != nil {
		if err := model.ValidateProviderURL(*req.ProviderURL); err != nil {
			return nil, err
		}
	}
	if req.Config != nil {
		typ := ""
		if req.Type != nil {
			typ = *req.Type
		} else if cur, _ := s.repo.GetByID(ctx, id); cur != nil {
			typ = cur.Type
		}
		if err := req.Config.Validate(typ); err != nil {
			return nil, err
		}
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

// ListContainerBacked returns providers whose verify endpoint is a container target,
// for the reconcile scheduler (#181).
func (s *AuthProviderService) ListContainerBacked(ctx context.Context) ([]model.AuthProvider, error) {
	return s.repo.ListContainerBacked(ctx)
}

// RecordReconcileStatus persists the latest container-reconcile health (#181 follow-up).
func (s *AuthProviderService) RecordReconcileStatus(ctx context.Context, id, status, ip, errMsg string) error {
	return s.repo.UpdateReconcileStatus(ctx, id, status, ip, errMsg)
}

// ReconcileContainerProvider recomputes the verify URL from a freshly-resolved IP and,
// if it changed, persists it and regenerates every dependent host's config via the
// fail-safe path. Returns whether the URL changed. (#181)
func (s *AuthProviderService) ReconcileContainerProvider(ctx context.Context, p model.AuthProvider, newIP string) (bool, error) {
	newURL := normalizeAuthProviderURL(buildProviderURL(p.ContainerScheme, newIP, p.ContainerPort))
	if newURL == "" || newURL == p.ProviderURL {
		return false, nil
	}
	if err := s.repo.UpdateProviderURL(ctx, p.ID, newURL); err != nil {
		return false, err
	}
	// If config regen fails (e.g. nginx -t), the file snapshot rolls back but the DB now
	// holds newURL — the next tick would see newURL==stored and never retry, leaving the
	// DB and nginx permanently split (DB=new IP, nginx=old). Revert provider_url so the
	// next tick re-detects the change and retries. (#181 adversarial review)
	if rerr := s.proxyHostSvc.RegenerateConfigsForAuthProvider(ctx, p.ID); rerr != nil {
		_ = s.repo.UpdateProviderURL(ctx, p.ID, p.ProviderURL)
		return false, rerr
	}
	return true, nil
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
