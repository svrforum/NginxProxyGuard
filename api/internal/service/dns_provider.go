package service

import (
	"context"
	"encoding/json"
	"fmt"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// dnsProviderRepo is the narrow repo dependency (interface for testability).
type dnsProviderRepo interface {
	Create(ctx context.Context, req *model.CreateDNSProviderRequest) (*model.DNSProvider, error)
	GetByID(ctx context.Context, id string) (*model.DNSProvider, error)
	GetDefault(ctx context.Context) (*model.DNSProvider, error)
	List(ctx context.Context, page, perPage int) ([]model.DNSProvider, int, error)
	Update(ctx context.Context, id string, req *model.UpdateDNSProviderRequest) (*model.DNSProvider, error)
	Delete(ctx context.Context, id string) error
	TestConnection(ctx context.Context, providerType string, credentials json.RawMessage) error
}

// DNSProviderInUseChecker reports how many certificates currently reference a
// DNS provider. Wired in bootstrap to avoid a cross-repo dependency here.
type DNSProviderInUseChecker func(ctx context.Context, providerID string) (int, error)

type DNSProviderService struct {
	repo         dnsProviderRepo
	inUseChecker DNSProviderInUseChecker
}

func NewDNSProviderService(repo *repository.DNSProviderRepository) *DNSProviderService {
	return &DNSProviderService{repo: repo}
}

// SetInUseChecker sets the dependency checker used to guard Delete.
func (s *DNSProviderService) SetInUseChecker(cb DNSProviderInUseChecker) {
	s.inUseChecker = cb
}

// Create creates a new DNS provider
func (s *DNSProviderService) Create(ctx context.Context, req *model.CreateDNSProviderRequest) (*model.DNSProvider, error) {
	// Validate credentials format
	if err := s.repo.TestConnection(ctx, req.ProviderType, req.Credentials); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	provider, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	return provider, nil
}

// GetByID retrieves a DNS provider by ID
func (s *DNSProviderService) GetByID(ctx context.Context, id string) (*model.DNSProvider, error) {
	return s.repo.GetByID(ctx, id)
}

// GetDefault retrieves the default DNS provider
func (s *DNSProviderService) GetDefault(ctx context.Context) (*model.DNSProvider, error) {
	return s.repo.GetDefault(ctx)
}

// List retrieves DNS providers with pagination
func (s *DNSProviderService) List(ctx context.Context, page, perPage int) (*model.DNSProviderListResponse, error) {
	providers, total, err := s.repo.List(ctx, page, perPage)
	if err != nil {
		return nil, err
	}

	totalPages := (total + perPage - 1) / perPage

	// Mask credentials in response
	maskedProviders := make([]model.DNSProvider, len(providers))
	for i, p := range providers {
		maskedProviders[i] = p.MaskCredentials()
	}

	return &model.DNSProviderListResponse{
		Data:       maskedProviders,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// Update updates a DNS provider
func (s *DNSProviderService) Update(ctx context.Context, id string, req *model.UpdateDNSProviderRequest) (*model.DNSProvider, error) {
	// If updating credentials, validate them
	if req.Credentials != nil {
		existing, err := s.repo.GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, model.ErrNotFound
		}

		if err := s.repo.TestConnection(ctx, existing.ProviderType, *req.Credentials); err != nil {
			return nil, fmt.Errorf("invalid credentials: %w", err)
		}
	}

	provider, err := s.repo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update DNS provider: %w", err)
	}

	return provider, nil
}

// Delete removes a DNS provider
func (s *DNSProviderService) Delete(ctx context.Context, id string) error {
	// In-use guard: certificates.dns_provider_id is FK ON DELETE SET NULL, so
	// deleting a referenced provider would silently switch dependent
	// certificates to HTTP-01 renewal — which can never succeed for wildcard
	// domains. Refuse instead of detaching silently.
	if s.inUseChecker != nil {
		count, err := s.inUseChecker(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to check DNS provider usage: %w", err)
		}
		if count > 0 {
			return fmt.Errorf("%w: referenced by %d certificate(s); reassign or delete those certificates first", model.ErrDNSProviderInUse, count)
		}
	}
	return s.repo.Delete(ctx, id)
}

// TestConnection tests DNS provider credentials
func (s *DNSProviderService) TestConnection(ctx context.Context, req *model.CreateDNSProviderRequest) error {
	return s.repo.TestConnection(ctx, req.ProviderType, req.Credentials)
}

// TestConnectionByID validates a STORED provider's credentials (read-only; no remote DNS change).
// Used by the proxy-host config test. (#157 follow-up)
func (s *DNSProviderService) TestConnectionByID(ctx context.Context, id string) error {
	prov, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if prov == nil {
		return fmt.Errorf("dns provider not found")
	}
	return s.repo.TestConnection(ctx, prov.ProviderType, prov.Credentials)
}
