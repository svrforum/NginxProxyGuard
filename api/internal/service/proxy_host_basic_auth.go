package service

import (
	"context"
	"fmt"
	"log"

	"nginx-proxy-guard/internal/model"
)

// validateBasicAuthConflict refuses an auth provider (ForwardAuth) on a host
// whose access list asks for a username and password (#387). Both answer a
// missing login with 401, and ForwardAuth's error_page 401 sends that 401 to
// the provider's login, so the password prompt would never show.
func (s *ProxyHostService) validateBasicAuthConflict(ctx context.Context, authProviderID, accessListID *string, proxyType string) error {
	if authProviderID == nil || *authProviderID == "" || accessListID == nil || *accessListID == "" ||
		proxyType == model.ProxyTypeStream || s.accessListRepo == nil {
		return nil
	}
	al, err := s.accessListRepo.GetByID(ctx, *accessListID)
	if err != nil {
		return fmt.Errorf("failed to get access list: %w", err)
	}
	if al != nil && len(al.AuthUsers) > 0 {
		return fmt.Errorf("conflict: access list %q asks for a username and password, which cannot be combined with an auth provider (ForwardAuth) on the same host", al.Name)
	}
	return nil
}

// AccessListUsedWithAuthProvider returns the first domain of a proxy host that
// uses access list listID and has an auth provider, or "" (#387). An access
// list with basic auth accounts cannot be attached to such a host.
func (s *ProxyHostService) AccessListUsedWithAuthProvider(ctx context.Context, listID string) (string, error) {
	hosts, err := s.repo.GetByAccessListID(ctx, listID)
	if err != nil {
		return "", fmt.Errorf("failed to get proxy hosts for access list %s: %w", listID, err)
	}
	for i := range hosts {
		h := &hosts[i]
		if h.AuthProviderID != nil && *h.AuthProviderID != "" && !h.IsStream() {
			if len(h.DomainNames) > 0 {
				return h.DomainNames[0], nil
			}
			return h.ID, nil
		}
	}
	return "", nil
}

// RemoveAccessListHtpasswd deletes the htpasswd file of a deleted access list,
// so its password hashes do not stay on disk. A failure is only logged: no
// config names the file any more.
func (s *ProxyHostService) RemoveAccessListHtpasswd(listID string) {
	r, ok := s.nginx.(interface{ RemoveAccessListHtpasswd(string) error })
	if !ok {
		return
	}
	if err := r.RemoveAccessListHtpasswd(listID); err != nil {
		log.Printf("[WARN] Access list %s: could not delete its htpasswd file: %v", listID, err)
	}
}
