package service

import (
	"context"
	"fmt"
	"log"

	"nginx-proxy-guard/internal/model"
)

// ImportFromHosts enables DDNS on the given proxy hosts with the given provider,
// then reconciles each so their domains become managed DDNS records. (#157)
//
// The provider type is validated once up front (must be cloudflare/duckdns). Each
// host is processed independently: a per-host failure is logged and skipped so a
// single bad host never aborts the batch. Only the DDNS opt-in fields are touched
// (no nginx reload) — UpdateDBOnly persists ddns_enabled/ddns_provider_id and the
// subsequent reconcile syncs the managed records.
func (s *ProxyHostService) ImportFromHosts(ctx context.Context, hostIDs []string, providerID string) error {
	if len(hostIDs) == 0 {
		return fmt.Errorf("invalid: no proxy hosts selected")
	}
	if providerID == "" {
		return fmt.Errorf("invalid: dns_provider_id is required")
	}

	// Validate the provider type once (cloudflare/duckdns) before touching hosts.
	if err := s.validateDDNSOptIn(ctx, true, &providerID); err != nil {
		return err
	}

	enabled := true
	for _, id := range hostIDs {
		req := &model.UpdateProxyHostRequest{
			DDNSEnabled:    &enabled,
			DDNSProviderID: &providerID,
		}
		host, err := s.UpdateDBOnly(ctx, id, req)
		if err != nil {
			log.Printf("[DDNS] import: enabling DDNS on host %s failed: %v", id, err)
			continue
		}
		if host == nil {
			log.Printf("[DDNS] import: proxy host %s not found; skipped", id)
			continue
		}
		// Reconcile is graceful and logs its own errors.
		s.reconcileHostDDNS(ctx, host)
	}
	return nil
}
