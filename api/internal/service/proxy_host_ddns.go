package service

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/model"
)

// ddnsDesiredDiff returns hostnames to create (in desired, not existing) and
// to delete (existing managed, not in desired). Pure for testability. (#157)
func ddnsDesiredDiff(desired, existing []string) (toCreate, toDelete []string) {
	ds := map[string]bool{}
	for _, d := range desired {
		ds[d] = true
	}
	es := map[string]bool{}
	for _, e := range existing {
		es[e] = true
	}
	seen := map[string]bool{}
	for _, d := range desired {
		if !es[d] && !seen[d] {
			seen[d] = true
			toCreate = append(toCreate, d)
		}
	}
	for _, e := range existing {
		if !ds[e] {
			toDelete = append(toDelete, e)
		}
	}
	return
}

// reconcileHostDDNS syncs a host's managed DDNS records to its domains.
// Graceful: errors are logged, never fatal to the host CRUD that triggered it. (#157)
//
// When the host opts out (ddns_enabled=false or no provider) all of its managed
// records are removed. Manually-created records (proxy_host_id IS NULL) and other
// hosts' records are never touched. The ddnsRepo dependency is optional; when it
// is nil (e.g. unit tests constructing a bare service) reconcile is a no-op.
//
// immediateSync controls the post-reconcile public-IP sync: interactive single-host
// saves (Create/Update/UI UpdateDBOnly) pass true so the record reflects the current
// IP within seconds; bulk import passes false and relies on the DDNS scheduler's next
// cycle, avoiding a burst of per-host public-IP detection + provider API writes.
func (s *ProxyHostService) reconcileHostDDNS(ctx context.Context, host *model.ProxyHost, immediateSync bool) {
	if s.ddnsRepo == nil || host == nil {
		return
	}

	managed := host.DDNSEnabled && host.DDNSProviderID != nil && *host.DDNSProviderID != ""

	if !managed {
		if _, err := s.ddnsRepo.DeleteByProxyHost(ctx, host.ID); err != nil {
			log.Printf("[DDNS] reconcile delete-all failed for host %s: %v", host.ID, err)
		}
		return
	}

	// Provider changed? Drop this host's managed records under any other provider
	// first, so the diff below recreates them under the current provider. (#157)
	if _, err := s.ddnsRepo.DeleteManagedWrongProvider(ctx, host.ID, *host.DDNSProviderID); err != nil {
		log.Printf("[DDNS] reconcile provider-prune failed for host %s: %v", host.ID, err)
	}

	// List existing AFTER the wrong-provider prune so old-provider hostnames are
	// seen as missing and recreated under the current provider. (#157)
	existing, err := s.ddnsRepo.ListByProxyHost(ctx, host.ID)
	if err != nil {
		log.Printf("[DDNS] reconcile list failed for host %s: %v", host.ID, err)
		return
	}
	existingNames := make([]string, 0, len(existing))
	for _, r := range existing {
		existingNames = append(existingNames, r.Hostname)
	}

	desired := []string(host.DomainNames)
	toCreate, _ := ddnsDesiredDiff(desired, existingNames)
	for _, name := range toCreate {
		created, err := s.ddnsRepo.CreateManaged(ctx, model.DDNSRecord{
			Hostname:      name,
			DNSProviderID: *host.DDNSProviderID,
			ProxyHostID:   &host.ID,
		})
		if err != nil {
			log.Printf("[DDNS] reconcile create %q failed: %v", name, err)
			continue
		}
		if !created {
			log.Printf("[DDNS] %q already exists (manual or other host); skipped", name)
		}
	}
	if err := s.ddnsRepo.DeleteManagedNotIn(ctx, host.ID, desired); err != nil {
		log.Printf("[DDNS] reconcile prune failed for host %s: %v", host.ID, err)
	}

	// Immediate first sync (async, graceful) so the record reflects the current public
	// IP within seconds instead of waiting for the scheduler. context.Background() so it
	// survives the request context ending. (#157 follow-up)
	if immediateSync && s.ddnsSyncer != nil {
		go s.ddnsSyncer.SyncByProxyHost(context.Background(), host.ID)
	}
}
