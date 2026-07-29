package service

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/config"
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
//
// removeProviderRecords applies only to the opt-out branch: when the user answered
// "also remove them at the DNS provider" in the host form, the managed records are
// deleted at the provider before the rows go away. Everything else keeps the
// historical DB-only behavior. (#219)
func (s *ProxyHostService) reconcileHostDDNS(ctx context.Context, host *model.ProxyHost, immediateSync, removeProviderRecords bool) {
	if s.ddnsRepo == nil || host == nil {
		return
	}

	managed := host.DDNSEnabled && host.DDNSProviderID != nil && *host.DDNSProviderID != ""

	if !managed {
		if removeProviderRecords && s.ddnsSyncer != nil {
			// Detached for the same reason as the host-delete path: a client that
			// navigates away mid-loop would cancel it after some records were already
			// gone at the provider, leaving rows whose last_status is still ok — which
			// the scheduler's needsUpdate gate never repairs. Bounded so an unreachable
			// provider API cannot hold the save open for the full HTTP client timeout
			// once per domain.
			ddnsCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.DDNSProviderDeleteTimeout)
			if err := s.ddnsSyncer.DeleteManagedByProxyHost(ddnsCtx, host.ID); err != nil {
				log.Printf("[DDNS] reconcile provider-delete failed for host %s: %v", host.ID, err)
			}
			cancel()
		}
		// Always run the DB-only sweep: it is the fallback when the syncer is not
		// wired and the mop-up for any row the provider path could not remove.
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
			Proxied:       host.DDNSProxied,
		})
		if err != nil {
			log.Printf("[DDNS] reconcile create %q failed: %v", name, err)
			continue
		}
		if !created {
			log.Printf("[DDNS] %q already exists (manual or other host); skipped", name)
		}
	}

	// Propagate a changed proxy (orange-cloud) setting onto records that already
	// exist. reconcile otherwise only creates/prunes by hostname, so toggling
	// DDNSProxied on a host whose domains are already managed would never update
	// the record — leaving the DB (and thus the next sync) stale. (#215)
	desiredSet := make(map[string]bool, len(desired))
	for _, d := range desired {
		desiredSet[d] = true
	}
	for _, r := range existing {
		if desiredSet[r.Hostname] && r.Proxied != host.DDNSProxied {
			proxied := host.DDNSProxied
			if _, err := s.ddnsRepo.Update(ctx, r.ID, &model.UpdateDDNSRecordRequest{Proxied: &proxied}); err != nil {
				log.Printf("[DDNS] reconcile proxied-update %q failed: %v", r.Hostname, err)
			}
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
