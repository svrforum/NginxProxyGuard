package nginx

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// HostConfigRender bundles the pre-aggregated inputs needed to render (or
// remove) one proxy host's config files inside a bulk atomic regeneration.
// Data aggregation (DB reads) happens in the service layer BEFORE the global
// nginx lock is taken; only file writes/test/reload run under the lock.
type HostConfigRender struct {
	Data          ProxyHostConfigData
	WAFExclusions []model.WAFRuleExclusion
	WAFAllowedIPs []string
	// Remove removes this host's config files instead of generating them
	// (disabled hosts).
	Remove bool
	// RemoveOldFilename optionally removes a stale config file whose name
	// changed (domain rename) before nginx -t runs, preventing duplicate
	// limit_req_zone errors.
	RemoveOldFilename string
}

// fileSnapshot records the original content (or absence) of every file a bulk
// operation may touch, so a failed nginx -t can restore the exact prior state.
type fileSnapshot struct {
	entries map[string]fileSnapshotEntry
	order   []string
}

type fileSnapshotEntry struct {
	content []byte
	existed bool
}

func newFileSnapshot() *fileSnapshot {
	return &fileSnapshot{entries: make(map[string]fileSnapshotEntry)}
}

// capture records a file's current state. The first capture of a path wins,
// so snapshots taken before any write always reflect the pre-operation state.
func (s *fileSnapshot) capture(path string) {
	if _, done := s.entries[path]; done {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		s.entries[path] = fileSnapshotEntry{existed: false}
	} else {
		s.entries[path] = fileSnapshotEntry{content: content, existed: true}
	}
	s.order = append(s.order, path)
}

// restoreSnapshot best-effort restores every captured file to its original
// state (rewrites existing files, removes files that did not exist).
func (m *Manager) restoreSnapshot(s *fileSnapshot) {
	for _, path := range s.order {
		e := s.entries[path]
		if e.existed {
			if err := m.writeFileAtomic(path, e.content, 0644); err != nil {
				log.Printf("[ERROR] Failed to restore %s during rollback: %v", path, err)
			}
		} else {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("[ERROR] Failed to remove %s during rollback: %v", path, err)
			}
		}
	}
}

// hostRenderPaths returns every file a render may create, modify or remove.
func (m *Manager) hostRenderPaths(r HostConfigRender) []string {
	host := r.Data.Host
	var paths []string
	if host.IsStream() {
		paths = append(paths, filepath.Join(m.getStreamConfigPath(), GetStreamConfigFilename(host)))
	} else {
		paths = append(paths, filepath.Join(m.configPath, GetConfigFilename(host)))
	}
	paths = append(paths,
		filepath.Join(m.modsecPath, fmt.Sprintf("host_%s.conf", host.ID)),
		filepath.Join(m.configPath, "includes", fmt.Sprintf("cloud_ips_%s.conf", host.ID)),
	)
	if r.RemoveOldFilename != "" {
		paths = append(paths,
			filepath.Join(m.configPath, r.RemoveOldFilename),
			filepath.Join(m.getStreamConfigPath(), r.RemoveOldFilename),
		)
	}
	return paths
}

// RegenerateConfigsAtomic regenerates configs for one or more hosts under a
// SINGLE global lock acquisition: snapshot all affected files → write all
// configs → nginx -t (+ reload when reload=true) → on any failure restore the
// snapshot and re-test/reload so nginx keeps running the last-known-good
// state. This is the required path for every multi-host fan-out (certificate,
// cloud provider, exploit rules, access list) and for single-host updates that
// defer the reload to the debounced reloader (reload=false): without it, a
// failed nginx -t leaves invalid files on disk that wedge every subsequent
// nginx operation system-wide.
func (m *Manager) RegenerateConfigsAtomic(ctx context.Context, renders []HostConfigRender, reload bool) error {
	return m.RegenerateConfigsAtomicWithRedirects(ctx, renders, nil, reload)
}

// RegenerateConfigsAtomicWithRedirects is RegenerateConfigsAtomic extended
// with redirect hosts: their configs embed certificate file paths too, so the
// certificate fan-out must regenerate them (and reload) under the same lock +
// snapshot — otherwise a cert used only by redirect hosts is renewed on disk
// but nginx keeps serving the old certificate from memory. Disabled redirect
// hosts have their config removed (mirroring GenerateRedirectConfigAndReload).
func (m *Manager) RegenerateConfigsAtomicWithRedirects(ctx context.Context, renders []HostConfigRender, redirectHosts []*model.RedirectHost, reload bool) error {
	if len(renders) == 0 && len(redirectHosts) == 0 {
		return nil
	}
	return m.executeWithLock(ctx, func() error {
		snap := newFileSnapshot()
		for _, r := range renders {
			for _, p := range m.hostRenderPaths(r) {
				snap.capture(p)
			}
		}
		for _, rh := range redirectHosts {
			snap.capture(filepath.Join(m.configPath, GetRedirectConfigFilename(rh)))
		}

		rollback := func(cause error) error {
			log.Printf("[WARN] Bulk nginx regeneration failed (%d host(s), %d redirect host(s)), rolling back: %v", len(renders), len(redirectHosts), cause)
			m.restoreSnapshot(snap)
			// Re-apply the restored last-known-good state so nginx is never
			// left running (or about to pick up) a partial write set.
			if reloadErr := m.testAndReloadNginx(ctx); reloadErr != nil {
				log.Printf("[ERROR] Rollback reload failed after bulk regeneration (configs restored but nginx may need manual intervention): %v", reloadErr)
			}
			return cause
		}

		for _, r := range renders {
			host := r.Data.Host

			if r.RemoveOldFilename != "" {
				if err := m.RemoveConfigByFilename(ctx, r.RemoveOldFilename); err != nil {
					log.Printf("[WARN] Failed to remove old config file %s: %v", r.RemoveOldFilename, err)
				}
			}

			if r.Remove {
				if err := m.RemoveConfig(ctx, host); err != nil {
					return rollback(fmt.Errorf("failed to remove config for host %s: %w", host.ID, err))
				}
				continue
			}

			if err := m.GenerateConfigFull(ctx, r.Data); err != nil {
				return rollback(fmt.Errorf("failed to generate config for host %s: %w", host.ID, err))
			}

			if host.WAFEnabled && !host.IsStream() {
				if err := m.GenerateHostWAFConfig(ctx, host, r.WAFExclusions, r.WAFAllowedIPs); err != nil {
					return rollback(fmt.Errorf("failed to generate WAF config for host %s: %w", host.ID, err))
				}
			} else {
				if err := m.RemoveHostWAFConfig(ctx, host.ID); err != nil {
					log.Printf("[WARN] Failed to remove WAF config for host %s: %v", host.ID, err)
				}
			}
		}

		for _, rh := range redirectHosts {
			if rh.Enabled {
				if err := m.GenerateRedirectConfig(ctx, rh); err != nil {
					return rollback(fmt.Errorf("failed to generate redirect config for host %s: %w", rh.ID, err))
				}
			} else if err := m.RemoveRedirectConfig(ctx, rh); err != nil {
				return rollback(fmt.Errorf("failed to remove redirect config for host %s: %w", rh.ID, err))
			}
		}

		var opErr error
		if reload {
			opErr = m.testAndReloadNginxWithRetry(ctx)
		} else {
			// Same transient-error backoff as the reload path: a docker/nginx
			// hiccup during `nginx -t` must not roll the just-written config
			// (e.g. a manual ban) out of disk before a retry. Genuine config
			// errors are non-transient and return immediately for rollback.
			opErr = m.testConfigWithRetry(ctx)
		}
		if opErr != nil {
			return rollback(opErr)
		}
		return nil
	})
}

// GenerateRedirectConfigAndReload atomically writes (or removes, when the host
// is disabled) a redirect host config, tests and reloads nginx, restoring the
// previous file when the test fails. Use this instead of calling
// GenerateRedirectConfig + TestConfig + ReloadNginx separately — the split
// form leaves an invalid config on disk when -t fails.
func (m *Manager) GenerateRedirectConfigAndReload(ctx context.Context, host *model.RedirectHost) error {
	return m.executeWithLock(ctx, func() error {
		configFile := filepath.Join(m.configPath, GetRedirectConfigFilename(host))
		snap := newFileSnapshot()
		snap.capture(configFile)

		rollback := func(cause error) error {
			log.Printf("[WARN] Nginx test failed for redirect host %s, rolling back: %v", host.ID, cause)
			m.restoreSnapshot(snap)
			if reloadErr := m.testAndReloadNginx(ctx); reloadErr != nil {
				log.Printf("[ERROR] Rollback reload failed for redirect host %s (config restored but nginx may need manual intervention): %v", host.ID, reloadErr)
			}
			return cause
		}

		if host.Enabled {
			if err := m.GenerateRedirectConfig(ctx, host); err != nil {
				return rollback(fmt.Errorf("failed to generate redirect config: %w", err))
			}
		} else {
			if err := m.RemoveRedirectConfig(ctx, host); err != nil {
				return rollback(fmt.Errorf("failed to remove redirect config: %w", err))
			}
		}

		if err := m.testAndReloadNginxWithRetry(ctx); err != nil {
			return rollback(err)
		}
		return nil
	})
}

// RemoveOrphanedHostConfigs deletes proxy/stream host config files on disk
// that no enabled host in the DB accounts for, plus their per-host WAF and
// cloud-IP include files. Boot reconciliation (SyncAllConfigs) is otherwise
// purely additive, so after a DB or volume restore the configs of deleted or
// disabled hosts would keep serving traffic indefinitely (nginx includes
// conf.d/*.conf wholesale). Only host-owned files are touched: filenames must
// match proxy_host_*.conf (conf.d), stream_host_*.conf (stream.d),
// host_*.conf (modsec) or includes/cloud_ips_*.conf — zzz_default.conf,
// redirect_host_*.conf, includes/ and *.conf.disabled leftovers are never
// removed. Best-effort: failures are logged, never fatal. Returns the removed
// filenames.
//
// fetchEnabled is called INSIDE the global lock to build the expected-filename
// set: the sync that calls this does many DB reads between fetching its own
// host list and reaching the sweep, so a host created meanwhile would be
// absent from a snapshot taken earlier and its just-written config deleted as
// a false orphan. Re-querying under the lock closes that TOCTOU window. If
// fetchEnabled errors, the sweep is skipped entirely (deleting on a partial
// list is worse than leaving a stale file for the next sync to catch).
func (m *Manager) RemoveOrphanedHostConfigs(ctx context.Context, fetchEnabled func(context.Context) ([]model.ProxyHost, error)) []string {
	var removed []string
	if err := m.executeWithLock(ctx, func() error {
		enabledHosts, err := fetchEnabled(ctx)
		if err != nil {
			return fmt.Errorf("failed to re-query enabled hosts for orphan sweep: %w", err)
		}

		expectedHTTP := make(map[string]struct{})
		expectedStream := make(map[string]struct{})
		activeIDs := make(map[string]struct{})
		for i := range enabledHosts {
			host := &enabledHosts[i]
			activeIDs[host.ID] = struct{}{}
			if host.IsStream() {
				expectedStream[GetStreamConfigFilename(host)] = struct{}{}
			} else {
				expectedHTTP[GetConfigFilename(host)] = struct{}{}
			}
		}

		httpRemoved, httpFailed := m.removeOrphanedConfFiles(m.configPath, "proxy_host_", expectedHTTP)
		streamRemoved, streamFailed := m.removeOrphanedConfFiles(m.getStreamConfigPath(), "stream_host_", expectedStream)
		removed = append(removed, httpRemoved...)
		removed = append(removed, streamRemoved...)
		// Only sweep the per-host includes when every orphaned conf file was
		// removed: a leftover conf referencing a deleted include would fail
		// nginx -t system-wide. (Includes are inert without a referencing conf.)
		if httpFailed || streamFailed {
			log.Printf("[WARN] Orphan sweep: skipping WAF/cloud include cleanup because some stale conf files could not be removed")
		} else {
			removed = append(removed, m.removeOrphanedHostIncludes(ctx, activeIDs)...)
		}
		return nil
	}); err != nil {
		log.Printf("[WARN] Orphaned host config sweep skipped: %v", err)
	}
	return removed
}

// removeOrphanedConfFiles removes prefix-matched .conf files in dir that are
// not in the expected set. Subdirectories (e.g. conf.d/includes) are skipped.
// anyFailed reports whether any matched orphan could not be removed.
func (m *Manager) removeOrphanedConfFiles(dir, prefix string, expected map[string]struct{}) (removed []string, anyFailed bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARN] Orphan sweep: failed to read %s: %v", dir, err)
			return nil, true
		}
		return nil, false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".conf") {
			continue
		}
		if _, ok := expected[name]; ok {
			continue
		}
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil {
			log.Printf("[WARN] Orphan sweep: failed to remove stale config %s: %v", path, err)
			anyFailed = true
			continue
		}
		log.Printf("[Sync] Removed stale nginx config %s (no enabled host in DB)", path)
		removed = append(removed, name)
	}
	return removed, anyFailed
}

// removeOrphanedHostIncludes removes per-host WAF (modsec/host_<id>.conf) and
// cloud-IP (includes/cloud_ips_<id>.conf) files whose host ID — derivable
// directly from the filename — is not an enabled host. These files are inert
// once the host config is gone, so removal is pure cleanup.
func (m *Manager) removeOrphanedHostIncludes(ctx context.Context, activeIDs map[string]struct{}) []string {
	var removed []string

	if entries, err := os.ReadDir(m.modsecPath); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasPrefix(name, "host_") || !strings.HasSuffix(name, ".conf") {
				continue
			}
			hostID := strings.TrimSuffix(strings.TrimPrefix(name, "host_"), ".conf")
			if _, ok := activeIDs[hostID]; ok {
				continue
			}
			if err := m.RemoveHostWAFConfig(ctx, hostID); err != nil {
				log.Printf("[WARN] Orphan sweep: failed to remove stale WAF config %s: %v", name, err)
				continue
			}
			log.Printf("[Sync] Removed stale WAF config %s (no enabled host in DB)", name)
			removed = append(removed, name)
		}
	}

	if entries, err := os.ReadDir(filepath.Join(m.configPath, "includes")); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasPrefix(name, "cloud_ips_") || !strings.HasSuffix(name, ".conf") {
				continue
			}
			hostID := strings.TrimSuffix(strings.TrimPrefix(name, "cloud_ips_"), ".conf")
			if _, ok := activeIDs[hostID]; ok {
				continue
			}
			if err := m.RemoveCloudIPsInclude(hostID); err != nil {
				log.Printf("[WARN] Orphan sweep: failed to remove stale cloud IPs include %s: %v", name, err)
				continue
			}
			log.Printf("[Sync] Removed stale cloud IPs include %s (no enabled host in DB)", name)
			removed = append(removed, name)
		}
	}

	return removed
}
