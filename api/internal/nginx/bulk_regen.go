package nginx

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

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
	if len(renders) == 0 {
		return nil
	}
	return m.executeWithLock(ctx, func() error {
		snap := newFileSnapshot()
		for _, r := range renders {
			for _, p := range m.hostRenderPaths(r) {
				snap.capture(p)
			}
		}

		rollback := func(cause error) error {
			log.Printf("[WARN] Bulk nginx regeneration failed (%d host(s)), rolling back: %v", len(renders), cause)
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

		var opErr error
		if reload {
			opErr = m.testAndReloadNginxWithRetry(ctx)
		} else {
			opErr = m.testConfigInternal(ctx)
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
