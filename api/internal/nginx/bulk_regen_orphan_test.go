package nginx

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// TestRemoveOrphanedHostConfigs verifies the boot drift-detection sweep:
// host config files with no enabled host in the DB are removed, while
// non-host-owned files (zzz_default.conf, redirect_host_*.conf, includes/,
// *.conf.disabled) and configs of enabled hosts are never touched.
func TestRemoveOrphanedHostConfigs(t *testing.T) {
	confDir := t.TempDir()
	streamDir := t.TempDir()
	modsecDir := t.TempDir()
	includesDir := filepath.Join(confDir, "includes")
	if err := os.MkdirAll(includesDir, 0755); err != nil {
		t.Fatal(err)
	}

	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("# test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Enabled hosts in "DB"
	httpHost := model.ProxyHost{
		ID:          "11111111-1111-1111-1111-111111111111",
		DomainNames: pq.StringArray{"keep.example.com"},
	}
	streamHost := model.ProxyHost{
		ID:               "22222222-2222-2222-2222-222222222222",
		ProxyType:        model.ProxyTypeStream,
		DomainNames:      pq.StringArray{"stream.example.com"},
		StreamListenPort: 5432,
	}
	enabled := []model.ProxyHost{httpHost, streamHost}

	keepConf := filepath.Join(confDir, GetConfigFilename(&httpHost))
	keepStream := filepath.Join(streamDir, GetStreamConfigFilename(&streamHost))
	orphanConf := filepath.Join(confDir, "proxy_host_deleted_example_com.conf")
	orphanStream := filepath.Join(streamDir, "stream_host_gone_example_com_9000.conf")
	defaultConf := filepath.Join(confDir, "zzz_default.conf")
	redirectConf := filepath.Join(confDir, "redirect_host_some_example_com.conf")
	disabledLeftover := filepath.Join(confDir, "proxy_host_old_example_com.conf.disabled")
	keepWAF := filepath.Join(modsecDir, "host_"+httpHost.ID+".conf")
	orphanWAF := filepath.Join(modsecDir, "host_33333333-3333-3333-3333-333333333333.conf")
	keepCloud := filepath.Join(includesDir, "cloud_ips_"+httpHost.ID+".conf")
	orphanCloud := filepath.Join(includesDir, "cloud_ips_44444444-4444-4444-4444-444444444444.conf")

	for _, p := range []string{keepConf, keepStream, orphanConf, orphanStream, defaultConf, redirectConf, disabledLeftover, keepWAF, orphanWAF, keepCloud, orphanCloud} {
		write(p)
	}

	m := &Manager{configPath: confDir, streamConfigPath: streamDir, modsecPath: modsecDir}
	removed := m.RemoveOrphanedHostConfigs(context.Background(), func(context.Context) ([]model.ProxyHost, error) {
		return enabled, nil
	})

	if len(removed) != 4 {
		t.Errorf("expected 4 removed files, got %d: %v", len(removed), removed)
	}

	for _, p := range []string{orphanConf, orphanStream, orphanWAF, orphanCloud} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected orphan %s to be removed", p)
		}
	}
	for _, p := range []string{keepConf, keepStream, defaultConf, redirectConf, disabledLeftover, keepWAF, keepCloud} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to be preserved, got: %v", p, err)
		}
	}
}

// TestRemoveOrphanedHostConfigs_FetchUnderLock proves the TOCTOU fix: a host
// created during the sync (absent from any earlier snapshot but present when
// the fetcher is invoked under the lock) keeps its just-written config.
func TestRemoveOrphanedHostConfigs_FetchUnderLock(t *testing.T) {
	confDir := t.TempDir()
	streamDir := t.TempDir()
	modsecDir := t.TempDir()

	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("# test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	newHost := model.ProxyHost{
		ID:          "55555555-5555-5555-5555-555555555555",
		DomainNames: pq.StringArray{"created-during-sync.example.com"},
	}
	newConf := filepath.Join(confDir, GetConfigFilename(&newHost))
	write(newConf)

	m := &Manager{configPath: confDir, streamConfigPath: streamDir, modsecPath: modsecDir}
	// The fetcher returns the host that appeared while the per-host loop ran.
	removed := m.RemoveOrphanedHostConfigs(context.Background(), func(context.Context) ([]model.ProxyHost, error) {
		return []model.ProxyHost{newHost}, nil
	})

	if len(removed) != 0 {
		t.Errorf("expected no removals when fetcher reports the host, got: %v", removed)
	}
	if _, err := os.Stat(newConf); err != nil {
		t.Errorf("config for host created during sync must survive, got: %v", err)
	}
}

// TestRemoveOrphanedHostConfigs_StaleRegenZombie reproduces the concurrency
// bug behind fix-21: a full-config regeneration (PUT /settings → SyncAllConfigs)
// reads the enabled-host list, and BEFORE it writes, host X is deleted and its
// certificate removed. Because the write loop iterates the stale list, it
// (re)writes proxy_host_X.conf still referencing X's now-deleted cert files. If
// nothing removes that conf, every later `nginx -t` fails system-wide on the
// missing certificate. The sweep — invoked as SyncAllConfigsWithDetails does,
// with a FRESH enabled-host fetcher (s.repo.GetAllEnabled) under the nginx lock,
// after the writes and before `nginx -t` — must delete the zombie so the
// dangling ssl_certificate reference can never reach nginx -t.
//
// This pins the load-bearing invariant: the sweep keys off the fresh re-query,
// NOT the stale write-list, so a host absent from the current DB has its conf
// removed regardless of what a racing regen just wrote.
func TestRemoveOrphanedHostConfigs_StaleRegenZombie(t *testing.T) {
	confDir := t.TempDir()
	streamDir := t.TempDir()
	modsecDir := t.TempDir()

	// Still-enabled host that the regen legitimately (re)wrote — must survive.
	keepHost := model.ProxyHost{
		ID:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		DomainNames: pq.StringArray{"keep.example.com"},
	}
	// Deleted host X: its conf was (re)written from the stale list and still
	// references its just-deleted certificate's files.
	zombieHost := model.ProxyHost{
		ID:          "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		DomainNames: pq.StringArray{"deleted.example.com"},
	}

	keepConf := filepath.Join(confDir, GetConfigFilename(&keepHost))
	zombieConf := filepath.Join(confDir, GetConfigFilename(&zombieHost))
	zombieWAF := filepath.Join(modsecDir, "host_"+zombieHost.ID+".conf")

	if err := os.WriteFile(keepConf, []byte("# keep\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// The zombie conf references a cert that no longer exists on disk — exactly
	// what poisons nginx -t if the conf is not swept.
	zombieBody := "server {\n  ssl_certificate /etc/nginx/certs/deleted-cert/fullchain.pem;\n}\n"
	if err := os.WriteFile(zombieConf, []byte(zombieBody), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zombieWAF, []byte("# waf\n"), 0644); err != nil {
		t.Fatal(err)
	}

	m := &Manager{configPath: confDir, streamConfigPath: streamDir, modsecPath: modsecDir}
	// Fresh re-query under the lock: X is gone from the DB, only keepHost remains.
	removed := m.RemoveOrphanedHostConfigs(context.Background(), func(context.Context) ([]model.ProxyHost, error) {
		return []model.ProxyHost{keepHost}, nil
	})

	// The zombie conf (and its per-host WAF include) must be gone; the enabled
	// host's conf must remain.
	if _, err := os.Stat(zombieConf); !os.IsNotExist(err) {
		t.Errorf("stale-regen zombie conf %s must be removed before nginx -t, still present (err=%v)", zombieConf, err)
	}
	if _, err := os.Stat(zombieWAF); !os.IsNotExist(err) {
		t.Errorf("orphan WAF include %s for deleted host must be removed", zombieWAF)
	}
	if _, err := os.Stat(keepConf); err != nil {
		t.Errorf("enabled host conf %s must be preserved, got: %v", keepConf, err)
	}

	foundZombie := false
	for _, name := range removed {
		if name == GetConfigFilename(&zombieHost) {
			foundZombie = true
		}
	}
	if !foundZombie {
		t.Errorf("expected removed set to include the zombie conf, got: %v", removed)
	}
}

// TestRemoveOrphanedHostConfigs_FetchError skips the sweep entirely on a
// fetcher error rather than deleting against a partial/empty list.
func TestRemoveOrphanedHostConfigs_FetchError(t *testing.T) {
	confDir := t.TempDir()
	streamDir := t.TempDir()
	modsecDir := t.TempDir()

	orphanConf := filepath.Join(confDir, "proxy_host_anything_example_com.conf")
	if err := os.WriteFile(orphanConf, []byte("# test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	m := &Manager{configPath: confDir, streamConfigPath: streamDir, modsecPath: modsecDir}
	removed := m.RemoveOrphanedHostConfigs(context.Background(), func(context.Context) ([]model.ProxyHost, error) {
		return nil, context.DeadlineExceeded
	})

	if len(removed) != 0 {
		t.Errorf("expected no removals on fetcher error, got: %v", removed)
	}
	if _, err := os.Stat(orphanConf); err != nil {
		t.Errorf("file must NOT be deleted when enabled-host fetch failed, got: %v", err)
	}
}
