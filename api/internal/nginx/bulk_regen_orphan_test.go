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
	removed := m.RemoveOrphanedHostConfigs(context.Background(), enabled)

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
