package nginx

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestDefaultServerConfig_CanaryLocation(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configPath: dir, httpPort: "80", httpsPort: "443", apiURL: "http://127.0.0.1:9080"}

	if err := m.GenerateDefaultServerConfig(context.Background(), "allow"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	out, err := os.ReadFile(dir + "/zzz_default.conf")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	cfg := string(out)

	for _, want := range []string{
		"location = /__npg_canary",
		"return 204",
		"deny all",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("canary location missing %q in:\n%s", want, cfg)
		}
	}
	canaryIdx := strings.Index(cfg, "location = /__npg_canary")
	end := strings.Index(cfg[canaryIdx:], "}")
	block := cfg[canaryIdx : canaryIdx+end]
	if strings.Contains(block, "access_log") {
		t.Errorf("canary block must not declare access_log (must inherit http-level):\n%s", block)
	}
}
