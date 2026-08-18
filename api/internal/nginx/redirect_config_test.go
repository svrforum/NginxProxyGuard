package nginx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestGenerateAllRedirectConfigsSkipsOnlyInvalidEnabledHost(t *testing.T) {
	configDir := t.TempDir()
	staleInvalid := filepath.Join(configDir, "redirect_host_invalid.example.com.conf")
	if err := os.WriteFile(staleInvalid, []byte("# stale invalid config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	manager := &Manager{configPath: configDir, httpPort: "80", httpsPort: "443"}
	hosts := []model.RedirectHost{
		{
			ID:                "invalid",
			DomainNames:       []string{"invalid.example.com"},
			ForwardScheme:     "https",
			ForwardDomainName: "target.example.com",
			ForwardPath:       "/$request_uri",
			RedirectCode:      301,
			Enabled:           true,
		},
		{
			ID:                "valid",
			DomainNames:       []string{"valid.example.com"},
			ForwardScheme:     "https",
			ForwardDomainName: "target.example.com:8443",
			ForwardPath:       "/docs#install",
			RedirectCode:      301,
			Enabled:           true,
		},
		{
			ID:                "disabled-invalid",
			DomainNames:       []string{"disabled.example.com; return 200"},
			ForwardScheme:     "https",
			ForwardDomainName: "target.example.com",
			RedirectCode:      301,
			Enabled:           false,
		},
	}

	if err := manager.GenerateAllRedirectConfigs(context.Background(), hosts); err != nil {
		t.Fatalf("batch generation failed instead of skipping one invalid row: %v", err)
	}
	if _, err := os.Stat(staleInvalid); !os.IsNotExist(err) {
		t.Fatalf("stale invalid config was not removed: %v", err)
	}
	validConfig := filepath.Join(configDir, GetRedirectConfigFilename(&hosts[1]))
	if _, err := os.Stat(validConfig); err != nil {
		t.Fatalf("valid host was not rendered: %v", err)
	}
}

// redirectOrderCLI records the order of the nginx calls and samples the config
// directory when `nginx -t` runs, so a test can prove the startup path really
// runs generate -> test -> reload rather than just counting calls.
type redirectOrderCLI struct {
	fakeNginxCLI
	configDir       string
	order           []string
	staleGoneAtTest bool
}

func (c *redirectOrderCLI) Test(ctx context.Context) error {
	c.order = append(c.order, "test")
	if _, err := os.Stat(filepath.Join(c.configDir, "redirect_host_legacy.example.com.conf")); os.IsNotExist(err) {
		c.staleGoneAtTest = true
	}
	return c.fakeNginxCLI.Test(ctx)
}

func (c *redirectOrderCLI) Reload(ctx context.Context) error {
	c.order = append(c.order, "reload")
	return c.fakeNginxCLI.Reload(ctx)
}

func TestGenerateAllRedirectConfigsAndReloadAppliesStaleRemoval(t *testing.T) {
	configDir := t.TempDir()
	stale := filepath.Join(configDir, "redirect_host_legacy.example.com.conf")
	if err := os.WriteFile(stale, []byte("# stale legacy config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cli := &redirectOrderCLI{configDir: configDir}
	manager := &Manager{configPath: configDir, httpPort: "80", httpsPort: "443", cli: cli}
	if err := manager.GenerateAllRedirectConfigsAndReload(context.Background(), nil); err != nil {
		t.Fatalf("startup redirect sync failed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale redirect config was not removed: %v", err)
	}
	if cli.testCalls != 1 || cli.reloadCalls != 1 {
		t.Fatalf("nginx calls = test:%d reload:%d, want test:1 reload:1", cli.testCalls, cli.reloadCalls)
	}
	if !cli.staleGoneAtTest {
		t.Fatal("nginx -t ran before the config sweep; the tested config is not the one that gets reloaded")
	}
	if len(cli.order) != 2 || cli.order[0] != "test" || cli.order[1] != "reload" {
		t.Fatalf("nginx call order = %v, want [test reload]", cli.order)
	}
}

func TestGenerateAllRedirectConfigsAndReloadSkipsReloadWhenTestFails(t *testing.T) {
	configDir := t.TempDir()
	stale := filepath.Join(configDir, "redirect_host_legacy.example.com.conf")
	if err := os.WriteFile(stale, []byte("# stale legacy config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cli := &redirectOrderCLI{configDir: configDir}
	cli.testErrs = []error{errors.New("nginx: [emerg] invalid directive in generated config")}
	manager := &Manager{configPath: configDir, httpPort: "80", httpsPort: "443", cli: cli}
	if err := manager.GenerateAllRedirectConfigsAndReload(context.Background(), nil); err == nil {
		t.Fatal("expected nginx test failure")
	}
	if cli.reloadCalls != 0 {
		t.Fatalf("reload calls = %d, want 0 (config test failed)", cli.reloadCalls)
	}
	if cli.testCalls != 1 {
		t.Fatalf("test calls = %d, want 1 (non-transient failure must not retry)", cli.testCalls)
	}
	if _, statErr := os.Stat(stale); !os.IsNotExist(statErr) {
		t.Fatalf("failed apply restored a swept stale config: %v", statErr)
	}
}

func TestGenerateAllRedirectConfigsAndReloadReturnsApplyFailure(t *testing.T) {
	configDir := t.TempDir()
	stale := filepath.Join(configDir, "redirect_host_unsafe.example.com.conf")
	if err := os.WriteFile(stale, []byte("# stale unsafe config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cli := &fakeNginxCLI{reloadErrs: []error{errors.New("reload failed: permission denied")}}
	manager := &Manager{configPath: configDir, httpPort: "80", httpsPort: "443", cli: cli}
	err := manager.GenerateAllRedirectConfigsAndReload(context.Background(), nil)
	if err == nil {
		t.Fatal("expected reload failure")
	}
	if cli.testCalls != 1 || cli.reloadCalls != 1 {
		t.Fatalf("nginx calls = test:%d reload:%d, want test:1 reload:1", cli.testCalls, cli.reloadCalls)
	}
	if _, statErr := os.Stat(stale); !os.IsNotExist(statErr) {
		t.Fatalf("failed apply restored an unsafe stale config: %v", statErr)
	}
}

func TestIsNginxUnreachableError(t *testing.T) {
	unreachable := []error{
		errors.New(`failed to apply redirect config sync to nginx: nginx -t failed: exit status 1: Error response from daemon: Container 5f0 is not running`),
		errors.New(`nginx -t failed: exit status 1: Error: No such container: npg-proxy`),
	}
	for _, err := range unreachable {
		if !IsNginxUnreachableError(err) {
			t.Errorf("IsNginxUnreachableError(%q) = false, want true", err)
		}
	}

	reachable := []error{
		nil,
		errors.New(`nginx -t failed: exit status 1: nginx: [emerg] invalid directive in /etc/nginx/conf.d/redirect_host_a.conf:3`),
		errors.New(`post-reload health probe failed: worker count is zero`),
		// These prove only that WE could not reach nginx, not that nginx is down:
		// it can be up and serving the stale config we just removed from disk, so
		// the warning has to stay loud.
		errors.New(`nginx -s reload failed: exit status 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock.`),
		errors.New(`nginx -t failed: exit status 1: exec: "nginx": executable file not found in $PATH`),
	}
	for _, err := range reachable {
		if IsNginxUnreachableError(err) {
			t.Errorf("IsNginxUnreachableError(%v) = true, want false", err)
		}
	}
}

func TestBulkRollbackDoesNotRestoreUnsafeRedirectConfig(t *testing.T) {
	configDir := t.TempDir()
	cli := &fakeNginxCLI{testErrs: []error{
		errors.New("nginx: [emerg] invalid directive in generated config"),
		nil, // rollback re-test
	}}
	manager := &Manager{configPath: configDir, httpPort: "80", httpsPort: "443", cli: cli}
	invalid := &model.RedirectHost{
		ID: "invalid", DomainNames: []string{"invalid.example.com"}, Enabled: true,
		ForwardScheme: "https", ForwardDomainName: "target.example.com", ForwardPath: "/$request_uri", RedirectCode: 301,
	}
	invalidConfig := filepath.Join(configDir, GetRedirectConfigFilename(invalid))
	if err := os.WriteFile(invalidConfig, []byte("# stale unsafe config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := manager.RegenerateConfigsAtomicWithRedirects(context.Background(), nil, []*model.RedirectHost{invalid}, true)
	if err == nil {
		t.Fatal("expected nginx test failure")
	}
	if _, statErr := os.Stat(invalidConfig); !os.IsNotExist(statErr) {
		t.Fatalf("rollback restored an unsafe redirect config: %v", statErr)
	}
}

func TestBulkRegenerationSkipsInvalidRedirectWithoutRollingBackOthers(t *testing.T) {
	configDir := t.TempDir()
	cli := &fakeNginxCLI{}
	manager := &Manager{configPath: configDir, httpPort: "80", httpsPort: "443", cli: cli}
	valid := &model.RedirectHost{
		ID: "valid", DomainNames: []string{"valid.example.com"}, Enabled: true,
		ForwardScheme: "https", ForwardDomainName: "target.example.com", RedirectCode: 301,
	}
	invalid := &model.RedirectHost{
		ID: "invalid", DomainNames: []string{"invalid.example.com"}, Enabled: true,
		ForwardScheme: "https", ForwardDomainName: "target.example.com", ForwardPath: "/$request_uri", RedirectCode: 301,
	}
	invalidConfig := filepath.Join(configDir, GetRedirectConfigFilename(invalid))
	if err := os.WriteFile(invalidConfig, []byte("# stale invalid config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := manager.RegenerateConfigsAtomicWithRedirects(context.Background(), nil, []*model.RedirectHost{invalid, valid}, true); err != nil {
		t.Fatalf("bulk regeneration rolled back because of one invalid redirect: %v", err)
	}
	if _, err := os.Stat(invalidConfig); !os.IsNotExist(err) {
		t.Fatalf("invalid redirect config remains active: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, GetRedirectConfigFilename(valid))); err != nil {
		t.Fatalf("valid redirect was not regenerated: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", cli.reloadCalls)
	}
}
