package nginx

// Tests for the shared filter-subscription IP geo (one radix tree for all
// hosts instead of a per-host `geo ... include filter_sub_ips.conf` copy) and
// for the shared per-server include files written by the manager.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// TestFilterSubscriptionSharedGeoRender pins the O(entries) design: a host
// using filter subscriptions must check the SHARED $filter_sub_ip geo variable
// and must NOT re-include the entries file into a per-host geo block.
func TestFilterSubscriptionSharedGeoRender(t *testing.T) {
	t.Run("no_manual_bans", func(t *testing.T) {
		host := baseHost("00000000-0000-0000-0000-0000000000f1", "127.0.0.1", true)
		data := ProxyHostConfigData{
			Host:                  host,
			GlobalSettings:        baseGlobalSettings(),
			UseFilterSubscription: true,
		}

		var buf bytes.Buffer
		if err := renderProxyHostConfig(context.Background(), &buf, data); err != nil {
			t.Fatalf("render failed: %v", err)
		}
		out := buf.String()

		if strings.Contains(out, "include /etc/nginx/conf.d/includes/filter_sub_ips.conf") {
			t.Errorf("host config must not re-include the shared entries file (per-host radix tree regression)")
		}
		if strings.Contains(out, "geo $banned_ip_") {
			t.Errorf("per-host banned geo must not render without manual bans")
		}
		for _, needle := range []string{
			"set $filter_ip_check $filter_sub_ip;",
			"if ($filter_ip_check = 2)",
			`set $block_reason_var "filter_subscription"`,
		} {
			if !strings.Contains(out, needle) {
				t.Errorf("missing %q in rendered config\n--- rendered ---\n%s", needle, out)
			}
		}
		// No trusted IPs configured → no trusted bypass guard.
		if strings.Contains(out, "set $filter_ip_check 0;") {
			t.Errorf("trusted bypass must not render without GlobalTrustedIPs")
		}
	})

	t.Run("with_manual_bans_and_trusted_ips", func(t *testing.T) {
		host := baseHost("00000000-0000-0000-0000-0000000000f2", "127.0.0.1", true)
		hostID := host.ID
		data := ProxyHostConfigData{
			Host:                  host,
			GlobalSettings:        baseGlobalSettings(),
			UseFilterSubscription: true,
			GlobalTrustedIPs:      []string{"192.0.2.10"},
			BannedIPs: []model.BannedIP{
				{ID: "ban1", ProxyHostID: &hostID, IPAddress: "203.0.113.10", Reason: "test"},
			},
		}

		var buf bytes.Buffer
		if err := renderProxyHostConfig(context.Background(), &buf, data); err != nil {
			t.Fatalf("render failed: %v", err)
		}
		out := buf.String()

		sanitized := strings.ReplaceAll(host.ID, "-", "_")
		for _, needle := range []string{
			// Manual bans keep their per-host geo (with trusted override)…
			"geo $banned_ip_" + sanitized + " {",
			"203.0.113.10 1; # test",
			"192.0.2.10 0; # global trusted IP (override)",
			"if ($banned_ip_" + sanitized + " = 1)",
			// …while subscription IPs use the shared geo with a trusted bypass.
			"set $filter_ip_check $filter_sub_ip;",
			"if ($trusted_ip_" + sanitized + " = 1) {\n        set $filter_ip_check 0;\n    }",
			"if ($filter_ip_check = 2)",
		} {
			if !strings.Contains(out, needle) {
				t.Errorf("missing %q in rendered config\n--- rendered ---\n%s", needle, out)
			}
		}
		if strings.Contains(out, "include /etc/nginx/conf.d/includes/filter_sub_ips.conf") {
			t.Errorf("per-host geo must not include the shared entries file")
		}
		// The old per-host value-2 check must be gone.
		if strings.Contains(out, "if ($banned_ip_"+sanitized+" = 2)") {
			t.Errorf("stale per-host '= 2' filter subscription check still rendered")
		}
	})
}

// TestEnsureFilterSubscriptionFiles_SharedGeo verifies the static shared geo
// wrapper is created (and self-heals) alongside the entry placeholders.
func TestEnsureFilterSubscriptionFiles_SharedGeo(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir())
	if err := m.EnsureFilterSubscriptionFiles(); err != nil {
		t.Fatalf("EnsureFilterSubscriptionFiles: %v", err)
	}

	geoPath := filepath.Join(m.configPath, "filter_sub_ips_geo.conf")
	content, err := os.ReadFile(geoPath)
	if err != nil {
		t.Fatalf("read %s: %v", geoPath, err)
	}
	for _, needle := range []string{
		"geo $filter_sub_ip {",
		"default 0;",
		"include /etc/nginx/conf.d/includes/filter_sub_ips.conf;",
	} {
		if !strings.Contains(string(content), needle) {
			t.Errorf("filter_sub_ips_geo.conf missing %q; got:\n%s", needle, content)
		}
	}

	// Stale/corrupted wrapper is rewritten on the next ensure.
	if err := os.WriteFile(geoPath, []byte("# broken\n"), 0644); err != nil {
		t.Fatalf("corrupt wrapper: %v", err)
	}
	if err := m.EnsureFilterSubscriptionFiles(); err != nil {
		t.Fatalf("EnsureFilterSubscriptionFiles (heal): %v", err)
	}
	healed, _ := os.ReadFile(geoPath)
	if !bytes.Equal(healed, []byte(filterSubIPGeoContent)) {
		t.Errorf("wrapper not healed; got:\n%s", healed)
	}
}

// TestGenerateConfigFullWritesSharedIncludes verifies GenerateConfigFull
// creates the shared per-server stanza include (and the filter geo when the
// host uses subscriptions) BEFORE the host config that references them exists.
func TestGenerateConfigFullWritesSharedIncludes(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir())

	host := baseHost("00000000-0000-0000-0000-0000000000f3", "127.0.0.1", true)
	data := ProxyHostConfigData{
		Host:                  host,
		GlobalSettings:        baseGlobalSettings(),
		UseFilterSubscription: true,
	}
	if err := m.GenerateConfigFull(context.Background(), data); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}

	commonPath := filepath.Join(m.configPath, "includes", "host_common.conf")
	common, err := os.ReadFile(commonPath)
	if err != nil {
		t.Fatalf("host_common.conf not written: %v", err)
	}
	for _, needle := range []string{
		"resolver " + m.dnsResolver + " valid=30s;",
		"set $skip_security_for_acme 0;",
		"error_page 502 /error_502.html;",
		"error_page 403 @blocked;",
		"location @blocked {",
	} {
		if !strings.Contains(string(common), needle) {
			t.Errorf("host_common.conf missing %q; got:\n%s", needle, common)
		}
	}

	if _, err := os.Stat(filepath.Join(m.configPath, "filter_sub_ips_geo.conf")); err != nil {
		t.Errorf("filter_sub_ips_geo.conf not written for UseFilterSubscription host: %v", err)
	}

	rendered, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(host)))
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	if !strings.Contains(string(rendered), "include /etc/nginx/conf.d/includes/host_common.conf;") {
		t.Errorf("host config missing the host_common.conf include line")
	}
}
