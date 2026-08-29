package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// renderWithProxies renders nginx.conf with a specific trusted-proxy config.
func renderWithProxies(t *testing.T, cfg TrustedProxyConfig) string {
	t.Helper()
	dir := t.TempDir()
	m := &Manager{configPath: filepath.Join(dir, "conf.d")}
	if err := os.MkdirAll(m.configPath, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := m.GenerateMainNginxConfig(context.Background(), baselineSettings(), nil, false, cfg); err != nil {
		t.Fatalf("GenerateMainNginxConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nginx.conf"))
	if err != nil {
		t.Fatalf("read generated nginx.conf: %v", err)
	}
	return string(b)
}

// The zero value must render exactly what NPG rendered before this setting
// existed. Everything downstream of the real-IP block — GeoIP verdicts, banned
// IPs, fail2ban attribution, rate-limit keys, ModSecurity's REMOTE_ADDR — moves
// with $remote_addr, so an install that never touches the setting must not see
// a single byte change.
func TestTrustedProxyDefaultsUnchanged(t *testing.T) {
	got := renderWithProxies(t, TrustedProxyConfig{})

	want := `    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    set_real_ip_from 127.0.0.0/8;
    set_real_ip_from ::1;
    set_real_ip_from fc00::/7;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;`
	if !strings.Contains(got, want) {
		t.Fatalf("default render changed.\nwant block:\n%s\n\ngot real_ip section:\n%s", want, realIPSection(got))
	}
}

// A fresh install whose settings row was created without reading DB defaults
// back hands the renderer empty strings. Rendering those verbatim emits
// `real_ip_header ;`, which fails nginx -t and — because the generator rolls
// back — leaves the install on the image-seeded nginx.conf with every Global
// Setting silently unapplied.
func TestTrustedProxyEmptyHeaderFallsBackToDefault(t *testing.T) {
	got := renderWithProxies(t, TrustedProxyConfig{Header: ""})
	if strings.Contains(got, "real_ip_header ;") {
		t.Fatal("empty header rendered `real_ip_header ;`, which nginx -t rejects")
	}
	if !strings.Contains(got, "real_ip_header X-Forwarded-For;") {
		t.Fatalf("empty header did not fall back to the default:\n%s", realIPSection(got))
	}
}

// An unsupported header must not reach nginx.conf even if a row is hand-edited
// in the database — the value is rendered into a directive.
func TestTrustedProxyUnknownHeaderFallsBackToDefault(t *testing.T) {
	got := renderWithProxies(t, TrustedProxyConfig{Header: "X-Evil; return 200"})
	if strings.Contains(got, "X-Evil") {
		t.Fatalf("unsupported header reached nginx.conf:\n%s", realIPSection(got))
	}
	if !strings.Contains(got, "real_ip_header X-Forwarded-For;") {
		t.Fatalf("unsupported header did not fall back to the default:\n%s", realIPSection(got))
	}
}

// Operator entries are additive: the built-ins stay, and stay first.
func TestTrustedProxyAdditiveAndOrdered(t *testing.T) {
	got := renderWithProxies(t, TrustedProxyConfig{
		CIDRs:  []string{"104.16.0.0/13", "203.0.113.7"},
		Header: "CF-Connecting-IP",
	})
	section := realIPSection(got)

	for _, builtin := range model.AlwaysTrustedProxyRanges() {
		if !strings.Contains(section, "set_real_ip_from "+builtin+";") {
			t.Errorf("built-in range %s was dropped:\n%s", builtin, section)
		}
	}
	for _, extra := range []string{"104.16.0.0/13", "203.0.113.7"} {
		if !strings.Contains(section, "set_real_ip_from "+extra+";") {
			t.Errorf("operator range %s missing:\n%s", extra, section)
		}
	}
	if !strings.Contains(section, "real_ip_header CF-Connecting-IP;") {
		t.Errorf("header override missing:\n%s", section)
	}
	// Built-ins first: a LAN/Docker peer must be resolved by the ranges that
	// have always been there regardless of what the operator added.
	if strings.Index(section, "10.0.0.0/8") > strings.Index(section, "104.16.0.0/13") {
		t.Errorf("operator ranges were emitted before the built-ins:\n%s", section)
	}
}

// A range that is already built in must not be emitted twice.
func TestTrustedProxyDeduplicatesAgainstBuiltins(t *testing.T) {
	got := renderWithProxies(t, TrustedProxyConfig{CIDRs: []string{"10.0.0.0/8"}})
	if n := strings.Count(realIPSection(got), "set_real_ip_from 10.0.0.0/8;"); n != 1 {
		t.Fatalf("10.0.0.0/8 emitted %d times, want 1", n)
	}
}

// realIPSection extracts the real-IP block for readable failure output.
func realIPSection(conf string) string {
	start := strings.Index(conf, "set_real_ip_from")
	if start < 0 {
		return conf
	}
	end := strings.Index(conf[start:], "real_ip_recursive")
	if end < 0 {
		return conf[start:]
	}
	return conf[start : start+end+len("real_ip_recursive on;")]
}
