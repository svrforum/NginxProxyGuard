package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestMainConfig_IncludesManagedStreamDirectory(t *testing.T) {
	s := baselineSettings()

	out := renderOnly(t, s)

	if !strings.Contains(out, "\nstream {") {
		t.Fatalf("expected managed stream block even without custom stream config; got:\n%s", out)
	}
	if !strings.Contains(out, "include /etc/nginx/stream.d/*.conf;") {
		t.Fatalf("expected stream.d include in managed stream block; got:\n%s", out)
	}
}

func TestGenerateConfigFull_StreamTCPHostWritesStreamConfig(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	streamDir := filepath.Join(dir, "stream.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}

	m := &Manager{
		configPath:       confDir,
		streamConfigPath: streamDir,
		dnsResolver:      "127.0.0.53 8.8.8.8",
		httpPort:         "80",
		httpsPort:        "443",
		streamAccessLog:  true,
		streamErrorLog:   true,
	}
	host := &model.ProxyHost{
		ID:                        "00000000-0000-0000-0000-000000000201",
		ProxyType:                 "stream",
		DomainNames:               []string{"db.example.com"},
		ForwardHost:               "10.0.0.20",
		ForwardPort:               5432,
		Enabled:                   true,
		StreamListenPort:          15432,
		StreamProtocol:            "tcp",
		StreamSSLPreread:          true,
		StreamProxyConnectTimeout: 3,
		StreamProxyTimeout:        600,
	}

	if err := m.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: host}); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(streamDir, "stream_host_db_example_com_15432.conf"))
	if err != nil {
		t.Fatalf("read stream config: %v", err)
	}
	out := string(body)
	for _, want := range []string{
		"server {",
		"listen 15432;",
		"server_name db.example.com;",
		"proxy_connect_timeout 3s;",
		"proxy_timeout 600s;",
		"proxy_pass 10.0.0.20:5432;",
		"ssl_preread on;",
		"access_log /var/log/nginx/stream_access.log stream_main;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in stream config; got:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(confDir, "proxy_host_db_example_com.conf")); !os.IsNotExist(err) {
		t.Fatalf("stream host should not write HTTP conf.d file, stat error: %v", err)
	}
}

func TestGenerateConfigFull_StreamUDPHostWritesUDPListen(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	streamDir := filepath.Join(dir, "stream.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}

	m := &Manager{
		configPath:       confDir,
		streamConfigPath: streamDir,
		dnsResolver:      "127.0.0.53 8.8.8.8",
		httpPort:         "80",
		httpsPort:        "443",
	}
	host := &model.ProxyHost{
		ID:                 "00000000-0000-0000-0000-000000000202",
		ProxyType:          "stream",
		DomainNames:        []string{"dns.example.com"},
		ForwardHost:        "10.0.0.53",
		ForwardPort:        53,
		Enabled:            true,
		StreamListenPort:   1053,
		StreamProtocol:     "udp",
		StreamProxyTimeout: 20,
	}

	if err := m.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: host}); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(streamDir, "stream_host_dns_example_com_1053.conf"))
	if err != nil {
		t.Fatalf("read stream config: %v", err)
	}
	out := string(body)
	for _, want := range []string{
		"listen 1053 udp reuseport;",
		"proxy_timeout 20s;",
		"proxy_pass 10.0.0.53:53;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in stream config; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ssl_preread on;") {
		t.Fatalf("UDP stream config should not enable ssl_preread; got:\n%s", out)
	}
}
