package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// renderOnly executes the template to a string so individual assertions can
// match directives without touching the filesystem. Useful for fast, focused
// property checks on the generated output.
func renderOnly(t *testing.T, s *model.GlobalSettings) string {
	t.Helper()
	m := &Manager{configPath: "/etc/nginx/conf.d"}
	dir := t.TempDir()
	// GenerateMainNginxConfig derives nginx.conf path from configPath's parent.
	m.configPath = filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(m.configPath, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := m.GenerateMainNginxConfig(context.Background(), s, nil); err != nil {
		t.Fatalf("GenerateMainNginxConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nginx.conf"))
	if err != nil {
		t.Fatalf("read generated nginx.conf: %v", err)
	}
	return string(b)
}

func baselineSettings() *model.GlobalSettings {
	return &model.GlobalSettings{
		WorkerProcesses:          0,
		WorkerConnections:        8192,
		MultiAccept:              true,
		UseEpoll:                 true,
		Sendfile:                 true,
		TCPNopush:                true,
		TCPNodelay:               true,
		KeepaliveTimeout:         65,
		KeepaliveRequests:        1000,
		TypesHashMaxSize:         2048,
		ServerTokens:             false,
		ClientBodyBufferSize:     "16k",
		ClientHeaderBufferSize:   "1k",
		ClientMaxBodySize:        "100m",
		LargeClientHeaderBuffers: "4 8k",
		ClientBodyTimeout:        90,
		ClientHeaderTimeout:      90,
		SendTimeout:              90,
		ProxyConnectTimeout:      90,
		ProxySendTimeout:         90,
		ProxyReadTimeout:         90,
		ProxyBufferSize:          "8k",
		ProxyBuffers:             "8 32k",
		ProxyBusyBuffersSize:     "128k",
		ProxyMaxTempFileSize:     "1024m",
		ProxyTempFileWriteSize:   "64k",
		GzipEnabled:              true,
		GzipVary:                 true,
		GzipProxied:              "any",
		GzipCompLevel:            6,
		GzipMinLength:            1000,
		GzipTypes:                "text/plain",
		BrotliEnabled:            true,
		BrotliStatic:             true,
		BrotliCompLevel:          6,
		BrotliMinLength:          1000,
		BrotliTypes:              "text/plain",
		SSLProtocols:             "TLSv1.2 TLSv1.3",
		SSLCiphers:               "ECDHE-RSA-AES128-GCM-SHA256",
		SSLPreferServerCiphers:   true,
		SSLSessionCache:          "shared:SSL:10m",
		SSLSessionTimeout:        "1d",
		SSLSessionTickets:        false,
		SSLStapling:              true,
		SSLStaplingVerify:        true,
		SSLECDHCurve:             "X25519",
		AccessLogEnabled:         true,
		ErrorLogLevel:            "warn",
		Resolver:                 "1.1.1.1 valid=300s",
		ResolverTimeout:          "5s",
		OpenFileCacheEnabled:     true,
		OpenFileCacheMax:         10000,
		OpenFileCacheInactive:    "60s",
		OpenFileCacheValid:       "30s",
		OpenFileCacheMinUses:     2,
		OpenFileCacheErrors:      true,
	}
}

// Issue #121: "brotli unchecked in UI" must render `brotli off` in nginx.conf,
// not the image default of `brotli on`. Without generation from DB the static
// file won the toggle every time.
func TestMainConfig_BrotliOffRendersOff(t *testing.T) {
	s := baselineSettings()
	s.BrotliEnabled = false
	out := renderOnly(t, s)
	if !strings.Contains(out, "brotli off;") {
		t.Errorf("expected `brotli off;` in output; got:\n%s", out)
	}
	if strings.Contains(out, "brotli on;") {
		t.Errorf("did not expect `brotli on;` when BrotliEnabled=false; got:\n%s", out)
	}
}

// Issue #121: operator-supplied custom_http_config must be injected verbatim
// inside the http { } block. Previously it stayed in DB with no effect.
func TestMainConfig_CustomHTTPConfigInjected(t *testing.T) {
	s := baselineSettings()
	s.CustomHTTPConfig = "proxy_headers_hash_max_size 1024;\nproxy_headers_hash_bucket_size 128;"
	out := renderOnly(t, s)
	if !strings.Contains(out, "proxy_headers_hash_max_size 1024;") {
		t.Errorf("custom_http_config line missing from output:\n%s", out)
	}
	if !strings.Contains(out, "proxy_headers_hash_bucket_size 128;") {
		t.Errorf("custom_http_config line missing from output:\n%s", out)
	}
}

// Issue #121: custom_stream_config must produce a top-level stream{} block.
// When unset, no stream block is emitted (nginx with no stream content but
// also no ngx_stream include would error out).
func TestMainConfig_CustomStreamEmitsStreamBlock(t *testing.T) {
	s := baselineSettings()
	s.CustomStreamConfig = "server {\n    listen 5555;\n    proxy_pass 127.0.0.1:6666;\n}"
	out := renderOnly(t, s)
	if !strings.Contains(out, "stream {") {
		t.Errorf("expected stream {} block when custom_stream_config is set; got:\n%s", out)
	}
	if !strings.Contains(out, "proxy_pass 127.0.0.1:6666;") {
		t.Errorf("stream directive missing from output:\n%s", out)
	}
}

func TestMainConfig_NoStreamBlockWhenEmpty(t *testing.T) {
	s := baselineSettings()
	s.CustomStreamConfig = ""
	out := renderOnly(t, s)
	if strings.Contains(out, "\nstream {") {
		t.Errorf("did not expect a stream{} block when custom_stream_config is empty; got:\n%s", out)
	}
}

// worker_processes 0 renders "auto" (nginx rejects a literal 0).
func TestMainConfig_WorkerProcessesZeroIsAuto(t *testing.T) {
	s := baselineSettings()
	s.WorkerProcesses = 0
	out := renderOnly(t, s)
	if !strings.Contains(out, "worker_processes auto;") {
		t.Errorf("expected `worker_processes auto;` when setting is 0; got:\n%s", out)
	}
}

// A specific worker_processes value is passed through as an integer.
func TestMainConfig_WorkerProcessesSpecific(t *testing.T) {
	s := baselineSettings()
	s.WorkerProcesses = 4
	out := renderOnly(t, s)
	if !strings.Contains(out, "worker_processes 4;") {
		t.Errorf("expected `worker_processes 4;`; got:\n%s", out)
	}
}

// Corrupt error_log_level in DB falls back to "warn" rather than producing
// `error_log … <garbage>` which nginx would reject.
func TestMainConfig_ErrorLogLevelFallsBackToWarn(t *testing.T) {
	s := baselineSettings()
	s.ErrorLogLevel = "not-a-level"
	out := renderOnly(t, s)
	if !strings.Contains(out, "error_log /var/log/nginx/error.log warn;") {
		t.Errorf("expected fallback to warn; got:\n%s", out)
	}
}

// fakeFailingCLI simulates `nginx -t` always failing so we can exercise the
// rollback branch inside GenerateMainNginxConfig without touching docker.
type fakeFailingCLI struct{}

func (f *fakeFailingCLI) Test(ctx context.Context) error {
	return &fakeErr{"nginx -t: invalid directive 'banana' in /etc/nginx/nginx.conf:42"}
}
func (f *fakeFailingCLI) Reload(ctx context.Context) error { return nil }

type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }

// When nginx -t rejects the generated config, the previous nginx.conf must be
// restored byte-for-byte and the error surfaced to the caller — otherwise a
// bad save would leave the container unable to reload / restart (regression
// against the #121 fix).
func TestMainConfig_RollsBackOnNginxTestFailure(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	targetConf := filepath.Join(dir, "nginx.conf")
	originalBody := []byte("# known-good nginx.conf content\n")
	if err := os.WriteFile(targetConf, originalBody, 0644); err != nil {
		t.Fatalf("seed nginx.conf: %v", err)
	}

	m := &Manager{configPath: confDir, cli: &fakeFailingCLI{}}

	err := m.GenerateMainNginxConfig(context.Background(), baselineSettings(), nil)
	if err == nil {
		t.Fatal("expected GenerateMainNginxConfig to return an error when nginx -t fails")
	}
	if !strings.Contains(err.Error(), "nginx -t") {
		t.Errorf("error should mention nginx -t failure, got: %v", err)
	}

	restored, readErr := os.ReadFile(targetConf)
	if readErr != nil {
		t.Fatalf("reading nginx.conf after rollback: %v", readErr)
	}
	if string(restored) != string(originalBody) {
		t.Errorf("expected nginx.conf to be restored to previous content\nwant:\n%s\ngot:\n%s",
			originalBody, restored)
	}
}

// Global limit_req zone is only emitted when the toggle is enabled.
func TestMainConfig_LimitReqZoneConditional(t *testing.T) {
	s := baselineSettings()
	s.LimitReqEnabled = false
	if strings.Contains(renderOnly(t, s), "zone=global_req_limit") {
		t.Error("limit_req_zone should not be present when disabled")
	}
	s.LimitReqEnabled = true
	s.LimitReqZoneSize = "10m"
	s.LimitReqRate = 50
	s.LimitReqBurst = 100
	out := renderOnly(t, s)
	if !strings.Contains(out, "zone=global_req_limit:10m rate=50r/s") {
		t.Errorf("expected limit_req_zone with configured values; got:\n%s", out)
	}
	// Issue #130: returning 429 (instead of nginx default 503) lets the
	// log_collector status-fallback tag the request as block_reason=rate_limit.
	if !strings.Contains(out, "limit_req_status 429;") {
		t.Errorf("expected limit_req_status 429 so blocks get tagged in access log; got:\n%s", out)
	}
}

// Issue #130: when system_settings.global_trusted_ips contains entries, the
// http-level limit_conn / limit_req zones must use a key that resolves to ""
// for whitelisted IPs (the same empty-key bypass per-host rate_limit uses),
// AND the geo block defining $global_trusted_ip must be emitted exactly once.
func TestMainConfig_GlobalTrustedIPsBypassRateLimit(t *testing.T) {
	s := baselineSettings()
	s.LimitReqEnabled = true
	s.LimitReqZoneSize = "10m"
	s.LimitReqRate = 50
	s.LimitReqBurst = 100
	s.LimitConnEnabled = true
	s.LimitConnZoneSize = "10m"
	s.LimitConnPerIP = 20

	m := &Manager{}
	dir := t.TempDir()
	m.configPath = filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(m.configPath, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	trusted := []string{"192.168.0.0/16", "10.0.0.5"}
	if err := m.GenerateMainNginxConfig(context.Background(), s, trusted); err != nil {
		t.Fatalf("GenerateMainNginxConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nginx.conf"))
	if err != nil {
		t.Fatalf("read generated nginx.conf: %v", err)
	}
	out := string(b)

	if strings.Count(out, "geo $global_trusted_ip") != 1 {
		t.Errorf("expected exactly one `geo $global_trusted_ip` block; got:\n%s", out)
	}
	for _, want := range []string{"192.168.0.0/16", "10.0.0.5"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected trusted IP %q in geo block; got:\n%s", want, out)
		}
	}
	// Both the conn zone and the req zone must consume the empty-key map var,
	// not $binary_remote_addr directly — otherwise trusted IPs still get counted.
	if !strings.Contains(out, "limit_conn_zone $global_conn_key") {
		t.Errorf("expected limit_conn_zone keyed off $global_conn_key when trusted IPs set; got:\n%s", out)
	}
	if !strings.Contains(out, "limit_req_zone $global_req_key") {
		t.Errorf("expected limit_req_zone keyed off $global_req_key when trusted IPs set; got:\n%s", out)
	}
}
