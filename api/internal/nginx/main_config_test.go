package nginx

import (
	"bytes"
	"context"
	"errors"
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
	if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{}, TrustedProxyConfig{}); err != nil {
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

// Issue #264: nginx absolutizes relative Location headers using its own listen
// port, so an operator whose router forwards 443 to a non-standard port got
// that internal port handed back to the browser. absolute_redirect off keeps
// those Location headers relative. port_in_redirect is deliberately NOT turned
// off: a client that really did connect on the alternate port still needs it.
func TestMainConfig_AbsoluteRedirectOff(t *testing.T) {
	out := renderOnly(t, baselineSettings())
	if !strings.Contains(out, "absolute_redirect off;") {
		t.Errorf("expected `absolute_redirect off;` in output; got:\n%s", out)
	}
	if strings.Contains(out, "port_in_redirect off;") {
		t.Errorf("did not expect `port_in_redirect off;` — it breaks direct access on the alternate port; got:\n%s", out)
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

// Issue #121: custom_stream_config must be injected into the managed top-level
// stream{} block used by first-class TCP/UDP stream proxy hosts.
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

func TestMainConfig_ManagedStreamBlockWhenCustomStreamEmpty(t *testing.T) {
	s := baselineSettings()
	s.CustomStreamConfig = ""
	out := renderOnly(t, s)
	if !strings.Contains(out, "\nstream {") {
		t.Errorf("expected managed stream{} block when custom_stream_config is empty; got:\n%s", out)
	}
	if !strings.Contains(out, "include /etc/nginx/stream.d/*.conf;") {
		t.Errorf("expected managed stream include; got:\n%s", out)
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

	err := m.GenerateMainNginxConfig(context.Background(), baselineSettings(), TrustedIPConfig{}, TrustedProxyConfig{})
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
	if strings.Contains(renderOnly(t, s), "zone=npg_global_req") {
		t.Error("limit_req_zone should not be present when disabled")
	}
	s.LimitReqEnabled = true
	s.LimitReqZoneSize = "10m"
	s.LimitReqRate = 50
	s.LimitReqBurst = 100
	out := renderOnly(t, s)
	if !strings.Contains(out, "zone=npg_global_req:10m rate=50r/s") {
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
	if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{Static: trusted}, TrustedProxyConfig{}); err != nil {
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

// #166: when system_settings.global_trusted_ips_bypass_waf is ON and trusted IPs
// exist, the http-level ModSecurity bypass rule (id:9000001, ctl:ruleEngine=Off)
// must be emitted with the trusted-IP CSV so those clients skip the WAF. It must
// be ABSENT when the flag is OFF, and ABSENT when the flag is ON but no trusted
// IPs exist — an empty @ipMatch would be invalid nginx AND a silent all-IP
// bypass. This is the load-bearing branch for the feature; guard it directly.
func TestMainConfig_GlobalTrustedIPsBypassWAF(t *testing.T) {
	render := func(t *testing.T, trusted []string, bypass bool) string {
		t.Helper()
		m := &Manager{}
		dir := t.TempDir()
		m.configPath = filepath.Join(dir, "conf.d")
		if err := os.MkdirAll(m.configPath, 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := m.GenerateMainNginxConfig(context.Background(), baselineSettings(), TrustedIPConfig{Static: trusted, BypassWAF: bypass}, TrustedProxyConfig{}); err != nil {
			t.Fatalf("GenerateMainNginxConfig: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "nginx.conf"))
		if err != nil {
			t.Fatalf("read generated nginx.conf: %v", err)
		}
		return string(b)
	}

	// Flag ON + trusted IPs -> bypass rule rendered with the exact CSV.
	on := render(t, []string{"203.0.113.7", "198.51.100.0/24"}, true)
	if !strings.Contains(on, "id:9000001") {
		t.Errorf("expected ModSecurity bypass rule id:9000001 when flag ON + IPs; got:\n%s", on)
	}
	if !strings.Contains(on, "ctl:ruleEngine=Off") {
		t.Errorf("expected ctl:ruleEngine=Off in the bypass rule; got:\n%s", on)
	}
	if !strings.Contains(on, `@ipMatch 203.0.113.7,198.51.100.0/24`) {
		t.Errorf("expected the bypass rule to @ipMatch the trusted-IP CSV; got:\n%s", on)
	}

	// Flag OFF (even with IPs present) -> no WAF bypass rule.
	if off := render(t, []string{"203.0.113.7"}, false); strings.Contains(off, "id:9000001") {
		t.Errorf("did not expect a WAF bypass rule when flag OFF; got:\n%s", off)
	}

	// Flag ON but no trusted IPs -> no rule (empty @ipMatch is invalid nginx and
	// would silently bypass every client).
	if onEmpty := render(t, nil, true); strings.Contains(onEmpty, "id:9000001") {
		t.Errorf("did not expect a WAF bypass rule when flag ON but no trusted IPs; got:\n%s", onEmpty)
	}
}

// httpLevelAccessLogDirectives returns the access_log directives written
// directly inside http { }, ignoring comments and anything nested deeper
// (server, location, stream blocks).
func httpLevelAccessLogDirectives(t *testing.T, conf string) []string {
	t.Helper()
	var out []string
	depth := 0
	inHTTP := false
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if depth == 0 && strings.HasPrefix(line, "http ") && strings.HasSuffix(line, "{") {
			inHTTP = true
		}
		if inHTTP && depth == 1 && strings.HasPrefix(line, "access_log ") {
			out = append(out, line)
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth == 0 {
			inHTTP = false
		}
	}
	return out
}

// A5: "Enable Access Log" off used to render an http-level `access_log off;`.
// nginx treats `off` as cancelling every access_log on that level, and
// conf.d/00-raw-logging.conf (the access_raw.log the log collector tails) is
// included at that same level — so the switch silently stopped all DB access
// logging while `nginx -t` still passed. Off must now drop only the
// docker-logs copy and leave the raw file and the include untouched.
func TestMainConfig_AccessLogOffKeepsRawFileLogging(t *testing.T) {
	s := baselineSettings()
	s.AccessLogEnabled = false
	out := renderOnly(t, s)

	if got := httpLevelAccessLogDirectives(t, out); len(got) != 0 {
		t.Errorf("access log copy off must render no http-level access_log directive; got %q", got)
	}
	if strings.Contains(out, "/var/log/nginx/access.log") {
		t.Errorf("access log copy off must not write to /var/log/nginx/access.log (docker logs); got:\n%s", out)
	}
	if !strings.Contains(out, "include /etc/nginx/conf.d/*.conf;") {
		t.Errorf("conf.d include (00-raw-logging.conf) must stay; got:\n%s", out)
	}
}

func TestMainConfig_AccessLogOnRendersStdoutCopy(t *testing.T) {
	out := renderOnly(t, baselineSettings())
	want := "access_log /var/log/nginx/access.log main buffer=64k flush=5s;"
	got := httpLevelAccessLogDirectives(t, out)
	if len(got) != 1 || got[0] != want {
		t.Errorf("access log copy on must render exactly %q at http level; got %q", want, got)
	}
}

// The zones' keys must not change with the trusted list: a running nginx
// refuses a reload that changes the key of a zone it has.
func TestMainConfig_GlobalZoneKeysDoNotDependOnTrustedIPs(t *testing.T) {
	s := baselineSettings()
	s.LimitConnEnabled, s.LimitConnZoneSize, s.LimitConnPerIP = true, "10m", 50
	s.LimitReqEnabled, s.LimitReqZoneSize, s.LimitReqRate, s.LimitReqBurst = true, "10m", 50, 100
	for _, trusted := range [][]string{nil, {"198.51.100.7"}} {
		m := &Manager{}
		dir := t.TempDir()
		m.configPath = filepath.Join(dir, "conf.d")
		if err := os.MkdirAll(m.configPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{Static: trusted}, TrustedProxyConfig{}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "nginx.conf"))
		if err != nil {
			t.Fatal(err)
		}
		out := string(b)
		for _, want := range []string{
			"geo $global_trusted_ip {",
			"limit_conn_zone $global_conn_key zone=npg_global_conn:10m;",
			"limit_conn npg_global_conn 50;",
			"limit_req_zone $global_req_key zone=npg_global_req:10m rate=50r/s;",
			"limit_req zone=npg_global_req burst=100 nodelay;",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("trusted=%v: missing %q", trusted, want)
			}
		}
		if strings.Contains(out, "zone=global_conn_limit") || strings.Contains(out, "zone=global_req_limit") {
			t.Errorf("trusted=%v: old names defined without any use of them", trusted)
		}
	}
}

func TestMainConfig_OldGlobalZoneNamesInUseGetAliases(t *testing.T) {
	s := baselineSettings()
	s.LimitConnEnabled, s.LimitConnZoneSize, s.LimitConnPerIP = true, "10m", 50
	s.LimitReqEnabled, s.LimitReqZoneSize, s.LimitReqRate, s.LimitReqBurst = true, "10m", 50, 100
	s.CustomHTTPConfig = "# limit_conn global_conn_limit 5;\nlimit_req_status 429;"
	m := &Manager{}
	dir := t.TempDir()
	m.configPath = filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(m.configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	m.SetLegacyZoneRefSource(func(context.Context) ([]string, error) {
		return []string{"location /x {\n    limit_req zone=global_req_limit burst=5;\n}"}, nil
	})
	if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{}, TrustedProxyConfig{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "nginx.conf"))
	out := string(b)
	if !strings.Contains(out, "limit_req_zone $global_req_key zone=global_req_limit:10m rate=50r/s;") {
		t.Error("global_req_limit is used by a host but not defined")
	}
	if strings.Contains(out, "zone=global_conn_limit") {
		t.Error("a name in a comment must not define an alias")
	}
}

// Rendering without an alias that a host still uses would fail nginx -t with
// an error that names no file, so a failed read of the hosts' Advanced Config
// fails the render before nginx.conf is written (as for a host's render).
func TestMainConfig_FailsWhenOldZoneNamesCannotBeRead(t *testing.T) {
	s := baselineSettings()
	s.LimitReqEnabled, s.LimitReqZoneSize, s.LimitReqRate, s.LimitReqBurst = true, "10m", 50, 100
	m := &Manager{}
	dir := t.TempDir()
	m.configPath = filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(m.configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(target, []byte("# previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	readErr := errors.New("db down")
	m.SetLegacyZoneRefSource(func(context.Context) ([]string, error) { return nil, readErr })
	if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{}, TrustedProxyConfig{}); !errors.Is(err, readErr) {
		t.Fatalf("err = %v, want the read error", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "# previous\n" {
		t.Errorf("nginx.conf was written although the old zone names could not be read")
	}
}

// The aliases render only inside the limit blocks, so with both limits off
// the old names are not read, and a failed read cannot block the render.
func TestMainConfig_OldZoneNamesNotReadWithLimitsOff(t *testing.T) {
	s := baselineSettings()
	s.LimitConnEnabled, s.LimitReqEnabled = false, false
	m := &Manager{}
	dir := t.TempDir()
	m.configPath = filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(m.configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	read := false
	m.SetLegacyZoneRefSource(func(context.Context) ([]string, error) {
		read = true
		return nil, errors.New("db down")
	})
	if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{}, TrustedProxyConfig{}); err != nil {
		t.Fatalf("GenerateMainNginxConfig: %v", err)
	}
	if read {
		t.Error("the old zone names were read with both global limits off")
	}
}

// A live old name in the custom HTTP config needs its alias as much as one in
// a host's Advanced Config.
func TestMainConfig_OldGlobalZoneNameInCustomHTTPConfigGetsAlias(t *testing.T) {
	s := baselineSettings()
	s.LimitConnEnabled, s.LimitConnZoneSize, s.LimitConnPerIP = true, "10m", 50
	s.CustomHTTPConfig = "limit_conn global_conn_limit 5;"
	if !strings.Contains(renderOnly(t, s), "limit_conn_zone $global_conn_key zone=global_conn_limit:10m;") {
		t.Error("global_conn_limit is used by the custom HTTP config but not defined")
	}
}

// The zones always key on $global_conn_key and $global_req_key, so the maps
// that define those variables are written with an empty trusted list too.
func TestMainConfig_KeyMapsWrittenWithoutTrustedIPs(t *testing.T) {
	s := baselineSettings()
	s.LimitConnEnabled, s.LimitConnZoneSize, s.LimitConnPerIP = true, "10m", 50
	s.LimitReqEnabled, s.LimitReqZoneSize, s.LimitReqRate, s.LimitReqBurst = true, "10m", 50, 100
	out := renderOnly(t, s)
	for _, want := range []string{
		"map $global_trusted_ip $global_conn_key {",
		"map $global_trusted_ip $global_req_key {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// Each rate-limited host defines six variables with long names, and from
// about 31 such hosts nginx's variables hash no longer fits the default
// max size (1024) with 128-byte buckets: nginx -t then warns "could not build
// optimal variables_hash". A max size of 4096 alone fits about 60 such hosts;
// with 256-byte buckets it fits about 400. These were measured with five
// variables; the sixth, $npg_trusted_<id> (#320), lowers them by about an
// eighth.
func TestMainConfig_VariablesHashSizedForManyRateLimitedHosts(t *testing.T) {
	out := renderOnly(t, baselineSettings())
	if n := strings.Count(out, "variables_hash_max_size"); n != 1 || !strings.Contains(out, "    variables_hash_max_size 4096;\n") {
		t.Errorf("want one `variables_hash_max_size 4096;` in the http block, got %d variables_hash_max_size line(s)", n)
	}
	if n := strings.Count(out, "variables_hash_bucket_size"); n != 1 || !strings.Contains(out, "    variables_hash_bucket_size 256;\n") {
		t.Errorf("want one `variables_hash_bucket_size 256;` in the http block, got %d variables_hash_bucket_size line(s)", n)
	}
}

// A second variables_hash_max_size in the http block fails nginx -t
// ("directive is duplicate"), so one the custom HTTP config sets is the only
// one. A commented-out line sets nothing.
func TestMainConfig_VariablesHashMaxSizeLeftToCustomHTTPConfig(t *testing.T) {
	s := baselineSettings()
	s.CustomHTTPConfig = "variables_hash_max_size 8192;"
	out := renderOnly(t, s)
	if n := strings.Count(out, "variables_hash_max_size"); n != 1 || !strings.Contains(out, "variables_hash_max_size 8192;") {
		t.Errorf("want only the custom HTTP config's variables_hash_max_size, got %d line(s)", n)
	}
	s.CustomHTTPConfig = "# variables_hash_max_size 8192;"
	if !strings.Contains(renderOnly(t, s), "    variables_hash_max_size 4096;\n") {
		t.Error("a commented-out variables_hash_max_size in the custom HTTP config left nginx.conf without its own")
	}
}

// A host's server block runs dozens of regex checks per request; without
// pcre_jit nginx interprets every one. The directive belongs to the main
// context, before events.
func TestMainConfig_PcreJitOn(t *testing.T) {
	out := renderOnly(t, baselineSettings())
	jit, events := strings.Index(out, "\npcre_jit on;\n"), strings.Index(out, "\nevents {")
	if jit < 0 || events < 0 || jit > events {
		t.Errorf("want `pcre_jit on;` in the main context before events (jit=%d events=%d)", jit, events)
	}
}

// inactive drops an entry nobody asked for in that time, whatever the host's
// cache TTL, so it has to outlast the gap between visits. A second
// proxy_cache_revalidate in the http block fails nginx -t, so one the custom
// HTTP config sets is the only one.
func TestMainConfig_ProxyCacheKeepsEntriesBetweenVisits(t *testing.T) {
	s := baselineSettings()
	out := renderOnly(t, s)
	if !strings.Contains(out, " max_size=10g min_free=1g inactive=7d ") {
		t.Error("proxy_cache_path: want max_size=10g min_free=1g inactive=7d")
	}
	if n := strings.Count(out, "proxy_cache_revalidate"); n != 1 || !strings.Contains(out, "    proxy_cache_revalidate on;\n") {
		t.Errorf("want one `proxy_cache_revalidate on;` in the http block, got %d line(s)", n)
	}
	s.CustomHTTPConfig = "proxy_cache_revalidate off;"
	out = renderOnly(t, s)
	if n := strings.Count(out, "proxy_cache_revalidate"); n != 1 || !strings.Contains(out, "proxy_cache_revalidate off;") {
		t.Errorf("want only the custom HTTP config's proxy_cache_revalidate, got %d line(s)", n)
	}
}

// renderMainWithTrusted renders nginx.conf with the global trusted list
// trusted and returns it.
func renderMainWithTrusted(t *testing.T, s *model.GlobalSettings, trusted TrustedIPConfig) string {
	t.Helper()
	dir := t.TempDir()
	m := &Manager{configPath: filepath.Join(dir, "conf.d")}
	if err := os.MkdirAll(m.configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.GenerateMainNginxConfig(context.Background(), s, trusted, TrustedProxyConfig{}); err != nil {
		t.Fatalf("GenerateMainNginxConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Global trusted domains reach nginx.conf only as includes in the geo of
// the global limits ($global_trusted_ip). With the WAF bypass on, the WAF
// rule (id:9000001) matches the static addresses alone: a domain never
// turns the WAF off, and domains alone write no rule.
func TestMainConfigTrustedDomainsAreGeoIncludesOnly(t *testing.T) {
	s := baselineSettings()
	s.LimitConnEnabled, s.LimitConnZoneSize, s.LimitConnPerIP = true, "10m", 50
	s.LimitReqEnabled, s.LimitReqZoneSize, s.LimitReqRate, s.LimitReqBurst = true, "10m", 50, 100
	names := []string{"office.example.com", "partner.example.com"}
	globalGeo := func(t *testing.T, out string) string {
		t.Helper()
		start := strings.Index(out, "geo $global_trusted_ip {")
		if start < 0 {
			t.Fatalf("no geo $global_trusted_ip")
		}
		return out[start : start+strings.Index(out[start:], "\n    }")]
	}
	include := func(name string) string {
		return "# dns: " + name + "\n        include " + DNSIncludeRenderDir + "/" + DNSIncludeKey(model.DNSScopeKindTrusted, name) + ".geo;"
	}

	out := renderMainWithTrusted(t, s, TrustedIPConfig{Static: []string{"192.0.2.7"}, Hostnames: names, BypassWAF: true})
	if !strings.Contains(out, `"@ipMatch 192.0.2.7" "id:9000001,`) {
		t.Errorf("the WAF rule does not match exactly the static address:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "id:9000001") && (strings.Contains(line, "example.com") || strings.Contains(line, DNSIncludeRenderDir)) {
			t.Errorf("a trusted domain reaches the WAF rule: %s", line)
		}
	}
	geo := globalGeo(t, out)
	for _, want := range []string{"192.0.2.7 1;", include(names[0]), include(names[1])} {
		if !strings.Contains(geo, want) {
			t.Errorf("the global trusted geo is missing %q:\n%s", want, geo)
		}
	}
	if n := strings.Count(out, DNSIncludeRenderDir); n != 2 {
		t.Errorf("nginx.conf names a domain file %d time(s), want 2 (the geo's includes)", n)
	}

	out = renderMainWithTrusted(t, s, TrustedIPConfig{Hostnames: names, BypassWAF: true})
	if strings.Contains(out, "id:9000001") {
		t.Errorf("trusted domains alone wrote the WAF bypass rule")
	}
	if geo := globalGeo(t, out); !strings.Contains(geo, include(names[0])) {
		t.Errorf("the global trusted geo does not include the domain:\n%s", geo)
	}

	if out := renderMainWithTrusted(t, baselineSettings(), TrustedIPConfig{Hostnames: names}); strings.Contains(out, DNSIncludeRenderDir) {
		t.Errorf("with both global limits off nginx.conf includes a domain file")
	}
}

// includeCheckingCLI is an nginx -t that runs check each time it is called.
type includeCheckingCLI struct {
	check func()
	tests int
}

func (c *includeCheckingCLI) Test(ctx context.Context) error {
	c.tests++
	c.check()
	return nil
}
func (c *includeCheckingCLI) Reload(ctx context.Context) error { return nil }

// nginx -t fails on a missing include, and a failed nginx -t rolls
// nginx.conf back to the previous release's: each trusted domain file the
// new nginx.conf includes exists before nginx -t reads it. A missing one is
// created empty (it lets no one through), and one the DNS entry service
// wrote keeps its content.
func TestGenerateMainNginxConfigCreatesMissingTrustedIncludes(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configPath: filepath.Join(dir, "conf.d")}
	if err := os.MkdirAll(m.configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	s := baselineSettings()
	s.LimitReqEnabled, s.LimitReqZoneSize, s.LimitReqRate, s.LimitReqBurst = true, "10m", 50, 100
	const office, partner = "office.example.com", "partner.example.com"
	keyOffice, keyPartner := DNSIncludeKey(model.DNSScopeKindTrusted, office), DNSIncludeKey(model.DNSScopeKindTrusted, partner)
	written := FormatDNSIncludeFile(office, model.DNSScopeKindTrusted, 4, ".geo", []string{"192.0.2.7"})
	if err := os.MkdirAll(m.dnsIncludeDiskDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.dnsIncludeDiskPath(keyOffice, ".geo"), written, 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{keyOffice: written, keyPartner: {}}
	cli := &includeCheckingCLI{check: func() {
		for key, content := range want {
			if got, err := os.ReadFile(m.dnsIncludeDiskPath(key, ".geo")); err != nil || !bytes.Equal(got, content) {
				t.Errorf("at nginx -t, %s.geo holds %q (%v), want %q", key, got, err, content)
			}
		}
	}}
	m.cli = cli

	if err := m.GenerateMainNginxConfig(context.Background(), s, TrustedIPConfig{Hostnames: []string{office, partner}}, TrustedProxyConfig{}); err != nil {
		t.Fatalf("GenerateMainNginxConfig: %v", err)
	}
	if cli.tests != 1 {
		t.Fatalf("nginx -t ran %d time(s), want once", cli.tests)
	}
	refs, err := m.ScanDNSIncludeReferences()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || !refs[keyOffice+".geo"] || !refs[keyPartner+".geo"] {
		t.Errorf("nginx.conf includes %v, want the two trusted domains' .geo files", refs)
	}
	if files, err := m.ReadDNSIncludeDir(); err != nil || len(files) != 2 {
		t.Errorf("%d file(s) in the directory (%v), want the two .geo files", len(files), err)
	}
}
