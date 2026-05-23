package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

const streamHostTemplate = `{{if .Host.Enabled -}}
# Stream proxy for {{join .Host.DomainNames ", "}}
{{if and .Upstream .Upstream.Servers -}}
upstream {{streamUpstreamName .Host}} {
{{if eq .Upstream.LoadBalance "least_conn"}}    least_conn;
{{else if eq .Upstream.LoadBalance "random"}}    random;
{{end -}}
{{range .Upstream.Servers}}    server {{streamBackend .Address .Port}}{{if ne .Weight 1}} weight={{.Weight}}{{end}}{{if ne .MaxFails 0}} max_fails={{.MaxFails}}{{end}}{{if ne .FailTimeout 0}} fail_timeout={{.FailTimeout}}s{{end}}{{if .IsBackup}} backup{{end}}{{if .IsDown}} down{{end}};
{{end -}}
}
{{end}}
server {
    listen {{streamListen .Host}}{{if eq (streamProtocol .Host) "udp"}} udp reuseport{{end}}{{if .Host.StreamAcceptProxyProtocol}} proxy_protocol{{end}};
{{if and .Host.StreamSSLPreread .Host.DomainNames}}    server_name {{join .Host.DomainNames " "}};
{{end}}{{if .Host.StreamProxyConnectTimeout}}    proxy_connect_timeout {{.Host.StreamProxyConnectTimeout}}s;
{{end}}{{if .Host.StreamProxyTimeout}}    proxy_timeout {{.Host.StreamProxyTimeout}}s;
{{end}}{{if .Host.StreamSendProxyProtocol}}    proxy_protocol on;
{{end}}{{if streamAccessLog}}    access_log /var/log/nginx/stream_access.log stream_main;
{{end}}{{if streamErrorLog}}    error_log /var/log/nginx/stream_error.log warn;
{{end}}{{if .Host.StreamSSLPreread}}    ssl_preread on;
{{end}}{{if and .Upstream .Upstream.Servers}}    proxy_pass {{streamUpstreamName .Host}};
{{else}}    resolver {{streamResolver}} valid=30s;
    resolver_timeout 5s;
    set $stream_backend {{streamBackend .Host.ForwardHost .Host.ForwardPort}};
    proxy_pass $stream_backend;
{{end}}
{{if .Host.AdvancedConfig}}
    # Advanced stream configuration
{{.Host.AdvancedConfig}}
{{end}}}
{{end -}}
`

// GenerateStreamConfig renders a single TCP/UDP stream proxy server file.
func (m *Manager) GenerateStreamConfig(ctx context.Context, data ProxyHostConfigData) error {
	_ = ctx
	if data.Host == nil {
		return fmt.Errorf("stream host is nil")
	}
	if data.Host.StreamListenPort <= 0 {
		return fmt.Errorf("stream listen port is required")
	}
	if data.Host.ForwardHost == "" || data.Host.ForwardPort <= 0 {
		return fmt.Errorf("stream upstream host and port are required")
	}
	if !model.ValidateStreamListenHost(data.Host.StreamListenHost) {
		return fmt.Errorf("invalid stream_listen_host %q: use an empty value, '*', or a local IP address; upstream hostnames belong in forward_host", data.Host.StreamListenHost)
	}
	// ssl_preread is a TCP-only directive in nginx's ngx_stream_ssl_preread_module.
	// Using it inside a UDP server block causes nginx to reject the config at load
	// time, which would then trigger a rollback on every reload until the user
	// fixes it via UI. Catch it at config generation so the API returns a clean
	// error instead of letting nginx -t fail.
	if data.Host.StreamSSLPreread && strings.EqualFold(model.NormalizeStreamProtocol(data.Host.StreamProtocol), "udp") {
		return fmt.Errorf("invalid stream config: ssl_preread is not supported for UDP stream hosts (TCP only)")
	}
	streamListenHost := model.NormalizeStreamListenHost(data.Host.StreamListenHost)

	funcMap := GetTemplateFuncMap("")
	funcMap["streamListen"] = func(host *model.ProxyHost) string {
		return formatListenAddress(streamListenHost, host.StreamListenPort)
	}
	funcMap["streamBackend"] = formatHostPort
	funcMap["streamProtocol"] = func(host *model.ProxyHost) string {
		return model.NormalizeStreamProtocol(host.StreamProtocol)
	}
	funcMap["streamResolver"] = func() string {
		resolver := strings.TrimSpace(m.dnsResolver)
		if resolver == "" {
			return "127.0.0.53 8.8.8.8"
		}
		return resolver
	}
	funcMap["streamUpstreamName"] = func(host *model.ProxyHost) string {
		return "stream_upstream_" + sanitizeFilename(host.ID)
	}
	funcMap["streamAccessLog"] = func() bool {
		return m.streamAccessLog
	}
	funcMap["streamErrorLog"] = func() bool {
		return m.streamErrorLog
	}

	tmpl, err := template.New("stream_host").Funcs(funcMap).Parse(streamHostTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse stream template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute stream template: %w", err)
	}

	streamDir := m.getStreamConfigPath()
	// Defensive MkdirAll: SyncAllConfigs path (existing-install upgrade) may
	// reach GenerateStreamConfig before GenerateMainNginxConfig has ensured
	// stream.d/ exists. writeFileAtomic would otherwise fail with ENOENT
	// because the temp file's target directory is missing. This is idempotent.
	if err := os.MkdirAll(streamDir, 0755); err != nil {
		return fmt.Errorf("failed to create stream config directory: %w", err)
	}
	configFile := filepath.Join(streamDir, GetStreamConfigFilename(data.Host))
	if err := m.writeFileAtomic(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write stream config file: %w", err)
	}

	return nil
}
