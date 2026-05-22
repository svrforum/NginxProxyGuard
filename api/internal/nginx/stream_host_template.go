package nginx

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
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
{{end}}    proxy_pass {{if and .Upstream .Upstream.Servers}}{{streamUpstreamName .Host}}{{else}}{{streamBackend .Host.ForwardHost .Host.ForwardPort}}{{end}};
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

	funcMap := GetTemplateFuncMap("")
	funcMap["streamListen"] = func(host *model.ProxyHost) string {
		return formatListenAddress(host.StreamListenHost, host.StreamListenPort)
	}
	funcMap["streamBackend"] = formatHostPort
	funcMap["streamProtocol"] = func(host *model.ProxyHost) string {
		return model.NormalizeStreamProtocol(host.StreamProtocol)
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

	configFile := filepath.Join(m.getStreamConfigPath(), GetStreamConfigFilename(data.Host))
	if err := m.writeFileAtomic(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write stream config file: %w", err)
	}

	return nil
}
