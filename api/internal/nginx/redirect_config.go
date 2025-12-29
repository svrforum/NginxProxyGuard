package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// RedirectHostConfigData holds data for redirect host config generation
type RedirectHostConfigData struct {
	Host      *model.RedirectHost
	HTTPPort  string
	HTTPSPort string
}

// Redirect host config template
const redirectHostTemplate = `# nginx-guard generated redirect config
# Redirect Host ID: {{.Host.ID}}
# Domain(s): {{join .Host.DomainNames ", "}}
# Target: {{.Host.ForwardScheme}}://{{.Host.ForwardDomainName}}{{.Host.ForwardPath}}
# Generated at: {{now}}

{{if .Host.Enabled}}
server {
    listen {{.HTTPPort}};
    listen [::]:{{.HTTPPort}};
    server_name {{join .Host.DomainNames " "}};

    # ACME HTTP-01 Challenge support
    location /.well-known/acme-challenge/ {
        root /etc/nginx/acme-challenge;
        try_files $uri =404;
    }

{{if .Host.BlockExploits}}
    # Block common exploits
    include /etc/nginx/includes/block_exploits.conf;
{{end}}

{{if .Host.SSLEnabled}}
    # Redirect HTTP to HTTPS
    {{if .Host.SSLForceHTTPS}}
    location / {
        return 301 https://$host$request_uri;
    }
    {{else}}
    location / {
        {{redirectReturn .Host}}
    }
    {{end}}
{{else}}
    location / {
        {{redirectReturn .Host}}
    }
{{end}}
}

{{if .Host.SSLEnabled}}
server {
    listen {{.HTTPSPort}} ssl;
    listen [::]:{{.HTTPSPort}} ssl;
    http2 on;
    listen {{.HTTPSPort}} quic;
    listen [::]:{{.HTTPSPort}} quic;
    server_name {{join .Host.DomainNames " "}};

    # SSL configuration
    ssl_certificate /etc/nginx/certs/{{certPath .Host}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{certPath .Host}}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_early_data on;

    # HTTP/3 Alt-Svc header
    add_header Alt-Svc 'h3=":{{.HTTPSPort}}"; ma=86400' always;

{{if .Host.BlockExploits}}
    # Block common exploits
    include /etc/nginx/includes/block_exploits.conf;
{{end}}

    location / {
        {{redirectReturn .Host}}
    }
}
{{end}}
{{end}}
`

// GenerateRedirectConfig generates nginx config for a redirect host
func (m *Manager) GenerateRedirectConfig(ctx context.Context, host *model.RedirectHost) error {
	funcMap := GetRedirectTemplateFuncMap()

	tmpl, err := template.New("redirect_host").Funcs(funcMap).Parse(redirectHostTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse redirect template: %w", err)
	}

	data := RedirectHostConfigData{
		Host:      host,
		HTTPPort:  m.httpPort,
		HTTPSPort: m.httpsPort,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute redirect template: %w", err)
	}

	configFile := filepath.Join(m.configPath, GetRedirectConfigFilename(host))
	if err := os.WriteFile(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write redirect config file: %w", err)
	}

	return nil
}

// RemoveRedirectConfig removes the nginx config for a redirect host
func (m *Manager) RemoveRedirectConfig(ctx context.Context, host *model.RedirectHost) error {
	configFile := filepath.Join(m.configPath, GetRedirectConfigFilename(host))

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}

	if err := os.Remove(configFile); err != nil {
		return fmt.Errorf("failed to remove redirect config file: %w", err)
	}

	return nil
}

// GenerateAllRedirectConfigs generates nginx configs for all redirect hosts
func (m *Manager) GenerateAllRedirectConfigs(ctx context.Context, hosts []model.RedirectHost) error {
	// Remove all existing redirect_host configs
	files, err := filepath.Glob(filepath.Join(m.configPath, "redirect_host_*.conf"))
	if err != nil {
		return fmt.Errorf("failed to list redirect config files: %w", err)
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("failed to remove redirect config file %s: %w", f, err)
		}
	}

	// Generate configs for all hosts
	for _, host := range hosts {
		if err := m.GenerateRedirectConfig(ctx, &host); err != nil {
			return fmt.Errorf("failed to generate redirect config for host %s: %w", host.ID, err)
		}
	}

	return nil
}
