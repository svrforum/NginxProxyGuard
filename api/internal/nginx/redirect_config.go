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

// Redirect host config template
const redirectHostTemplate = `# nginx-guard generated redirect config
# Redirect Host ID: {{.ID}}
# Domain(s): {{join .DomainNames ", "}}
# Target: {{.ForwardScheme}}://{{.ForwardDomainName}}{{.ForwardPath}}
# Generated at: {{now}}

{{if .Enabled}}
server {
    listen 80;
    listen [::]:80;
    server_name {{join .DomainNames " "}};

    # ACME HTTP-01 Challenge support
    location /.well-known/acme-challenge/ {
        root /etc/nginx/acme-challenge;
        try_files $uri =404;
    }

{{if .BlockExploits}}
    # Block common exploits
    include /etc/nginx/includes/block_exploits.conf;
{{end}}

{{if .SSLEnabled}}
    # Redirect HTTP to HTTPS
    {{if .SSLForceHTTPS}}
    location / {
        return 301 https://$host$request_uri;
    }
    {{else}}
    location / {
        {{redirectReturn .}}
    }
    {{end}}
{{else}}
    location / {
        {{redirectReturn .}}
    }
{{end}}
}

{{if .SSLEnabled}}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    listen 443 quic;
    listen [::]:443 quic;
    server_name {{join .DomainNames " "}};

    # SSL configuration
    ssl_certificate /etc/nginx/certs/{{certPath .}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{certPath .}}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_early_data on;

    # HTTP/3 Alt-Svc header
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

{{if .BlockExploits}}
    # Block common exploits
    include /etc/nginx/includes/block_exploits.conf;
{{end}}

    location / {
        {{redirectReturn .}}
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

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, host); err != nil {
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
