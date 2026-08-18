package nginx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// RedirectHostConfigData holds data for redirect host config generation
type RedirectHostConfigData struct {
	Host       *model.RedirectHost
	HTTPPort   string
	HTTPSPort  string
	EnableIPv6 bool
}

// InvalidRedirectHostConfigError distinguishes an unsafe legacy/restored row
// from operational render failures. Batch callers skip only this row while
// still failing on I/O, template, and nginx errors.
type InvalidRedirectHostConfigError struct {
	HostID string
	Err    error
}

func (e *InvalidRedirectHostConfigError) Error() string {
	return fmt.Sprintf("invalid redirect host %q: %v", e.HostID, e.Err)
}

func (e *InvalidRedirectHostConfigError) Unwrap() error { return e.Err }

func isInvalidRedirectHostConfig(err error) bool {
	var validationErr *InvalidRedirectHostConfigError
	return errors.As(err, &validationErr)
}

func (m *Manager) skipInvalidRedirectConfig(ctx context.Context, host *model.RedirectHost, err error) error {
	log.Printf("[ERROR] [RedirectHost] SKIPPING unsafe redirect host id=%q; its nginx config will be removed: %v",
		host.ID, err)
	if removeErr := m.RemoveRedirectConfig(ctx, host); removeErr != nil {
		return fmt.Errorf("remove config for skipped invalid redirect host %s: %w", host.ID, removeErr)
	}
	return nil
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
{{if .EnableIPv6}}    listen [::]:{{.HTTPPort}};
{{end}}    server_name {{join .Host.DomainNames " "}};

    # Disable WAF for redirect host
    modsecurity off;

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
{{if .EnableIPv6}}    listen [::]:{{.HTTPSPort}} ssl;
{{end}}    http2 on;
    listen {{.HTTPSPort}} quic;
{{if .EnableIPv6}}    listen [::]:{{.HTTPSPort}} quic;
{{end}}
    server_name {{join .Host.DomainNames " "}};

    # Disable WAF for redirect host
    modsecurity off;

    # SSL configuration (inherits ssl_protocols, ssl_ciphers, ssl_ecdh_curve from http block)
    ssl_certificate /etc/nginx/certs/{{certPath .Host}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{certPath .Host}}/privkey.pem;
    ssl_early_data on;

    # HTTP/3 Alt-Svc header (1 hour cache for faster fallback on connection issues)
    add_header Alt-Svc 'h3=":{{.HTTPSPort}}"; ma=3600' always;

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
	if err := model.ValidateRedirectHost(host); err != nil {
		return &InvalidRedirectHostConfigError{HostID: host.ID, Err: err}
	}

	funcMap := GetRedirectTemplateFuncMap()

	tmpl, err := template.New("redirect_host").Funcs(funcMap).Parse(redirectHostTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse redirect template: %w", err)
	}

	// Check if SSL is enabled but no certificate is assigned or cert files don't exist
	if host.SSLEnabled && (host.CertificateID == nil || *host.CertificateID == "") {
		log.Printf("[WARN] SSL temporarily disabled for redirect host %s (%s): no certificate assigned. Config will be HTTP-only until a certificate is assigned.",
			host.ID, strings.Join(host.DomainNames, ", "))
		host.SSLEnabled = false
		host.SSLForceHTTPS = false
	} else if host.SSLEnabled && host.CertificateID != nil && *host.CertificateID != "" {
		certPath := filepath.Join(m.certsPath, *host.CertificateID, "fullchain.pem")
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			log.Printf("[WARN] SSL temporarily disabled for redirect host %s (%s): certificate file not found at %s. Config will be HTTP-only until certificate is ready.",
				host.ID, strings.Join(host.DomainNames, ", "), certPath)
			host.SSLEnabled = false
			host.SSLForceHTTPS = false
		}
	}

	data := RedirectHostConfigData{
		Host:       host,
		HTTPPort:   m.httpPort,
		HTTPSPort:  m.httpsPort,
		EnableIPv6: m.enableIPv6,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute redirect template: %w", err)
	}

	configFile := filepath.Join(m.configPath, GetRedirectConfigFilename(host))

	// Use atomic write to prevent nginx from reading partial config
	if err := m.writeFileAtomic(configFile, buf.Bytes(), 0644); err != nil {
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

// GenerateAllRedirectConfigs generates nginx configs for all redirect hosts.
// Invalid enabled rows are removed and skipped individually; operational errors
// still abort because continuing after an I/O failure could leave a partial set.
func (m *Manager) GenerateAllRedirectConfigs(ctx context.Context, hosts []model.RedirectHost) error {
	// Clear stale and disabled configs first. Active valid rows are recreated
	// below, while invalid rows stay absent from the loaded nginx configuration.
	files, err := filepath.Glob(filepath.Join(m.configPath, "redirect_host_*.conf"))
	if err != nil {
		return fmt.Errorf("failed to list redirect config files: %w", err)
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("failed to remove redirect config file %s: %w", f, err)
		}
	}

	for i := range hosts {
		host := &hosts[i]
		// Disabled rows never reach an nginx directive context.
		if !host.Enabled {
			continue
		}
		if err := m.GenerateRedirectConfig(ctx, host); err != nil {
			if isInvalidRedirectHostConfig(err) {
				if skipErr := m.skipInvalidRedirectConfig(ctx, host, err); skipErr != nil {
					return skipErr
				}
				continue
			}
			return fmt.Errorf("failed to generate redirect config for host %s: %w", host.ID, err)
		}
	}

	return nil
}

// GenerateAllRedirectConfigsAndReload reconciles every redirect config and
// applies the resulting set to the running nginx instance. Generation and the
// test/reload are serialized under the global nginx lock so another config
// operation cannot interleave between the file sweep and reload. The reload
// runs through the retrying path, which also performs the post-reload health
// probe (SyncAllConfigs' plain ReloadNginx does not), so a probe failure at
// boot surfaces here as an error.
//
// Unlike normal user-driven updates, this startup reconciliation deliberately
// does not restore swept files when applying the new set fails: an old file may
// belong to an unsafe legacy redirect row. Keeping it absent on disk ensures a
// later successful reload cannot reactivate it.
func (m *Manager) GenerateAllRedirectConfigsAndReload(ctx context.Context, hosts []model.RedirectHost) error {
	return m.executeWithLock(ctx, func() error {
		if err := m.GenerateAllRedirectConfigs(ctx, hosts); err != nil {
			return err
		}
		if err := m.testAndReloadNginxWithRetry(ctx); err != nil {
			return fmt.Errorf("failed to apply redirect config sync to nginx: %w", err)
		}
		return nil
	})
}

// nginxUnreachablePattern matches docker/exec failures that mean there is no
// nginx container to talk to, as opposed to a configuration problem. At API
// boot this is the normal case for production compose, where nginx has
// `depends_on: api` and therefore starts only afterwards.
var nginxUnreachablePattern = regexp.MustCompile(
	// Only signals that actually prove nginx is NOT running belong here. A dead
	// docker socket or a missing binary can happen while nginx is up and serving
	// stale config, and that case must stay loud.
	`(?i)(is not running|no such container)`,
)

// IsNginxUnreachableError reports whether err comes from nginx being
// unreachable rather than from a bad configuration. Callers use it to choose a
// log level: a failed apply against a *running* nginx leaves it serving stale
// config, while an unreachable nginx simply reads the synced files when it
// starts.
func IsNginxUnreachableError(err error) bool {
	if err == nil {
		return false
	}
	return nginxUnreachablePattern.MatchString(err.Error())
}
