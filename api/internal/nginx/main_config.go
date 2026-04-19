package nginx

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// mainNginxConfigTemplate renders /etc/nginx/nginx.conf from DB-stored global
// settings. Historically this file was a static copy baked into the Docker
// image, so every HTTP/stream setting the operator edited in the UI silently
// stayed in the database and never reached nginx (issue #121).
//
// Structural sections (module loads, real_ip, GeoIP include, log_format, map
// blocks, proxy_cache_path, modsecurity base, include conf.d/*.conf) are kept
// fixed because they are deployment invariants. Everything operators can tune
// from the Global Settings UI flows through here.
const mainNginxConfigTemplate = `# Nginx Proxy Guard main configuration
# Auto-generated from global_settings — do NOT edit by hand. Changes made here
# are overwritten on every reload. Edit via the Global Settings UI instead.
# HTTP/3, ModSecurity v3, Brotli compression, GeoIP2

# Load dynamic modules
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
load_module /usr/lib/nginx/modules/ngx_http_brotli_filter_module.so;
load_module /usr/lib/nginx/modules/ngx_http_brotli_static_module.so;
load_module /usr/lib/nginx/modules/ngx_http_headers_more_filter_module.so;
load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;
load_module /usr/lib/nginx/modules/ngx_stream_geoip2_module.so;

user nginx;
worker_processes {{.WorkerProcessesStr}};
{{if .WorkerRlimitNofileSet}}worker_rlimit_nofile {{.WorkerRlimitNofile}};
{{else}}worker_rlimit_nofile 65535;
{{end}}error_log /var/log/nginx/error.log {{.ErrorLogLevel}};
pid /var/run/nginx.pid;

events {
    worker_connections {{.WorkerConnections}};
{{if .UseEpoll}}    use epoll;
{{end}}{{if .MultiAccept}}    multi_accept on;
{{end}}}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # ==========================================================================
    # Real IP Configuration
    # Extract real client IP from X-Forwarded-For when behind proxies/Docker
    # ==========================================================================
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    set_real_ip_from 127.0.0.0/8;
    set_real_ip_from ::1;
    set_real_ip_from fc00::/7;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    # ==========================================================================
    # GeoIP2 Configuration (conditionally loaded by entrypoint)
    # ==========================================================================
    include /etc/nginx/geoip/geoip-active.conf;

    # ==========================================================================
    # Proxy Cache
    # ==========================================================================
    proxy_cache_path /var/cache/nginx/proxy levels=1:2 keys_zone=proxy_cache:100m max_size=10g inactive=60m use_temp_path=off;

    # ==========================================================================
    # Log variables and formats
    # block_reason_var / bot_category_var / exploit_rule_var are set by server
    # blocks when blocking occurs.
    # ==========================================================================
    map $uri $block_reason_var  { default "-"; }
    map $uri $bot_category_var  { default "-"; }
    map $uri $exploit_rule_var  { default "-"; }

    log_format main '$remote_addr - $remote_user [$time_local] "$host" '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time" '
                    'ua="$upstream_addr" us="$upstream_status" '
                    'geo="$geoip2_country_code" asn="$geoip2_asn" '
                    'block="$block_reason_var" bot="$bot_category_var" '
                    'exploit_rule="$exploit_rule_var"';

    log_format json_combined escape=json '{'
        '"time":"$time_iso8601",'
        '"remote_addr":"$remote_addr",'
        '"host":"$host",'
        '"request_method":"$request_method",'
        '"request_uri":"$request_uri",'
        '"status":$status,'
        '"body_bytes_sent":$body_bytes_sent,'
        '"request_time":$request_time,'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent",'
        '"http_x_forwarded_for":"$http_x_forwarded_for",'
        '"upstream_response_time":"$upstream_response_time",'
        '"upstream_addr":"$upstream_addr",'
        '"upstream_status":"$upstream_status",'
        '"geoip_country":"$geoip2_country_code",'
        '"geoip_country_name":"$geoip2_country_name",'
        '"geoip_continent":"$geoip2_continent_code",'
        '"geoip_asn":$geoip2_asn,'
        '"geoip_org":"$geoip2_org",'
        '"block_reason":"$block_reason_var",'
        '"bot_category":"$bot_category_var",'
        '"exploit_rule":"$exploit_rule_var"'
    '}';

{{if .AccessLogEnabled}}    access_log /var/log/nginx/access.log main buffer=64k flush=5s;
{{else}}    access_log off;
{{end}}
    # WebSocket and keepalive support
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' '';
    }

    # ==========================================================================
    # Performance
    # ==========================================================================
{{if .Sendfile}}    sendfile on;
{{else}}    sendfile off;
{{end}}{{if .TCPNopush}}    tcp_nopush on;
{{else}}    tcp_nopush off;
{{end}}{{if .TCPNodelay}}    tcp_nodelay on;
{{else}}    tcp_nodelay off;
{{end}}    keepalive_timeout {{.KeepaliveTimeout}};
    keepalive_requests {{.KeepaliveRequests}};
    types_hash_max_size {{.TypesHashMaxSize}};
    variables_hash_bucket_size 128;
    server_names_hash_bucket_size 128;
{{if .ServerTokens}}    server_tokens on;
{{else}}    server_tokens off;
{{end}}{{if .ResetTimedoutConnection}}    reset_timedout_connection on;
{{else}}    reset_timedout_connection off;
{{end}}{{if gt .LimitRate 0}}    limit_rate {{.LimitRate}};
    limit_rate_after {{.LimitRateAfter}};
{{end}}
{{if .OpenFileCacheEnabled}}    # File descriptor cache for static files
    open_file_cache max={{.OpenFileCacheMax}} inactive={{.OpenFileCacheInactive}};
    open_file_cache_valid {{.OpenFileCacheValid}};
    open_file_cache_min_uses {{.OpenFileCacheMinUses}};
{{if .OpenFileCacheErrors}}    open_file_cache_errors on;
{{else}}    open_file_cache_errors off;
{{end}}{{else}}    open_file_cache off;
{{end}}
    # ==========================================================================
    # Client buffer / size limits
    # ==========================================================================
    client_body_buffer_size {{.ClientBodyBufferSize}};
    client_header_buffer_size {{.ClientHeaderBufferSize}};
    client_max_body_size {{.ClientMaxBodySize}};
    large_client_header_buffers {{.LargeClientHeaderBuffers}};
    client_body_timeout {{.ClientBodyTimeout}};
    client_header_timeout {{.ClientHeaderTimeout}};
    send_timeout {{.SendTimeout}};

    # Proxy timeouts (defaults; per-host may override)
    proxy_connect_timeout {{.ProxyConnectTimeout}};
    proxy_send_timeout {{.ProxySendTimeout}};
    proxy_read_timeout {{.ProxyReadTimeout}};

    # Proxy buffering (defaults; per-host may override)
    proxy_buffer_size {{.ProxyBufferSize}};
    proxy_buffers {{.ProxyBuffers}};
    proxy_busy_buffers_size {{.ProxyBusyBuffersSize}};
    proxy_max_temp_file_size {{.ProxyMaxTempFileSize}};
    proxy_temp_file_write_size {{.ProxyTempFileWriteSize}};
{{if ne .ProxyBuffering ""}}    proxy_buffering {{.ProxyBuffering}};
{{end}}{{if ne .ProxyRequestBuffering ""}}    proxy_request_buffering {{.ProxyRequestBuffering}};
{{end}}
    # ==========================================================================
    # Gzip
    # ==========================================================================
{{if .GzipEnabled}}    gzip on;
{{if .GzipVary}}    gzip_vary on;
{{end}}{{if ne .GzipProxied ""}}    gzip_proxied {{.GzipProxied}};
{{end}}    gzip_comp_level {{.GzipCompLevel}};
{{if ne .GzipBuffers ""}}    gzip_buffers {{.GzipBuffers}};
{{end}}{{if ne .GzipHTTPVersion ""}}    gzip_http_version {{.GzipHTTPVersion}};
{{end}}    gzip_min_length {{.GzipMinLength}};
{{if ne .GzipTypes ""}}    gzip_types {{.GzipTypes}};
{{end}}{{else}}    gzip off;
{{end}}
    # ==========================================================================
    # Brotli
    # ==========================================================================
{{if .BrotliEnabled}}    brotli on;
{{if .BrotliStatic}}    brotli_static on;
{{else}}    brotli_static off;
{{end}}    brotli_comp_level {{.BrotliCompLevel}};
    brotli_min_length {{.BrotliMinLength}};
{{if ne .BrotliTypes ""}}    brotli_types {{.BrotliTypes}};
{{end}}{{else}}    brotli off;
{{end}}
    # ==========================================================================
    # SSL / TLS
    # ==========================================================================
    ssl_protocols {{.SSLProtocols}};
{{if ne .SSLCiphers ""}}    ssl_ciphers {{.SSLCiphers}};
{{end}}{{if .SSLPreferServerCiphers}}    ssl_prefer_server_ciphers on;
{{else}}    ssl_prefer_server_ciphers off;
{{end}}{{if ne .SSLSessionCache ""}}    ssl_session_cache {{.SSLSessionCache}};
{{end}}{{if ne .SSLSessionTimeout ""}}    ssl_session_timeout {{.SSLSessionTimeout}};
{{end}}{{if .SSLSessionTickets}}    ssl_session_tickets on;
{{else}}    ssl_session_tickets off;
{{end}}{{if ne .SSLECDHCurve ""}}    ssl_ecdh_curve {{.SSLECDHCurve}};
{{end}}
    # OCSP Stapling
{{if .SSLStapling}}    ssl_stapling on;
{{if .SSLStaplingVerify}}    ssl_stapling_verify on;
{{else}}    ssl_stapling_verify off;
{{end}}{{else}}    ssl_stapling off;
{{end}}{{if ne .Resolver ""}}    resolver {{.Resolver}};
{{end}}{{if ne .ResolverTimeout ""}}    resolver_timeout {{.ResolverTimeout}};
{{end}}
    # HTTP/3 (QUIC)
    ssl_early_data on;
    quic_retry on;

    # ==========================================================================
    # HTTP/3 Host header fix for ModSecurity
    # HTTP/3 uses :authority pseudo-header; forward it as Host for audit logs.
    # ==========================================================================
    more_set_input_headers "Host: $host";

    # Security headers (safe defaults for all responses)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # ==========================================================================
    # ModSecurity / OWASP CRS Global Configuration
    # CRS rules are loaded ONCE here at the http level for performance.
    # Per-host WAF tuning (paranoia, exclusions, mode) merges with this base
    # via modsecurity_rules in each server block.
    # ==========================================================================
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/crs-global.conf;

{{if .LimitConnEnabled}}    # ==========================================================================
    # Global connection limit (DDoS protection)
    # ==========================================================================
    limit_conn_zone $binary_remote_addr zone=global_conn_limit:{{.LimitConnZoneSize}};
    limit_conn global_conn_limit {{.LimitConnPerIP}};
{{end}}{{if .LimitReqEnabled}}    # ==========================================================================
    # Global request rate limit (DDoS protection)
    # ==========================================================================
    limit_req_zone $binary_remote_addr zone=global_req_limit:{{.LimitReqZoneSize}} rate={{.LimitReqRate}}r/s;
    limit_req zone=global_req_limit burst={{.LimitReqBurst}} nodelay;
{{end}}{{if ne .CustomHTTPConfig ""}}
    # ==========================================================================
    # Custom HTTP config (from Global Settings → Advanced)
    # ==========================================================================
{{.CustomHTTPConfig}}
{{end}}
    # Virtual hosts, default server, redirect hosts, filter subscriptions, etc.
    # zzz_default.conf supplies /health, /nginx_status, ACME challenge, and
    # direct-IP access policy.
    include /etc/nginx/conf.d/*.conf;
}
{{if ne .CustomStreamConfig ""}}
# ==============================================================================
# Stream block (from Global Settings → Advanced → custom_stream_config)
# ==============================================================================
stream {
{{.CustomStreamConfig}}
}
{{end}}`

// MainConfigData carries the rendered values for mainNginxConfigTemplate.
// It is constructed from a *model.GlobalSettings; see buildMainConfigData.
type MainConfigData struct {
	WorkerProcessesStr    string // "auto" when 0, else the number
	WorkerRlimitNofileSet bool
	WorkerRlimitNofile    int
	WorkerConnections     int
	MultiAccept           bool
	UseEpoll              bool
	ErrorLogLevel         string

	Sendfile          bool
	TCPNopush         bool
	TCPNodelay        bool
	KeepaliveTimeout  int
	KeepaliveRequests int
	TypesHashMaxSize  int
	ServerTokens      bool

	ResetTimedoutConnection bool
	LimitRate               int
	LimitRateAfter          string

	OpenFileCacheEnabled  bool
	OpenFileCacheMax      int
	OpenFileCacheInactive string
	OpenFileCacheValid    string
	OpenFileCacheMinUses  int
	OpenFileCacheErrors   bool

	ClientBodyBufferSize     string
	ClientHeaderBufferSize   string
	ClientMaxBodySize        string
	LargeClientHeaderBuffers string
	ClientBodyTimeout        int
	ClientHeaderTimeout      int
	SendTimeout              int

	ProxyConnectTimeout    int
	ProxySendTimeout       int
	ProxyReadTimeout       int
	ProxyBufferSize        string
	ProxyBuffers           string
	ProxyBusyBuffersSize   string
	ProxyMaxTempFileSize   string
	ProxyTempFileWriteSize string
	ProxyBuffering         string
	ProxyRequestBuffering  string

	GzipEnabled     bool
	GzipVary        bool
	GzipProxied     string
	GzipCompLevel   int
	GzipBuffers     string
	GzipHTTPVersion string
	GzipMinLength   int
	GzipTypes       string

	BrotliEnabled   bool
	BrotliStatic    bool
	BrotliCompLevel int
	BrotliMinLength int
	BrotliTypes     string

	SSLProtocols           string
	SSLCiphers             string
	SSLPreferServerCiphers bool
	SSLSessionCache        string
	SSLSessionTimeout      string
	SSLSessionTickets      bool
	SSLStapling            bool
	SSLStaplingVerify      bool
	SSLECDHCurve           string

	Resolver        string
	ResolverTimeout string

	AccessLogEnabled bool

	LimitConnEnabled  bool
	LimitConnZoneSize string
	LimitConnPerIP    int

	LimitReqEnabled  bool
	LimitReqZoneSize string
	LimitReqRate     int
	LimitReqBurst    int

	CustomHTTPConfig   string
	CustomStreamConfig string
}

// validErrorLogLevels keeps the error_log directive from rejecting a bogus
// value persisted in DB (e.g. old row where the column was never populated).
var validErrorLogLevels = map[string]bool{
	"debug": true, "info": true, "notice": true,
	"warn": true, "error": true, "crit": true, "alert": true, "emerg": true,
}

// buildMainConfigData translates a GlobalSettings row into template inputs,
// applying fallbacks for fields where a zero value would produce an invalid
// nginx directive (e.g. empty ssl_protocols, 0 worker_connections).
func buildMainConfigData(s *model.GlobalSettings) MainConfigData {
	d := MainConfigData{
		WorkerConnections:        s.WorkerConnections,
		MultiAccept:              s.MultiAccept,
		UseEpoll:                 s.UseEpoll,
		ErrorLogLevel:            s.ErrorLogLevel,
		Sendfile:                 s.Sendfile,
		TCPNopush:                s.TCPNopush,
		TCPNodelay:               s.TCPNodelay,
		KeepaliveTimeout:         s.KeepaliveTimeout,
		KeepaliveRequests:        s.KeepaliveRequests,
		TypesHashMaxSize:         s.TypesHashMaxSize,
		ServerTokens:             s.ServerTokens,
		ResetTimedoutConnection:  s.ResetTimedoutConnection,
		LimitRate:                s.LimitRate,
		LimitRateAfter:           s.LimitRateAfter,
		OpenFileCacheEnabled:     s.OpenFileCacheEnabled,
		OpenFileCacheMax:         s.OpenFileCacheMax,
		OpenFileCacheInactive:    s.OpenFileCacheInactive,
		OpenFileCacheValid:       s.OpenFileCacheValid,
		OpenFileCacheMinUses:     s.OpenFileCacheMinUses,
		OpenFileCacheErrors:      s.OpenFileCacheErrors,
		ClientBodyBufferSize:     s.ClientBodyBufferSize,
		ClientHeaderBufferSize:   s.ClientHeaderBufferSize,
		ClientMaxBodySize:        s.ClientMaxBodySize,
		LargeClientHeaderBuffers: s.LargeClientHeaderBuffers,
		ClientBodyTimeout:        s.ClientBodyTimeout,
		ClientHeaderTimeout:      s.ClientHeaderTimeout,
		SendTimeout:              s.SendTimeout,
		ProxyConnectTimeout:      s.ProxyConnectTimeout,
		ProxySendTimeout:         s.ProxySendTimeout,
		ProxyReadTimeout:         s.ProxyReadTimeout,
		ProxyBufferSize:          s.ProxyBufferSize,
		ProxyBuffers:             s.ProxyBuffers,
		ProxyBusyBuffersSize:     s.ProxyBusyBuffersSize,
		ProxyMaxTempFileSize:     s.ProxyMaxTempFileSize,
		ProxyTempFileWriteSize:   s.ProxyTempFileWriteSize,
		ProxyBuffering:           s.ProxyBuffering,
		ProxyRequestBuffering:    s.ProxyRequestBuffering,
		GzipEnabled:              s.GzipEnabled,
		GzipVary:                 s.GzipVary,
		GzipProxied:              s.GzipProxied,
		GzipCompLevel:            s.GzipCompLevel,
		GzipBuffers:              s.GzipBuffers,
		GzipHTTPVersion:          s.GzipHTTPVersion,
		GzipMinLength:            s.GzipMinLength,
		GzipTypes:                s.GzipTypes,
		BrotliEnabled:            s.BrotliEnabled,
		BrotliStatic:             s.BrotliStatic,
		BrotliCompLevel:          s.BrotliCompLevel,
		BrotliMinLength:          s.BrotliMinLength,
		BrotliTypes:              s.BrotliTypes,
		SSLProtocols:             s.SSLProtocols,
		SSLCiphers:               s.SSLCiphers,
		SSLPreferServerCiphers:   s.SSLPreferServerCiphers,
		SSLSessionCache:          s.SSLSessionCache,
		SSLSessionTimeout:        s.SSLSessionTimeout,
		SSLSessionTickets:        s.SSLSessionTickets,
		SSLStapling:              s.SSLStapling,
		SSLStaplingVerify:        s.SSLStaplingVerify,
		SSLECDHCurve:             s.SSLECDHCurve,
		Resolver:                 s.Resolver,
		ResolverTimeout:          s.ResolverTimeout,
		AccessLogEnabled:         s.AccessLogEnabled,
		LimitConnEnabled:         s.LimitConnEnabled,
		LimitConnZoneSize:        s.LimitConnZoneSize,
		LimitConnPerIP:           s.LimitConnPerIP,
		LimitReqEnabled:          s.LimitReqEnabled,
		LimitReqZoneSize:         s.LimitReqZoneSize,
		LimitReqRate:             s.LimitReqRate,
		LimitReqBurst:            s.LimitReqBurst,
		CustomHTTPConfig:         strings.TrimSpace(s.CustomHTTPConfig),
		CustomStreamConfig:       strings.TrimSpace(s.CustomStreamConfig),
	}
	if s.WorkerProcesses <= 0 {
		d.WorkerProcessesStr = "auto"
	} else {
		d.WorkerProcessesStr = fmt.Sprintf("%d", s.WorkerProcesses)
	}
	if s.WorkerRlimitNofile != nil && *s.WorkerRlimitNofile > 0 {
		d.WorkerRlimitNofileSet = true
		d.WorkerRlimitNofile = *s.WorkerRlimitNofile
	}
	if !validErrorLogLevels[d.ErrorLogLevel] {
		d.ErrorLogLevel = "warn"
	}
	return d
}

// GenerateMainNginxConfig renders /etc/nginx/nginx.conf from DB global
// settings, writes it atomically, and runs `nginx -t` against the result.
// On test failure it restores the previous nginx.conf so a bad save can
// never leave the container unable to reload or restart.
//
// Call from startup and from SettingsService.UpdateGlobalSettings.
func (m *Manager) GenerateMainNginxConfig(ctx context.Context, s *model.GlobalSettings) error {
	if s == nil {
		return fmt.Errorf("global settings are nil")
	}

	tmpl, err := template.New("nginx_main").Parse(mainNginxConfigTemplate)
	if err != nil {
		return fmt.Errorf("parse main nginx template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, buildMainConfigData(s)); err != nil {
		return fmt.Errorf("execute main nginx template: %w", err)
	}

	// nginx.conf lives one directory up from conf.d/ (configPath).
	target := filepath.Join(filepath.Dir(m.configPath), "nginx.conf")

	// Back up the existing file so a bad template render can be undone.
	// On the very first boot no backup exists yet — that's fine; a template
	// failure there just means nginx stays on whatever the image seeded.
	var backup []byte
	backupExists := false
	if b, err := os.ReadFile(target); err == nil {
		backup = b
		backupExists = true
	}

	// All nginx file ops share globalNginxMutex; other writers must not
	// interleave a reload while we swap nginx.conf and validate it.
	return m.executeWithLock(ctx, func() error {
		if err := m.writeFileAtomic(target, buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}

		// Skip validation in unit tests (no docker) and when explicitly
		// disabled; the production path always runs it.
		if m.skipTest || m.cli == nil {
			return nil
		}
		if err := m.testConfigInternal(ctx); err != nil {
			log.Printf("[MainConfig] nginx -t rejected generated nginx.conf; rolling back: %v", err)
			if backupExists {
				if writeErr := m.writeFileAtomic(target, backup, 0644); writeErr != nil {
					log.Printf("[MainConfig] ERROR: failed to restore previous nginx.conf: %v", writeErr)
				}
			} else {
				if rmErr := os.Remove(target); rmErr != nil && !os.IsNotExist(rmErr) {
					log.Printf("[MainConfig] ERROR: failed to remove invalid first-boot nginx.conf: %v", rmErr)
				}
			}
			return fmt.Errorf("generated nginx.conf failed nginx -t: %w", err)
		}
		return nil
	})
}
