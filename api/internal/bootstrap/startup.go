package bootstrap

import (
	"context"
	"log"
	"os"
	"strings"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
)

// resolveNginxStatusURL reads NGINX_STATUS_URL with a stable default.
func resolveNginxStatusURL() string {
	if v := os.Getenv("NGINX_STATUS_URL"); v != "" {
		return v
	}
	return "http://host.docker.internal:80/nginx_status"
}

// resolveNginxCanaryURL targets the internal /__npg_canary location. It reuses
// the nginx_status host:port (same reachability as StatsCollector) and only
// swaps the path, so it inherits the established host-network routing.
func resolveNginxCanaryURL() string {
	if v := os.Getenv("NGINX_CANARY_URL"); v != "" {
		return v
	}
	status := resolveNginxStatusURL()
	if i := strings.LastIndex(status, "/"); i > len("https://") {
		return status[:i] + "/__npg_canary"
	}
	return "http://host.docker.internal:80/__npg_canary"
}

// resolveAccessLogPath reads NGINX_ACCESS_LOG with a stable default.
// Default targets the buffered file written by every proxy_host config —
// /var/log/nginx/access.log is a symlink to /dev/stdout and has no readable
// content for the file-tail consumer.
func resolveAccessLogPath() string {
	if v := os.Getenv("NGINX_ACCESS_LOG"); v != "" {
		return v
	}
	return "/etc/nginx/logs/access_raw.log"
}

// runStartup performs startup-time side effects: ensure include files,
// load global settings, sync configs, and spin up background services.
// Mirrors the original ordering in main.go.
func runStartup(ctx context.Context, c *Container) error {
	if err := c.Nginx.EnsureFilterSubscriptionFiles(); err != nil {
		log.Printf("[Startup] Warning: failed to ensure filter subscription files: %v", err)
	}

	directIPAction := loadGlobalSettingsForStartup(ctx, c)

	// Regenerate main nginx.conf from global settings so operator-edited
	// values (brotli, timeouts, custom_http/stream_config, …) actually
	// reach nginx (issue #121). We do this before syncing host configs so
	// the very first reload after boot is already on the DB-driven file.
	log.Println("[Startup] Regenerating main nginx.conf from global settings...")
	if settings, err := c.Repositories.GlobalSettings.Get(ctx); err != nil {
		log.Printf("[Startup] Warning: failed to load global settings for nginx.conf: %v", err)
	} else {
		// Pull global trusted IPs so the http-level limit_conn / limit_req
		// zones honor the same whitelist the per-host configs already use.
		var trustedIPs []string
		var trustedBypassWAF bool
		// Zero value reproduces the pre-#278 behaviour, so a settings read
		// failure here still renders a config nginx accepts.
		var trustedProxies nginx.TrustedProxyConfig
		if sys, err := c.Repositories.SystemSettings.Get(ctx); err == nil && sys != nil {
			trustedIPs = service.ParseGlobalTrustedIPs(sys.GlobalTrustedIPs)
			trustedBypassWAF = sys.GlobalTrustedIPsBypassWAF
			trustedProxies = service.ResolveTrustedProxyConfig(sys)
		}
		if err := c.Nginx.GenerateMainNginxConfig(ctx, settings, trustedIPs, trustedBypassWAF, trustedProxies); err != nil {
			log.Printf("[Startup] Warning: failed to regenerate nginx.conf: %v", err)
		} else {
			log.Println("[Startup] nginx.conf regenerated successfully")
		}
	}

	// Generate shared filter subscription config files BEFORE syncing host configs.
	log.Println("[Startup] Generating shared filter subscription configs...")
	{
		tmp := service.NewFilterSubscriptionService(c.Repositories.FilterSubscription, nil, c.Nginx, nil)
		if err := tmp.RegenerateSharedConfigs(ctx); err != nil {
			log.Printf("[Startup] Warning: failed to generate filter subscription configs: %v", err)
		} else {
			log.Println("[Startup] Filter subscription configs generated successfully")
		}
	}

	// Recover certificates stranded in 'pending'/'renewing' by a previous
	// crash/restart — their issuance goroutines died with the process and the
	// renewal scheduler only selects 'issued' certs, so without this they
	// silently drop out of auto-renewal forever.
	if recovered, failed, err := c.Repositories.Certificate.RecoverInterruptedStates(ctx); err != nil {
		log.Printf("[Startup] Warning: failed to recover interrupted certificates: %v", err)
	} else if recovered > 0 || failed > 0 {
		log.Printf("[Startup] Recovered interrupted certificates: %d back to issued (will re-renew on schedule), %d marked error (retry from UI)", recovered, failed)
	}

	// Sync proxy hosts (auto-recovery on failure).
	log.Println("[Startup] Syncing all proxy host configs...")
	if err := c.Services.ProxyHost.SyncAllConfigs(ctx); err != nil {
		log.Printf("[Startup] Warning: failed to sync proxy host configs: %v", err)
	} else {
		log.Println("[Startup] Proxy host configs synced successfully")
	}

	// Re-converge the cloudflared token file to DB state (covers volume
	// re-creation and backup restore).
	if err := c.Services.CloudflareTunnel.SyncTokenFile(ctx); err != nil {
		log.Printf("[CloudflareTunnel] startup token sync failed: %v", err)
	}
	// Managed mode: re-converge the remote catch-all rule in the background —
	// this is what follows an NGINX_HTTPS_PORT change without operator action.
	c.Services.CloudflareTunnel.SyncCatchallAtStartup(ctx)

	// Regenerate default server config.
	log.Println("[Startup] Regenerating default server config...")
	if err := c.Nginx.GenerateDefaultServerConfig(ctx, directIPAction); err != nil {
		log.Printf("[Startup] Warning: failed to regenerate default server config: %v", err)
	} else {
		log.Printf("[Startup] Default server config regenerated successfully (action: %s)\n", directIPAction)
	}

	// Sync redirect host configs. This is the last nginx-touching step of
	// startup on purpose: it sweeps every redirect_host_*.conf before
	// regenerating the valid enabled ones, and applies the result itself
	// (test + reload). Anything writing nginx config after it would ride an
	// unreloaded disk state again.
	log.Println("[Startup] Syncing all redirect host configs...")
	redirectHosts, _, err := c.Repositories.RedirectHost.List(ctx, 1, config.MaxWAFRulesLimit)
	if err != nil {
		log.Printf("[Startup] Warning: failed to list redirect hosts: %v", err)
	} else if err := c.Nginx.GenerateAllRedirectConfigsAndReload(ctx, redirectHosts); err != nil {
		if nginx.IsNginxUnreachableError(err) {
			// Expected on a production cold start: compose has nginx
			// depends_on: api, so nginx is not up yet and will read the
			// freshly synced files when it starts.
			log.Printf("[Startup] Redirect host configs synced on disk; nginx is not reachable yet, so it will pick them up when it starts: %v", err)
		} else {
			log.Printf("[Startup] ERROR: failed to apply redirect host config sync — if nginx is already running it may still be serving removed redirect configs until the next successful reload: %v", err)
		}
	} else {
		log.Println("[Startup] Redirect host configs synced and applied successfully")
	}

	// Surface the default-credentials risk in container logs (H1). The
	// initial-setup gate blocks protected endpoints server-side, but the
	// operator still needs a loud, actionable nudge to change admin/admin.
	if stillDefault, err := c.Repositories.Auth.IsInitialSetupRequired(ctx); err == nil && stillDefault {
		log.Println("[Startup] WARN: default admin account still has initial credentials (admin/admin) — " +
			"protected endpoints are blocked until you change them via the UI / /api/v1/auth/change-credentials")
	}

	return nil
}

// loadGlobalSettingsForStartup loads IPv6/direct-IP settings so nginx
// config generation uses the right defaults from the first generation.
func loadGlobalSettingsForStartup(ctx context.Context, c *Container) string {
	directIPAction := "allow"
	settings, err := c.Repositories.GlobalSettings.Get(ctx)
	if err != nil {
		log.Printf("[Startup] Warning: failed to load global settings: %v", err)
		return directIPAction
	}
	if settings != nil {
		directIPAction = settings.DirectIPAccessAction
		c.Nginx.SetEnableIPv6(settings.EnableIPv6)
		log.Printf("[Startup] Global settings loaded: enable_ipv6=%v, direct_ip_action=%s", settings.EnableIPv6, directIPAction)
	}
	return directIPAction
}

// startBackgroundServices launches goroutine-based background workers.
// Must be called after runStartup so configs are stable by the time
// collectors and schedulers begin emitting work.
func startBackgroundServices(ctx context.Context, c *Container) {
	if c.Services.LogCollector != nil {
		// Boot-time guarantee for v2.14.2's file-tail dependency: raw log
		// storage must be on or LogCollector finds an empty file forever
		// (issue #145). Force-enable here before the collector starts so
		// the WARN-and-keep-going path in LogCollector never fires for a
		// recoverable cause.
		if c.Handlers != nil && c.Handlers.SystemSettings != nil {
			if err := c.Handlers.SystemSettings.EnsureRawLogEnabled(ctx); err != nil {
				log.Printf("[Startup] Warning: failed to ensure raw log enabled: %v", err)
			}
		}
		go c.Services.LogCollector.Start(ctx)
	}
	if c.Services.PipelineCanary != nil {
		go c.Services.PipelineCanary.Start(ctx)
	}
	go c.Services.WAFAutoBan.Start(ctx)
	go c.Services.Fail2ban.Start(ctx)
	go c.Services.StatsCollector.Start(ctx)

	if os.Getenv("ENABLE_DOCKER_LOGS") != "false" {
		go c.Services.DockerLogCollector.Start(ctx)
	}

	// CloudProvider + GeoIP scheduler start themselves via their own Start() methods.
	c.Services.CloudProvider.Start()
	c.Services.GeoIPScheduler.Start()
}
