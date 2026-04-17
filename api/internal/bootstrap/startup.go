package bootstrap

import (
	"context"
	"log"
	"os"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/service"
)

// resolveNginxStatusURL reads NGINX_STATUS_URL with a stable default.
func resolveNginxStatusURL() string {
	if v := os.Getenv("NGINX_STATUS_URL"); v != "" {
		return v
	}
	return "http://host.docker.internal:80/nginx_status"
}

// resolveAccessLogPath reads NGINX_ACCESS_LOG with a stable default.
func resolveAccessLogPath() string {
	if v := os.Getenv("NGINX_ACCESS_LOG"); v != "" {
		return v
	}
	return "/var/log/nginx/access.log"
}

// runStartup performs startup-time side effects: ensure include files,
// load global settings, sync configs, and spin up background services.
// Mirrors the original ordering in main.go.
func runStartup(ctx context.Context, c *Container) error {
	if err := c.Nginx.EnsureFilterSubscriptionFiles(); err != nil {
		log.Printf("[Startup] Warning: failed to ensure filter subscription files: %v", err)
	}

	directIPAction := loadGlobalSettingsForStartup(ctx, c)

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

	// Sync proxy hosts (auto-recovery on failure).
	log.Println("[Startup] Syncing all proxy host configs...")
	if err := c.Services.ProxyHost.SyncAllConfigs(ctx); err != nil {
		log.Printf("[Startup] Warning: failed to sync proxy host configs: %v", err)
	} else {
		log.Println("[Startup] Proxy host configs synced successfully")
	}

	// Sync redirect host configs.
	log.Println("[Startup] Syncing all redirect host configs...")
	redirectHosts, _, err := c.Repositories.RedirectHost.List(ctx, 1, config.MaxWAFRulesLimit)
	if err != nil {
		log.Printf("[Startup] Warning: failed to list redirect hosts: %v", err)
	} else if err := c.Nginx.GenerateAllRedirectConfigs(ctx, redirectHosts); err != nil {
		log.Printf("[Startup] Warning: failed to sync redirect host configs: %v", err)
	} else {
		log.Println("[Startup] Redirect host configs synced successfully")
	}

	// Regenerate default server config.
	log.Println("[Startup] Regenerating default server config...")
	if err := c.Nginx.GenerateDefaultServerConfig(ctx, directIPAction); err != nil {
		log.Printf("[Startup] Warning: failed to regenerate default server config: %v", err)
	} else {
		log.Printf("[Startup] Default server config regenerated successfully (action: %s)\n", directIPAction)
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
		go c.Services.LogCollector.Start(ctx)
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
