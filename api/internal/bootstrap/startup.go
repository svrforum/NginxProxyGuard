package bootstrap

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
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

// While compose recreates the containers on an upgrade, nginx starts after
// the API, so the startup steps that validate with nginx -t roll back to the
// previous release's files. They run again once nginx is up: checked every
// bootNginxPoll, for at most bootNginxWait.
const (
	bootNginxPoll = 5 * time.Second
	bootNginxWait = 10 * time.Minute
)

// mainNginxConfStep regenerates the main nginx.conf from global settings so
// operator-edited values (brotli, timeouts, custom_http/stream_config, …)
// actually reach nginx (issue #121). The settings are read each time it runs,
// so the run once nginx is up applies a save made in the meantime.
func mainNginxConfStep(c *Container) nginx.DeferredStep {
	return nginx.DeferredStep{Name: "nginx.conf", Apply: func(ctx context.Context) error {
		settings, err := c.Repositories.GlobalSettings.Get(ctx)
		if err != nil {
			return fmt.Errorf("load global settings: %w", err)
		}
		// Pull the global trusted list (IPs and domains) so the http-level
		// limit_conn / limit_req zones honor the same whitelist the per-host
		// configs already use. Its zero value trusts no one.
		var trusted nginx.TrustedIPConfig
		// Zero value reproduces the pre-#278 behaviour, so a settings read
		// failure here still renders a config nginx accepts.
		var trustedProxies nginx.TrustedProxyConfig
		if sys, err := c.Repositories.SystemSettings.Get(ctx); err == nil && sys != nil {
			trusted = service.ResolveTrustedIPConfig(sys)
			trustedProxies = service.ResolveTrustedProxyConfig(sys)
		}
		return c.Nginx.GenerateMainNginxConfig(ctx, settings, trusted, trustedProxies)
	}}
}

// filterSubscriptionStep writes the shared filter subscription configs from
// the enabled subscriptions' entries as they are when it runs.
func filterSubscriptionStep(c *Container) nginx.DeferredStep {
	return nginx.DeferredStep{Name: "filter subscription configs", Apply: func(ctx context.Context) error {
		tmp := service.NewFilterSubscriptionService(c.Repositories.FilterSubscription, nil, c.Nginx, nil)
		return tmp.RegenerateSharedConfigs(ctx)
	}}
}

// runStartup performs startup-time side effects: ensure include files,
// load global settings, sync configs, and spin up background services.
// Mirrors the original ordering in main.go. It returns the steps nginx could
// not validate because it was not running, for applyWhenNginxUp.
func runStartup(ctx context.Context, c *Container) ([]nginx.DeferredStep, error) {
	service.WarnIPListMatchingChangeOnce(ctx, c.DB.DB)
	if err := c.Nginx.EnsureFilterSubscriptionFiles(); err != nil {
		log.Printf("[Startup] Warning: failed to ensure filter subscription files: %v", err)
	}
	// Domain include files before any step below writes or reloads
	// nginx config.
	startDNSEntries(ctx, c)

	directIPAction := loadGlobalSettingsForStartup(ctx, c)

	// Custom error pages on disk before any config that names them is
	// rendered (#335).
	if pages, err := c.Repositories.CustomErrorPage.List(ctx); err != nil {
		log.Printf("[Startup] Warning: failed to load custom error pages: %v", err)
	} else if err := c.Nginx.SyncCustomErrorPages(pages); err != nil {
		log.Printf("[Startup] Warning: failed to write custom error pages: %v", err)
	}

	var later nginx.DeferredSteps

	// Main nginx.conf first, before syncing host configs, so the very first
	// reload after boot is already on the DB-driven file.
	warnLegacyZoneNames(ctx, c)
	log.Println("[Startup] Regenerating main nginx.conf from global settings...")
	if deferred, err := later.Run(ctx, mainNginxConfStep(c)); deferred {
		log.Printf("[Startup] nginx is not running yet; nginx.conf stays on its previous version and is applied once nginx is up: %v", err)
	} else if err != nil {
		log.Printf("[Startup] Warning: failed to regenerate nginx.conf: %v", err)
	} else {
		log.Println("[Startup] nginx.conf regenerated successfully")
	}

	// Generate shared filter subscription config files BEFORE syncing host configs.
	log.Println("[Startup] Generating shared filter subscription configs...")
	if deferred, err := later.Run(ctx, filterSubscriptionStep(c)); deferred {
		log.Printf("[Startup] nginx is not running yet; filter subscription configs stay on their previous version and are applied once nginx is up: %v", err)
	} else if err != nil {
		log.Printf("[Startup] Warning: failed to generate filter subscription configs: %v", err)
	} else {
		log.Println("[Startup] Filter subscription configs generated successfully")
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

	return later.Steps(), nil
}

// applyWhenNginxUp runs, in the background, the startup steps nginx could not
// validate because it was not running yet, once it is up, and reloads it. ctx
// must be the API's root context: startup's own context ends when Startup
// returns, and shutdown cancels the root one.
func applyWhenNginxUp(ctx context.Context, c *Container, steps []nginx.DeferredStep) {
	if len(steps) == 0 {
		return
	}
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.Name
	}
	what := strings.Join(names, " and ")
	go func() {
		err := c.Nginx.ApplyWhenUp(ctx, steps, bootNginxPoll, bootNginxWait)
		switch {
		case err == nil:
			log.Printf("[Startup] nginx is up; applied the %s it could not test at boot, and reloaded it", what)
		case ctx.Err() != nil:
			// Shutting down.
		default:
			// err names the part that failed; a step that failed has
			// rolled back to its previous version.
			log.Printf("[Startup] ERROR: applying the %s nginx could not test at boot failed: %v", what, err)
		}
	}()
}

// warnLegacyZoneNames tells the operator, at every start while it is so,
// where Advanced Config or the custom HTTP config uses a rate limit zone by
// its name from before v2.62.0 (legacyZoneWarnings). One query and one
// settings read.
func warnLegacyZoneNames(ctx context.Context, c *Container) {
	uses, err := c.Repositories.ProxyHost.ListLegacyZoneRefUses(ctx)
	if err != nil {
		log.Printf("[Startup] Warning: could not read Advanced Config for old rate limit zone names: %v", err)
	}
	var customHTTPConfig string
	if settings, err := c.Repositories.GlobalSettings.Get(ctx); err == nil && settings != nil {
		customHTTPConfig = settings.CustomHTTPConfig
	}
	for _, line := range legacyZoneWarnings(uses, customHTTPConfig) {
		log.Printf("[WARN] [Startup] %s", line)
	}
}

// legacyZoneWarnings returns the startup warning's lines: one per place that
// uses an old zone name (a host's Advanced Config, named by the host's
// domain, or the custom HTTP config), sorted, then one line of advice. NPG
// keeps those names defined as aliases (nginx.LegacyZoneRefs), but they count
// separately, and the first reload after the upgrade can be refused once
// where such a zone's key changed. Nil when no place uses one.
func legacyZoneWarnings(uses []repository.LegacyZoneRefUse, customHTTPConfig string) []string {
	const what = " uses rate limit zone names from before v2.62.0: "
	var lines []string
	for _, u := range uses {
		if names := legacyZoneNameList(nginx.FindLegacyZoneRefs(u.Text)); names != "" {
			lines = append(lines, "host "+u.Domain+"'s Advanced Config"+what+names+".")
		}
	}
	if names := legacyZoneNameList(nginx.FindLegacyZoneRefs(customHTTPConfig)); names != "" {
		lines = append(lines, "the custom HTTP config"+what+names+".")
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return append(lines, "Change the config to the new names. NPG keeps the old names defined as separate zones only while the matching rate limit is on. If nginx refuses the first reload after this upgrade, restart the nginx container once.")
}

// legacyZoneNameList lists the old zone names in refs with their new names,
// sorted, or returns "" when there are none.
func legacyZoneNameList(refs nginx.LegacyZoneRefs) string {
	var names []string
	for id := range refs.RateHosts {
		names = append(names, "rate_"+id+" (now npg_rl_"+id+")")
	}
	if refs.GlobalConn {
		names = append(names, "global_conn_limit (now npg_global_conn)")
	}
	if refs.GlobalReq {
		names = append(names, "global_req_limit (now npg_global_req)")
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
	if c.Services.RawLogArchiver != nil {
		go c.Services.RawLogArchiver.Start(ctx)
	}

	if os.Getenv("ENABLE_DOCKER_LOGS") != "false" {
		go c.Services.DockerLogCollector.Start(ctx)
	}

	// CloudProvider + GeoIP scheduler start themselves via their own Start() methods.
	c.Services.CloudProvider.Start()
	c.Services.GeoIPScheduler.Start()

	// A raw log reclaim the previous process left running resumes about five
	// minutes after start-up.
	go c.Services.RawLogReclaim.ResumeIfRunning(ctx)
}
