package bootstrap

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
	"nginx-proxy-guard/pkg/cache"
)

// Services bundles every service constructed from repositories and infrastructure.
// Background services (log collector, WAF auto-ban, etc.) expose Stop semantics so
// the container can shut them down cleanly.
type Services struct {
	ProxyHost          *service.ProxyHostService
	DNSProvider        *service.DNSProviderService
	Certificate        *service.CertificateService
	NginxReloader      *service.NginxReloader
	FilterSubscription *service.FilterSubscriptionService
	Audit              *service.AuditService
	Challenge          *service.ChallengeService
	Auth               *service.AuthService
	DockerStats        *service.DockerStatsService
	DockerLogCollector *service.DockerLogCollector
	Security           *service.SecurityService
	Settings           *service.SettingsService
	GeoIP              *service.GeoIPService
	CloudProvider      *service.CloudProviderService
	GeoIPScheduler     *service.GeoIPScheduler
	LogCollector       *service.LogCollector
	WAFAutoBan         *service.WAFAutoBanService
	Fail2ban           *service.Fail2banService
	StatsCollector     *service.StatsCollector
}

// InitServices creates the full service graph in the same order as the
// original main.go.  Cross-service callbacks are applied afterwards via
// wireServiceCallbacks so nothing here depends on construction order.
func InitServices(
	cfg *config.Config,
	db *database.DB,
	redisCache *cache.RedisClient,
	nginxManager *nginx.Manager,
	repos *Repositories,
) *Services {
	svcs := &Services{}

	svcs.ProxyHost = service.NewProxyHostService(
		repos.ProxyHost,
		repos.WAF,
		repos.AccessList,
		repos.Geo,
		repos.RateLimit,
		repos.SecurityHeaders,
		repos.BotFilter,
		repos.Upstream,
		repos.SystemSettings,
		repos.CloudProvider,
		repos.GlobalSettings,
		repos.URIBlock,
		repos.ExploitBlockRule,
		repos.Certificate,
		repos.SystemLog,
		nginxManager,
	)

	svcs.DNSProvider = service.NewDNSProviderService(repos.DNSProvider)

	svcs.Certificate = service.NewCertificateService(
		repos.Certificate,
		repos.DNSProvider,
		repos.SystemSettings,
		cfg.NginxCertsPath,
		cfg.ACMEEmail,
		redisCache,
	)

	svcs.NginxReloader = service.NewNginxReloader(nginxManager, config.NginxReloaderDebounce)

	svcs.FilterSubscription = service.NewFilterSubscriptionService(
		repos.FilterSubscription,
		svcs.ProxyHost,
		nginxManager,
		svcs.NginxReloader,
	)

	svcs.Audit = service.NewAuditService(repos.AuditLog)

	svcs.Challenge = service.NewChallengeService(repos.Challenge)

	svcs.Auth = service.NewAuthServiceWithCache(repos.Auth, cfg.JWTSecret, redisCache)

	svcs.DockerStats = service.NewDockerStatsService()

	svcs.DockerLogCollector = service.NewDockerLogCollector(repos.SystemLog, repos.SystemSettings)

	svcs.Security = service.NewSecurityService(
		repos.RateLimit,
		repos.BotFilter,
		repos.SecurityHeaders,
		repos.Upstream,
		repos.ProxyHost,
		svcs.ProxyHost,
		repos.IPBanHistory,
		repos.URIBlock,
		redisCache,
		svcs.NginxReloader,
	)

	svcs.Settings = service.NewSettingsService(
		repos.GlobalSettings,
		repos.SystemSettings,
		repos.Dashboard,
		repos.Backup,
		repos.ProxyHost,
		repos.RedirectHost,
		repos.Certificate,
		repos.WAF,
		nginxManager,
		svcs.ProxyHost,
		svcs.DockerStats,
		redisCache,
		cfg.BackupPath,
	)

	svcs.GeoIP = service.NewGeoIPServiceWithCache(redisCache)

	svcs.CloudProvider = service.NewCloudProviderService(repos.CloudProvider)

	svcs.GeoIPScheduler = service.NewGeoIPScheduler(
		repos.SystemSettings,
		repos.GeoIPHistory,
		svcs.GeoIP,
	)

	if cfg.LogCollection {
		svcs.LogCollector = service.NewLogCollector(
			repos.Log,
			cfg.NginxContainer,
			svcs.GeoIP,
			redisCache,
		)
	}

	svcs.WAFAutoBan = service.NewWAFAutoBanService(
		db.DB,
		repos.SystemSettings,
		repos.RateLimit,
		repos.ProxyHost,
		svcs.ProxyHost,
		repos.IPBanHistory,
	)

	svcs.Fail2ban = service.NewFail2banService(
		db.DB,
		repos.RateLimit,
		repos.ProxyHost,
		svcs.ProxyHost,
		redisCache,
		repos.IPBanHistory,
	)

	svcs.StatsCollector = service.NewStatsCollector(
		db.DB,
		resolveNginxStatusURL(),
		resolveAccessLogPath(),
	)

	return svcs
}

// wireServiceCallbacks hooks cross-service callbacks and setter injections.
// These are intentionally done after construction to avoid cycles.
func wireServiceCallbacks(svcs *Services, repos *Repositories) {
	// ProxyHost: enable clone and filter-subscription-aware config generation.
	svcs.ProxyHost.SetCertificateService(svcs.Certificate)
	svcs.ProxyHost.SetFilterSubscriptionRepo(repos.FilterSubscription)

	// Certificate: regenerate proxy-host configs after a cert is ready.
	svcs.Certificate.SetCertificateReadyCallback(func(ctx context.Context, certificateID string) error {
		log.Printf("Certificate %s is ready, regenerating nginx configs for affected proxy hosts", certificateID)
		return svcs.ProxyHost.RegenerateConfigsForCertificate(ctx, certificateID)
	})

	// Challenge: resolve system-settings lazily.
	svcs.Challenge.SetSystemSettingsRepo(repos.SystemSettings)

	// Cloud provider: regenerate configs when IP ranges change.
	svcs.CloudProvider.SetIPRangesUpdatedCallback(func(ctx context.Context, updatedProviders []string) error {
		log.Printf("[CloudProvider] IP ranges updated for %v, regenerating affected nginx configs", updatedProviders)
		return svcs.ProxyHost.RegenerateConfigsForCloudProviders(ctx, updatedProviders)
	})

	// GeoIP scheduler: re-seed cloud provider ranges on GeoIP update.
	svcs.GeoIPScheduler.SetCloudProviderService(svcs.CloudProvider)

	// Log collector: wire downstream consumers when log collection is enabled.
	if svcs.LogCollector != nil {
		svcs.LogCollector.SetWAFAutoBanService(svcs.WAFAutoBan)
		svcs.LogCollector.SetFail2banService(svcs.Fail2ban)
		svcs.LogCollector.SetProxyHostRepo(repos.ProxyHost)
		svcs.LogCollector.SetSystemSettingsRepo(repos.SystemSettings)
	}
}

// StopBackgroundServices gracefully stops services with explicit Stop semantics.
// Context-driven services (WAFAutoBan, Fail2ban) stop via the root context
// cancellation that drives their Start goroutines.
func (s *Services) StopBackgroundServices() {
	if s == nil {
		return
	}
	if s.LogCollector != nil {
		s.LogCollector.Stop()
	}
	if s.StatsCollector != nil {
		s.StatsCollector.Stop()
	}
	if s.DockerLogCollector != nil {
		s.DockerLogCollector.Stop()
	}
	if s.CloudProvider != nil {
		s.CloudProvider.Stop()
	}
	if s.GeoIPScheduler != nil {
		s.GeoIPScheduler.Stop()
	}
	if s.GeoIP != nil {
		s.GeoIP.Close()
	}
}
