package bootstrap

import (
	"log"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// Repositories bundles every repository constructed against the database.
// Struct ordering mirrors the original main.go construction order.
type Repositories struct {
	ProxyHost          *repository.ProxyHostRepository
	DNSProvider        *repository.DNSProviderRepository
	Certificate        *repository.CertificateRepository
	Log                *repository.LogRepository
	WAF                *repository.WAFRepository
	AccessList         *repository.AccessListRepository
	AuthProvider       *repository.AuthProviderRepository
	RedirectHost       *repository.RedirectHostRepository
	Geo                *repository.GeoRepository
	GlobalGeo          *repository.GlobalGeoRepository
	GlobalBotFilter    *repository.GlobalBotFilterRepository
	GlobalSecHeaders   *repository.GlobalSecurityHeadersRepository
	GlobalCloud        *repository.GlobalCloudProvidersRepository
	GlobalRateLimit    *repository.GlobalRateLimitRepository
	GlobalWAF          *repository.GlobalWAFRepository
	RateLimit          *repository.RateLimitRepository
	IPBanHistory       *repository.IPBanHistoryRepository
	BotFilter          *repository.BotFilterRepository
	SecurityHeaders    *repository.SecurityHeadersRepository
	Upstream           *repository.UpstreamRepository
	GlobalSettings     *repository.GlobalSettingsRepository
	Dashboard          *repository.DashboardRepository
	Backup             *repository.BackupRepository
	SystemLog          *repository.SystemLogRepository
	LogFilterPreset    *repository.LogFilterPresetRepository
	Auth               *repository.AuthRepository
	Role               *repository.RoleRepository
	User               *repository.UserRepository
	SystemSettings     *repository.SystemSettingsRepository
	APIToken           *repository.APITokenRepository
	AuditLog           *repository.AuditLogRepository
	Challenge          *repository.ChallengeRepository
	CloudProvider      *repository.CloudProviderRepository
	URIBlock           *repository.URIBlockRepository
	GeoIPHistory       *repository.GeoIPHistoryRepository
	ExploitBlockRule   *repository.ExploitBlockRuleRepository
	FilterSubscription *repository.FilterSubscriptionRepository
	HealthDetailed     *repository.HealthDetailedRepository
	DDNS               *repository.DDNSRepository
	CloudflareTunnel   *repository.CloudflareTunnelRepository
}

// InitRepositories instantiates every repository and, if a cache is
// available, wires it into the repositories that support caching.
func InitRepositories(db *database.DB, redisCache *cache.RedisClient) *Repositories {
	repos := &Repositories{
		ProxyHost:          repository.NewProxyHostRepository(db),
		DNSProvider:        repository.NewDNSProviderRepository(db),
		Certificate:        repository.NewCertificateRepository(db),
		Log:                repository.NewLogRepository(db),
		WAF:                repository.NewWAFRepository(db),
		AccessList:         repository.NewAccessListRepository(db),
		AuthProvider:       repository.NewAuthProviderRepository(db),
		RedirectHost:       repository.NewRedirectHostRepository(db),
		Geo:                repository.NewGeoRepository(db),
		GlobalGeo:          repository.NewGlobalGeoRepository(db),
		RateLimit:          repository.NewRateLimitRepository(db.DB),
		IPBanHistory:       repository.NewIPBanHistoryRepository(db.DB),
		BotFilter:          repository.NewBotFilterRepository(db.DB),
		GlobalBotFilter:    repository.NewGlobalBotFilterRepository(db.DB),
		SecurityHeaders:    repository.NewSecurityHeadersRepository(db.DB),
		GlobalSecHeaders:   repository.NewGlobalSecurityHeadersRepository(db.DB),
		GlobalCloud:        repository.NewGlobalCloudProvidersRepository(db.DB),
		GlobalRateLimit:    repository.NewGlobalRateLimitRepository(db.DB),
		GlobalWAF:          repository.NewGlobalWAFRepository(db.DB),
		Upstream:           repository.NewUpstreamRepository(db.DB),
		GlobalSettings:     repository.NewGlobalSettingsRepository(db.DB),
		Dashboard:          repository.NewDashboardRepository(db.DB),
		Backup:             repository.NewBackupRepository(db.DB),
		SystemLog:          repository.NewSystemLogRepository(db.DB),
		LogFilterPreset:    repository.NewLogFilterPresetRepository(db.DB),
		Auth:               repository.NewAuthRepository(db.DB),
		Role:               repository.NewRoleRepository(db),
		User:               repository.NewUserRepository(db),
		SystemSettings:     repository.NewSystemSettingsRepository(db.DB),
		APIToken:           repository.NewAPITokenRepository(db.DB),
		AuditLog:           repository.NewAuditLogRepository(db.DB),
		Challenge:          repository.NewChallengeRepository(db.DB),
		CloudProvider:      repository.NewCloudProviderRepository(db.DB),
		URIBlock:           repository.NewURIBlockRepository(db),
		GeoIPHistory:       repository.NewGeoIPHistoryRepository(db.DB),
		ExploitBlockRule:   repository.NewExploitBlockRuleRepository(db.DB),
		FilterSubscription: repository.NewFilterSubscriptionRepository(db.DB),
		HealthDetailed:     repository.NewHealthDetailedRepository(db.DB),
		DDNS:               repository.NewDDNSRepository(db),
		CloudflareTunnel:   repository.NewCloudflareTunnelRepository(db.DB),
	}

	if redisCache != nil {
		repos.ProxyHost.SetCache(redisCache)
		repos.Log.SetCache(redisCache)
		repos.GlobalSettings.SetCache(redisCache)
		repos.SystemSettings.SetCache(redisCache)
		repos.ExploitBlockRule.SetCache(redisCache)
		repos.RateLimit.SetCache(redisCache)
		repos.FilterSubscription.SetCache(redisCache)
		repos.Certificate.SetCache(redisCache)
		repos.Geo.SetCache(redisCache)
		repos.BotFilter.SetCache(redisCache)
		log.Println("Valkey cache wired to repositories")
	}

	// CloudProvider writes to geo_restrictions directly (blocked_cloud_providers
	// column). Wire it to the geo repo so those writes invalidate the per-host
	// geo cache — otherwise geo.Update's read-modify-write would clobber the
	// cloud-provider settings after a 60s cache window.
	repos.CloudProvider.SetGeoRepo(repos.Geo)

	return repos
}
