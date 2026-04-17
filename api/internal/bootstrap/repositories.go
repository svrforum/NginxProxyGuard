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
	RedirectHost       *repository.RedirectHostRepository
	Geo                *repository.GeoRepository
	RateLimit          *repository.RateLimitRepository
	IPBanHistory       *repository.IPBanHistoryRepository
	BotFilter          *repository.BotFilterRepository
	SecurityHeaders    *repository.SecurityHeadersRepository
	Upstream           *repository.UpstreamRepository
	GlobalSettings     *repository.GlobalSettingsRepository
	Dashboard          *repository.DashboardRepository
	Backup             *repository.BackupRepository
	SystemLog          *repository.SystemLogRepository
	Auth               *repository.AuthRepository
	SystemSettings     *repository.SystemSettingsRepository
	APIToken           *repository.APITokenRepository
	AuditLog           *repository.AuditLogRepository
	Challenge          *repository.ChallengeRepository
	CloudProvider      *repository.CloudProviderRepository
	URIBlock           *repository.URIBlockRepository
	GeoIPHistory       *repository.GeoIPHistoryRepository
	ExploitBlockRule   *repository.ExploitBlockRuleRepository
	FilterSubscription *repository.FilterSubscriptionRepository
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
		RedirectHost:       repository.NewRedirectHostRepository(db),
		Geo:                repository.NewGeoRepository(db),
		RateLimit:          repository.NewRateLimitRepository(db.DB),
		IPBanHistory:       repository.NewIPBanHistoryRepository(db.DB),
		BotFilter:          repository.NewBotFilterRepository(db.DB),
		SecurityHeaders:    repository.NewSecurityHeadersRepository(db.DB),
		Upstream:           repository.NewUpstreamRepository(db.DB),
		GlobalSettings:     repository.NewGlobalSettingsRepository(db.DB),
		Dashboard:          repository.NewDashboardRepository(db.DB),
		Backup:             repository.NewBackupRepository(db.DB),
		SystemLog:          repository.NewSystemLogRepository(db.DB),
		Auth:               repository.NewAuthRepository(db.DB),
		SystemSettings:     repository.NewSystemSettingsRepository(db.DB),
		APIToken:           repository.NewAPITokenRepository(db.DB),
		AuditLog:           repository.NewAuditLogRepository(db.DB),
		Challenge:          repository.NewChallengeRepository(db.DB),
		CloudProvider:      repository.NewCloudProviderRepository(db.DB),
		URIBlock:           repository.NewURIBlockRepository(db),
		GeoIPHistory:       repository.NewGeoIPHistoryRepository(db.DB),
		ExploitBlockRule:   repository.NewExploitBlockRuleRepository(db.DB),
		FilterSubscription: repository.NewFilterSubscriptionRepository(db.DB),
	}

	if redisCache != nil {
		repos.ProxyHost.SetCache(redisCache)
		repos.Log.SetCache(redisCache)
		repos.GlobalSettings.SetCache(redisCache)
		repos.SystemSettings.SetCache(redisCache)
		repos.ExploitBlockRule.SetCache(redisCache)
		log.Println("Valkey cache wired to repositories")
	}

	return repos
}
