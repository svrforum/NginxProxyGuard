package bootstrap

import (
	"nginx-proxy-guard/internal/handler"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/pkg/cache"
)

// Handlers bundles every HTTP handler.
type Handlers struct {
	ProxyHost          *handler.ProxyHostHandler
	DNSProvider        *handler.DNSProviderHandler
	Certificate        *handler.CertificateHandler
	Log                *handler.LogHandler
	WAFTest            *handler.WAFTestHandler
	WAF                *handler.WAFHandler
	ExploitBlockRule   *handler.ExploitBlockRuleHandler
	AccessList         *handler.AccessListHandler
	RedirectHost       *handler.RedirectHostHandler
	Geo                *handler.GeoHandler
	Security           *handler.SecurityHandler
	Settings           *handler.SettingsHandler
	SystemLog          *handler.SystemLogHandler
	Auth               *handler.AuthHandler
	SystemSettings     *handler.SystemSettingsHandler
	APIToken           *handler.APITokenHandler
	AuditLog           *handler.AuditLogHandler
	Challenge          *handler.ChallengeHandler
	CloudProvider      *handler.CloudProviderHandler
	FilterSubscription *handler.FilterSubscriptionHandler
	Swagger            *handler.SwaggerHandler
	Metrics            *handler.MetricsHandler
}

// InitHandlers constructs every HTTP handler with the previously built
// services and repositories.
func InitHandlers(
	repos *Repositories,
	svcs *Services,
	nginxManager *nginx.Manager,
	redisCache *cache.RedisClient,
) *Handlers {
	h := &Handlers{}

	h.ProxyHost = handler.NewProxyHostHandler(svcs.ProxyHost, svcs.Audit)
	h.DNSProvider = handler.NewDNSProviderHandler(svcs.DNSProvider)
	h.Certificate = handler.NewCertificateHandler(svcs.Certificate, svcs.Audit)
	h.Log = handler.NewLogHandler(repos.Log, redisCache, repos.RateLimit)
	h.WAFTest = handler.NewWAFTestHandler()
	h.WAF = handler.NewWAFHandler(repos.WAF, repos.ProxyHost, repos.Geo, nginxManager)
	h.ExploitBlockRule = handler.NewExploitBlockRuleHandler(repos.ExploitBlockRule, repos.ProxyHost, svcs.ProxyHost)
	h.AccessList = handler.NewAccessListHandler(repos.AccessList)
	h.RedirectHost = handler.NewRedirectHostHandler(repos.RedirectHost, nginxManager, svcs.Audit)
	h.Geo = handler.NewGeoHandler(
		repos.Geo,
		repos.ProxyHost,
		nginxManager,
		repos.AccessList,
		repos.RateLimit,
		repos.SecurityHeaders,
		repos.BotFilter,
		repos.Upstream,
	)
	h.Security = handler.NewSecurityHandler(svcs.Security, svcs.Audit)
	h.Settings = handler.NewSettingsHandler(svcs.Settings, svcs.Audit)
	h.SystemLog = handler.NewSystemLogHandler(repos.SystemLog)
	h.Auth = handler.NewAuthHandler(svcs.Auth, svcs.Audit)
	h.SystemSettings = handler.NewSystemSettingsHandler(
		repos.SystemSettings,
		repos.GeoIPHistory,
		nginxManager,
		svcs.Audit,
		svcs.DockerLogCollector,
		svcs.GeoIPScheduler,
		svcs.CloudProvider,
		svcs.ProxyHost,
	)
	h.APIToken = handler.NewAPITokenHandler(repos.APIToken, repos.AuditLog)
	h.AuditLog = handler.NewAuditLogHandler(repos.AuditLog, repos.APIToken)
	h.Challenge = handler.NewChallengeHandler(svcs.Challenge, svcs.Audit)
	h.CloudProvider = handler.NewCloudProviderHandler(repos.CloudProvider, svcs.ProxyHost, svcs.Audit)
	h.FilterSubscription = handler.NewFilterSubscriptionHandler(svcs.FilterSubscription, svcs.Audit)
	h.Swagger = handler.NewSwaggerHandler()
	h.Metrics = handler.NewMetricsHandler()

	return h
}
