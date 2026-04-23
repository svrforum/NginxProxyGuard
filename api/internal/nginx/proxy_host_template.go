package nginx

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// proxyHostTemplatesFS embeds the section-based template files.
// The template is split into nine positional chunks whose concatenation
// reproduces the original monolithic template byte-for-byte. See Phase 4a
// of docs/superpowers/plans/2026-04-17-codebase-cleanup.md for context.
//
//go:embed templates/proxy_host/*.tmpl
var proxyHostTemplatesFS embed.FS

// proxyHostTemplateSectionOrder defines the concatenation order of the
// section files. Changing this order will change the rendered config.
var proxyHostTemplateSectionOrder = []string{
	"header.conf.tmpl",
	"rate_limit.conf.tmpl",
	"access_list.conf.tmpl",
	"upstream.conf.tmpl",
	"base.conf.tmpl",
	"waf.conf.tmpl",
	"ssl.conf.tmpl",
	"cache.conf.tmpl",
	"advanced.conf.tmpl",
}

// proxyHostTemplate is the concatenated template body used by the nginx
// config generator. It is assembled at init from the embedded .tmpl files
// so the rendering logic (see manager.go's GenerateConfigFull) remains
// unchanged while the template content is split across semantic files.
var proxyHostTemplate = mustLoadProxyHostTemplate()

func mustLoadProxyHostTemplate() string {
	var b strings.Builder
	for _, name := range proxyHostTemplateSectionOrder {
		data, err := fs.ReadFile(proxyHostTemplatesFS, "templates/proxy_host/"+name)
		if err != nil {
			panic(fmt.Sprintf("nginx: failed to load template section %q: %v", name, err))
		}
		b.Write(data)
	}
	return b.String()
}

// ProxyHostConfigData holds all data for proxy host config generation
type ProxyHostConfigData struct {
	Host                          *model.ProxyHost
	AccessList                    *model.AccessList
	GeoRestriction                *model.GeoRestriction
	RateLimit                     *model.RateLimit
	SecurityHeaders               *model.SecurityHeaders
	BotFilter                     *model.BotFilter
	BannedIPs                     []model.BannedIP
	Upstream                      *model.Upstream
	GlobalSettings                *model.GlobalSettings // Global nginx settings (timeouts, compression, etc.)
	SuspiciousClientsList         string                // Newline-separated list of suspicious clients from system settings
	BadBotsList                   string                // Newline-separated list of bad bots from system settings
	AIBotsList                    string                // Newline-separated list of AI bots from system settings
	SearchEnginesList             string                // Newline-separated list of allowed search engines from system settings
	BlockedCloudIPRanges          []string              // CIDR ranges of blocked cloud providers
	CloudProviderChallengeMode    bool                  // If true, show challenge instead of blocking cloud providers
	CloudProviderAllowSearchBots  bool                  // If true, allow search engine bots to bypass cloud provider blocking
	URIBlock                      *model.URIBlock       // URI path blocking settings
	GlobalBlockExploitsExceptions string                // Global newline-separated list of exploit exceptions from system settings
	ExploitBlockRules             []model.ExploitBlockRuleForRender // Dynamic exploit blocking rules + URI exclusions (service layer populates)
	UseFilterSubscription         bool                    // If true, include shared filter subscription configs (IPs + UAs)
	HasCustomLocationRoot         bool                  // True if AdvancedConfig contains a location / block
	AdvancedConfigHasLocation     bool                  // True if AdvancedConfig contains any location directive
	AdvancedConfigDirectives      map[string]bool       // Set of directive names present in AdvancedConfig (e.g. "proxy_connect_timeout")
	AdvancedConfigServerLevel     string                // Server-level directives extracted from AdvancedConfig (ssl_stapling, etc.)
	AdvancedConfigLocationLevel   string                // Location-level directives extracted from AdvancedConfig
	GlobalTrustedIPs              []string              // Global trusted IPs that bypass all security (from system settings)
	HTTPPort                      string                // HTTP listen port (default: 80)
	HTTPSPort                     string                // HTTPS listen port (default: 443)
	EnableIPv6                    bool                  // Enable IPv6 listen directives
}
