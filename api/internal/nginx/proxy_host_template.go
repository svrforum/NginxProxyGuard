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
//
// Files prefixed with an underscore (e.g. _security.conf.tmpl) hold
// named partials (`{{define "_security"}}...{{end}}`) shared by both the
// HTTP server block (base.conf.tmpl) and the HTTPS server block
// (ssl.conf.tmpl + cache.conf.tmpl). Partials must appear before any
// caller in this slice and are invoked via `{{template "_security" .}}`.
var proxyHostTemplateSectionOrder = []string{
	"header.conf.tmpl",
	"rate_limit.conf.tmpl",
	"access_list.conf.tmpl",
	"upstream.conf.tmpl",
	"_security.conf.tmpl",
	"auth_request.conf.tmpl",
	"_challenge.conf.tmpl",
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
	AuthProvider                  *model.AuthProvider // ForwardAuth provider (#179); nil if none / stream
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
	AdvancedConfigAuthRequest     bool                  // True if AdvancedConfig is rendered into the server block and sets auth_request at its top level (legacy, see GenerateConfigFull)
	GlobalTrustedIPs              []string              // Global trusted IPs that bypass all security (from system settings)
	TrustedHostnames              []string              // Global trusted domains (#320): their addresses get the GlobalTrustedIPs bypasses except the ban override, the filter subscription bypass and the WAF bypass (exception_list_dns.go)
	LegacyRateZoneAlias           bool                  // Also define rate_<id>, the zone's name before v2.62.0, which Advanced Config or the custom HTTP config still uses (LegacyZoneRefs)
	HTTPPort                      string                // HTTP listen port (default: 80)
	HTTPSPort                     string                // HTTPS listen port (default: 443)
	EnableIPv6                    bool                  // Enable IPv6 listen directives
}

// CloudChallenge reports whether cloud provider blocking challenges visitors
// instead of blocking them: _security marks the request ($cloud_challenge)
// and the challenge gate decides, as for the geo challenge. A host with an
// auth_request of its own blocks instead (403): an auth provider
// (ForwardAuth) holds location /'s one auth_request, and one left at the top
// level of a legacy Advanced Config covers the whole server or location /
// itself - the gate would replace that login, or not load at all.
func (d ProxyHostConfigData) CloudChallenge() bool {
	return len(d.BlockedCloudIPRanges) > 0 && d.CloudProviderChallengeMode && d.AuthProvider == nil &&
		d.Host != nil && !advancedConfigHasTopLevel(d.Host.AdvancedConfig, "auth_request")
}

// RateLimitEnabled reports whether the host has rate limiting on. The rate
// limit key chain reads $npg_trusted_<id>, so access_list.conf defines that
// variable for such a host even when there are no global trusted IPs or
// domains, and $trusted_ip_<id> too, as before: Advanced Config may read it.
func (d ProxyHostConfigData) RateLimitEnabled() bool {
	return d.RateLimit != nil && d.RateLimit.Enabled
}

// ChallengeGate reports whether the host renders the challenge gate: the
// internal /_challenge/validate location, the challenge endpoints,
// @challenge_redirect and the auth_request in front of the content. Geo
// restriction in challenge mode or the cloud provider challenge. A host with
// ForwardAuth renders neither (geoForAuthProvider, CloudChallenge); the
// check here keeps callers that build the data themselves, such as the DNS
// entry host index, in step with the config.
func (d ProxyHostConfigData) ChallengeGate() bool {
	return (d.GeoRestriction != nil && d.GeoRestriction.ChallengeMode && d.AuthProvider == nil) || d.CloudChallenge()
}

// AccessPhaseAuth reports whether the host asks for a login: an auth
// provider (ForwardAuth; the service sets it only when it is enabled and the
// host is not a stream), or auth_request or auth_basic anywhere in its
// Advanced Config (AdvancedConfigHasAuth). It errs towards true: a mention in
// any block counts.
func (d ProxyHostConfigData) AccessPhaseAuth() bool {
	return d.AuthProvider != nil || (d.Host != nil && AdvancedConfigHasAuth(d.Host.AdvancedConfig))
}

// ListSkipsLogin reports whether the host's access list lets the addresses
// it allows skip the host's login: the block renders "satisfy any" (it is
// left out next to the challenge gate, _security.conf.tmpl) on a host with a
// login (AccessPhaseAuth). The access list editor, the host form and the DNS
// entry overview warn about domain entries in such a list. A client the list
// does not allow is sent to the login there, not given the list's 403, so
// the fail2ban gate leaves the host out (#320).
func (d ProxyHostConfigData) ListSkipsLogin() bool {
	return d.AccessList != nil && len(d.AccessList.Items) > 0 && d.AccessList.SatisfyAny &&
		!d.ChallengeGate() && d.AccessPhaseAuth()
}
