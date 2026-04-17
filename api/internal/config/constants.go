package config

import "time"

// Application version
const AppVersion = "2.11.0"

// Health status constants
const (
	StatusOK         = "ok"
	StatusError      = "error"
	StatusHealthy    = "healthy"
	StatusUnhealthy  = "unhealthy"
	StatusPending    = "pending"
	StatusDisabled   = "disabled"
	StatusDegraded   = "degraded"
	StatusConnecting = "connecting"
	StatusUnknown    = "unknown"
)

// File permission constants
const (
	DefaultDirPermissions  = 0755
	DefaultFilePermissions = 0644
)

// Timeout constants
const (
	HTTPClientTimeout       = 30 * time.Second
	StatsCollectionInterval = 30 * time.Second
	Fail2banTickerInterval  = 30 * time.Second
)

// Certificate constants
const (
	CertDefaultValidityDays    = 365
	CertRenewalThresholdDays   = 30
	CertRenewalCheckInterval   = 24 * time.Hour
)

// WAF and security constants
const (
	WAFAutoBanWindowSeconds  = 300
	WAFRuleCategoryDivisor   = 1000
	MaxWAFRulesLimit         = 10000
	MaxLogLinesDisplay       = 1000
)

// Rate limiting defaults
const (
	DefaultRPS           = 10
	DefaultBurstSize     = 20
	DefaultZoneSize      = "10m"
	DefaultLimitResponse = 429
)

// Proxy host validation constants
const (
	MinParanoiaLevel        = 1
	MaxParanoiaLevel        = 4
	DefaultAnomalyThreshold = 5
)

// Log collection constants
const (
	LogBatchSize         = 100
	LogListMaxLimit      = 1000
	DefaultLogBufferSize = 64 * 1024
	MaxLogBufferSize     = 1024 * 1024
)

// Pagination defaults
const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// Handler-specific limits
const (
	DefaultAuditLogLimit   = 50
	DefaultWAFRuleLimit    = 100
	DefaultDashboardLimit  = 100
	MaxDashboardLimit      = 1000
	MaxFilterArraySize     = 100
)

// Security constants
const (
	HSTSMaxAge = 31536000 // 1 year in seconds
)

// Service-specific timeouts
const (
	CPUSamplingDuration     = 500 * time.Millisecond
	NginxReloaderDebounce   = 2 * time.Second
	ContextTimeout          = 30 * time.Second
	NginxTestTimeout        = 60 * time.Second
	NginxReloadTimeout      = 30 * time.Second
)

// Reload retry behavior — governs testAndReloadNginxWithRetry.
// Transient errors (docker/network/IO glitches) retry with exponential backoff.
// Non-transient errors (nginx syntax, reload rejection) return immediately.
const (
	ReloadMaxRetries     = 2                      // additional retries after first attempt (total 3 tries)
	ReloadRetryBaseDelay = 500 * time.Millisecond // 500ms, 1s, 2s doubling
)

// Post-reload health verification — runs after a successful nginx reload.
// Failure triggers the Phase 1 rollback mechanism.
const (
	WorkerReadyTimeout = 2 * time.Second
	HealthProbeTimeout = 500 * time.Millisecond
)

// GeoIP constants
const (
	MinGeoIPDatabaseSize = 1000000 // 1MB minimum for valid GeoIP database
)

// Redis/cache constants
const (
	RedisMaxRetries       = 5
	RedisRetryBaseSeconds = 1
)

// Log collector constants
const (
	LogCollectorMaxRetries = 3
	LogBufferMultiplier    = 10
)

// Filter subscription constants
const (
	FilterFetchTimeout         = 30 * time.Second
	FilterFetchConnectTimeout  = 5 * time.Second
	FilterMaxResponseSize      = 10 * 1024 * 1024 // 10MB
	FilterMaxTotalEntries      = 100000
	FilterMaxEntriesPerFile    = 25000
	FilterMaxRedirects         = 3
	FilterRefreshCheckInterval = 10 * time.Minute
	FilterCatalogBaseURL       = "https://raw.githubusercontent.com/svrforum/npg-filters/main/"
	FilterCatalogIndexURL      = "https://raw.githubusercontent.com/svrforum/npg-filters/main/index.json"
)
