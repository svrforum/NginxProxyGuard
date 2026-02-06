package config

import "time"

// Application version
const AppVersion = "1.3.37"

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
