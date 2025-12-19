package model

import (
	"net"
	"time"
)

type LogType string

const (
	LogTypeAccess LogType = "access"
	LogTypeError  LogType = "error"
	LogTypeModSec LogType = "modsec"
)

type BlockReason string

const (
	BlockReasonNone                   BlockReason = "none"
	BlockReasonWAF                    BlockReason = "waf"
	BlockReasonBotFilter              BlockReason = "bot_filter"
	BlockReasonRateLimit              BlockReason = "rate_limit"
	BlockReasonGeoBlock               BlockReason = "geo_block"
	BlockReasonExploitBlock           BlockReason = "exploit_block"
	BlockReasonBannedIP               BlockReason = "banned_ip"
	BlockReasonURIBlock               BlockReason = "uri_block"
	BlockReasonCloudProviderChallenge BlockReason = "cloud_provider_challenge"
)

type LogSeverity string

const (
	LogSeverityDebug  LogSeverity = "debug"
	LogSeverityInfo   LogSeverity = "info"
	LogSeverityNotice LogSeverity = "notice"
	LogSeverityWarn   LogSeverity = "warn"
	LogSeverityError  LogSeverity = "error"
	LogSeverityCrit   LogSeverity = "crit"
	LogSeverityAlert  LogSeverity = "alert"
	LogSeverityEmerg  LogSeverity = "emerg"
)

type Log struct {
	ID        string    `json:"id"`
	LogType   LogType   `json:"log_type"`
	Timestamp time.Time `json:"timestamp"`

	// Common fields
	Host     *string `json:"host,omitempty"`
	ClientIP *net.IP `json:"client_ip,omitempty"`

	// GeoIP fields
	GeoCountry     *string `json:"geo_country,omitempty"`
	GeoCountryCode *string `json:"geo_country_code,omitempty"`
	GeoCity        *string `json:"geo_city,omitempty"`
	GeoASN         *string `json:"geo_asn,omitempty"`
	GeoOrg         *string `json:"geo_org,omitempty"`

	// Access log fields
	RequestMethod        *string  `json:"request_method,omitempty"`
	RequestURI           *string  `json:"request_uri,omitempty"`
	RequestProtocol      *string  `json:"request_protocol,omitempty"`
	StatusCode           *int     `json:"status_code,omitempty"`
	BodyBytesSent        *int64   `json:"body_bytes_sent,omitempty"`
	RequestTime          *float64 `json:"request_time,omitempty"`
	UpstreamResponseTime *float64 `json:"upstream_response_time,omitempty"`
	HTTPReferer          *string  `json:"http_referer,omitempty"`
	HTTPUserAgent        *string  `json:"http_user_agent,omitempty"`
	HTTPXForwardedFor    *string  `json:"http_x_forwarded_for,omitempty"`

	// Error log fields
	Severity     *LogSeverity `json:"severity,omitempty"`
	ErrorMessage *string      `json:"error_message,omitempty"`

	// ModSecurity WAF fields
	RuleID       *int    `json:"rule_id,omitempty"`
	RuleMessage  *string `json:"rule_message,omitempty"`
	RuleSeverity *string `json:"rule_severity,omitempty"`
	RuleData     *string `json:"rule_data,omitempty"`
	AttackType   *string `json:"attack_type,omitempty"`
	ActionTaken  *string `json:"action_taken,omitempty"`

	// Block reason fields
	BlockReason *BlockReason `json:"block_reason,omitempty"`
	BotCategory *string      `json:"bot_category,omitempty"` // bad_bot, ai_bot, suspicious, custom
	ExploitRule *string      `json:"exploit_rule,omitempty"` // e.g., SQLI-001, RFI-001, VCS-001

	// Metadata
	ProxyHostID *string `json:"proxy_host_id,omitempty"`
	RawLog      *string `json:"raw_log,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

type CreateLogRequest struct {
	LogType   LogType   `json:"log_type" validate:"required,oneof=access error modsec"`
	Timestamp time.Time `json:"timestamp"`

	// Common fields
	Host     string `json:"host,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`

	// GeoIP fields
	GeoCountry     string `json:"geo_country,omitempty"`
	GeoCountryCode string `json:"geo_country_code,omitempty"`
	GeoCity        string `json:"geo_city,omitempty"`
	GeoASN         string `json:"geo_asn,omitempty"`
	GeoOrg         string `json:"geo_org,omitempty"`

	// Access log fields
	RequestMethod        string  `json:"request_method,omitempty"`
	RequestURI           string  `json:"request_uri,omitempty"`
	RequestProtocol      string  `json:"request_protocol,omitempty"`
	StatusCode           int     `json:"status_code,omitempty"`
	BodyBytesSent        int64   `json:"body_bytes_sent,omitempty"`
	RequestTime          float64 `json:"request_time,omitempty"`
	UpstreamResponseTime float64 `json:"upstream_response_time,omitempty"`
	HTTPReferer          string  `json:"http_referer,omitempty"`
	HTTPUserAgent        string  `json:"http_user_agent,omitempty"`
	HTTPXForwardedFor    string  `json:"http_x_forwarded_for,omitempty"`

	// Error log fields
	Severity     LogSeverity `json:"severity,omitempty"`
	ErrorMessage string      `json:"error_message,omitempty"`

	// ModSecurity WAF fields
	RuleID       int    `json:"rule_id,omitempty"`
	RuleMessage  string `json:"rule_message,omitempty"`
	RuleSeverity string `json:"rule_severity,omitempty"`
	RuleData     string `json:"rule_data,omitempty"`
	AttackType   string `json:"attack_type,omitempty"`
	ActionTaken  string `json:"action_taken,omitempty"`

	// Block reason fields
	BlockReason BlockReason `json:"block_reason,omitempty"`
	BotCategory string      `json:"bot_category,omitempty"` // bad_bot, ai_bot, suspicious, custom
	ExploitRule string      `json:"exploit_rule,omitempty"` // e.g., SQLI-001, RFI-001, VCS-001

	// Metadata
	ProxyHostID string `json:"proxy_host_id,omitempty"`
	RawLog      string `json:"raw_log,omitempty"`
}

type LogFilter struct {
	LogType     *LogType     `json:"log_type,omitempty"`
	Host        *string      `json:"host,omitempty"`
	ClientIP    *string      `json:"client_ip,omitempty"`
	StatusCode  *int         `json:"status_code,omitempty"`
	Severity    *LogSeverity `json:"severity,omitempty"`
	RuleID      *int         `json:"rule_id,omitempty"`
	ProxyHostID *string      `json:"proxy_host_id,omitempty"`
	StartTime   *time.Time   `json:"start_time,omitempty"`
	EndTime     *time.Time   `json:"end_time,omitempty"`
	Search      *string      `json:"search,omitempty"` // Full-text search in request_uri, error_message, etc.

	// Block reason filters
	BlockReason *BlockReason `json:"block_reason,omitempty"`
	BotCategory *string      `json:"bot_category,omitempty"`
	ExploitRule *string      `json:"exploit_rule,omitempty"` // Filter by specific exploit rule ID

	// Array filters for multi-select support
	Hosts      []string `json:"hosts,omitempty"`       // Filter by multiple hosts
	ClientIPs  []string `json:"client_ips,omitempty"`  // Filter by multiple IPs
	URIs       []string `json:"uris,omitempty"`        // Filter by multiple URIs
	UserAgents []string `json:"user_agents,omitempty"` // Filter by multiple User-Agents

	// Extended filters
	UserAgent      *string  `json:"user_agent,omitempty"`       // Filter by User-Agent (ILIKE) - legacy single value
	URI            *string  `json:"uri,omitempty"`              // Filter by URI (ILIKE) - legacy single value
	Method         *string  `json:"method,omitempty"`           // Filter by HTTP method (exact)
	GeoCountryCode *string  `json:"geo_country_code,omitempty"` // Filter by country code (exact)
	StatusCodes    []int    `json:"status_codes,omitempty"`     // Filter by multiple status codes
	MinSize        *int64   `json:"min_size,omitempty"`         // Minimum response size (bytes)
	MaxSize        *int64   `json:"max_size,omitempty"`         // Maximum response size (bytes)
	MinRequestTime *float64 `json:"min_request_time,omitempty"` // Minimum request time (seconds)

	// Exclude filters
	ExcludeIPs        []string `json:"exclude_ips,omitempty"`         // Exclude specific IPs
	ExcludeUserAgents []string `json:"exclude_user_agents,omitempty"` // Exclude specific User-Agents (contains)
	ExcludeURIs       []string `json:"exclude_uris,omitempty"`        // Exclude specific URIs (contains)
	ExcludeHosts      []string `json:"exclude_hosts,omitempty"`       // Exclude specific hosts
	ExcludeCountries  []string `json:"exclude_countries,omitempty"`   // Exclude specific country codes

	// Sorting
	SortBy    *string `json:"sort_by,omitempty"`    // timestamp, body_bytes_sent, request_time, status_code
	SortOrder *string `json:"sort_order,omitempty"` // asc, desc (default: desc)
}

type LogListResponse struct {
	Data       []Log `json:"data"`
	Total      int   `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

type LogStats struct {
	TotalLogs       int64            `json:"total_logs"`
	AccessLogs      int64            `json:"access_logs"`
	ErrorLogs       int64            `json:"error_logs"`
	ModSecLogs      int64            `json:"modsec_logs"`
	TopStatusCodes  []StatusCodeStat `json:"top_status_codes"`
	TopClientIPs    []ClientIPStat   `json:"top_client_ips"`
	TopUserAgents   []UserAgentStat  `json:"top_user_agents"`
	TopAttackedURIs []URIStat        `json:"top_attacked_uris"`
	TopRuleIDs      []RuleIDStat     `json:"top_rule_ids"`
}

type StatusCodeStat struct {
	StatusCode int   `json:"status_code"`
	Count      int64 `json:"count"`
}

type ClientIPStat struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

// UserAgentStat is defined in dashboard.go

type URIStat struct {
	URI   string `json:"uri"`
	Count int64  `json:"count"`
}

type RuleIDStat struct {
	RuleID  int    `json:"rule_id"`
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

type LogSettings struct {
	ID                 string    `json:"id"`
	RetentionDays      int       `json:"retention_days"`
	MaxLogsPerType     *int64    `json:"max_logs_per_type,omitempty"`
	AutoCleanupEnabled bool      `json:"auto_cleanup_enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type UpdateLogSettingsRequest struct {
	RetentionDays      *int   `json:"retention_days,omitempty"`
	MaxLogsPerType     *int64 `json:"max_logs_per_type,omitempty"`
	AutoCleanupEnabled *bool  `json:"auto_cleanup_enabled,omitempty"`
}
