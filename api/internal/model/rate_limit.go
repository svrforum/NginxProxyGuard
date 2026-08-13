package model

import "time"

// RateLimit represents rate limiting configuration for a proxy host
type RateLimit struct {
	ID                string    `json:"id"`
	ProxyHostID       string    `json:"proxy_host_id"`
	Enabled           bool      `json:"enabled"`
	RequestsPerSecond int       `json:"requests_per_second"`
	BurstSize         int       `json:"burst_size"`
	ZoneSize          string    `json:"zone_size"`
	LimitBy           string    `json:"limit_by"` // ip, uri, ip_uri
	LimitResponse     int       `json:"limit_response"`
	WhitelistIPs      string    `json:"whitelist_ips,omitempty"`
	// DisableGlobal opts this host out of the global rate-limit default when it
	// is not running its own (enabled=false). Tri-state with Enabled (#198 slice 5).
	DisableGlobal     bool      `json:"disable_global"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CreateRateLimitRequest is the request to create/update rate limit config
type CreateRateLimitRequest struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	RequestsPerSecond int    `json:"requests_per_second,omitempty"`
	BurstSize         int    `json:"burst_size,omitempty"`
	ZoneSize          string `json:"zone_size,omitempty"`
	LimitBy           string `json:"limit_by,omitempty"`
	LimitResponse     int    `json:"limit_response,omitempty"`
	WhitelistIPs      string `json:"whitelist_ips,omitempty"`
	DisableGlobal     *bool  `json:"disable_global,omitempty"`
}

// GlobalRateLimit is the singleton global rate-limit default hosts inherit
// unless they override or opt out (#198 slice 5). The nginx limit_req zone
// stays per-host; only these values are inherited.
type GlobalRateLimit struct {
	ID                string    `json:"id"`
	Enabled           bool      `json:"enabled"`
	RequestsPerSecond int       `json:"requests_per_second"`
	BurstSize         int       `json:"burst_size"`
	ZoneSize          string    `json:"zone_size"`
	LimitBy           string    `json:"limit_by"`
	LimitResponse     int       `json:"limit_response"`
	WhitelistIPs      string    `json:"whitelist_ips,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// UpdateGlobalRateLimitRequest is the partial-update request for the singleton.
type UpdateGlobalRateLimitRequest struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	RequestsPerSecond int    `json:"requests_per_second,omitempty"`
	BurstSize         int    `json:"burst_size,omitempty"`
	ZoneSize          string `json:"zone_size,omitempty"`
	LimitBy           string `json:"limit_by,omitempty"`
	LimitResponse     int    `json:"limit_response,omitempty"`
	WhitelistIPs      string `json:"whitelist_ips,omitempty"`
}

// Fail2banConfig represents fail2ban-style auto blocking configuration
type Fail2banConfig struct {
	ID          string    `json:"id"`
	ProxyHostID string    `json:"proxy_host_id"`
	Enabled     bool      `json:"enabled"`
	MaxRetries  int       `json:"max_retries"`
	FindTime    int       `json:"find_time"`  // seconds
	BanTime     int       `json:"ban_time"`   // seconds, 0 = permanent
	FailCodes   string    `json:"fail_codes"` // comma separated: 401,403
	Action      string    `json:"action"`     // block, log, notify
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateFail2banRequest is the request to create/update fail2ban config
type CreateFail2banRequest struct {
	Enabled    *bool  `json:"enabled,omitempty"`
	MaxRetries int    `json:"max_retries,omitempty"`
	FindTime   int    `json:"find_time,omitempty"`
	BanTime    int    `json:"ban_time,omitempty"`
	FailCodes  string `json:"fail_codes,omitempty"`
	Action     string `json:"action,omitempty"`
}

// BannedIP represents an auto-blocked IP address
type BannedIP struct {
	ID           string     `json:"id"`
	ProxyHostID  *string    `json:"proxy_host_id,omitempty"`
	IPAddress    string     `json:"ip_address"`
	Reason       string     `json:"reason,omitempty"`
	FailCount    int        `json:"fail_count"`
	BannedAt     time.Time  `json:"banned_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	IsPermanent  bool       `json:"is_permanent"`
	IsAutoBanned bool       `json:"is_auto_banned"`
	CreatedAt    time.Time  `json:"created_at"`
}

// BannedIPListResponse is the response for listing banned IPs
type BannedIPListResponse struct {
	Data       []BannedIP `json:"data"`
	Total      int        `json:"total"`
	Page       int        `json:"page"`
	PerPage    int        `json:"per_page"`
	TotalPages int        `json:"total_pages"`
}

// IPBanHistory event types
const (
	BanEventTypeBan   = "ban"
	BanEventTypeUnban = "unban"
)

// IPBanHistory sources
const (
	BanSourceFail2ban    = "fail2ban"
	BanSourceWAFAutoBan  = "waf_auto_ban"
	BanSourceManual      = "manual"
	BanSourceAPI         = "api"
	BanSourceExpired     = "expired"
)

// IPBanHistory represents a single ban/unban event in the history
type IPBanHistory struct {
	ID           string                 `json:"id"`
	EventType    string                 `json:"event_type"` // ban, unban
	IPAddress    string                 `json:"ip_address"`
	ProxyHostID  *string                `json:"proxy_host_id,omitempty"`
	DomainName   string                 `json:"domain_name,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
	Source       string                 `json:"source"` // fail2ban, waf_auto_ban, manual, api, expired
	BanDuration  *int                   `json:"ban_duration,omitempty"` // seconds, 0 = permanent
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
	IsPermanent  bool                   `json:"is_permanent"`
	IsAuto       bool                   `json:"is_auto"`
	FailCount    *int                   `json:"fail_count,omitempty"`
	UserID       *string                `json:"user_id,omitempty"`
	UserEmail    string                 `json:"user_email,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// IPBanHistoryListResponse is the response for listing ban history
type IPBanHistoryListResponse struct {
	Data       []IPBanHistory `json:"data"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PerPage    int            `json:"per_page"`
	TotalPages int            `json:"total_pages"`
}

// IPBanHistoryFilter represents filter options for querying ban history
type IPBanHistoryFilter struct {
	IPAddress   string     `json:"ip_address,omitempty"`
	EventType   string     `json:"event_type,omitempty"` // ban, unban
	Source      string     `json:"source,omitempty"`
	ProxyHostID string     `json:"proxy_host_id,omitempty"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	EndDate     *time.Time `json:"end_date,omitempty"`
	Page        int        `json:"page"`
	PerPage     int        `json:"per_page"`
}

// IPBanHistoryStats represents statistics for ban history
type IPBanHistoryStats struct {
	TotalBans       int            `json:"total_bans"`
	TotalUnbans     int            `json:"total_unbans"`
	ActiveBans      int            `json:"active_bans"`
	BansBySource    map[string]int `json:"bans_by_source"`
	TopBannedIPs    []IPBanCount   `json:"top_banned_ips"`
}

// IPBanCount represents ban count for a specific IP
type IPBanCount struct {
	IPAddress string `json:"ip_address"`
	BanCount  int    `json:"ban_count"`
}

// BannedIPStatsWindowDays are the windows a caller may ask for. Traffic for one
// IP cannot use the client_ip index inside compressed chunks, so the scan cost
// grows with the window — the list is closed to keep an open-ended request from
// walking the whole hypertable. (#242)
var BannedIPStatsWindowDays = []int{1, 7, 30}

// DefaultBannedIPStatsWindowDays is what the modal opens with.
const DefaultBannedIPStatsWindowDays = 7

// BannedIPStats answers "who is this address, and what has it been doing here?"
// for one banned IP: where it geolocates, how much it asked for inside the
// window, how much of that was refused, and how often it has been banned.
type BannedIPStats struct {
	IPAddress   string `json:"ip_address"`
	WindowDays  int    `json:"window_days"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`

	// Traffic inside the window. Zero everywhere is a real answer: the ban is
	// doing its job, or the logs have aged out.
	TotalRequests   int        `json:"total_requests"`
	BlockedRequests int        `json:"blocked_requests"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`

	TopHosts []BannedIPTarget `json:"top_hosts"`
	TopURIs  []BannedIPTarget `json:"top_uris"`

	// Ban history spans all time, not the window — "banned 4 times before" is
	// the point, and ip_ban_history is small enough to read in full.
	BanCount   int        `json:"ban_count"`
	FirstBanAt *time.Time `json:"first_ban_at,omitempty"`
	LastBanAt  *time.Time `json:"last_ban_at,omitempty"`
}

// BannedIPTarget is one host or URI this address went after, with how often.
type BannedIPTarget struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}
