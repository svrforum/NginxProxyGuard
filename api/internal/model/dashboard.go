package model

import "time"

// DashboardStatsHourly represents hourly aggregated statistics
type DashboardStatsHourly struct {
	ID          string     `json:"id" db:"id"`
	ProxyHostID *string    `json:"proxy_host_id,omitempty" db:"proxy_host_id"`
	HourBucket  time.Time  `json:"hour_bucket" db:"hour_bucket"`

	// Request stats
	TotalRequests int64 `json:"total_requests" db:"total_requests"`

	// Status code breakdown
	Status2xx int64 `json:"status_2xx" db:"status_2xx"`
	Status3xx int64 `json:"status_3xx" db:"status_3xx"`
	Status4xx int64 `json:"status_4xx" db:"status_4xx"`
	Status5xx int64 `json:"status_5xx" db:"status_5xx"`

	// Response time stats (ms)
	AvgResponseTime float64 `json:"avg_response_time" db:"avg_response_time"`
	MaxResponseTime float64 `json:"max_response_time" db:"max_response_time"`
	MinResponseTime float64 `json:"min_response_time" db:"min_response_time"`
	P95ResponseTime float64 `json:"p95_response_time" db:"p95_response_time"`
	P99ResponseTime float64 `json:"p99_response_time" db:"p99_response_time"`

	// Bandwidth
	BytesSent     int64 `json:"bytes_sent" db:"bytes_sent"`
	BytesReceived int64 `json:"bytes_received" db:"bytes_received"`

	// Security stats
	WAFBlocked  int64 `json:"waf_blocked" db:"waf_blocked"`
	WAFDetected int64 `json:"waf_detected" db:"waf_detected"`
	RateLimited int64 `json:"rate_limited" db:"rate_limited"`
	BotBlocked  int64 `json:"bot_blocked" db:"bot_blocked"`

	// Top data (JSONB)
	TopCountries []CountryStat `json:"top_countries,omitempty"`
	TopPaths     []PathStat    `json:"top_paths,omitempty"`
	TopIPs       []IPStat      `json:"top_ips,omitempty"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// DashboardStatsDaily represents daily aggregated statistics
type DashboardStatsDaily struct {
	ID          string    `json:"id" db:"id"`
	ProxyHostID *string   `json:"proxy_host_id,omitempty" db:"proxy_host_id"`
	DayBucket   time.Time `json:"day_bucket" db:"day_bucket"`

	TotalRequests   int64   `json:"total_requests" db:"total_requests"`
	Status2xx       int64   `json:"status_2xx" db:"status_2xx"`
	Status3xx       int64   `json:"status_3xx" db:"status_3xx"`
	Status4xx       int64   `json:"status_4xx" db:"status_4xx"`
	Status5xx       int64   `json:"status_5xx" db:"status_5xx"`
	AvgResponseTime float64 `json:"avg_response_time" db:"avg_response_time"`
	MaxResponseTime float64 `json:"max_response_time" db:"max_response_time"`
	BytesSent       int64   `json:"bytes_sent" db:"bytes_sent"`
	BytesReceived   int64   `json:"bytes_received" db:"bytes_received"`
	WAFBlocked      int64   `json:"waf_blocked" db:"waf_blocked"`
	RateLimited     int64   `json:"rate_limited" db:"rate_limited"`
	BotBlocked      int64   `json:"bot_blocked" db:"bot_blocked"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CountryStat represents country statistics
type CountryStat struct {
	CountryCode string `json:"country_code,omitempty"`
	Country     string `json:"country"`
	Count       int64  `json:"count"`
}

// GeoIPStat represents detailed GeoIP statistics for globe visualization
type GeoIPStat struct {
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	Count       int64   `json:"count"`
	Percentage  float64 `json:"percentage"`
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
}

// GeoIPStatsResponse is the API response for GeoIP stats
type GeoIPStatsResponse struct {
	Data       []GeoIPStat `json:"data"`
	TotalCount int64       `json:"total_count"`
}

// PathStat represents path statistics
type PathStat struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// IPStat represents IP statistics
type IPStat struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

// UserAgentStat represents User-Agent statistics
type UserAgentStat struct {
	UserAgent string `json:"user_agent"`
	Count     int64  `json:"count"`
	Category  string `json:"category,omitempty"` // bot, browser, crawler, etc.
}

// SystemHealth represents system health metrics
type SystemHealth struct {
	ID         string    `json:"id" db:"id"`
	RecordedAt time.Time `json:"recorded_at" db:"recorded_at"`

	// Nginx status
	NginxStatus             string `json:"nginx_status" db:"nginx_status"`
	NginxWorkers            int    `json:"nginx_workers" db:"nginx_workers"`
	NginxConnectionsActive  int    `json:"nginx_connections_active" db:"nginx_connections_active"`
	NginxConnectionsReading int    `json:"nginx_connections_reading" db:"nginx_connections_reading"`
	NginxConnectionsWriting int    `json:"nginx_connections_writing" db:"nginx_connections_writing"`
	NginxConnectionsWaiting int    `json:"nginx_connections_waiting" db:"nginx_connections_waiting"`

	// Database status
	DBStatus      string `json:"db_status" db:"db_status"`
	DBConnections int    `json:"db_connections" db:"db_connections"`

	// System resources
	CPUUsage    float64 `json:"cpu_usage" db:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage" db:"memory_usage"`
	MemoryTotal uint64  `json:"memory_total"`
	MemoryUsed  uint64  `json:"memory_used"`
	DiskUsage   float64 `json:"disk_usage" db:"disk_usage"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskPath    string  `json:"disk_path"`

	// Host system info
	UptimeSeconds uint64 `json:"uptime_seconds" db:"uptime_seconds"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Platform      string `json:"platform"`
	KernelVersion string `json:"kernel_version"`

	// Network I/O
	NetworkIn  uint64 `json:"network_in"`
	NetworkOut uint64 `json:"network_out"`

	// Certificate status
	CertsTotal        int `json:"certs_total" db:"certs_total"`
	CertsExpiringSoon int `json:"certs_expiring_soon" db:"certs_expiring_soon"`
	CertsExpired      int `json:"certs_expired" db:"certs_expired"`

	// Upstream health
	UpstreamsTotal     int `json:"upstreams_total" db:"upstreams_total"`
	UpstreamsHealthy   int `json:"upstreams_healthy" db:"upstreams_healthy"`
	UpstreamsUnhealthy int `json:"upstreams_unhealthy" db:"upstreams_unhealthy"`
}

// DashboardSummary represents the main dashboard view
type DashboardSummary struct {
	// System Health
	SystemHealth SystemHealth `json:"system_health"`

	// Overview stats (last 24 hours)
	TotalRequests24h   int64   `json:"total_requests_24h"`
	TotalBandwidth24h  int64   `json:"total_bandwidth_24h"`
	AvgResponseTime24h float64 `json:"avg_response_time_24h"`
	ErrorRate24h       float64 `json:"error_rate_24h"`

	// Security stats (last 24 hours)
	WAFBlocked24h  int64 `json:"waf_blocked_24h"`
	RateLimited24h int64 `json:"rate_limited_24h"`
	BotBlocked24h  int64 `json:"bot_blocked_24h"`
	BannedIPs      int   `json:"banned_ips"`

	// Blocked stats (last 24 hours) - like BunkerWeb
	BlockedRequests24h  int64 `json:"blocked_requests_24h"`
	BlockedUniqueIPs24h int   `json:"blocked_unique_ips_24h"`

	// Host stats
	TotalProxyHosts    int `json:"total_proxy_hosts"`
	ActiveProxyHosts   int `json:"active_proxy_hosts"`
	TotalRedirectHosts int `json:"total_redirect_hosts"`

	// Certificate stats
	TotalCertificates    int `json:"total_certificates"`
	ExpiringCertificates int `json:"expiring_certificates"`

	// Charts data
	RequestsChart    []ChartDataPoint    `json:"requests_chart"`
	BandwidthChart   []ChartDataPoint    `json:"bandwidth_chart"`
	StatusCodeChart  []StatusCodePoint   `json:"status_code_chart"`
	SecurityChart    []SecurityChartPoint `json:"security_chart"`

	// Top data
	TopHosts      []HostStat      `json:"top_hosts"`
	TopCountries  []CountryStat   `json:"top_countries"`
	TopPaths      []PathStat      `json:"top_paths"`
	TopIPs        []IPStat        `json:"top_ips"`
	TopUserAgents []UserAgentStat `json:"top_user_agents"`

	// Storage is attached live per request (never cached with the summary).
	Storage *StorageStatus `json:"storage,omitempty"`
}

// ChartDataPoint represents a single data point for charts
type ChartDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// StatusCodePoint represents status code distribution at a point in time
type StatusCodePoint struct {
	Timestamp time.Time `json:"timestamp"`
	Status2xx int64     `json:"status_2xx"`
	Status3xx int64     `json:"status_3xx"`
	Status4xx int64     `json:"status_4xx"`
	Status5xx int64     `json:"status_5xx"`
}

// SecurityChartPoint represents security events at a point in time
type SecurityChartPoint struct {
	Timestamp   time.Time `json:"timestamp"`
	WAFBlocked  int64     `json:"waf_blocked"`
	RateLimited int64     `json:"rate_limited"`
	BotBlocked  int64     `json:"bot_blocked"`
}

// HostStat represents per-host statistics
type HostStat struct {
	HostID   string `json:"host_id"`
	Domain   string `json:"domain"`
	Requests int64  `json:"requests"`
}

// DashboardQueryParams represents query parameters for dashboard
type DashboardQueryParams struct {
	ProxyHostID string    `json:"proxy_host_id,omitempty"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Granularity string    `json:"granularity"` // hourly, daily
}
