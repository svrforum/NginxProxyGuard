package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

type DashboardRepository struct {
	db *sql.DB
}

func NewDashboardRepository(db *sql.DB) *DashboardRepository {
	return &DashboardRepository{db: db}
}

// GetSummary returns the main dashboard summary
func (r *DashboardRepository) GetSummary(ctx context.Context) (*model.DashboardSummary, error) {
	summary := &model.DashboardSummary{}

	// Get system health
	health, err := r.GetSystemHealth(ctx)
	if err == nil && health != nil {
		summary.SystemHealth = *health
	}

	// Get 24h stats
	now := time.Now()
	last24h := now.Add(-24 * time.Hour)

	// Total requests, bandwidth, response time in last 24h
	row := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(total_requests), 0),
		       COALESCE(SUM(bytes_sent + bytes_received), 0),
		       COALESCE(AVG(avg_response_time), 0),
		       COALESCE(SUM(status_4xx + status_5xx), 0),
		       COALESCE(SUM(total_requests), 1)
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1
	`, last24h)

	var totalReq, totalBW, totalErrors, totalForRate int64
	var avgRT float64
	row.Scan(&totalReq, &totalBW, &avgRT, &totalErrors, &totalForRate)
	summary.TotalRequests24h = totalReq
	summary.TotalBandwidth24h = totalBW
	summary.AvgResponseTime24h = avgRT
	if totalForRate > 0 {
		summary.ErrorRate24h = float64(totalErrors) / float64(totalForRate) * 100
	}

	// Security stats in last 24h from dashboard_stats_hourly
	row = r.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(waf_blocked), 0),
		       COALESCE(SUM(rate_limited), 0),
		       COALESCE(SUM(bot_blocked), 0)
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1
	`, last24h)
	row.Scan(&summary.WAFBlocked24h, &summary.RateLimited24h, &summary.BotBlocked24h)

	// Fallback: Get security stats from logs_partitioned table if dashboard_stats_hourly is empty
	if summary.WAFBlocked24h == 0 && summary.RateLimited24h == 0 && summary.BotBlocked24h == 0 {
		row = r.db.QueryRowContext(ctx, `
			SELECT
				COUNT(*) FILTER (WHERE block_reason = 'waf'),
				COUNT(*) FILTER (WHERE block_reason = 'rate_limit'),
				COUNT(*) FILTER (WHERE block_reason = 'bot_filter')
			FROM logs_partitioned
			WHERE created_at >= $1
		`, last24h)
		row.Scan(&summary.WAFBlocked24h, &summary.RateLimited24h, &summary.BotBlocked24h)
	}

	// Banned IPs count
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM banned_ips WHERE (expires_at > NOW() OR is_permanent = TRUE)").Scan(&summary.BannedIPs)

	// Blocked requests stats (from logs_partitioned table)
	// Only count security blocks: 403 Forbidden, modsec logs
	// Also get total requests, bandwidth, response time, error rate from logs for fallback
	row = r.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE log_type = 'access'),
			COUNT(*) FILTER (WHERE status_code = 403 OR log_type = 'modsec'),
			COUNT(DISTINCT client_ip) FILTER (WHERE status_code = 403 OR log_type = 'modsec'),
			COALESCE(SUM(body_bytes_sent) FILTER (WHERE log_type = 'access'), 0),
			COALESCE(AVG(request_time) FILTER (WHERE log_type = 'access' AND request_time > 0), 0),
			COUNT(*) FILTER (WHERE log_type = 'access' AND status_code >= 400),
			COUNT(*) FILTER (WHERE log_type = 'access')
		FROM logs_partitioned
		WHERE created_at >= $1
	`, last24h)
	var totalFromLogs, bandwidthFromLogs, errorsFromLogs, totalAccessLogs int64
	var avgRtFromLogs float64
	row.Scan(&totalFromLogs, &summary.BlockedRequests24h, &summary.BlockedUniqueIPs24h,
		&bandwidthFromLogs, &avgRtFromLogs, &errorsFromLogs, &totalAccessLogs)
	// Use logs count if dashboard_stats_hourly is incomplete (fallback)
	if totalFromLogs > summary.TotalRequests24h {
		summary.TotalRequests24h = totalFromLogs
	}
	if bandwidthFromLogs > summary.TotalBandwidth24h {
		summary.TotalBandwidth24h = bandwidthFromLogs
	}
	if avgRtFromLogs > 0 && summary.AvgResponseTime24h == 0 {
		// Convert from seconds to milliseconds
		summary.AvgResponseTime24h = avgRtFromLogs * 1000
	}
	if totalAccessLogs > 0 && summary.ErrorRate24h == 0 {
		summary.ErrorRate24h = float64(errorsFromLogs) / float64(totalAccessLogs) * 100
	}

	// Host and certificate counts - combined into single query for performance
	r.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM proxy_hosts),
			(SELECT COUNT(*) FROM proxy_hosts WHERE enabled = TRUE),
			(SELECT COUNT(*) FROM redirect_hosts),
			(SELECT COUNT(*) FROM certificates),
			(SELECT COUNT(*) FROM certificates WHERE expires_at < NOW() + INTERVAL '30 days' AND expires_at > NOW())
	`).Scan(&summary.TotalProxyHosts, &summary.ActiveProxyHosts, &summary.TotalRedirectHosts,
		&summary.TotalCertificates, &summary.ExpiringCertificates)

	// Get chart data (last 24 hours, hourly)
	summary.RequestsChart = r.getRequestsChart(ctx, last24h, now)
	summary.BandwidthChart = r.getBandwidthChart(ctx, last24h, now)
	summary.StatusCodeChart = r.getStatusCodeChart(ctx, last24h, now)
	summary.SecurityChart = r.getSecurityChart(ctx, last24h, now)

	// Get top data
	summary.TopHosts = r.getTopHosts(ctx, last24h)
	summary.TopCountries = r.getTopCountries(ctx, last24h)
	summary.TopPaths = r.getTopPaths(ctx, last24h)
	summary.TopIPs = r.getTopIPs(ctx, last24h)
	summary.TopUserAgents = r.getTopUserAgents(ctx, last24h)

	return summary, nil
}

func (r *DashboardRepository) getRequestsChart(ctx context.Context, start, end time.Time) []model.ChartDataPoint {
	rows, err := r.db.QueryContext(ctx, `
		SELECT hour_bucket, SUM(total_requests)
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1 AND hour_bucket <= $2
		GROUP BY hour_bucket
		ORDER BY hour_bucket
	`, start, end)
	if err != nil {
		return []model.ChartDataPoint{}
	}
	defer rows.Close()

	var points []model.ChartDataPoint
	for rows.Next() {
		var p model.ChartDataPoint
		rows.Scan(&p.Timestamp, &p.Value)
		points = append(points, p)
	}
	return points
}

func (r *DashboardRepository) getBandwidthChart(ctx context.Context, start, end time.Time) []model.ChartDataPoint {
	rows, err := r.db.QueryContext(ctx, `
		SELECT hour_bucket, SUM(bytes_sent + bytes_received)
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1 AND hour_bucket <= $2
		GROUP BY hour_bucket
		ORDER BY hour_bucket
	`, start, end)
	if err != nil {
		return []model.ChartDataPoint{}
	}
	defer rows.Close()

	var points []model.ChartDataPoint
	for rows.Next() {
		var p model.ChartDataPoint
		rows.Scan(&p.Timestamp, &p.Value)
		points = append(points, p)
	}
	return points
}

func (r *DashboardRepository) getStatusCodeChart(ctx context.Context, start, end time.Time) []model.StatusCodePoint {
	rows, err := r.db.QueryContext(ctx, `
		SELECT hour_bucket, SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx)
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1 AND hour_bucket <= $2
		GROUP BY hour_bucket
		ORDER BY hour_bucket
	`, start, end)
	if err != nil {
		return []model.StatusCodePoint{}
	}
	defer rows.Close()

	var points []model.StatusCodePoint
	for rows.Next() {
		var p model.StatusCodePoint
		rows.Scan(&p.Timestamp, &p.Status2xx, &p.Status3xx, &p.Status4xx, &p.Status5xx)
		points = append(points, p)
	}
	return points
}

func (r *DashboardRepository) getSecurityChart(ctx context.Context, start, end time.Time) []model.SecurityChartPoint {
	rows, err := r.db.QueryContext(ctx, `
		SELECT hour_bucket, SUM(waf_blocked), SUM(rate_limited), SUM(bot_blocked)
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1 AND hour_bucket <= $2
		GROUP BY hour_bucket
		ORDER BY hour_bucket
	`, start, end)
	if err != nil {
		return []model.SecurityChartPoint{}
	}
	defer rows.Close()

	var points []model.SecurityChartPoint
	for rows.Next() {
		var p model.SecurityChartPoint
		rows.Scan(&p.Timestamp, &p.WAFBlocked, &p.RateLimited, &p.BotBlocked)
		points = append(points, p)
	}
	return points
}

func (r *DashboardRepository) getTopHosts(ctx context.Context, since time.Time) []model.HostStat {
	// First try to get from dashboard_stats_hourly with proxy_host_id
	rows, err := r.db.QueryContext(ctx, `
		SELECT h.proxy_host_id, p.domain_names[1], SUM(h.total_requests) as total
		FROM dashboard_stats_hourly h
		JOIN proxy_hosts p ON p.id = h.proxy_host_id
		WHERE h.hour_bucket >= $1 AND h.proxy_host_id IS NOT NULL
		GROUP BY h.proxy_host_id, p.domain_names[1]
		ORDER BY total DESC
		LIMIT 10
	`, since)
	if err == nil {
		defer rows.Close()
		var stats []model.HostStat
		for rows.Next() {
			var s model.HostStat
			rows.Scan(&s.HostID, &s.Domain, &s.Requests)
			stats = append(stats, s)
		}
		if len(stats) > 0 {
			return stats
		}
	}

	// Fallback: aggregate from logs_partitioned table directly using host column
	// Exclude health check hosts (nginx, localhost, IPs, _, 0.0.0.0)
	rows, err = r.db.QueryContext(ctx, `
		SELECT COALESCE(proxy_host_id::TEXT, ''), host, COUNT(*) as total
		FROM logs_partitioned
		WHERE created_at >= $1
		  AND log_type = 'access'
		  AND host IS NOT NULL
		  AND host != ''
		  AND host NOT IN ('nginx', 'localhost', '_', '0.0.0.0')
		  AND host !~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
		GROUP BY proxy_host_id, host
		ORDER BY total DESC
		LIMIT 10
	`, since)
	if err != nil {
		return []model.HostStat{}
	}
	defer rows.Close()

	var stats []model.HostStat
	for rows.Next() {
		var s model.HostStat
		rows.Scan(&s.HostID, &s.Domain, &s.Requests)
		stats = append(stats, s)
	}
	return stats
}

func (r *DashboardRepository) getTopIPs(ctx context.Context, since time.Time) []model.IPStat {
	// Exclude local/internal IPs (127.x.x.x, ::1, 172.16-31.x.x, 10.x.x.x, 192.168.x.x)
	rows, err := r.db.QueryContext(ctx, `
		SELECT HOST(client_ip), COUNT(*) as total
		FROM logs_partitioned
		WHERE created_at >= $1
		  AND log_type = 'access'
		  AND client_ip IS NOT NULL
		  AND NOT (
		    client_ip <<= '127.0.0.0/8'::inet OR
		    client_ip <<= '::1/128'::inet OR
		    client_ip <<= '10.0.0.0/8'::inet OR
		    client_ip <<= '172.16.0.0/12'::inet OR
		    client_ip <<= '192.168.0.0/16'::inet
		  )
		GROUP BY client_ip
		ORDER BY total DESC
		LIMIT 10
	`, since)
	if err != nil {
		return []model.IPStat{}
	}
	defer rows.Close()

	var stats []model.IPStat
	for rows.Next() {
		var s model.IPStat
		rows.Scan(&s.IP, &s.Count)
		stats = append(stats, s)
	}
	return stats
}

func (r *DashboardRepository) getTopCountries(ctx context.Context, since time.Time) []model.CountryStat {
	// Aggregate from JSONB top_countries column
	rows, err := r.db.QueryContext(ctx, `
		SELECT key, SUM(value::INT) as total
		FROM dashboard_stats_hourly, jsonb_each_text(top_countries)
		WHERE hour_bucket >= $1
		GROUP BY key
		ORDER BY total DESC
		LIMIT 10
	`, since)
	if err != nil {
		return []model.CountryStat{}
	}
	defer rows.Close()

	var stats []model.CountryStat
	for rows.Next() {
		var s model.CountryStat
		rows.Scan(&s.Country, &s.Count)
		stats = append(stats, s)
	}
	return stats
}

// GetGeoIPStats returns detailed GeoIP statistics from logs_partitioned table
func (r *DashboardRepository) GetGeoIPStats(ctx context.Context, since time.Time) ([]model.GeoIPStat, int64, error) {
	// Get total count first
	var totalCount int64
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM logs_partitioned
		WHERE log_type = 'access'
		AND timestamp >= $1
		AND geo_country_code IS NOT NULL
		AND geo_country_code != ''
	`, since).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	// Get country stats
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			geo_country_code,
			COALESCE(geo_country, geo_country_code) as country_name,
			COUNT(*) as request_count
		FROM logs_partitioned
		WHERE log_type = 'access'
		AND timestamp >= $1
		AND geo_country_code IS NOT NULL
		AND geo_country_code != ''
		GROUP BY geo_country_code, geo_country
		ORDER BY request_count DESC
		LIMIT 50
	`, since)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var stats []model.GeoIPStat
	for rows.Next() {
		var s model.GeoIPStat
		err := rows.Scan(&s.CountryCode, &s.Country, &s.Count)
		if err != nil {
			continue
		}
		// Calculate percentage
		if totalCount > 0 {
			s.Percentage = float64(s.Count) / float64(totalCount) * 100
		}
		// Add coordinates
		if coords, ok := countryCoordinates[s.CountryCode]; ok {
			s.Lat = coords[0]
			s.Lng = coords[1]
		}
		stats = append(stats, s)
	}

	return stats, totalCount, nil
}

// Country coordinates (ISO 3166-1 alpha-2 to lat/lng)
var countryCoordinates = map[string][2]float64{
	"US": {37.0902, -95.7129},
	"CN": {35.8617, 104.1954},
	"JP": {36.2048, 138.2529},
	"KR": {35.9078, 127.7669},
	"DE": {51.1657, 10.4515},
	"GB": {55.3781, -3.4360},
	"FR": {46.2276, 2.2137},
	"BR": {-14.2350, -51.9253},
	"IN": {20.5937, 78.9629},
	"RU": {61.5240, 105.3188},
	"AU": {-25.2744, 133.7751},
	"CA": {56.1304, -106.3468},
	"IT": {41.8719, 12.5674},
	"ES": {40.4637, -3.7492},
	"NL": {52.1326, 5.2913},
	"SG": {1.3521, 103.8198},
	"HK": {22.3193, 114.1694},
	"TW": {23.6978, 120.9605},
	"VN": {14.0583, 108.2772},
	"TH": {15.8700, 100.9925},
	"ID": {-0.7893, 113.9213},
	"MY": {4.2105, 101.9758},
	"PH": {12.8797, 121.7740},
	"PK": {30.3753, 69.3451},
	"BD": {23.6850, 90.3563},
	"MX": {23.6345, -102.5528},
	"AR": {-38.4161, -63.6167},
	"CL": {-35.6751, -71.5430},
	"CO": {4.5709, -74.2973},
	"PE": {-9.1900, -75.0152},
	"VE": {6.4238, -66.5897},
	"ZA": {-30.5595, 22.9375},
	"EG": {26.8206, 30.8025},
	"NG": {9.0820, 8.6753},
	"KE": {-0.0236, 37.9062},
	"SA": {23.8859, 45.0792},
	"AE": {23.4241, 53.8478},
	"IL": {31.0461, 34.8516},
	"TR": {38.9637, 35.2433},
	"PL": {51.9194, 19.1451},
	"UA": {48.3794, 31.1656},
	"CZ": {49.8175, 15.4730},
	"SE": {60.1282, 18.6435},
	"NO": {60.4720, 8.4689},
	"FI": {61.9241, 25.7482},
	"DK": {56.2639, 9.5018},
	"AT": {47.5162, 14.5501},
	"CH": {46.8182, 8.2275},
	"BE": {50.5039, 4.4699},
	"PT": {39.3999, -8.2245},
	"GR": {39.0742, 21.8243},
	"RO": {45.9432, 24.9668},
	"HU": {47.1625, 19.5033},
	"NZ": {-40.9006, 174.8860},
	"IE": {53.1424, -7.6921},
}

func (r *DashboardRepository) getTopPaths(ctx context.Context, since time.Time) []model.PathStat {
	// This would need to aggregate from JSONB, simplified for now
	return []model.PathStat{}
}

func (r *DashboardRepository) getTopUserAgents(ctx context.Context, since time.Time) []model.UserAgentStat {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			COALESCE(http_user_agent, 'Unknown') as ua,
			COUNT(*) as total
		FROM logs_partitioned
		WHERE created_at >= $1
		  AND log_type = 'access'
		  AND http_user_agent IS NOT NULL
		  AND http_user_agent != ''
		  AND http_user_agent != '-'
		GROUP BY http_user_agent
		ORDER BY total DESC
		LIMIT 10
	`, since)
	if err != nil {
		return []model.UserAgentStat{}
	}
	defer rows.Close()

	var stats []model.UserAgentStat
	for rows.Next() {
		var s model.UserAgentStat
		rows.Scan(&s.UserAgent, &s.Count)
		// Categorize user agent
		s.Category = categorizeUserAgent(s.UserAgent)
		stats = append(stats, s)
	}
	return stats
}

// categorizeUserAgent categorizes a user agent string
func categorizeUserAgent(ua string) string {
	uaLower := strings.ToLower(ua)

	// Search engine bots
	if strings.Contains(uaLower, "googlebot") || strings.Contains(uaLower, "bingbot") ||
		strings.Contains(uaLower, "yandexbot") || strings.Contains(uaLower, "baiduspider") ||
		strings.Contains(uaLower, "duckduckbot") {
		return "search_engine"
	}

	// AI bots
	if strings.Contains(uaLower, "gptbot") || strings.Contains(uaLower, "claudebot") ||
		strings.Contains(uaLower, "anthropic") || strings.Contains(uaLower, "chatgpt") ||
		strings.Contains(uaLower, "ccbot") || strings.Contains(uaLower, "bytespider") {
		return "ai_bot"
	}

	// Bad bots / crawlers
	if strings.Contains(uaLower, "ahrefsbot") || strings.Contains(uaLower, "mj12bot") ||
		strings.Contains(uaLower, "semrushbot") || strings.Contains(uaLower, "dotbot") ||
		strings.Contains(uaLower, "petalbot") || strings.Contains(uaLower, "scrapy") {
		return "bad_bot"
	}

	// Monitoring / health check
	if strings.Contains(uaLower, "uptime") || strings.Contains(uaLower, "pingdom") ||
		strings.Contains(uaLower, "healthcheck") || strings.Contains(uaLower, "monitoring") ||
		strings.Contains(uaLower, "kube-probe") || strings.Contains(uaLower, "prometheus") {
		return "monitoring"
	}

	// CLI tools
	if strings.Contains(uaLower, "curl") || strings.Contains(uaLower, "wget") ||
		strings.Contains(uaLower, "python-requests") || strings.Contains(uaLower, "httpie") ||
		strings.Contains(uaLower, "axios") || strings.Contains(uaLower, "node-fetch") {
		return "cli_tool"
	}

	// Browsers
	if strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "firefox") ||
		strings.Contains(uaLower, "safari") || strings.Contains(uaLower, "edge") ||
		strings.Contains(uaLower, "opera") || strings.Contains(uaLower, "mozilla") {
		return "browser"
	}

	// Mobile apps
	if strings.Contains(uaLower, "android") || strings.Contains(uaLower, "iphone") ||
		strings.Contains(uaLower, "ipad") || strings.Contains(uaLower, "mobile") {
		return "mobile"
	}

	return "other"
}

// GetSystemHealth returns current system health
func (r *DashboardRepository) GetSystemHealth(ctx context.Context) (*model.SystemHealth, error) {
	// Try to get latest recorded health
	query := `
		SELECT id, recorded_at, nginx_status, nginx_workers, nginx_connections_active,
		       nginx_connections_reading, nginx_connections_writing, nginx_connections_waiting,
		       db_status, db_connections, cpu_usage, memory_usage, disk_usage,
		       certs_total, certs_expiring_soon, certs_expired,
		       upstreams_total, upstreams_healthy, upstreams_unhealthy
		FROM system_health
		ORDER BY recorded_at DESC
		LIMIT 1
	`

	var h model.SystemHealth
	err := r.db.QueryRowContext(ctx, query).Scan(
		&h.ID, &h.RecordedAt, &h.NginxStatus, &h.NginxWorkers, &h.NginxConnectionsActive,
		&h.NginxConnectionsReading, &h.NginxConnectionsWriting, &h.NginxConnectionsWaiting,
		&h.DBStatus, &h.DBConnections, &h.CPUUsage, &h.MemoryUsage, &h.DiskUsage,
		&h.CertsTotal, &h.CertsExpiringSoon, &h.CertsExpired,
		&h.UpstreamsTotal, &h.UpstreamsHealthy, &h.UpstreamsUnhealthy,
	)
	if err == sql.ErrNoRows {
		// Return a default health check with live data
		h = model.SystemHealth{
			RecordedAt:  time.Now(),
			NginxStatus: "unknown",
			DBStatus:    "ok",
		}
	} else if err != nil {
		return nil, err
	}

	// Always fetch live certificate counts
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE status = 'issued'").Scan(&h.CertsTotal)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE expires_at < NOW() + INTERVAL '30 days' AND expires_at > NOW() AND status = 'issued'").Scan(&h.CertsExpiringSoon)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE expires_at < NOW() OR status = 'expired'").Scan(&h.CertsExpired)

	// Always fetch live upstream counts
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM upstreams").Scan(&h.UpstreamsTotal)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM upstreams WHERE is_healthy = TRUE").Scan(&h.UpstreamsHealthy)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM upstreams WHERE is_healthy = FALSE").Scan(&h.UpstreamsUnhealthy)

	return &h, nil
}

// RecordSystemHealth saves a system health snapshot
func (r *DashboardRepository) RecordSystemHealth(ctx context.Context, health *model.SystemHealth) error {
	query := `
		INSERT INTO system_health (nginx_status, nginx_workers, nginx_connections_active,
		       nginx_connections_reading, nginx_connections_writing, nginx_connections_waiting,
		       db_status, db_connections, cpu_usage, memory_usage, disk_usage,
		       certs_total, certs_expiring_soon, certs_expired,
		       upstreams_total, upstreams_healthy, upstreams_unhealthy)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	_, err := r.db.ExecContext(ctx, query,
		health.NginxStatus, health.NginxWorkers, health.NginxConnectionsActive,
		health.NginxConnectionsReading, health.NginxConnectionsWriting, health.NginxConnectionsWaiting,
		health.DBStatus, health.DBConnections, health.CPUUsage, health.MemoryUsage, health.DiskUsage,
		health.CertsTotal, health.CertsExpiringSoon, health.CertsExpired,
		health.UpstreamsTotal, health.UpstreamsHealthy, health.UpstreamsUnhealthy,
	)
	return err
}

// RecordHourlyStats records hourly statistics
func (r *DashboardRepository) RecordHourlyStats(ctx context.Context, stats *model.DashboardStatsHourly) error {
	topCountriesJSON, _ := json.Marshal(stats.TopCountries)
	topPathsJSON, _ := json.Marshal(stats.TopPaths)
	topIPsJSON, _ := json.Marshal(stats.TopIPs)

	query := `
		INSERT INTO dashboard_stats_hourly (proxy_host_id, hour_bucket, total_requests,
		       status_2xx, status_3xx, status_4xx, status_5xx,
		       avg_response_time, max_response_time, min_response_time, p95_response_time, p99_response_time,
		       bytes_sent, bytes_received, waf_blocked, waf_detected, rate_limited, bot_blocked,
		       top_countries, top_paths, top_ips)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
		ON CONFLICT (proxy_host_id, hour_bucket) DO UPDATE SET
			total_requests = dashboard_stats_hourly.total_requests + EXCLUDED.total_requests,
			status_2xx = dashboard_stats_hourly.status_2xx + EXCLUDED.status_2xx,
			status_3xx = dashboard_stats_hourly.status_3xx + EXCLUDED.status_3xx,
			status_4xx = dashboard_stats_hourly.status_4xx + EXCLUDED.status_4xx,
			status_5xx = dashboard_stats_hourly.status_5xx + EXCLUDED.status_5xx,
			bytes_sent = dashboard_stats_hourly.bytes_sent + EXCLUDED.bytes_sent,
			bytes_received = dashboard_stats_hourly.bytes_received + EXCLUDED.bytes_received,
			waf_blocked = dashboard_stats_hourly.waf_blocked + EXCLUDED.waf_blocked,
			waf_detected = dashboard_stats_hourly.waf_detected + EXCLUDED.waf_detected,
			rate_limited = dashboard_stats_hourly.rate_limited + EXCLUDED.rate_limited,
			bot_blocked = dashboard_stats_hourly.bot_blocked + EXCLUDED.bot_blocked
	`

	_, err := r.db.ExecContext(ctx, query,
		stats.ProxyHostID, stats.HourBucket, stats.TotalRequests,
		stats.Status2xx, stats.Status3xx, stats.Status4xx, stats.Status5xx,
		stats.AvgResponseTime, stats.MaxResponseTime, stats.MinResponseTime, stats.P95ResponseTime, stats.P99ResponseTime,
		stats.BytesSent, stats.BytesReceived, stats.WAFBlocked, stats.WAFDetected, stats.RateLimited, stats.BotBlocked,
		topCountriesJSON, topPathsJSON, topIPsJSON,
	)
	return err
}

// GetHourlyStats returns hourly stats for a time range
func (r *DashboardRepository) GetHourlyStats(ctx context.Context, params *model.DashboardQueryParams) ([]model.DashboardStatsHourly, error) {
	query := `
		SELECT id, proxy_host_id, hour_bucket, total_requests,
		       status_2xx, status_3xx, status_4xx, status_5xx,
		       avg_response_time, max_response_time, min_response_time, p95_response_time, p99_response_time,
		       bytes_sent, bytes_received, waf_blocked, waf_detected, rate_limited, bot_blocked,
		       top_countries, top_paths, top_ips, created_at
		FROM dashboard_stats_hourly
		WHERE hour_bucket >= $1 AND hour_bucket <= $2
	`
	args := []interface{}{params.StartTime, params.EndTime}

	if params.ProxyHostID != "" {
		query += " AND proxy_host_id = $3"
		args = append(args, params.ProxyHostID)
	}

	query += " ORDER BY hour_bucket DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []model.DashboardStatsHourly
	for rows.Next() {
		var s model.DashboardStatsHourly
		var proxyHostID sql.NullString
		var topCountries, topPaths, topIPs []byte

		err := rows.Scan(
			&s.ID, &proxyHostID, &s.HourBucket, &s.TotalRequests,
			&s.Status2xx, &s.Status3xx, &s.Status4xx, &s.Status5xx,
			&s.AvgResponseTime, &s.MaxResponseTime, &s.MinResponseTime, &s.P95ResponseTime, &s.P99ResponseTime,
			&s.BytesSent, &s.BytesReceived, &s.WAFBlocked, &s.WAFDetected, &s.RateLimited, &s.BotBlocked,
			&topCountries, &topPaths, &topIPs, &s.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if proxyHostID.Valid {
			s.ProxyHostID = &proxyHostID.String
		}

		json.Unmarshal(topCountries, &s.TopCountries)
		json.Unmarshal(topPaths, &s.TopPaths)
		json.Unmarshal(topIPs, &s.TopIPs)

		stats = append(stats, s)
	}
	return stats, nil
}

// CleanupOldStats removes stats older than retention period
func (r *DashboardRepository) CleanupOldStats(ctx context.Context, hourlyRetentionDays, dailyRetentionDays int) error {
	// Cleanup hourly stats
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM dashboard_stats_hourly
		WHERE hour_bucket < NOW() - INTERVAL '1 day' * $1
	`, hourlyRetentionDays)
	if err != nil {
		return err
	}

	// Cleanup daily stats
	_, err = r.db.ExecContext(ctx, `
		DELETE FROM dashboard_stats_daily
		WHERE day_bucket < NOW() - INTERVAL '1 day' * $1
	`, dailyRetentionDays)
	if err != nil {
		return err
	}

	// Cleanup old health records (keep last 24 hours)
	_, err = r.db.ExecContext(ctx, `
		DELETE FROM system_health
		WHERE recorded_at < NOW() - INTERVAL '24 hours'
	`)
	return err
}

// GetSystemHealthHistory returns historical system health data for charts
func (r *DashboardRepository) GetSystemHealthHistory(ctx context.Context, since time.Time, limit int) ([]model.SystemHealth, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Use window function to evenly sample data points across the time range
	// This ensures we get data from the entire requested period, not just the oldest records
	query := `
		WITH numbered AS (
			SELECT *,
			       ROW_NUMBER() OVER (ORDER BY recorded_at ASC) as rn,
			       COUNT(*) OVER () as total_count
			FROM system_health
			WHERE recorded_at >= $1
		)
		SELECT id, recorded_at, nginx_status, nginx_workers, nginx_connections_active,
		       nginx_connections_reading, nginx_connections_writing, nginx_connections_waiting,
		       db_status, db_connections, cpu_usage, memory_usage, disk_usage,
		       COALESCE(memory_total, 0), COALESCE(memory_used, 0),
		       COALESCE(disk_total, 0), COALESCE(disk_used, 0), COALESCE(disk_path, '/'),
		       COALESCE(network_in, 0), COALESCE(network_out, 0), COALESCE(uptime_seconds, 0),
		       COALESCE(hostname, ''), COALESCE(os, ''), COALESCE(platform, ''), COALESCE(kernel_version, ''),
		       certs_total, certs_expiring_soon, certs_expired,
		       upstreams_total, upstreams_healthy, upstreams_unhealthy
		FROM numbered
		WHERE total_count <= $2
		   OR rn = 1
		   OR rn = total_count
		   OR (rn - 1) % GREATEST(1, CEIL((total_count - 1)::float / ($2 - 1)))::int = 0
		ORDER BY recorded_at ASC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []model.SystemHealth
	for rows.Next() {
		var h model.SystemHealth
		err := rows.Scan(
			&h.ID, &h.RecordedAt, &h.NginxStatus, &h.NginxWorkers, &h.NginxConnectionsActive,
			&h.NginxConnectionsReading, &h.NginxConnectionsWriting, &h.NginxConnectionsWaiting,
			&h.DBStatus, &h.DBConnections, &h.CPUUsage, &h.MemoryUsage, &h.DiskUsage,
			&h.MemoryTotal, &h.MemoryUsed, &h.DiskTotal, &h.DiskUsed, &h.DiskPath,
			&h.NetworkIn, &h.NetworkOut, &h.UptimeSeconds,
			&h.Hostname, &h.OS, &h.Platform, &h.KernelVersion,
			&h.CertsTotal, &h.CertsExpiringSoon, &h.CertsExpired,
			&h.UpstreamsTotal, &h.UpstreamsHealthy, &h.UpstreamsUnhealthy,
		)
		if err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, nil
}

// AggregateToDaily aggregates hourly stats to daily
func (r *DashboardRepository) AggregateToDaily(ctx context.Context, date time.Time) error {
	query := `
		INSERT INTO dashboard_stats_daily (proxy_host_id, day_bucket, total_requests,
		       status_2xx, status_3xx, status_4xx, status_5xx,
		       avg_response_time, max_response_time, bytes_sent, bytes_received,
		       waf_blocked, rate_limited, bot_blocked)
		SELECT proxy_host_id, DATE($1), SUM(total_requests),
		       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
		       AVG(avg_response_time), MAX(max_response_time), SUM(bytes_sent), SUM(bytes_received),
		       SUM(waf_blocked), SUM(rate_limited), SUM(bot_blocked)
		FROM dashboard_stats_hourly
		WHERE DATE(hour_bucket) = DATE($1)
		GROUP BY proxy_host_id
		ON CONFLICT (proxy_host_id, day_bucket) DO UPDATE SET
			total_requests = EXCLUDED.total_requests,
			status_2xx = EXCLUDED.status_2xx,
			status_3xx = EXCLUDED.status_3xx,
			status_4xx = EXCLUDED.status_4xx,
			status_5xx = EXCLUDED.status_5xx,
			avg_response_time = EXCLUDED.avg_response_time,
			max_response_time = EXCLUDED.max_response_time,
			bytes_sent = EXCLUDED.bytes_sent,
			bytes_received = EXCLUDED.bytes_received,
			waf_blocked = EXCLUDED.waf_blocked,
			rate_limited = EXCLUDED.rate_limited,
			bot_blocked = EXCLUDED.bot_blocked
	`

	_, err := r.db.ExecContext(ctx, query, date)
	return err
}
