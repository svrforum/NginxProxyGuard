package service

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// combinedLogPattern is precompiled regex for combined log format parsing
var combinedLogPattern = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d+) (\d+)`)

// nginxStatusHTTPClient bounds the stub_status fetch. The default http.Get
// client has NO timeout, so a stalled host.docker.internal route (issue #146)
// could wedge the collector goroutine indefinitely.
var nginxStatusHTTPClient = &http.Client{Timeout: 5 * time.Second}

type StatsCollector struct {
	db              *sql.DB
	nginxStatusURL  string
	accessLogPath   string
	lastLogPosition int64
	// mu guards only the nginx_status backoff state below. It is deliberately
	// NOT held across network or DB work, so /health/detailed (which calls
	// NginxStatusReachable) can never block behind a slow collection cycle.
	mu     sync.Mutex
	stopCh chan struct{}

	// nginx_status fetch failure backoff state. Without this, a misconfigured
	// host.docker.internal env (typical on plain Linux Docker without
	// extra_hosts: host-gateway) caused a 30s error-log flood that buried
	// real signal. We now warn once with a remediation hint, then quietly
	// retry with exponential backoff up to nginxStatusMaxBackoff.
	statusFailCount    int
	statusNextAttempt  time.Time
	statusWarnedOnce   bool
	nginxStatusBackoffBase time.Duration
	nginxStatusMaxBackoff  time.Duration

	// The dashboard's hourly totals, rebuilt from the logs by recomputeRollup.
	// Only the collector goroutine touches these.
	rollup            hourlyRollupRecomputer
	rollupLastAttempt time.Time
	rollupSwept       bool

	// DiskGuard (D1), wired by SetDiskSource; nil when it is disabled.
	diskSource diskPrimarySource
}

// hourlyRollupRecomputer rebuilds the dashboard's hourly totals for the hours
// in [from, to) from the logs. DashboardRepository implements it.
type hourlyRollupRecomputer interface {
	RecomputeHourlyRollup(ctx context.Context, from, to time.Time) (int64, error)
}

const (
	// rollupInterval is how often the current hour is rebuilt.
	rollupInterval = time.Minute
	// rollupLateWindow is how long into an hour the previous hour is rebuilt
	// too: a row's created_at is when the transaction that stored it began,
	// so a batch that began before the hour turned can commit after it.
	rollupLateWindow = 10 * time.Minute
	// rollupBootSweep is how far back the first rebuild after boot reaches:
	// it repairs what went unrecorded while the API was down, and what the
	// old incremental rollup got wrong, across the dashboard's whole 24 hours.
	rollupBootSweep = 25 * time.Hour
	// rollupTimeout bounds one rebuild; the boot sweep reads a day of logs.
	rollupTimeout = 2 * time.Minute
)

type NginxStatus struct {
	ActiveConnections int
	Accepts           int64
	Handled           int64
	Requests          int64
	Reading           int
	Writing           int
	Waiting           int
}

// HostResources contains host system resource information
type HostResources struct {
	CPUUsage      float64 // CPU usage percentage (0-100)
	MemoryUsage   float64 // Memory usage percentage (0-100)
	MemoryTotal   uint64  // Total memory in bytes
	MemoryUsed    uint64  // Used memory in bytes
	DiskUsage     float64 // Disk usage percentage (0-100)
	DiskTotal     uint64  // Total disk space in bytes
	DiskUsed      uint64  // Used disk space in bytes
	DiskPath      string  // Monitored disk path
	NetworkIn     uint64  // Network bytes received (cumulative since boot)
	NetworkOut    uint64  // Network bytes sent (cumulative since boot)
	UptimeSeconds uint64  // System uptime in seconds
	Hostname      string  // System hostname
	OS            string  // Operating system
	Platform      string  // Platform (e.g., ubuntu, centos)
	KernelVersion string  // Kernel version
}

type AccessLogEntry struct {
	Timestamp    time.Time
	ClientIP     string
	Method       string
	Path         string
	StatusCode   int
	BytesSent    int64
	ResponseTime float64
	Host         string
	UserAgent    string
}

func NewStatsCollector(db *sql.DB, nginxStatusURL, accessLogPath string) *StatsCollector {
	return &StatsCollector{
		db:             db,
		nginxStatusURL: nginxStatusURL,
		accessLogPath:  accessLogPath,
		stopCh:         make(chan struct{}),
		// Backoff starts at 30s (= the collect interval, so we skip exactly
		// one cycle on first failure) and caps at 30 minutes — long enough
		// to be quiet, short enough that an operator fixing the env sees
		// recovery within a reasonable wait.
		nginxStatusBackoffBase: 30 * time.Second,
		nginxStatusMaxBackoff:  30 * time.Minute,
	}
}

// SetRollupRepo wires the dashboard's hourly totals. Without it the collector
// records system health only.
func (sc *StatsCollector) SetRollupRepo(r hourlyRollupRecomputer) {
	sc.rollup = r
}

func (sc *StatsCollector) Start(ctx context.Context) {
	log.Println("Starting stats collector...")

	// Collect stats every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial collection
	sc.collectStats()

	for {
		select {
		case <-ctx.Done():
			log.Println("Stats collector stopped")
			return
		case <-sc.stopCh:
			log.Println("Stats collector stopped")
			return
		case <-ticker.C:
			sc.collectStats()
		}
	}
}

func (sc *StatsCollector) Stop() {
	close(sc.stopCh)
}

// NginxStatusReachable reports whether the last nginx_status fetch succeeded.
// Used by /health/detailed to surface issue #146 (host.docker.internal /
// extra_hosts misconfig) without auto-healing it.
func (sc *StatsCollector) NginxStatusReachable() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.statusFailCount == 0
}

func (sc *StatsCollector) collectStats() {
	// Only ever called from the single Start goroutine; the backoff state it
	// shares with NginxStatusReachable is locked inside
	// getNginxStatusWithBackoff, not across the whole (slow) collection.
	log.Println("[StatsCollector] Collecting stats...")

	// 1. Collect Nginx status — with backoff on repeated failure (issue #146).
	//    Skip the HTTP call entirely while we're still within the backoff
	//    window, so we don't generate a "Failed to get nginx status" line
	//    every 30 seconds on environments where the URL is unreachable.
	nginxStatus, err := sc.getNginxStatusWithBackoff()
	if err != nil {
		nginxStatus = NginxStatus{ActiveConnections: -1} // Mark as failed
	} else if nginxStatus.ActiveConnections >= 0 {
		log.Printf("[StatsCollector] Nginx status: connections=%d, reading=%d, writing=%d, waiting=%d",
			nginxStatus.ActiveConnections, nginxStatus.Reading, nginxStatus.Writing, nginxStatus.Waiting)
	}

	// 2. Rebuild the dashboard's hourly request totals from the logs (at most
	//    once a minute; see recomputeRollup)
	sc.recomputeRollup()

	// 3. Record to database (nginx stats only, host resources are fetched live)
	if err := sc.recordStats(nginxStatus); err != nil {
		log.Printf("[StatsCollector] Failed to record stats: %v", err)
	}

	log.Printf("[StatsCollector] Stats collected: nginx_connections=%d", nginxStatus.ActiveConnections)
}

// rollupWindow returns the hours [from, to) to rebuild at now: the current
// hour; the previous one too early in an hour; the last 25 hours until the
// first rebuild after boot has succeeded. Hours are UTC hours, as the
// rollup's date_trunc('hour', created_at, 'UTC') buckets them.
func rollupWindow(now time.Time, swept bool) (from, to time.Time) {
	hour := now.Truncate(time.Hour)
	from = hour
	switch {
	case !swept:
		from = hour.Add(-rollupBootSweep)
	case now.Sub(hour) < rollupLateWindow:
		from = hour.Add(-time.Hour)
	}
	return from, hour.Add(time.Hour)
}

// recomputeRollup rebuilds the dashboard's hourly totals from the logs, at
// most once per rollupInterval. Every rebuild overwrites the hours it covers
// with what the logs hold, so a missed or failed run is made good by the next
// one rather than lost.
func (sc *StatsCollector) recomputeRollup() {
	if sc.rollup == nil {
		return
	}
	now := time.Now()
	if !sc.rollupLastAttempt.IsZero() && now.Sub(sc.rollupLastAttempt) < rollupInterval {
		return
	}
	sc.rollupLastAttempt = now

	from, to := rollupWindow(now, sc.rollupSwept)
	ctx, cancel := context.WithTimeout(context.Background(), rollupTimeout)
	defer cancel()
	rows, err := sc.rollup.RecomputeHourlyRollup(ctx, from, to)
	if err != nil {
		log.Printf("[StatsCollector] Failed to rebuild dashboard hourly stats from %s: %v", from.UTC().Format(time.RFC3339), err)
		return
	}
	if !sc.rollupSwept {
		sc.rollupSwept = true
		log.Printf("[StatsCollector] Rebuilt dashboard hourly stats from the logs for the last %d hours (%d hourly rows) in %v",
			int(to.Sub(from)/time.Hour), rows, time.Since(now).Round(time.Millisecond))
	}
}

// getNginxStatusWithBackoff wraps getNginxStatus with first-failure warn +
// exponential backoff. On success it resets the failure counter so a brief
// network blip doesn't permanently suppress logging. See issue #146.
func (sc *StatsCollector) getNginxStatusWithBackoff() (NginxStatus, error) {
	sc.mu.Lock()
	if !sc.statusNextAttempt.IsZero() && time.Now().Before(sc.statusNextAttempt) {
		next := sc.statusNextAttempt
		sc.mu.Unlock()
		return NginxStatus{}, fmt.Errorf("skipped (backoff until %s)", next.Format(time.RFC3339))
	}
	sc.mu.Unlock()

	// HTTP fetch happens outside the mutex (it has a 5s client timeout, but
	// even that must not stall NginxStatusReachable / health checks).
	status, err := sc.getNginxStatus()

	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err == nil {
		if sc.statusFailCount > 0 {
			log.Printf("[StatsCollector] nginx_status recovered after %d failures", sc.statusFailCount)
		}
		sc.statusFailCount = 0
		sc.statusNextAttempt = time.Time{}
		sc.statusWarnedOnce = false
		return status, nil
	}
	sc.statusFailCount++
	// Compute the next attempt: 30s, 60s, 2m, 4m, 8m, ..., capped.
	backoff := sc.nginxStatusBackoffBase * (1 << (sc.statusFailCount - 1))
	if backoff > sc.nginxStatusMaxBackoff || backoff <= 0 {
		backoff = sc.nginxStatusMaxBackoff
	}
	sc.statusNextAttempt = time.Now().Add(backoff)
	if !sc.statusWarnedOnce {
		log.Printf("[StatsCollector] nginx_status unreachable at %s (%v). Active-connection metrics will be unavailable. Set NGINX_STATUS_URL or add `extra_hosts: host.docker.internal:host-gateway` to your docker-compose for the api service. Suppressing further messages until recovery.", sc.nginxStatusURL, err)
		sc.statusWarnedOnce = true
	}
	return status, err
}

func (sc *StatsCollector) getNginxStatus() (NginxStatus, error) {
	status := NginxStatus{}

	resp, err := nginxStatusHTTPClient.Get(sc.nginxStatusURL)
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return status, err
	}

	// Parse nginx stub_status output:
	// Active connections: 1
	// server accepts handled requests
	//  16 16 31
	// Reading: 0 Writing: 1 Waiting: 0
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Active connections:") {
			fmt.Sscanf(line, "Active connections: %d", &status.ActiveConnections)
		} else if strings.HasPrefix(line, "Reading:") {
			fmt.Sscanf(line, "Reading: %d Writing: %d Waiting: %d",
				&status.Reading, &status.Writing, &status.Waiting)
		} else if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			fmt.Sscanf(line, "%d %d %d", &status.Accepts, &status.Handled, &status.Requests)
		}
	}

	return status, nil
}

// getHostResources collects host system resource metrics using gopsutil
func (sc *StatsCollector) getHostResources() HostResources {
	resources := HostResources{
		DiskPath: "/",
	}

	// Get CPU usage (average over 500ms for faster collection)
	cpuPercent, err := cpu.Percent(500*time.Millisecond, false)
	if err == nil && len(cpuPercent) > 0 {
		resources.CPUUsage = cpuPercent[0]
	}

	// Get memory stats
	memStats, err := mem.VirtualMemory()
	if err == nil {
		resources.MemoryUsage = memStats.UsedPercent
		resources.MemoryTotal = memStats.Total
		resources.MemoryUsed = memStats.Used
	}

	// The disk that matters: the database's when DiskGuard can see it.
	// system_health's disk_* columns therefore follow that disk, which is what
	// the history chart, the digest and DiskGuard's growth estimate read.
	if pct, total, used, path, ok := primaryDiskUsage(sc.diskSource); ok {
		resources.DiskUsage = pct
		resources.DiskTotal = total
		resources.DiskUsed = used
		resources.DiskPath = path
	}

	// Get network I/O stats (all interfaces combined)
	netStats, err := net.IOCounters(false) // false = combine all interfaces
	if err == nil && len(netStats) > 0 {
		resources.NetworkIn = netStats[0].BytesRecv
		resources.NetworkOut = netStats[0].BytesSent
	}

	// Get host info
	hostInfo, err := host.Info()
	if err == nil {
		resources.UptimeSeconds = hostInfo.Uptime
		resources.Hostname = hostInfo.Hostname
		resources.OS = hostInfo.OS
		resources.Platform = hostInfo.Platform
		resources.KernelVersion = hostInfo.KernelVersion
	}

	return resources
}

func (sc *StatsCollector) parseNewLogEntries() ([]AccessLogEntry, error) {
	var entries []AccessLogEntry

	// Check if file is a regular file or symlink to stdout
	info, err := os.Lstat(sc.accessLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[StatsCollector] Access log not found: %s", sc.accessLogPath)
			return entries, nil
		}
		return nil, err
	}

	// Skip if it's a symlink (often points to /dev/stdout in Docker)
	if info.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(sc.accessLogPath)
		if strings.Contains(target, "stdout") || strings.Contains(target, "stderr") {
			log.Printf("[StatsCollector] Access log is symlink to %s, skipping log parsing", target)
			return entries, nil
		}
	}

	file, err := os.Open(sc.accessLogPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Seek to last position
	if sc.lastLogPosition > 0 {
		_, err = file.Seek(sc.lastLogPosition, 0)
		if err != nil {
			// File might have been rotated, start from beginning
			sc.lastLogPosition = 0
			file.Seek(0, 0)
		}
	}

	scanner := bufio.NewScanner(file)
	const maxEntries = 10000 // Cap to prevent unbounded memory growth
	// JSON log format pattern
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := sc.parseJSONLogLine(line)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
		if len(entries) >= maxEntries {
			break
		}
	}

	// Update position
	pos, _ := file.Seek(0, 1)
	sc.lastLogPosition = pos

	return entries, scanner.Err()
}

func (sc *StatsCollector) parseJSONLogLine(line string) (AccessLogEntry, error) {
	var entry AccessLogEntry
	var logData map[string]interface{}

	if err := json.Unmarshal([]byte(line), &logData); err != nil {
		// Try combined log format
		return sc.parseCombinedLogLine(line)
	}

	// Parse JSON log format
	if ts, ok := logData["time_local"].(string); ok {
		entry.Timestamp, _ = time.Parse("02/Jan/2006:15:04:05 -0700", ts)
	}
	if ip, ok := logData["remote_addr"].(string); ok {
		entry.ClientIP = ip
	}
	if method, ok := logData["request_method"].(string); ok {
		entry.Method = method
	}
	if uri, ok := logData["request_uri"].(string); ok {
		entry.Path = uri
	}
	if status, ok := logData["status"].(float64); ok {
		entry.StatusCode = int(status)
	}
	if bytes, ok := logData["body_bytes_sent"].(float64); ok {
		entry.BytesSent = int64(bytes)
	}
	if rt, ok := logData["request_time"].(float64); ok {
		entry.ResponseTime = rt
	}
	if host, ok := logData["host"].(string); ok {
		entry.Host = host
	}
	if ua, ok := logData["http_user_agent"].(string); ok {
		entry.UserAgent = ua
	}

	return entry, nil
}

func (sc *StatsCollector) parseCombinedLogLine(line string) (AccessLogEntry, error) {
	var entry AccessLogEntry

	// Combined log format:
	// 127.0.0.1 - - [02/Dec/2025:10:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
	matches := combinedLogPattern.FindStringSubmatch(line)
	if len(matches) < 7 {
		return entry, fmt.Errorf("invalid log format")
	}

	entry.ClientIP = matches[1]
	entry.Timestamp, _ = time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
	entry.Method = matches[3]
	entry.Path = matches[4]
	entry.StatusCode, _ = strconv.Atoi(matches[5])
	entry.BytesSent, _ = strconv.ParseInt(matches[6], 10, 64)

	return entry, nil
}

type AggregatedStats struct {
	TotalRequests int64
	// TimedRequests counts requests whose request_time is a real latency
	// measurement. WebSocket upgrades (HTTP 101) are excluded because their
	// request_time is the connection lifetime, not latency. (GitHub Issue #148)
	TimedRequests int64
	TotalBytes    int64
	TotalTime     float64
	Status2xx     int
	Status3xx     int
	Status4xx     int
	Status5xx     int
	WAFBlocked    int
	RateLimited   int
	BotBlocked    int
	HostStats     map[string]int64
	PathStats     map[string]int64
	ErrorCount    int
}

// accumulateRow folds one access-log row into the aggregate. WebSocket upgrades
// (HTTP 101) are counted as requests, but their request_time is the connection
// lifetime — not latency — so they are excluded from the response-time average,
// keeping a single long-lived socket from skewing avg_response_time. (Issue #148)
func (stats *AggregatedStats) accumulateRow(statusCode int, bodyBytes int64, requestTime float64, host, uri, blockReason string) {
	stats.TotalRequests++

	switch {
	case statusCode >= 200 && statusCode < 300:
		stats.Status2xx++
	case statusCode >= 300 && statusCode < 400:
		stats.Status3xx++
	case statusCode >= 400 && statusCode < 500:
		stats.Status4xx++
	case statusCode >= 500:
		stats.Status5xx++
		stats.ErrorCount++
	}

	switch blockReason {
	case "waf":
		stats.WAFBlocked++
	case "rate_limit":
		stats.RateLimited++
	case "bot_filter":
		stats.BotBlocked++
	}

	stats.TotalBytes += bodyBytes
	// HTTP 101 = WebSocket upgrade; request_time is the connection lifetime.
	if statusCode != 101 {
		stats.TotalTime += requestTime // Already in seconds
		stats.TimedRequests++
	}

	if host != "" {
		stats.HostStats[host]++
	}
	if uri != "" {
		stats.PathStats[uri]++
	}
}

func (sc *StatsCollector) aggregateStats(entries []AccessLogEntry) AggregatedStats {
	stats := AggregatedStats{
		HostStats: make(map[string]int64),
		PathStats: make(map[string]int64),
	}

	for _, e := range entries {
		stats.accumulateRow(e.StatusCode, e.BytesSent, e.ResponseTime, e.Host, e.Path, "")
	}

	return stats
}

func (sc *StatsCollector) recordStats(nginxStatus NginxStatus) error {
	// Record system health (always) - including host resources
	nginxStatusStr := "unknown"
	if nginxStatus.ActiveConnections >= 0 {
		nginxStatusStr = "ok"
	}

	// Collect host resources for historical data
	hostResources := sc.getHostResources()

	log.Printf("[StatsCollector] Recording system health: nginx=%s, connections=%d, cpu=%.1f%%, mem=%.1f%%",
		nginxStatusStr, nginxStatus.ActiveConnections, hostResources.CPUUsage, hostResources.MemoryUsage)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := sc.db.ExecContext(ctx, `
		INSERT INTO system_health (
			nginx_status, nginx_connections_active,
			nginx_connections_reading, nginx_connections_writing, nginx_connections_waiting,
			cpu_usage, memory_usage, memory_total, memory_used,
			disk_usage, disk_total, disk_used, disk_path,
			network_in, network_out, uptime_seconds,
			hostname, os, platform, kernel_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`, nginxStatusStr, nginxStatus.ActiveConnections,
		nginxStatus.Reading, nginxStatus.Writing, nginxStatus.Waiting,
		hostResources.CPUUsage, hostResources.MemoryUsage, hostResources.MemoryTotal, hostResources.MemoryUsed,
		hostResources.DiskUsage, hostResources.DiskTotal, hostResources.DiskUsed, hostResources.DiskPath,
		hostResources.NetworkIn, hostResources.NetworkOut, hostResources.UptimeSeconds,
		hostResources.Hostname, hostResources.OS, hostResources.Platform, hostResources.KernelVersion)
	if err != nil {
		log.Printf("[StatsCollector] Failed to record system health: %v", err)
	} else {
		log.Println("[StatsCollector] System health recorded successfully")
	}

	// Note: system_health cleanup is handled by PartitionScheduler.cleanupDashboardStats()
	// which runs daily via DashboardRepository.CleanupOldStats()

	// The hourly request totals are rebuilt from the logs by recomputeRollup.
	return nil
}

// GetCurrentHealth returns current system health for dashboard
func (sc *StatsCollector) GetCurrentHealth() (map[string]interface{}, error) {
	nginxStatus, err := sc.getNginxStatus()
	if err != nil {
		return nil, err
	}

	// Get host resources
	hostResources := sc.getHostResources()

	return map[string]interface{}{
		"nginx_status":              "ok",
		"nginx_connections_active":  nginxStatus.ActiveConnections,
		"nginx_connections_reading": nginxStatus.Reading,
		"nginx_connections_writing": nginxStatus.Writing,
		"nginx_connections_waiting": nginxStatus.Waiting,
		"db_status":                 "ok",
		// Host resources
		"cpu_usage":      hostResources.CPUUsage,
		"memory_usage":   hostResources.MemoryUsage,
		"memory_total":   hostResources.MemoryTotal,
		"memory_used":    hostResources.MemoryUsed,
		"disk_usage":     hostResources.DiskUsage,
		"disk_total":     hostResources.DiskTotal,
		"disk_used":      hostResources.DiskUsed,
		"disk_path":      hostResources.DiskPath,
		"network_in":     hostResources.NetworkIn,
		"network_out":    hostResources.NetworkOut,
		"uptime_seconds": hostResources.UptimeSeconds,
		"hostname":       hostResources.Hostname,
		"os":             hostResources.OS,
		"platform":       hostResources.Platform,
		"kernel_version": hostResources.KernelVersion,
	}, nil
}
