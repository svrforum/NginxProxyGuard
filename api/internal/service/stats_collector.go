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
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type StatsCollector struct {
	db              *sql.DB
	nginxStatusURL  string
	accessLogPath   string
	lastLogPosition int64
	mu              sync.Mutex
	stopCh          chan struct{}
}

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
	}
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

func (sc *StatsCollector) collectStats() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	log.Println("[StatsCollector] Collecting stats...")

	// 1. Collect Nginx status
	nginxStatus, err := sc.getNginxStatus()
	if err != nil {
		log.Printf("[StatsCollector] Failed to get nginx status: %v", err)
		nginxStatus = NginxStatus{ActiveConnections: -1} // Mark as failed
	} else {
		log.Printf("[StatsCollector] Nginx status: connections=%d, reading=%d, writing=%d, waiting=%d",
			nginxStatus.ActiveConnections, nginxStatus.Reading, nginxStatus.Writing, nginxStatus.Waiting)
	}

	// 2. Aggregate stats from system_logs (docker_nginx source)
	stats := sc.aggregateStatsFromDB()

	// 3. Record to database (nginx stats only, host resources are fetched live)
	if err := sc.recordStats(nginxStatus, stats); err != nil {
		log.Printf("[StatsCollector] Failed to record stats: %v", err)
	}

	log.Printf("[StatsCollector] Stats collected: requests=%d, nginx_connections=%d",
		stats.TotalRequests, nginxStatus.ActiveConnections)
}

func (sc *StatsCollector) getNginxStatus() (NginxStatus, error) {
	status := NginxStatus{}

	resp, err := http.Get(sc.nginxStatusURL)
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

	// Get disk usage for root partition
	diskStats, err := disk.Usage("/")
	if err == nil {
		resources.DiskUsage = diskStats.UsedPercent
		resources.DiskTotal = diskStats.Total
		resources.DiskUsed = diskStats.Used
		resources.DiskPath = "/"
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
	// JSON log format pattern
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := sc.parseJSONLogLine(line)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
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
	pattern := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d+) (\d+)`)
	matches := pattern.FindStringSubmatch(line)
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
	TotalRequests   int64
	TotalBytes      int64
	TotalTime       float64
	Status2xx       int
	Status3xx       int
	Status4xx       int
	Status5xx       int
	HostStats       map[string]int64
	PathStats       map[string]int64
	ErrorCount      int
}

// aggregateStatsFromDB queries logs table for nginx request stats
func (sc *StatsCollector) aggregateStatsFromDB() AggregatedStats {
	stats := AggregatedStats{
		HostStats: make(map[string]int64),
		PathStats: make(map[string]int64),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query access logs from the last collection interval (30 seconds + buffer)
	// Only include requests to actual proxy hosts (exclude internal like localhost, nginx)
	query := `
		SELECT status_code, body_bytes_sent, request_time, host, request_uri
		FROM logs_partitioned
		WHERE log_type = 'access'
		  AND created_at > NOW() - INTERVAL '35 seconds'
		  AND host IS NOT NULL
		  AND host NOT IN ('localhost', 'nginx', '127.0.0.1', '', '_', '0.0.0.0')
		  AND host NOT LIKE 'localhost:%'
		  AND request_uri NOT IN ('/health', '/nginx_status')
		  AND request_uri NOT LIKE '/.well-known/%'
	`

	rows, err := sc.db.QueryContext(ctx, query)
	if err != nil {
		log.Printf("[StatsCollector] Failed to query logs: %v", err)
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var statusCode int
		var bodyBytes int64
		var requestTime float64
		var host, uri string

		if err := rows.Scan(&statusCode, &bodyBytes, &requestTime, &host, &uri); err != nil {
			continue
		}

		stats.TotalRequests++

		// Categorize status code
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

		// Accumulate bytes and time
		stats.TotalBytes += bodyBytes
		stats.TotalTime += requestTime // Already in seconds

		// Track host stats
		if host != "" {
			stats.HostStats[host]++
		}

		// Track path stats
		if uri != "" {
			stats.PathStats[uri]++
		}
	}

	return stats
}

func (sc *StatsCollector) aggregateStats(entries []AccessLogEntry) AggregatedStats {
	stats := AggregatedStats{
		HostStats: make(map[string]int64),
		PathStats: make(map[string]int64),
	}

	for _, e := range entries {
		stats.TotalRequests++
		stats.TotalBytes += e.BytesSent
		stats.TotalTime += e.ResponseTime

		switch {
		case e.StatusCode >= 200 && e.StatusCode < 300:
			stats.Status2xx++
		case e.StatusCode >= 300 && e.StatusCode < 400:
			stats.Status3xx++
		case e.StatusCode >= 400 && e.StatusCode < 500:
			stats.Status4xx++
		case e.StatusCode >= 500:
			stats.Status5xx++
			stats.ErrorCount++
		}

		if e.Host != "" {
			stats.HostStats[e.Host]++
		}
		if e.Path != "" {
			stats.PathStats[e.Path]++
		}
	}

	return stats
}

func (sc *StatsCollector) recordStats(nginxStatus NginxStatus, stats AggregatedStats) error {
	now := time.Now()
	hourBucket := now.Truncate(time.Hour)

	// Record system health first (always) - including host resources
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

	// Skip traffic stats if no new data
	if stats.TotalRequests == 0 {
		return nil
	}

	// Calculate averages
	avgResponseTime := 0.0
	if stats.TotalRequests > 0 {
		avgResponseTime = stats.TotalTime / float64(stats.TotalRequests) * 1000 // Convert to ms
	}

	// Insert hourly stats (global, not per proxy host)
	_, err = sc.db.Exec(`
		INSERT INTO dashboard_stats_hourly (
			proxy_host_id, hour_bucket, total_requests,
			status_2xx, status_3xx, status_4xx, status_5xx,
			avg_response_time, bytes_sent,
			waf_blocked, rate_limited, bot_blocked
		) VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, 0, 0, 0)
	`, hourBucket, stats.TotalRequests,
		stats.Status2xx, stats.Status3xx, stats.Status4xx, stats.Status5xx,
		avgResponseTime, stats.TotalBytes)
	if err != nil {
		return fmt.Errorf("failed to record hourly stats: %w", err)
	}

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
