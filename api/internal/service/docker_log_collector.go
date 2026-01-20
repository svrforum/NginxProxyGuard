package service

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

type SystemLogConfig struct {
	Enabled         bool              `json:"enabled"`
	Levels          map[string]string `json:"levels"`           // container_name -> min_level (debug, info, warn, error)
	ExcludePatterns []string          `json:"exclude_patterns"` // regex patterns to exclude
	StdoutExcluded  []string          `json:"stdout_excluded"`  // list of containers to exclude stdout from
}

var defaultSystemLogConfig = SystemLogConfig{
	Enabled: true,
	Levels: map[string]string{
		"npg-proxy": "info",
		"npg-api":   "info",
		"npg-db":    "warn",
		"npg-ui":    "warn",
	},
	ExcludePatterns: []string{
		"/health",
		"/nginx_status",
		"/.well-known/",
		"HEAD /",
	},
	StdoutExcluded: []string{
		"npg-proxy", // Exclude nginx access logs from system logs (they are in Access Logs)
	},
}

// DockerLogCollector collects logs from Docker containers
type DockerLogCollector struct {
	systemLogRepo       *repository.SystemLogRepository
	systemSettingsRepo  *repository.SystemSettingsRepository
	containers          []ContainerConfig
	stopCh              chan struct{}
	wg                  sync.WaitGroup
	config              SystemLogConfig
	mu                  sync.RWMutex // Protects config
}

type ContainerConfig struct {
	Name   string
	Source repository.SystemLogSource
}

func NewDockerLogCollector(systemLogRepo *repository.SystemLogRepository, systemSettingsRepo *repository.SystemSettingsRepository) *DockerLogCollector {
	collector := &DockerLogCollector{
		systemLogRepo:      systemLogRepo,
		systemSettingsRepo: systemSettingsRepo,
		containers: []ContainerConfig{
			{Name: "npg-proxy", Source: repository.SourceDockerNginx},
			{Name: "npg-api", Source: repository.SourceDockerAPI},
			{Name: "npg-db", Source: repository.SourceDockerDB},
			{Name: "npg-ui", Source: repository.SourceDockerUI},
		},
		stopCh: make(chan struct{}),
		config: defaultSystemLogConfig,
	}
	collector.loadConfig()
	return collector
}

func (c *DockerLogCollector) loadConfig() {
	if c.systemSettingsRepo == nil {
		return
	}

	settings, err := c.systemSettingsRepo.Get(context.Background())
	if err != nil {
		log.Printf("[DockerLogCollector] Failed to load settings from DB: %v", err)
		return
	}

	var levels map[string]string
	if len(settings.SystemLogsLevels) > 0 {
		if err := json.Unmarshal(settings.SystemLogsLevels, &levels); err != nil {
			log.Printf("[DockerLogCollector] Failed to parse log levels: %v", err)
			return
		}
	}

	c.mu.Lock()
	c.config = SystemLogConfig{
		Enabled:         settings.SystemLogsEnabled,
		Levels:          levels,
		ExcludePatterns: settings.SystemLogsExcludePatterns,
		StdoutExcluded:  settings.SystemLogsStdoutExcluded,
	}
	c.mu.Unlock()
	log.Printf("[DockerLogCollector] Loaded configuration from DB")
}

// ReloadConfig reloads the configuration from DB
func (c *DockerLogCollector) ReloadConfig() error {
	c.loadConfig()
	return nil
}

func (c *DockerLogCollector) GetConfig() SystemLogConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

func (c *DockerLogCollector) UpdateConfig(config SystemLogConfig) error {
	// Write to DB
	levelsJSON, err := json.Marshal(config.Levels)
	if err != nil {
		return err
	}
	levelsRaw := json.RawMessage(levelsJSON)

	req := &model.UpdateSystemSettingsRequest{
		SystemLogsEnabled:         &config.Enabled,
		SystemLogsLevels:          &levelsRaw,
		SystemLogsExcludePatterns: &config.ExcludePatterns,
		SystemLogsStdoutExcluded:  &config.StdoutExcluded,
	}

	_, err = c.systemSettingsRepo.Update(context.Background(), req)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.config = config
	c.mu.Unlock()

	return nil
}

func (c *DockerLogCollector) shouldLog(container string, level repository.SystemLogLevel, message string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.config.Enabled {
		return false
	}

	// Check exclude patterns
	for _, pattern := range c.config.ExcludePatterns {
		if strings.Contains(message, pattern) {
			return false
		}
	}

	// Check level
	minLevelStr, ok := c.config.Levels[container]
	if !ok {
		minLevelStr = "info" // Default to info
	}

	return isLevelEnabled(level, minLevelStr)
}

func isLevelEnabled(level repository.SystemLogLevel, minLevelStr string) bool {
	levels := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
		"fatal": 4,
	}

	minLevel, ok := levels[strings.ToLower(minLevelStr)]
	if !ok {
		minLevel = 1 // Default to info
	}

	// Map repository level to int
	currentLevel := 1 // Default info
	switch level {
	case repository.LevelDebug:
		currentLevel = 0
	case repository.LevelInfo:
		currentLevel = 1
	case repository.LevelWarn:
		currentLevel = 2
	case repository.LevelError:
		currentLevel = 3
	case repository.LevelFatal:
		currentLevel = 4
	}

	return currentLevel >= minLevel
}

// Start begins collecting logs from all configured containers
func (c *DockerLogCollector) Start(ctx context.Context) {
	log.Println("[DockerLogCollector] Starting docker log collection...")

	for _, container := range c.containers {
		c.wg.Add(1)
		go c.collectContainerLogs(ctx, container)
	}
}

// Stop signals all collectors to stop
func (c *DockerLogCollector) Stop() {
	log.Println("[DockerLogCollector] Stopping docker log collection...")
	close(c.stopCh)
	c.wg.Wait()
	log.Println("[DockerLogCollector] Stopped")
}

func (c *DockerLogCollector) collectContainerLogs(ctx context.Context, container ContainerConfig) {
	defer c.wg.Done()

	log.Printf("[DockerLogCollector] Starting log collection for %s", container.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
			c.tailContainerLogs(ctx, container)
			// If the tail command exits, wait a bit before retrying
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-time.After(5 * time.Second):
				log.Printf("[DockerLogCollector] Reconnecting to %s logs...", container.Name)
			}
		}
	}
}

func (c *DockerLogCollector) tailContainerLogs(ctx context.Context, container ContainerConfig) {
	// Use docker logs with --follow and --since to stream new logs
	cmd := exec.CommandContext(ctx, "docker", "logs", "--follow", "--since", "1s", container.Name)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[DockerLogCollector] Failed to get stdout pipe for %s: %v", container.Name, err)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("[DockerLogCollector] Failed to get stderr pipe for %s: %v", container.Name, err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[DockerLogCollector] Failed to start docker logs for %s: %v", container.Name, err)
		return
	}

	// Process stdout and stderr concurrently
	done := make(chan struct{})
	go func() {
		// Check if stdout is excluded for this container
		excludeStdout := false
		c.mu.RLock()
		for _, name := range c.config.StdoutExcluded {
			if name == container.Name {
				excludeStdout = true
				break
			}
		}
		c.mu.RUnlock()

		if !excludeStdout {
			c.processLogStream(ctx, container, stdout, false)
		} else {
			// consume stdout to prevent blocking, but discard
			io.Copy(io.Discard, stdout)
		}
		done <- struct{}{}
	}()
	go func() {
		c.processLogStream(ctx, container, stderr, true)
		done <- struct{}{}
	}()

	// Wait for both streams to close
	<-done
	<-done

	cmd.Wait()
}

func (c *DockerLogCollector) processLogStream(ctx context.Context, container ContainerConfig, reader io.Reader, isStderr bool) {
	scanner := bufio.NewScanner(reader)
	// Increase buffer size for long log lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	batch := make([]repository.SystemLog, 0, 10)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.flushBatch(ctx, batch)
			return
		case <-c.stopCh:
			c.flushBatch(ctx, batch)
			return
		case <-ticker.C:
			if len(batch) > 0 {
				c.flushBatch(ctx, batch)
				batch = batch[:0]
			}
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					log.Printf("[DockerLogCollector] Scanner error for %s: %v", container.Name, err)
				}
				c.flushBatch(ctx, batch)
				return
			}

			line := scanner.Text()
			if line == "" {
				continue
			}

			// Skip internal collector logs to avoid recursion
			// Also filter PostgreSQL DETAIL logs and INSERT INTO system_logs to prevent infinite feedback loops
			if strings.Contains(line, "[DockerLogCollector]") ||
				strings.Contains(line, "[StatsCollector]") ||
				strings.Contains(line, "[PartitionScheduler]") ||
				strings.Contains(line, "INSERT INTO system_logs") ||
				strings.Contains(line, "DETAIL:  Parameters:") {
				continue
			}

			logEntry := c.parseLogLine(container, line, isStderr)
			if logEntry != nil {
				batch = append(batch, *logEntry)

				if len(batch) >= 10 {
					c.flushBatch(ctx, batch)
					batch = batch[:0]
				}
			}
		}
	}
}

func (c *DockerLogCollector) parseLogLine(container ContainerConfig, line string, isStderr bool) *repository.SystemLog {
	level := repository.LevelInfo
	source := container.Source
	component := ""

	// Parse details if JSON (Echo logger format)
	var details json.RawMessage
	var logData map[string]interface{}

	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		if err := json.Unmarshal([]byte(line), &logData); err == nil {
			details = json.RawMessage(line)

			// Check if this is an Echo HTTP request log
			if uri, ok := logData["uri"].(string); ok {
				// Filter health check requests to separate source
				if uri == "/health" || uri == "/nginx_status" ||
					strings.HasPrefix(uri, "/.well-known/") {
					source = repository.SourceHealthCheck
					level = repository.LevelDebug // Health checks are debug level
				} else {
					// Normal HTTP request - use status to determine level
					if status, ok := logData["status"].(float64); ok {
						if status >= 500 {
							level = repository.LevelError
						} else if status >= 400 {
							level = repository.LevelWarn
						} else {
							level = repository.LevelInfo
						}
					}
				}
			}
		}
	}

	// For nginx logs, parse the custom log format
	if container.Source == repository.SourceDockerNginx && details == nil {
		if parsed := c.parseNginxLogLine(line); parsed != nil {
			details, _ = json.Marshal(parsed)

			// Check if health check
			if uri, ok := parsed["uri"].(string); ok {
				if uri == "/health" || uri == "/nginx_status" ||
					strings.HasPrefix(uri, "/.well-known/") {
					source = repository.SourceHealthCheck
					level = repository.LevelDebug
				} else {
					// Set level based on status
					if status, ok := parsed["status"].(int); ok {
						if status >= 500 {
							level = repository.LevelError
						} else if status >= 400 {
							level = repository.LevelWarn
						} else {
							level = repository.LevelInfo
						}
					}
				}
			}
		}
	}

	// For other non-JSON logs, detect level from content
	if details == nil {
		lineLower := strings.ToLower(line)
		
		// Postgres format: "... [PID] LEVEL:  message"
		// Nginx error format: "... [level] ..."
		
		if strings.Contains(line, "ERROR:") || strings.Contains(line, "[error]") || strings.HasPrefix(lineLower, "error") {
			level = repository.LevelError
		} else if strings.Contains(line, "WARN:") || strings.Contains(line, "WARNING:") || strings.Contains(line, "[warn]") || strings.HasPrefix(lineLower, "warn") {
			level = repository.LevelWarn
		} else if strings.Contains(line, "FATAL:") || strings.Contains(line, "PANIC:") || strings.Contains(line, "[fatal]") || strings.Contains(line, "[panic]") {
			level = repository.LevelFatal
		} else if strings.Contains(line, "DEBUG:") || strings.Contains(line, "[debug]") {
			level = repository.LevelDebug
		} else {
			// Default to Info
			level = repository.LevelInfo
			
			// Only upgrade to Error/Warn based on keywords if we are fairly sure (avoiding false positives)
			// e.g. "Go panic" or similar unformatted critical application errors
			if strings.HasPrefix(lineLower, "panic:") || strings.HasPrefix(lineLower, "fatal error:") {
				level = repository.LevelFatal
			}
		}

		// Filter nginx health check logs
		if strings.Contains(line, "/health") || strings.Contains(line, "/nginx_status") {
			source = repository.SourceHealthCheck
			level = repository.LevelDebug
		}
	}

	// Extract component if available (e.g., "[ComponentName]")
	if idx := strings.Index(line, "["); idx >= 0 {
		if endIdx := strings.Index(line[idx:], "]"); endIdx > 0 {
			component = line[idx+1 : idx+endIdx]
		}
	}

	// Check configuration before returning
	if !c.shouldLog(container.Name, level, line) {
		return nil
	}

	return &repository.SystemLog{
		Source:        source,
		Level:         level,
		Message:       line,
		Details:       details,
		ContainerName: container.Name,
		Component:     component,
	}
}

// parseNginxLogLine parses nginx custom log format:
// '$remote_addr - $remote_user [$time_local] "$host" "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" rt=$request_time ...'
func (c *DockerLogCollector) parseNginxLogLine(line string) map[string]interface{} {
	// Pattern: IP - user [time] "host" "METHOD URI PROTO" status bytes "referer" "ua" "xff" rt=X.XXX ...
	pattern := regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" "(\S+) (\S+) ([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" rt=(\S+)`)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) < 13 {
		return nil
	}

	status, _ := strconv.Atoi(matches[8])
	bodyBytes, _ := strconv.ParseInt(matches[9], 10, 64)

	// Parse and validate request_time (Issue #29 fix)
	var requestTime float64
	rawRequestTime := matches[13]
	if rawRequestTime != "" && rawRequestTime != "-" {
		if parsed, err := strconv.ParseFloat(rawRequestTime, 64); err == nil {
			requestTime = validateRequestTime(parsed, rawRequestTime)
		}
	}

	return map[string]interface{}{
		"remote_addr":      matches[1],
		"remote_user":      matches[2],
		"time_local":       matches[3],
		"host":             matches[4],
		"method":           matches[5],
		"uri":              matches[6],
		"protocol":         matches[7],
		"status":           status,
		"body_bytes_sent":  bodyBytes,
		"http_referer":     matches[10],
		"http_user_agent":  matches[11],
		"http_xff":         matches[12],
		"request_time":     requestTime,
	}
}

func (c *DockerLogCollector) flushBatch(ctx context.Context, batch []repository.SystemLog) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := c.systemLogRepo.CreateBatch(ctx, batch); err != nil {
		log.Printf("[DockerLogCollector] Failed to save batch: %v", err)
	}
}

// LogHealthCheck logs a health check request to system logs
func (c *DockerLogCollector) LogHealthCheck(ctx context.Context, clientIP, path string, statusCode int, responseTime float64) error {
	details, _ := json.Marshal(map[string]interface{}{
		"client_ip":     clientIP,
		"path":          path,
		"status_code":   statusCode,
		"response_time": responseTime,
	})

	log := &repository.SystemLog{
		Source:    repository.SourceHealthCheck,
		Level:     repository.LevelInfo,
		Message:   "Health check request: " + path,
		Details:   details,
		Component: "HealthCheck",
	}

	return c.systemLogRepo.Create(ctx, log)
}

// LogInternalEvent logs an internal application event
func LogInternalEvent(ctx context.Context, repo *repository.SystemLogRepository, level repository.SystemLogLevel, component, message string, details map[string]interface{}) error {
	var detailsJSON json.RawMessage
	if details != nil {
		detailsJSON, _ = json.Marshal(details)
	}

	log := &repository.SystemLog{
		Source:    repository.SourceInternal,
		Level:     level,
		Message:   message,
		Details:   detailsJSON,
		Component: component,
	}

	return repo.Create(ctx, log)
}
