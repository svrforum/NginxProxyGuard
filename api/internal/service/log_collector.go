package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

const (
	// MaxRequestTime is the maximum valid request time in seconds (24 hours)
	// Values exceeding this are likely erroneous and will be replaced with 0
	MaxRequestTime = 86400.0
)

// validateRequestTime validates a parsed request_time value
// Returns the validated value (or 0 if invalid) and logs warnings for invalid values
func validateRequestTime(value float64, rawValue string) float64 {
	// Check for NaN
	if math.IsNaN(value) {
		log.Printf("[LogCollector] Warning: invalid request_time: NaN (raw: %s)", rawValue)
		return 0
	}

	// Check for Infinity
	if math.IsInf(value, 0) {
		log.Printf("[LogCollector] Warning: invalid request_time: Inf (raw: %s)", rawValue)
		return 0
	}

	// Check for negative values
	if value < 0 {
		log.Printf("[LogCollector] Warning: invalid request_time: negative value %.6f (raw: %s)", value, rawValue)
		return 0
	}

	// Check for unreasonably large values (> 24 hours)
	if value > MaxRequestTime {
		log.Printf("[LogCollector] Warning: invalid request_time: exceeds max %.2f > %.2f (raw: %s)", value, MaxRequestTime, rawValue)
		return 0
	}

	return value
}

// BotMatcher helps detect bot filter blocks from access logs
type BotMatcher struct {
	badBotPatterns         []string
	aiBotPatterns          []string
	suspiciousPatterns     []string
	searchEnginePatterns   []string
	mu                     sync.RWMutex
}

func NewBotMatcher() *BotMatcher {
	return &BotMatcher{
		badBotPatterns:       model.KnownBadBots,
		aiBotPatterns:        model.AIBots,
		suspiciousPatterns:   model.SuspiciousClients,
		searchEnginePatterns: model.SearchEngineBots,
	}
}

// MatchBot checks if a user agent matches any bot category
// Returns (category, matched) where category is "bad_bot", "ai_bot", "suspicious", "search_engine", or ""
func (m *BotMatcher) MatchBot(userAgent string) (string, bool) {
	if userAgent == "" {
		return "", false
	}

	ua := strings.ToLower(userAgent)

	// Check bad bots first
	for _, pattern := range m.badBotPatterns {
		if strings.Contains(ua, strings.ToLower(pattern)) {
			return "bad_bot", true
		}
	}

	// Check AI bots
	for _, pattern := range m.aiBotPatterns {
		if strings.Contains(ua, strings.ToLower(pattern)) {
			return "ai_bot", true
		}
	}

	// Check suspicious clients
	for _, pattern := range m.suspiciousPatterns {
		if strings.Contains(ua, strings.ToLower(pattern)) {
			return "suspicious", true
		}
	}

	// Check search engines (usually allowed, but log for reference)
	for _, pattern := range m.searchEnginePatterns {
		if strings.Contains(ua, strings.ToLower(pattern)) {
			return "search_engine", true
		}
	}

	return "", false
}

type LogCollector struct {
	logRepo        *repository.LogRepository
	proxyHostRepo  *repository.ProxyHostRepository
	geoIP          *GeoIPService
	wafAutoBan     *WAFAutoBanService
	fail2ban       *Fail2banService
	botMatcher     *BotMatcher
	redisCache     *cache.RedisClient
	nginxContainer string
	batchSize      int
	flushInterval  time.Duration
	buffer         []model.CreateLogRequest
	bufferMu       sync.Mutex
	stopCh         chan struct{}
	lastAccessPos  int64 // Track position in access log
	lastErrorPos   int64 // Track position in error log
	useRedisBuffer bool  // Whether to use Redis for log buffering

	// Domain to host ID cache for Fail2ban
	domainCacheMu    sync.RWMutex
	domainCache      map[string]string // domain -> hostID
	domainCacheTime  time.Time
}

func NewLogCollector(logRepo *repository.LogRepository, nginxContainer string, geoIP *GeoIPService, redisCache *cache.RedisClient) *LogCollector {
	// Use Redis buffer if available and ready
	useRedis := redisCache != nil && redisCache.IsReady()

	return &LogCollector{
		logRepo:        logRepo,
		geoIP:          geoIP,
		botMatcher:     NewBotMatcher(),
		redisCache:     redisCache,
		nginxContainer: nginxContainer,
		batchSize:      500,
		flushInterval:  1 * time.Second,
		buffer:         make([]model.CreateLogRequest, 0, 500),
		stopCh:         make(chan struct{}),
		domainCache:    make(map[string]string),
		useRedisBuffer: useRedis,
	}
}

// SetProxyHostRepo sets the proxy host repository for domain lookups
func (c *LogCollector) SetProxyHostRepo(repo *repository.ProxyHostRepository) {
	c.proxyHostRepo = repo
}

// SetWAFAutoBanService sets the WAF auto-ban service for processing WAF events
func (c *LogCollector) SetWAFAutoBanService(svc *WAFAutoBanService) {
	c.wafAutoBan = svc
}

// SetFail2banService sets the Fail2ban service for processing failed requests
func (c *LogCollector) SetFail2banService(svc *Fail2banService) {
	c.fail2ban = svc
}

// getHostIDByDomain returns the host ID for a given domain (with caching)
func (c *LogCollector) getHostIDByDomain(ctx context.Context, domain string) string {
	if domain == "" || c.proxyHostRepo == nil {
		return ""
	}

	// Check cache first
	c.domainCacheMu.RLock()
	if hostID, ok := c.domainCache[domain]; ok {
		c.domainCacheMu.RUnlock()
		return hostID
	}
	c.domainCacheMu.RUnlock()

	// Refresh cache if stale (every 60 seconds)
	c.domainCacheMu.Lock()
	defer c.domainCacheMu.Unlock()

	if time.Since(c.domainCacheTime) > 60*time.Second {
		// Refresh entire cache
		hosts, _, err := c.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
		if err == nil {
			c.domainCache = make(map[string]string)
			for _, host := range hosts {
				for _, d := range host.DomainNames {
					c.domainCache[d] = host.ID
				}
			}
			c.domainCacheTime = time.Now()
		}
	}

	return c.domainCache[domain]
}

func (c *LogCollector) Start(ctx context.Context) {
	log.Println("Starting log collector...")

	// Check Redis buffer status
	if c.useRedisBuffer {
		log.Println("[LogCollector] Redis buffer enabled for high-throughput log buffering")
	} else {
		log.Println("[LogCollector] Using in-memory buffer (Redis not available)")
	}

	// Start periodic flush
	go c.flushLoop(ctx)

	// Start log streaming
	go c.streamAccessLogs(ctx)
	go c.streamErrorLogs(ctx)
	go c.streamModSecLogs(ctx)

	log.Println("Log collector started")
}

func (c *LogCollector) Stop() {
	close(c.stopCh)
	c.flush(context.Background()) // Final flush
	log.Println("Log collector stopped")
}

func (c *LogCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.flush(ctx)
		}
	}
}

func (c *LogCollector) flush(ctx context.Context) {
	var logs []model.CreateLogRequest

	// Check Redis buffer first
	if c.useRedisBuffer && c.redisCache != nil && c.redisCache.IsReady() {
		redisLogs, err := c.flushRedisBuffer(ctx)
		if err != nil {
			log.Printf("[LogCollector] Failed to flush Redis buffer: %v", err)
		} else if len(redisLogs) > 0 {
			logs = append(logs, redisLogs...)
		}
	}

	// Also flush memory buffer
	c.bufferMu.Lock()
	if len(c.buffer) > 0 {
		logs = append(logs, c.buffer...)
		c.buffer = make([]model.CreateLogRequest, 0, c.batchSize)
	}
	c.bufferMu.Unlock()

	if len(logs) == 0 {
		return
	}

	// Retry logic with exponential backoff
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := c.logRepo.CreateBatch(ctx, logs); err != nil {
			log.Printf("[LogCollector] Failed to batch insert logs (attempt %d/%d): %v", attempt+1, maxRetries, err)
			if attempt < maxRetries-1 {
				// Exponential backoff: 100ms, 200ms, 400ms
				backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
				time.Sleep(backoff)
				continue
			}
			// Final failure - put logs back to buffer to avoid data loss
			c.bufferMu.Lock()
			// Prepend failed logs to buffer (oldest first)
			c.buffer = append(logs, c.buffer...)
			// Cap buffer size to prevent memory exhaustion (keep newest)
			maxBufferSize := c.batchSize * 10
			if len(c.buffer) > maxBufferSize {
				droppedCount := len(c.buffer) - maxBufferSize
				c.buffer = c.buffer[droppedCount:]
				log.Printf("[LogCollector] WARNING: Buffer overflow, dropped %d oldest logs", droppedCount)
			}
			c.bufferMu.Unlock()
		} else {
			if len(logs) > 0 {
				log.Printf("[LogCollector] Flushed %d logs to database", len(logs))
			}
			break
		}
	}
}

// flushRedisBuffer reads logs from Redis buffer and converts them to CreateLogRequest
func (c *LogCollector) flushRedisBuffer(ctx context.Context) ([]model.CreateLogRequest, error) {
	entries, err := c.redisCache.ReadLogEntries(ctx, int64(c.batchSize))
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, nil
	}

	logs := make([]model.CreateLogRequest, 0, len(entries))
	for _, entry := range entries {
		logReq := model.CreateLogRequest{
			LogType:         model.LogType(entry.LogType),
			Timestamp:       entry.Timestamp,
			Host:            entry.Host,
			ClientIP:        entry.ClientIP,
			RequestMethod:   entry.Method,
			RequestURI:      entry.URI,
			RequestProtocol: entry.Protocol,
			StatusCode:      entry.StatusCode,
			BodyBytesSent:   entry.BodyBytes,
			HTTPUserAgent:   entry.UserAgent,
			HTTPReferer:     entry.Referer,
			BlockReason:     model.ParseBlockReason(entry.BlockReason),
			BotCategory:     entry.BotCategory,
			ExploitRule:     entry.ExploitRule,
			GeoCountry:      entry.GeoCountry,
			GeoCountryCode:  entry.GeoCountryCode,
			GeoCity:         entry.GeoCity,
			GeoASN:          entry.GeoASN,
			GeoOrg:          entry.GeoOrg,
			RequestTime:     entry.RequestTime,
			RawLog:          entry.RawLog,
		}

		// Parse extra fields for WAF logs
		if entry.Extra != nil {
			if ruleID, ok := entry.Extra["rule_id"]; ok {
				logReq.RuleID, _ = strconv.ParseInt(ruleID, 10, 64)
			}
			logReq.RuleMessage = entry.Extra["rule_message"]
			logReq.RuleSeverity = entry.Extra["rule_severity"]
			logReq.AttackType = entry.Extra["attack_type"]
			logReq.ActionTaken = entry.Extra["action_taken"]
		}

		logs = append(logs, logReq)
	}

	return logs, nil
}

// sanitizeString removes null bytes (0x00) from strings to prevent PostgreSQL UTF8 encoding errors
func sanitizeString(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// truncateString truncates a string to the specified max length to prevent DB overflow
// Also removes null bytes to prevent PostgreSQL UTF8 encoding errors
func truncateString(s string, maxLen int) string {
	// Remove null bytes first
	s = sanitizeString(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func (c *LogCollector) addLog(logReq model.CreateLogRequest) {
	// Enrich with GeoIP data if available
	if c.geoIP != nil && logReq.ClientIP != "" {
		if info := c.geoIP.Lookup(logReq.ClientIP); info != nil {
			logReq.GeoCountry = truncateString(info.Country, 500)
			logReq.GeoCountryCode = info.CountryCode // max 2 chars
			logReq.GeoCity = truncateString(info.City, 500)
			logReq.GeoASN = truncateString(info.ASN, 500)
			logReq.GeoOrg = truncateString(info.Org, 1000)
		}
	}

	// Sanitize and truncate string fields to prevent PostgreSQL UTF8 encoding errors (null bytes)
	// and prevent overflow for long fields
	logReq.Host = truncateString(logReq.Host, 500)
	logReq.ClientIP = sanitizeString(logReq.ClientIP)
	logReq.RequestMethod = truncateString(logReq.RequestMethod, 50)
	logReq.RequestURI = sanitizeString(logReq.RequestURI)
	logReq.RequestProtocol = truncateString(logReq.RequestProtocol, 50)
	logReq.HTTPReferer = sanitizeString(logReq.HTTPReferer)
	logReq.HTTPUserAgent = sanitizeString(logReq.HTTPUserAgent)
	logReq.HTTPXForwardedFor = sanitizeString(logReq.HTTPXForwardedFor)
	logReq.RuleSeverity = truncateString(logReq.RuleSeverity, 100)
	logReq.RuleMessage = sanitizeString(logReq.RuleMessage)
	logReq.RuleData = sanitizeString(logReq.RuleData)
	logReq.AttackType = truncateString(logReq.AttackType, 500)
	logReq.ActionTaken = truncateString(logReq.ActionTaken, 100)
	logReq.BotCategory = truncateString(logReq.BotCategory, 100)
	logReq.ExploitRule = sanitizeString(logReq.ExploitRule)
	logReq.ErrorMessage = sanitizeString(logReq.ErrorMessage)
	logReq.RawLog = sanitizeString(logReq.RawLog)

	// Try Redis buffer first (if available)
	if c.useRedisBuffer && c.redisCache != nil && c.redisCache.IsReady() {
		entry := &cache.LogEntry{
			LogType:        string(logReq.LogType),
			Timestamp:      logReq.Timestamp,
			Host:           logReq.Host,
			ClientIP:       logReq.ClientIP,
			Method:         logReq.RequestMethod,
			URI:            logReq.RequestURI,
			Protocol:       logReq.RequestProtocol,
			StatusCode:     logReq.StatusCode,
			BodyBytes:      logReq.BodyBytesSent,
			UserAgent:      logReq.HTTPUserAgent,
			Referer:        logReq.HTTPReferer,
			BlockReason:    string(logReq.BlockReason),
			BotCategory:    logReq.BotCategory,
			ExploitRule:    logReq.ExploitRule,
			GeoCountry:     logReq.GeoCountry,
			GeoCountryCode: logReq.GeoCountryCode,
			GeoCity:        logReq.GeoCity,
			GeoASN:         logReq.GeoASN,
			GeoOrg:         logReq.GeoOrg,
			RequestTime:    logReq.RequestTime,
			RawLog:         logReq.RawLog,
		}

		// Add extra fields for WAF logs
		if logReq.LogType == model.LogTypeModSec {
			entry.Extra = map[string]string{
				"rule_id":       fmt.Sprintf("%d", logReq.RuleID),
				"rule_message":  logReq.RuleMessage,
				"rule_severity": logReq.RuleSeverity,
				"attack_type":   logReq.AttackType,
				"action_taken":  logReq.ActionTaken,
			}
		}

		if err := c.redisCache.AddLogEntry(context.Background(), entry); err != nil {
			// Fallback to memory buffer on Redis error
			log.Printf("[LogCollector] Redis buffer failed, falling back to memory: %v", err)
			c.addLogToMemoryBuffer(logReq)
		}
		return
	}

	// Fallback to memory buffer
	c.addLogToMemoryBuffer(logReq)
}

func (c *LogCollector) addLogToMemoryBuffer(logReq model.CreateLogRequest) {
	c.bufferMu.Lock()
	c.buffer = append(c.buffer, logReq)
	shouldFlush := len(c.buffer) >= c.batchSize
	c.bufferMu.Unlock()

	if shouldFlush {
		go c.flush(context.Background())
	}
}

// Access log format (with host and timing):
// 172.19.0.1 - - [02/Dec/2025:00:47:05 +0000] "app.local" "GET / HTTP/2.0" 200 595 "-" "Mozilla/5.0..." "-" rt=0.001 ... block="bot_filter" bot="ai_bot"
var accessLogRegex = regexp.MustCompile(
	`^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"`,
)

// Regex patterns for parsing additional log fields
var (
	blockReasonRegex = regexp.MustCompile(`block="([^"]*)"`)
	botCategoryRegex = regexp.MustCompile(`bot="([^"]*)"`)
	exploitRuleRegex = regexp.MustCompile(`exploit_rule="([^"]*)"`)
	requestTimeRegex = regexp.MustCompile(`rt=([0-9.]+)`)
	geoCountryRegex  = regexp.MustCompile(`geo="([^"]*)"`)
)

// Old access log format (without host) - fallback
var accessLogRegexOld = regexp.MustCompile(
	`^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"`,
)

func (c *LogCollector) parseAccessLog(line string) (*model.CreateLogRequest, error) {
	// Try new format with host first
	matches := accessLogRegex.FindStringSubmatch(line)
	if matches != nil && len(matches) >= 13 {
		// New format: client - user [time] "host" "method uri protocol" status bytes "referer" "ua" "xff"
		timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[3])
		if err != nil {
			timestamp = time.Now()
		}

		statusCode, _ := strconv.Atoi(matches[8])
		bodyBytes, _ := strconv.ParseInt(matches[9], 10, 64)

		host := matches[4]
		referer := matches[10]
		if referer == "-" {
			referer = ""
		}

		xForwardedFor := matches[12]
		if xForwardedFor == "-" {
			xForwardedFor = ""
		}

		// Extract block_reason, bot_category, and exploit_rule from log line (set by nginx)
		var blockReason model.BlockReason
		var botCategory string
		var exploitRule string

		if brMatches := blockReasonRegex.FindStringSubmatch(line); brMatches != nil {
			blockReason = model.ParseBlockReason(brMatches[1])
		}
		if bcMatches := botCategoryRegex.FindStringSubmatch(line); bcMatches != nil && bcMatches[1] != "-" {
			botCategory = bcMatches[1]
		}
		if erMatches := exploitRuleRegex.FindStringSubmatch(line); erMatches != nil && erMatches[1] != "-" {
			exploitRule = erMatches[1]
		}

		// Extract geo country code from log line
		var geoCountryCode string
		if geoMatches := geoCountryRegex.FindStringSubmatch(line); geoMatches != nil && geoMatches[1] != "-" && geoMatches[1] != "" {
			geoCountryCode = geoMatches[1]
		}

		// Extract request_time from log line (rt=0.001)
		var requestTime float64
		if rtMatches := requestTimeRegex.FindStringSubmatch(line); rtMatches != nil {
			rawValue := rtMatches[1]
			if parsed, err := strconv.ParseFloat(rawValue, 64); err == nil {
				requestTime = validateRequestTime(parsed, rawValue)
			}
		}

		return &model.CreateLogRequest{
			LogType:           model.LogTypeAccess,
			Timestamp:         timestamp,
			Host:              host,
			ClientIP:          matches[1],
			RequestMethod:     matches[5],
			RequestURI:        matches[6],
			RequestProtocol:   matches[7],
			StatusCode:        statusCode,
			BodyBytesSent:     bodyBytes,
			HTTPReferer:       referer,
			HTTPUserAgent:     matches[11],
			HTTPXForwardedFor: xForwardedFor,
			BlockReason:       blockReason,
			BotCategory:       botCategory,
			ExploitRule:       exploitRule,
			GeoCountryCode:    geoCountryCode,
			RequestTime:       requestTime,
			RawLog:            line,
		}, nil
	}

	// Fallback to old format without host
	matches = accessLogRegexOld.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse access log: %s", line)
	}

	// Old format: client - user [time] "method uri protocol" status bytes "referer" "ua" "xff"
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[3])
	if err != nil {
		timestamp = time.Now()
	}

	statusCode, _ := strconv.Atoi(matches[7])
	bodyBytes, _ := strconv.ParseInt(matches[8], 10, 64)

	referer := matches[9]
	if referer == "-" {
		referer = ""
	}

	xForwardedFor := matches[11]
	if xForwardedFor == "-" {
		xForwardedFor = ""
	}

	return &model.CreateLogRequest{
		LogType:           model.LogTypeAccess,
		Timestamp:         timestamp,
		Host:              "",
		ClientIP:          matches[1],
		RequestMethod:     matches[4],
		RequestURI:        matches[5],
		RequestProtocol:   matches[6],
		StatusCode:        statusCode,
		BodyBytesSent:     bodyBytes,
		HTTPReferer:       referer,
		HTTPUserAgent:     matches[10],
		HTTPXForwardedFor: xForwardedFor,
		RawLog:            line,
	}, nil
}

// Error log format:
// 2025/12/01 14:37:15 [error] 1#1: *123 error message, client: 1.2.3.4, ...
var errorLogRegex = regexp.MustCompile(
	`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\d+#\d+:\s+(.+)`,
)

func (c *LogCollector) parseErrorLog(line string) (*model.CreateLogRequest, error) {
	matches := errorLogRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse error log: %s", line)
	}

	// Parse timestamp (nginx error log doesn't include timezone, use local)
	timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", matches[1], time.Local)
	if err != nil {
		timestamp = time.Now()
	}

	severity := model.LogSeverity(matches[2])

	// Try to extract client IP from message
	clientIP := ""
	clientIPRegex := regexp.MustCompile(`client:\s+(\d+\.\d+\.\d+\.\d+)`)
	if ipMatches := clientIPRegex.FindStringSubmatch(matches[3]); ipMatches != nil {
		clientIP = ipMatches[1]
	}

	return &model.CreateLogRequest{
		LogType:      model.LogTypeError,
		Timestamp:    timestamp,
		ClientIP:     clientIP,
		Severity:     severity,
		ErrorMessage: matches[3],
		RawLog:       line,
	}, nil
}

// ModSecurity audit log in JSON format
type ModSecAuditLog struct {
	Transaction struct {
		TimeStamp     string  `json:"time_stamp"`
		ClientIP      string  `json:"client_ip"`
		ClientPort    int     `json:"client_port"`
		HostIP        string  `json:"host_ip"`
		HostPort      int     `json:"host_port"`
		UniqueID      string  `json:"unique_id"`
		Request       struct {
			Method      string            `json:"method"`
			URI         string            `json:"uri"`
			HTTPVersion float64           `json:"http_version"`
			Headers     map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int               `json:"http_code"`
			Headers  map[string]string `json:"headers"`
		} `json:"response"`
		Producer struct {
			ModSecurity string   `json:"modsecurity"`
			Connector   string   `json:"connector"`
			SeqRules    string   `json:"secrules_engine"`
		} `json:"producer"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				Match      string   `json:"match"`
				Reference  string   `json:"reference"`
				RuleID     string   `json:"ruleId"`
				File       string   `json:"file"`
				LineNumber string   `json:"lineNumber"`
				Data       string   `json:"data"`
				Severity   string   `json:"severity"`
				Ver        string   `json:"ver"`
				Rev        string   `json:"rev"`
				Tags       []string `json:"tags"`
				Maturity   string   `json:"maturity"`
				Accuracy   string   `json:"accuracy"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

func (c *LogCollector) parseModSecLog(line string) (*model.CreateLogRequest, error) {
	var auditLog ModSecAuditLog
	if err := json.Unmarshal([]byte(line), &auditLog); err != nil {
		return nil, fmt.Errorf("failed to parse modsec log: %w", err)
	}

	tx := auditLog.Transaction

	// Parse timestamp (format: "Tue Dec  2 00:42:29 2025")
	// ModSecurity timestamp doesn't include timezone, so use local timezone
	timestamp, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", tx.TimeStamp, time.Local)
	if err != nil {
		// Try alternate format with double space for single digit day
		timestamp, err = time.ParseInLocation("Mon Jan  2 15:04:05 2006", tx.TimeStamp, time.Local)
		if err != nil {
			timestamp = time.Now()
		}
	}

	// Get first meaningful rule info (skip the final anomaly evaluation rule)
	var ruleID int64
	var ruleMessage, ruleSeverity, ruleData, attackType string
	for _, msg := range tx.Messages {
		// Skip the anomaly evaluation message, we want the actual attack rule
		if strings.Contains(msg.Message, "Anomaly Score Exceeded") {
			continue
		}
		ruleMessage = msg.Message
		ruleSeverity = msg.Details.Severity
		ruleData = msg.Details.Data
		if id, err := strconv.ParseInt(msg.Details.RuleID, 10, 64); err == nil {
			ruleID = id
		}
		// Extract attack type from tags
		for _, tag := range msg.Details.Tags {
			if strings.HasPrefix(tag, "attack-") {
				attackType = strings.TrimPrefix(tag, "attack-")
				break
			}
		}
		if attackType == "" && len(msg.Details.Tags) > 0 {
			attackType = msg.Details.Tags[0]
		}
		break // Use first meaningful message
	}

	// If we only have anomaly message, use it
	if ruleID == 0 && len(tx.Messages) > 0 {
		msg := tx.Messages[0]
		ruleMessage = msg.Message
		if id, err := strconv.ParseInt(msg.Details.RuleID, 10, 64); err == nil {
			ruleID = id
		}
	}

	// Skip logging if no WAF rules were triggered (messages is empty)
	// This prevents logging bot filter blocks, rate limits, etc. as WAF events
	if len(tx.Messages) == 0 {
		return nil, fmt.Errorf("no WAF rules triggered, skipping (likely bot filter or other block)")
	}

	// Determine action taken based on SecRuleEngine mode and response code
	// In DetectionOnly mode, WAF never blocks - any error codes are from other sources (rate limit, etc.)
	actionTaken := "logged"
	isDetectionOnly := strings.EqualFold(tx.Producer.SeqRules, "DetectionOnly")
	if !isDetectionOnly && tx.Response.HTTPCode == 403 {
		// Only mark as blocked if:
		// 1. WAF is in blocking mode (SecRuleEngine On)
		// 2. Response is 403 (WAF's default blocking response)
		// Note: Other error codes (404, 405, 429, 500) are from upstream or other nginx modules, not WAF
		actionTaken = "blocked"
	}
	// Check if this is an excluded rule (pass action)
	if strings.Contains(ruleMessage, "[EXCLUDED]") {
		actionTaken = "excluded"
		// Clean up the message by removing [EXCLUDED] prefix
		ruleMessage = strings.TrimSpace(strings.Replace(ruleMessage, "[EXCLUDED]", "", 1))
	}

	// Get host from request headers (case-insensitive lookup)
	// HTTP/1.1 and HTTP/2 use "Host" header, HTTP/3 uses ":authority" pseudo-header
	var host string
	for k, v := range tx.Request.Headers {
		lowerKey := strings.ToLower(k)
		if lowerKey == "host" || k == ":authority" {
			host = v
			break
		}
	}

	// Fallback 1: extract host from response "Link" header (WordPress/API response headers)
	// This is more reliable than Referer since it's from the actual server response
	if host == "" {
		for k, v := range tx.Response.Headers {
			if strings.ToLower(k) == "link" && v != "" {
				// Link header format: <https://example.com/wp-json/>; rel="..."
				if strings.Contains(v, "://") {
					start := strings.Index(v, "://") + 3
					end := strings.Index(v[start:], "/")
					if end > 0 {
						host = v[start : start+end]
						break
					}
				}
			}
		}
	}

	// Fallback 2: extract host from response "X-Pingback" or other headers with full URL
	if host == "" {
		for k, v := range tx.Response.Headers {
			lowerKey := strings.ToLower(k)
			if (lowerKey == "x-pingback" || lowerKey == "location") && strings.Contains(v, "://") {
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					host = u.Host
					break
				}
			}
		}
	}

	// Fallback 3: extract host from referer header (NOT recommended - can be incorrect)
	// Only use this as last resort since referer domain often differs from request host
	if host == "" {
		for k, v := range tx.Request.Headers {
			if strings.ToLower(k) == "referer" && v != "" {
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					host = u.Host
				}
				break
			}
		}
	}

	// Determine block reason for WAF events
	var blockReason model.BlockReason
	if actionTaken == "blocked" {
		blockReason = model.BlockReasonWAF
	}

	return &model.CreateLogRequest{
		LogType:         model.LogTypeModSec,
		Timestamp:       timestamp,
		Host:            host,
		ClientIP:        tx.ClientIP,
		RequestMethod:   tx.Request.Method,
		RequestURI:      tx.Request.URI,
		RequestProtocol: fmt.Sprintf("HTTP/%.1f", tx.Request.HTTPVersion),
		StatusCode:      tx.Response.HTTPCode,
		RuleID:          ruleID,
		RuleMessage:     ruleMessage,
		RuleSeverity:    ruleSeverity,
		RuleData:        ruleData,
		AttackType:      attackType,
		ActionTaken:     actionTaken,
		BlockReason:     blockReason,
		RawLog:          line,
	}, nil
}

func (c *LogCollector) streamAccessLogs(ctx context.Context) {
	c.streamLogs(ctx, "access", func(line string) {
		// Check if this is a ModSecurity JSON log (starts with {"transaction")
		if strings.HasPrefix(strings.TrimSpace(line), "{\"transaction\"") {
			log.Printf("[DEBUG] Detected ModSec JSON log (len=%d)", len(line))
			if logReq, err := c.parseModSecLog(line); err == nil {
				log.Printf("[DEBUG] Successfully parsed ModSec log: rule=%d, type=%s", logReq.RuleID, logReq.AttackType)
				c.addLog(*logReq)

				// Notify WAF auto-ban service (only for blocked requests, not logged/detection mode)
				if c.wafAutoBan != nil && logReq.ClientIP != "" && logReq.ActionTaken == "blocked" {
					c.wafAutoBan.RecordWAFEvent(ctx, logReq.ClientIP, logReq.Host, logReq.RuleID, logReq.RuleMessage)
				}
			} else {
				// Skip non-WAF logs silently (e.g., bot filter blocks)
				if !strings.Contains(err.Error(), "no WAF rules triggered") {
					log.Printf("[ERROR] Failed to parse ModSec log: %v", err)
				}
			}
			return
		}
		// Regular access log
		if logReq, err := c.parseAccessLog(line); err == nil {
			// Block reason is now extracted from nginx log format directly in parseAccessLog()
			// Only use fallback pattern matching if nginx didn't provide block_reason
			if logReq.BlockReason == "" {
				// Fallback: Detect bot filter blocks using pattern matching (for older logs)
				if logReq.StatusCode == 403 && logReq.HTTPUserAgent != "" {
					if category, matched := c.botMatcher.MatchBot(logReq.HTTPUserAgent); matched {
						logReq.BlockReason = model.BlockReasonBotFilter
						logReq.BotCategory = category
					}
				}
				// Fallback: Detect rate limit blocks (429 status)
				if logReq.StatusCode == 429 {
					logReq.BlockReason = model.BlockReasonRateLimit
				}
			}

			// Notify Fail2ban service for error responses (4xx, 5xx)
			if c.fail2ban != nil && logReq.ClientIP != "" && logReq.StatusCode >= 400 {
				hostID := c.getHostIDByDomain(ctx, logReq.Host)
				if hostID != "" {
					c.fail2ban.RecordFailedRequest(ctx, hostID, logReq.ClientIP, logReq.StatusCode, logReq.RequestURI)
				}
			}

			c.addLog(*logReq)
		}
	})
}

func (c *LogCollector) streamErrorLogs(ctx context.Context) {
	c.streamLogs(ctx, "error", func(line string) {
		// Skip startup messages and notices
		if strings.Contains(line, "[notice]") || strings.Contains(line, "[warn]") {
			return
		}
		if logReq, err := c.parseErrorLog(line); err == nil {
			c.addLog(*logReq)
		}
	})
}

func (c *LogCollector) streamModSecLogs(ctx context.Context) {
	// ModSecurity audit logs are now collected from stdout via streamAccessLogs
	// This function is kept for potential future use with file-based audit logs
	// Currently, ModSec JSON logs are detected and parsed in streamAccessLogs
}

func (c *LogCollector) streamLogs(ctx context.Context, logType string, handler func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		// Use docker logs with --follow
		args := []string{"logs", "--follow", "--since", "1s"}
		if logType == "access" {
			args = append(args, "--tail", "0") // Start from now
		}
		args = append(args, c.nginxContainer)

		cmd := exec.CommandContext(ctx, "docker", args...)

		var stdout, stderr *bufio.Scanner
		if logType == "access" {
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				log.Printf("Failed to get stdout pipe for %s logs: %v", logType, err)
				time.Sleep(5 * time.Second)
				continue
			}
			stdout = bufio.NewScanner(pipe)
			// Increase buffer size to 1MB for large log lines (e.g., long URLs, headers)
			stdout.Buffer(make([]byte, 1024*1024), 1024*1024)
		} else {
			pipe, err := cmd.StderrPipe()
			if err != nil {
				log.Printf("Failed to get stderr pipe for %s logs: %v", logType, err)
				time.Sleep(5 * time.Second)
				continue
			}
			stderr = bufio.NewScanner(pipe)
			// Increase buffer size to 1MB for large log lines
			stderr.Buffer(make([]byte, 1024*1024), 1024*1024)
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Failed to start docker logs for %s: %v", logType, err)
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := stdout
		if stderr != nil {
			scanner = stderr
		}

		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				handler(line)
			}
		}

		// Check for scanner errors (e.g., buffer overflow)
		if err := scanner.Err(); err != nil {
			log.Printf("[LogCollector] Scanner error for %s logs: %v", logType, err)
		}

		cmd.Wait()
		time.Sleep(1 * time.Second) // Brief pause before reconnecting
	}
}

func (c *LogCollector) streamDockerExecLogs(ctx context.Context, logFile string, handler func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		// Use docker exec to tail the log file
		cmd := exec.CommandContext(ctx, "docker", "exec", c.nginxContainer, "tail", "-F", "-n", "0", logFile)

		pipe, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Failed to get stdout pipe for modsec logs: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Failed to start tail for modsec logs: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				handler(line)
			}
		}

		cmd.Wait()
		time.Sleep(5 * time.Second)
	}
}

// Manual log ingestion for API uploads
func (c *LogCollector) IngestLog(ctx context.Context, req *model.CreateLogRequest) error {
	c.addLog(*req)
	return nil
}

// Force flush for testing
func (c *LogCollector) Flush(ctx context.Context) {
	c.flush(ctx)
}
