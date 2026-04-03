package service

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"os/exec"
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

func lowercaseSlice(src []string) []string {
	dst := make([]string, len(src))
	for i, s := range src {
		dst[i] = strings.ToLower(s)
	}
	return dst
}

func NewBotMatcher() *BotMatcher {
	return &BotMatcher{
		badBotPatterns:       lowercaseSlice(model.KnownBadBots),
		aiBotPatterns:        lowercaseSlice(model.AIBots),
		suspiciousPatterns:   lowercaseSlice(model.SuspiciousClients),
		searchEnginePatterns: lowercaseSlice(model.SearchEngineBots),
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
		if strings.Contains(ua, pattern) {
			return "bad_bot", true
		}
	}

	// Check AI bots
	for _, pattern := range m.aiBotPatterns {
		if strings.Contains(ua, pattern) {
			return "ai_bot", true
		}
	}

	// Check suspicious clients
	for _, pattern := range m.suspiciousPatterns {
		if strings.Contains(ua, pattern) {
			return "suspicious", true
		}
	}

	// Check search engines (usually allowed, but log for reference)
	for _, pattern := range m.searchEnginePatterns {
		if strings.Contains(ua, pattern) {
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
	flushMu        sync.Mutex // 동시 flush 방지
	stopCh         chan struct{}
	lastAccessPos  int64 // Track position in access log
	lastErrorPos   int64 // Track position in error log
	useRedisBuffer bool  // Whether to use Redis for log buffering

	// Domain to host ID cache for Fail2ban
	domainCacheMu    sync.RWMutex
	domainCache      map[string]string // domain -> hostID
	domainCacheTime  time.Time

	// Global trusted IPs cache (bypass all security)
	settingsRepo     *repository.SystemSettingsRepository
	trustedIPsMu     sync.RWMutex
	trustedIPs       map[string]bool   // exact IP -> true
	trustedCIDRs     []string          // CIDR ranges
	trustedIPsTime   time.Time
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

// SetSystemSettingsRepo sets the system settings repository for trusted IP lookups
func (c *LogCollector) SetSystemSettingsRepo(repo *repository.SystemSettingsRepository) {
	c.settingsRepo = repo
}

// trustedIPCacheTTL is how long the trusted IP list is cached before refreshing from DB.
const trustedIPCacheTTL = 60 * time.Second

// isTrustedIP checks if the given IP is in the global trusted IPs list.
// The list is cached and refreshed every 60 seconds.
func (c *LogCollector) isTrustedIP(ctx context.Context, ip string) bool {
	if ip == "" || c.settingsRepo == nil {
		return false
	}

	c.trustedIPsMu.RLock()
	cacheValid := time.Since(c.trustedIPsTime) < trustedIPCacheTTL
	exactIPs := c.trustedIPs
	cidrs := c.trustedCIDRs
	c.trustedIPsMu.RUnlock()

	if cacheValid {
		return c.matchTrustedIP(ip, exactIPs, cidrs)
	}

	// Refresh cache under write lock (re-check to avoid thundering herd)
	c.trustedIPsMu.Lock()
	if time.Since(c.trustedIPsTime) < trustedIPCacheTTL {
		// Another goroutine already refreshed
		exactIPs = c.trustedIPs
		cidrs = c.trustedCIDRs
		c.trustedIPsMu.Unlock()
		return c.matchTrustedIP(ip, exactIPs, cidrs)
	}
	c.trustedIPsMu.Unlock()

	// Fetch from DB (outside lock to avoid blocking other goroutines)
	settings, err := c.settingsRepo.Get(ctx)

	newExactIPs := make(map[string]bool)
	var newCIDRs []string
	if err == nil && settings.GlobalTrustedIPs != "" {
		for _, line := range strings.Split(settings.GlobalTrustedIPs, "\n") {
			entry := strings.TrimSpace(line)
			if entry == "" || strings.HasPrefix(entry, "#") {
				continue
			}
			if strings.Contains(entry, "/") {
				newCIDRs = append(newCIDRs, entry)
			} else {
				newExactIPs[entry] = true
			}
		}
	}

	c.trustedIPsMu.Lock()
	c.trustedIPs = newExactIPs
	c.trustedCIDRs = newCIDRs
	c.trustedIPsTime = time.Now()
	c.trustedIPsMu.Unlock()

	return c.matchTrustedIP(ip, newExactIPs, newCIDRs)
}

func (c *LogCollector) matchTrustedIP(ip string, exactIPs map[string]bool, cidrs []string) bool {
	if exactIPs[ip] {
		return true
	}
	for _, cidr := range cidrs {
		if ipMatchesCIDR(ip, cidr) {
			return true
		}
	}
	return false
}

// ipMatchesCIDR checks if an IP address falls within a CIDR range
func ipMatchesCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return network.Contains(parsedIP)
}

// getHostIDByDomain returns the host ID for a given domain (with caching)
func (c *LogCollector) getHostIDByDomain(ctx context.Context, domain string) string {
	if domain == "" || c.proxyHostRepo == nil {
		return ""
	}

	// Check cache first (fast path)
	c.domainCacheMu.RLock()
	if hostID, ok := c.domainCache[domain]; ok {
		c.domainCacheMu.RUnlock()
		return hostID
	}
	needsRefresh := time.Since(c.domainCacheTime) > 60*time.Second
	c.domainCacheMu.RUnlock()

	if !needsRefresh {
		return ""
	}

	// DB query OUTSIDE lock
	hosts, _, err := c.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
	if err != nil {
		return ""
	}

	// Build new cache
	newCache := make(map[string]string)
	for _, host := range hosts {
		for _, d := range host.DomainNames {
			newCache[d] = host.ID
		}
	}

	// Swap cache under write lock (fast)
	c.domainCacheMu.Lock()
	c.domainCache = newCache
	c.domainCacheTime = time.Now()
	c.domainCacheMu.Unlock()

	return newCache[domain]
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

	log.Println("Log collector started")
}

func (c *LogCollector) Stop() {
	close(c.stopCh)
	c.flushMu.Lock()
	c.flushInner(context.Background())
	c.flushMu.Unlock()
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
	if !c.flushMu.TryLock() {
		return // 다른 flush 진행 중
	}
	defer c.flushMu.Unlock()
	c.flushInner(ctx)
}

func (c *LogCollector) flushInner(ctx context.Context) {
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

	if err := c.logRepo.CreateBatch(ctx, logs); err != nil {
		log.Printf("[LogCollector] Failed to batch insert %d logs: %v", len(logs), err)
	} else {
		log.Printf("[LogCollector] Flushed %d logs to database", len(logs))
	}
}

// flushRedisBuffer reads logs from Redis buffer and converts them to CreateLogRequest.
// Loops up to 5 times (max 2500 entries) to drain backlog.
func (c *LogCollector) flushRedisBuffer(ctx context.Context) ([]model.CreateLogRequest, error) {
	var allLogs []model.CreateLogRequest
	const maxIterations = 5

	for i := 0; i < maxIterations; i++ {
		entries, err := c.redisCache.ReadLogEntries(ctx, int64(c.batchSize))
		if err != nil {
			return allLogs, err // 읽은 만큼은 반환
		}
		if len(entries) == 0 {
			break
		}

		for _, entry := range entries {
			logReq := model.CreateLogRequest{
				LogType:              model.LogType(entry.LogType),
				Timestamp:            entry.Timestamp,
				Host:                 entry.Host,
				ClientIP:             entry.ClientIP,
				RequestMethod:        entry.Method,
				RequestURI:           entry.URI,
				RequestProtocol:      entry.Protocol,
				StatusCode:           entry.StatusCode,
				BodyBytesSent:        entry.BodyBytes,
				HTTPUserAgent:        entry.UserAgent,
				HTTPReferer:          entry.Referer,
				BlockReason:          model.ParseBlockReason(entry.BlockReason),
				BotCategory:          entry.BotCategory,
				ExploitRule:          entry.ExploitRule,
				GeoCountry:           entry.GeoCountry,
				GeoCountryCode:       entry.GeoCountryCode,
				GeoCity:              entry.GeoCity,
				GeoASN:               entry.GeoASN,
				GeoOrg:               entry.GeoOrg,
				RequestTime:          entry.RequestTime,
				HTTPXForwardedFor:    entry.XForwardedFor,
				UpstreamResponseTime: entry.UpstreamResponseTime,
				Severity:             model.LogSeverity(entry.Severity),
				ErrorMessage:         entry.ErrorMessage,
				ProxyHostID:          entry.ProxyHostID,
				RawLog:               entry.RawLog,
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

			allLogs = append(allLogs, logReq)
		}

		if len(entries) < c.batchSize {
			break // 버퍼 완전 소진
		}
	}
	return allLogs, nil
}

// sanitizeString removes null bytes (0x00) from strings to prevent PostgreSQL UTF8 encoding errors
func sanitizeString(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// truncateString truncates a string to the specified max rune length to prevent DB overflow.
// Uses rune-based truncation to avoid splitting multi-byte UTF-8 characters.
// Also removes null bytes to prevent PostgreSQL UTF8 encoding errors.
func truncateString(s string, maxLen int) string {
	s = sanitizeString(s)
	if len(s) <= maxLen {
		return s // 빠른 경로: 바이트 길이가 한도 이내면 rune도 반드시 한도 내
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
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
			LogType:              string(logReq.LogType),
			Timestamp:            logReq.Timestamp,
			Host:                 logReq.Host,
			ClientIP:             logReq.ClientIP,
			Method:               logReq.RequestMethod,
			URI:                  logReq.RequestURI,
			Protocol:             logReq.RequestProtocol,
			StatusCode:           logReq.StatusCode,
			BodyBytes:            logReq.BodyBytesSent,
			UserAgent:            logReq.HTTPUserAgent,
			Referer:              logReq.HTTPReferer,
			BlockReason:          string(logReq.BlockReason),
			BotCategory:          logReq.BotCategory,
			ExploitRule:          logReq.ExploitRule,
			GeoCountry:           logReq.GeoCountry,
			GeoCountryCode:       logReq.GeoCountryCode,
			GeoCity:              logReq.GeoCity,
			GeoASN:               logReq.GeoASN,
			GeoOrg:               logReq.GeoOrg,
			RequestTime:          logReq.RequestTime,
			XForwardedFor:        logReq.HTTPXForwardedFor,
			UpstreamResponseTime: logReq.UpstreamResponseTime,
			Severity:             string(logReq.Severity),
			ErrorMessage:         logReq.ErrorMessage,
			ProxyHostID:          logReq.ProxyHostID,
			RawLog:               logReq.RawLog,
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

func (c *LogCollector) streamAccessLogs(ctx context.Context) {
	c.streamLogs(ctx, "access", func(line string) {
		// Check if this is a ModSecurity JSON log (starts with {"transaction")
		if strings.HasPrefix(strings.TrimSpace(line), "{\"transaction\"") {
			log.Printf("[DEBUG] Detected ModSec JSON log (len=%d)", len(line))
			if logReq, err := c.parseModSecLog(line); err == nil {
				log.Printf("[DEBUG] Successfully parsed ModSec log: rule=%d, type=%s", logReq.RuleID, logReq.AttackType)
				c.addLog(*logReq)

				// Notify WAF auto-ban service (only for blocked requests, not logged/detection mode)
				// Skip for globally trusted IPs
				if c.wafAutoBan != nil && logReq.ClientIP != "" && logReq.ActionTaken == "blocked" && !c.isTrustedIP(ctx, logReq.ClientIP) {
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

			// 모든 access 로그에 ProxyHostID 할당 (캐시된 맵 조회, 성능 영향 미미)
			if logReq.Host != "" {
				hostID := c.getHostIDByDomain(ctx, logReq.Host)
				if hostID != "" {
					logReq.ProxyHostID = hostID
				}
			}

			// Notify Fail2ban service for error responses (4xx, 5xx)
			// Skip for globally trusted IPs
			if c.fail2ban != nil && logReq.ClientIP != "" && logReq.StatusCode >= 400 && logReq.ProxyHostID != "" && !c.isTrustedIP(ctx, logReq.ClientIP) {
				c.fail2ban.RecordFailedRequest(ctx, logReq.ProxyHostID, logReq.ClientIP, logReq.StatusCode, logReq.RequestURI)
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

// Manual log ingestion for API uploads
func (c *LogCollector) IngestLog(ctx context.Context, req *model.CreateLogRequest) error {
	c.addLog(*req)
	return nil
}

// Force flush for testing
func (c *LogCollector) Flush(ctx context.Context) {
	c.flush(ctx)
}
