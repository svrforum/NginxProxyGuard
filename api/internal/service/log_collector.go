package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// streamIdleThreshold is how long the access log stream may be silent before
// the watchdog assumes the underlying `docker logs --follow` RPC is stuck and
// restarts it. Production incident (2026-05-19) showed a stream can silently
// stall for days while the docker CLI subprocess remains alive.
// 5min is generous: even the quietest production hosts see crawler/bot
// traffic well within that window.
const streamIdleThreshold = 5 * time.Minute

// streamWatchdogInterval is how often the watchdog checks the last-line
// timestamp. 30s gives ~10 checks per threshold window, low overhead.
const streamWatchdogInterval = 30 * time.Second

// streamMaxAge is the hard cap on a single `docker logs --follow` subprocess
// lifetime. Forces a reconnect regardless of activity. v2.14.1's idle-only
// watchdog failed to fire in a production incident (2026-05-20, 11h stall);
// this acts as belt-and-suspenders so a stuck stream cannot exceed 1 hour
// even if the idle detection path is somehow defeated.
const streamMaxAge = 1 * time.Hour

// streamHeartbeatTicks controls how often the watchdog logs a heartbeat
// (every N watchdog ticks). With 30s ticks * 10 = every 5 min — visible
// proof the watchdog goroutine is alive, cheap to diagnose next time.
const streamHeartbeatTicks = 10

// canonicalAccessLogPath is the path every shipped proxy_host config writes
// to (via 00-raw-logging.conf + per-host access_log directives) and that the
// shared npg_nginx_data volume exposes inside the npg-api container. Used
// both as the code default and as the auto-fallback when a user's compose
// still carries the pre-v2.14.2 NGINX_ACCESS_LOG=/var/log/nginx/access.log
// value (a symlink to /dev/stdout that is not mounted into npg-api and so
// silently produces zero ingestion after the docker-logs → file-tail switch).
const canonicalAccessLogPath = "/etc/nginx/logs/access_raw.log"

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
	logRepo         *repository.LogRepository
	proxyHostRepo   *repository.ProxyHostRepository
	geoIP           *GeoIPService
	wafAutoBan      *WAFAutoBanService
	fail2ban        *Fail2banService
	botMatcher      *BotMatcher
	redisCache      *cache.RedisClient
	nginxContainer  string
	accessLogPath   string // Path to nginx access_raw.log (file-tail source)
	batchSize       int
	flushInterval   time.Duration
	buffer          []model.CreateLogRequest
	bufferMu        sync.Mutex
	flushMu         sync.Mutex // 동시 flush 방지
	stopCh          chan struct{}
	useRedisBuffer  bool         // Whether to use Redis for log buffering
	lastFlushAt     atomic.Int64 // unix seconds of the last successful flush, for /health/detailed
	accessLastFlush atomic.Int64 // unix sec of last access-log flush
	modsecLastFlush atomic.Int64 // unix sec of last modsec flush
	errorLastFlush  atomic.Int64 // unix sec of last error-log flush
	actualTailPath  atomic.Value // string, the resolved file-tail source (post-fallback)

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

	// Verbose per-line logging. Default off — on a busy server the previous
	// always-on DEBUG lines flooded the API container log. Enable with
	// LOG_COLLECTOR_DEBUG=1 for local diagnostics.
	debugLog bool

	// Boot probe: if no flush has happened within bootProbeTimeout after
	// Start(), emit a single explicit warning. Surfaces silent failures
	// where the file-tail source has no content (issue #141/#145 pattern).
	startedAt        time.Time
	bootProbeWarned  atomic.Bool
}

func NewLogCollector(logRepo *repository.LogRepository, nginxContainer string, accessLogPath string, geoIP *GeoIPService, redisCache *cache.RedisClient) *LogCollector {
	// Use Redis buffer if available and ready
	useRedis := redisCache != nil && redisCache.IsReady()

	return &LogCollector{
		logRepo:        logRepo,
		geoIP:          geoIP,
		botMatcher:     NewBotMatcher(),
		redisCache:     redisCache,
		nginxContainer: nginxContainer,
		accessLogPath:  accessLogPath,
		batchSize:      500,
		flushInterval:  1 * time.Second,
		buffer:         make([]model.CreateLogRequest, 0, 500),
		stopCh:         make(chan struct{}),
		domainCache:    make(map[string]string),
		useRedisBuffer: useRedis,
		debugLog:       os.Getenv("LOG_COLLECTOR_DEBUG") == "1",
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
	c.startedAt = time.Now()

	// Check Redis buffer status
	if c.useRedisBuffer {
		log.Println("[LogCollector] Redis buffer enabled for high-throughput log buffering")
	} else {
		log.Println("[LogCollector] Using in-memory buffer (Redis not available)")
	}

	// Start periodic flush
	go c.flushLoop(ctx)

	// Start log streaming:
	//   - access logs: tail nginx file directly (immune to docker logs RPC stalls)
	//   - ModSec JSON: still via docker logs --follow stdout, with watchdog
	//   - error logs: docker logs --follow stderr
	go c.streamFileAccessLogs(ctx)
	go c.streamModSecLogs(ctx)
	go c.streamErrorLogs(ctx)

	// Boot probe: warn explicitly if no log has been flushed within
	// bootProbeTimeout. The earlier "no logs" failures (#141/#144/#145) were
	// silent for days; this surfaces them within a minute so operators see
	// the actionable signal in API container logs and /health/detailed.
	go c.runBootProbe(ctx)

	log.Println("Log collector started")
}

// runBootProbe emits a single explicit warning if no log row has been flushed
// within the boot probe window. Trigger is intentionally generous (60s) so a
// genuinely idle server doesn't false-alarm; the warning's wording points the
// operator at the exact files/env to check.
func (c *LogCollector) runBootProbe(ctx context.Context) {
	const bootProbeTimeout = 60 * time.Second
	select {
	case <-ctx.Done():
		return
	case <-c.stopCh:
		return
	case <-time.After(bootProbeTimeout):
	}
	if c.AccessLastFlushUnix() != 0 {
		return // access logs did flush — the recurring silent failure is ruled out
	}
	if c.bootProbeWarned.Swap(true) {
		return // someone else already warned
	}
	configured := c.accessLogPath
	actual := c.AccessLogPathActual()
	log.Printf("[LogCollector] WARN: no logs flushed in %s after start — likely silent failure. "+
		"Check (1) nginx is generating /etc/nginx/logs/access_raw.log (system_settings.raw_log_enabled must be true), "+
		"(2) NGINX_ACCESS_LOG env points to that path (currently configured=%q actual=%q), "+
		"(3) for ModSec/error: docker logs RPC reachable. "+
		"Also see /api/v1/health/detailed for the same info.",
		bootProbeTimeout, configured, actual)
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
		if size, err := c.redisCache.GetLogBufferSize(ctx); err == nil {
			metrics.LogCollectorBufferSize.WithLabelValues("redis").Set(float64(size))
		}
	}

	// Also flush memory buffer
	c.bufferMu.Lock()
	if len(c.buffer) > 0 {
		logs = append(logs, c.buffer...)
		c.buffer = make([]model.CreateLogRequest, 0, c.batchSize)
	}
	memSize := len(c.buffer)
	c.bufferMu.Unlock()
	metrics.LogCollectorBufferSize.WithLabelValues("memory").Set(float64(memSize))

	if len(logs) == 0 {
		return
	}

	if err := c.logRepo.CreateBatch(ctx, logs); err != nil {
		log.Printf("[LogCollector] Failed to batch insert %d logs: %v", len(logs), err)
	} else {
		log.Printf("[LogCollector] Flushed %d logs to database", len(logs))
		c.recordFlushedByType(logs)
		c.lastFlushAt.Store(time.Now().Unix())
	}
}

// recordFlushedByType bumps the per-type Prometheus counter after a successful
// batch insert. Kept separate from flushInner so the counting loop doesn't
// distract from the flush control flow.
func (c *LogCollector) recordFlushedByType(logs []model.CreateLogRequest) {
	byType := make(map[model.LogType]int, 3)
	for _, l := range logs {
		byType[l.LogType]++
	}
	now := time.Now().Unix()
	for t, n := range byType {
		metrics.LogCollectorFlushedTotal.WithLabelValues(string(t)).Add(float64(n))
		switch t {
		case model.LogTypeAccess:
			c.accessLastFlush.Store(now)
		case model.LogTypeModSec:
			c.modsecLastFlush.Store(now)
		case model.LogTypeError:
			c.errorLastFlush.Store(now)
		}
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
				UpstreamAddr:         entry.UpstreamAddr,
				UpstreamStatus:       entry.UpstreamStatus,
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
			UpstreamAddr:         logReq.UpstreamAddr,
			UpstreamStatus:       logReq.UpstreamStatus,
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

// handleAccessLine processes a single nginx access log line.
// Shared by streamFileAccessLogs (file-tail source) and any other access log path.
func (c *LogCollector) handleAccessLine(ctx context.Context, line string) {
	logReq, err := c.parseAccessLog(line)
	if err != nil {
		metrics.LogCollectorParseErrorsTotal.WithLabelValues("file").Inc()
		return
	}

	// Block reason is now extracted from nginx log format directly in parseAccessLog().
	// Only use fallback pattern matching if nginx didn't provide block_reason.
	if logReq.BlockReason == "" {
		if logReq.StatusCode == 403 && logReq.HTTPUserAgent != "" {
			if category, matched := c.botMatcher.MatchBot(logReq.HTTPUserAgent); matched {
				logReq.BlockReason = model.BlockReasonBotFilter
				logReq.BotCategory = category
			}
		}
		if logReq.StatusCode == 429 {
			logReq.BlockReason = model.BlockReasonRateLimit
		}
	}

	if logReq.Host != "" {
		if hostID := c.getHostIDByDomain(ctx, logReq.Host); hostID != "" {
			logReq.ProxyHostID = hostID
		}
	}

	// Notify Fail2ban service for error responses (4xx, 5xx).
	// Skip for globally trusted IPs.
	if c.fail2ban != nil && logReq.ClientIP != "" && logReq.StatusCode >= 400 && logReq.ProxyHostID != "" && !c.isTrustedIP(ctx, logReq.ClientIP) {
		c.fail2ban.RecordFailedRequest(ctx, logReq.ProxyHostID, logReq.ClientIP, logReq.StatusCode, logReq.RequestURI)
	}

	c.addLog(*logReq)
}

// handleModSecLine processes a single ModSec audit JSON line.
// Two DEBUG log lines used to run for every audit line; on a busy server they
// flooded the API container log. They're now gated behind LOG_COLLECTOR_DEBUG
// so production stays quiet while local debugging can still opt in.
func (c *LogCollector) handleModSecLine(ctx context.Context, line string) {
	if c.debugLog {
		log.Printf("[DEBUG] Detected ModSec JSON log (len=%d)", len(line))
	}
	logReq, err := c.parseModSecLog(line)
	if err != nil {
		if !strings.Contains(err.Error(), "no WAF rules triggered") {
			metrics.LogCollectorParseErrorsTotal.WithLabelValues("modsec").Inc()
			snippet := line
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			log.Printf("[ERROR] Failed to parse ModSec log: %v | line=%s", err, snippet)
		}
		return
	}
	if c.debugLog {
		log.Printf("[DEBUG] Successfully parsed ModSec log: rule=%d, type=%s", logReq.RuleID, logReq.AttackType)
	}
	c.addLog(*logReq)

	// Notify WAF auto-ban service (only for blocked requests, not logged/detection mode).
	// Skip for globally trusted IPs.
	if c.wafAutoBan != nil && logReq.ClientIP != "" && logReq.ActionTaken == "blocked" && !c.isTrustedIP(ctx, logReq.ClientIP) {
		c.wafAutoBan.RecordWAFEvent(ctx, logReq.ClientIP, logReq.Host, logReq.RuleID, logReq.RuleMessage)
	}
}

// streamModSecLogs reads ModSec JSON audit lines from nginx stdout via
// `docker logs --follow`. Regular access log lines coming through the same
// stream are silently dropped — they are now captured from the file by
// streamFileAccessLogs, which is immune to dockerd RPC stalls.
func (c *LogCollector) streamModSecLogs(ctx context.Context) {
	c.streamLogs(ctx, "access", func(line string) {
		if strings.HasPrefix(strings.TrimSpace(line), "{\"transaction\"") {
			c.handleModSecLine(ctx, line)
		}
		// else: regular access log — handled by streamFileAccessLogs.
	})
}

// resolveTailPath returns the path streamFileAccessLogs should actually tail.
// It honors c.accessLogPath when usable and falls back to canonicalAccessLogPath
// otherwise. Two known-bad inputs are auto-corrected:
//
//  1. A symlink whose target is under /dev/* (the pre-v2.14.2 default
//     /var/log/nginx/access.log resolves to /dev/stdout; reading it returns
//     immediate EOF and yields zero ingestion).
//  2. A path that does not exist inside npg-api at all (the same legacy
//     default refers to a file in npg-proxy that npg-api never mounts —
//     os.Open returns ENOENT and the outer retry loop spins forever).
//
// Both cases were silently introduced for upgrading users by the v2.14.2
// docker-logs → file-tail switch. The fallback is logged at WARN level so the
// operator can fix their NGINX_ACCESS_LOG env at leisure without losing logs.
func (c *LogCollector) resolveTailPath() string {
	configured := c.accessLogPath

	if target, err := os.Readlink(configured); err == nil && strings.HasPrefix(target, "/dev/") {
		log.Printf("[LogCollector] WARN: NGINX_ACCESS_LOG %s is a symlink to %s (legacy stdout pipe); falling back to %s. Remove the env override or set it to the canonical path to silence this.", configured, target, canonicalAccessLogPath)
		metrics.LogCollectorFallbackTotal.Inc()
		return canonicalAccessLogPath
	}

	if _, err := os.Stat(configured); os.IsNotExist(err) {
		if _, err := os.Stat(canonicalAccessLogPath); err == nil {
			log.Printf("[LogCollector] WARN: NGINX_ACCESS_LOG %s does not exist inside npg-api (likely a stale pre-v2.14.2 value); falling back to %s. Remove the env override or set it to the canonical path to silence this.", configured, canonicalAccessLogPath)
			metrics.LogCollectorFallbackTotal.Inc()
			return canonicalAccessLogPath
		}
	}

	return configured
}

// streamFileAccessLogs tails the nginx access_raw.log file directly, bypassing
// docker logs --follow. Background: the dockerd `docker logs` streaming RPC
// can silently stall (production incidents 2026-05-19 and 2026-05-20), and
// scanner.Scan() blocks indefinitely without surfacing an error. A file-based
// tail has a well-understood failure mode (file gone, rotation, truncate) and
// avoids the dockerd dependency entirely for the high-volume access path.
//
// nginx writes access logs to both /dev/stdout (consumed by docker logs) and
// /etc/nginx/logs/access_raw.log (this function's source). Both files share
// the same `main` format. Rotation is handled by logrotate daily (file is
// renamed to access_raw.log-YYYYMMDD.gz and a new access_raw.log is created).
func (c *LogCollector) streamFileAccessLogs(ctx context.Context) {
	if c.accessLogPath == "" {
		log.Printf("[LogCollector] file-tail disabled: accessLogPath is empty")
		return
	}
	// Resolve once at startup so a stale pre-v2.14.2 NGINX_ACCESS_LOG env in
	// the user's docker-compose.yml (e.g. /var/log/nginx/access.log, a stdout
	// symlink that is not even mounted into npg-api) auto-falls back to the
	// canonical file written by every proxy_host config. Without this, users
	// upgrading from <=2.14.1 without touching their compose see zero access
	// log ingestion forever — a silent breaking change introduced in 2.14.2.
	tailPath := c.resolveTailPath()
	c.actualTailPath.Store(tailPath)
	log.Printf("[LogCollector] starting file-tail of %s", tailPath)

	var (
		file   *os.File
		reader *bufio.Reader
		curIno uint64
	)
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	// inodeOf returns the inode of a path, or 0 on error.
	inodeOf := func(path string) uint64 {
		st, err := os.Stat(path)
		if err != nil {
			return 0
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return 0
		}
		return sys.Ino
	}

	// openTail opens the file. seekToEnd=true is used on first open to skip
	// historical lines (already captured before this run). On rotation we
	// reopen the new file from the beginning to avoid losing any lines.
	openTail := func(seekToEnd bool) error {
		if file != nil {
			_ = file.Close()
			file = nil
		}
		f, err := os.Open(tailPath)
		if err != nil {
			return err
		}
		if seekToEnd {
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				_ = f.Close()
				return err
			}
		}
		file = f
		reader = bufio.NewReaderSize(f, 64*1024)
		curIno = inodeOf(tailPath)
		return nil
	}

	// First open: skip historical content.
	for file == nil {
		if err := openTail(true); err != nil {
			log.Printf("[LogCollector] file-tail open failed: %v (retry in 5s)", err)
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-time.After(5 * time.Second):
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			c.handleAccessLine(ctx, strings.TrimRight(line, "\n"))
			continue
		}
		if err != io.EOF {
			log.Printf("[LogCollector] file-tail read error: %v (reopening)", err)
			if err := openTail(false); err != nil {
				time.Sleep(1 * time.Second)
			}
			continue
		}

		// EOF: either no new data yet, or the file was rotated. Detect rotation
		// by comparing inode. Bare file-gone is also possible mid-rotation.
		newIno := inodeOf(tailPath)
		if newIno == 0 {
			// File temporarily missing (logrotate window). Brief wait and retry.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if newIno != curIno {
			// Rotation: open the new file from the beginning.
			log.Printf("[LogCollector] file-tail detected rotation (inode %d -> %d)", curIno, newIno)
			if err := openTail(false); err != nil {
				log.Printf("[LogCollector] file-tail reopen after rotation failed: %v", err)
				time.Sleep(1 * time.Second)
			}
			continue
		}
		// Same file, no new data. Short poll.
		time.Sleep(200 * time.Millisecond)
	}
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

		// Watchdog: detect silently stalled `docker logs --follow` streams.
		// Two independent triggers — idle threshold + hard max-age — plus a
		// periodic heartbeat log so the goroutine's liveness is verifiable.
		// Only enabled for "access" because error streams legitimately stay
		// silent for long periods on healthy hosts and would false-positive.
		var lastLineUnix atomic.Int64
		lastLineUnix.Store(time.Now().Unix())
		watchdogDone := make(chan struct{})
		watchdogStop := make(chan struct{})
		if logType == "access" {
			cmdStartedAt := time.Now()
			log.Printf("[LogCollector] %s watchdog started (idle=%v max=%v)", logType, streamIdleThreshold, streamMaxAge)
			go func() {
				defer close(watchdogDone)
				t := time.NewTicker(streamWatchdogInterval)
				defer t.Stop()
				maxAge := time.NewTimer(streamMaxAge)
				defer maxAge.Stop()
				ticks := 0
				for {
					select {
					case <-watchdogStop:
						return
					case <-ctx.Done():
						return
					case <-maxAge.C:
						log.Printf("[LogCollector] %s stream age %v reached max %v, forcing reconnect", logType, time.Since(cmdStartedAt).Round(time.Second), streamMaxAge)
						metrics.LogCollectorWatchdogRestartTotal.WithLabelValues("max_age").Inc()
						if cmd.Process != nil {
							_ = cmd.Process.Kill()
						}
						return
					case <-t.C:
						ticks++
						idle := time.Since(time.Unix(lastLineUnix.Load(), 0))
						if ticks%streamHeartbeatTicks == 0 {
							log.Printf("[LogCollector] %s watchdog heartbeat: idle=%v age=%v", logType, idle.Round(time.Second), time.Since(cmdStartedAt).Round(time.Second))
						}
						if idle > streamIdleThreshold {
							log.Printf("[LogCollector] %s stream idle for %v, restarting docker logs", logType, idle.Round(time.Second))
							metrics.LogCollectorWatchdogRestartTotal.WithLabelValues("idle").Inc()
							if cmd.Process != nil {
								_ = cmd.Process.Kill()
							}
							return
						}
					}
				}
			}()
		} else {
			close(watchdogDone)
		}

		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				if logType == "access" {
					lastLineUnix.Store(time.Now().Unix())
				}
				handler(line)
			}
		}

		// Stop watchdog before Wait so it can't race with subprocess exit.
		close(watchdogStop)
		<-watchdogDone

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

// AccessLogPathConfigured returns the path that NGINX_ACCESS_LOG resolved to
// at startup (before any fallback). Used by /api/v1/health/detailed.
func (c *LogCollector) AccessLogPathConfigured() string {
	return c.accessLogPath
}

// AccessLogPathActual returns the path the file-tail is actually reading
// (post-fallback). Empty until streamFileAccessLogs has started.
func (c *LogCollector) AccessLogPathActual() string {
	if v, ok := c.actualTailPath.Load().(string); ok {
		return v
	}
	return ""
}

// HasBootProbeFired reports whether the boot probe has emitted its silent-
// failure warning. Used by /health/detailed to surface the same signal.
func (c *LogCollector) HasBootProbeFired() bool {
	return c.bootProbeWarned.Load()
}

// LastFlushUnix returns the unix timestamp (seconds) of the last successful
// CreateBatch. Zero if no flush has happened yet.
func (c *LogCollector) LastFlushUnix() int64 {
	return c.lastFlushAt.Load()
}

func (c *LogCollector) AccessLastFlushUnix() int64 { return c.accessLastFlush.Load() }
func (c *LogCollector) ModsecLastFlushUnix() int64 { return c.modsecLastFlush.Load() }
func (c *LogCollector) ErrorLastFlushUnix() int64  { return c.errorLastFlush.Load() }
