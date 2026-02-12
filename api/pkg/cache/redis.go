package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrCacheMiss = errors.New("cache miss")
	ErrNotReady  = errors.New("cache not ready")
)

// Cache prefixes for different data types
const (
	PrefixBannedIP     = "banned_ip:"       // Set of banned IPs
	PrefixRateLimit    = "rate_limit:"      // Rate limiting counters
	PrefixFail2ban     = "fail2ban:"        // Fail2ban event counters
	PrefixWAFCounter   = "waf_counter:"     // WAF auto-ban counters
	PrefixConfig       = "config:"          // Configuration cache
	PrefixSession      = "session:"         // Session data
	PrefixLogBuffer    = "log_buffer"       // Log buffering stream
	PrefixURIBlock     = "uri_block:"       // URI block rules per host
	PrefixLock         = "lock:"            // Distributed locks
)

// Retry configuration constants
const (
	maxRetries            = 5              // Maximum number of connection retry attempts
	retryBaseIntervalSecs = 1              // Base interval in seconds for retry backoff
)

// RedisClient wraps the Redis client with helper methods
type RedisClient struct {
	client *redis.Client
	ready  bool
	mu     sync.RWMutex
}

// NewRedisClient creates a new Redis client from URL
// URL format: redis://[:password@]host:port/db
func NewRedisClient(redisURL string) (*RedisClient, error) {
	if redisURL == "" {
		log.Println("[Cache] Redis URL not configured, caching disabled")
		return &RedisClient{ready: false}, nil
	}

	opts, err := parseRedisURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	rc := &RedisClient{
		client: client,
		ready:  false,
	}

	// Test connection in background
	go rc.connect()

	return rc, nil
}

func parseRedisURL(redisURL string) (*redis.Options, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return nil, err
	}

	opts := &redis.Options{
		Addr:         u.Host,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	}

	if u.User != nil {
		password, _ := u.User.Password()
		opts.Password = password
	}

	// Parse database number from path
	if u.Path != "" && u.Path != "/" {
		db, err := strconv.Atoi(strings.TrimPrefix(u.Path, "/"))
		if err == nil {
			opts.DB = db
		}
	}

	return opts, nil
}

func (r *RedisClient) connect() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if r.client == nil {
		return
	}

	// Retry connection with backoff
	for i := 0; i < maxRetries; i++ {
		if err := r.client.Ping(ctx).Err(); err != nil {
			log.Printf("[Cache] Redis connection attempt %d/%d failed: %v", i+1, maxRetries, err)
			time.Sleep(time.Duration((i+1)*retryBaseIntervalSecs) * time.Second)
			continue
		}

		r.mu.Lock()
		r.ready = true
		r.mu.Unlock()
		log.Println("[Cache] Redis connected successfully")
		return
	}

	log.Println("[Cache] Redis connection failed after retries, caching disabled")
}

// IsReady returns whether the cache is connected
func (r *RedisClient) IsReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready && r.client != nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// Client returns the underlying Redis client (use with caution)
func (r *RedisClient) Client() *redis.Client {
	return r.client
}

// ========================================
// Banned IP Cache Operations
// ========================================

// IsBannedIP checks if an IP is in the banned set (fast O(1) lookup)
func (r *RedisClient) IsBannedIP(ctx context.Context, ip string) (bool, error) {
	if !r.IsReady() {
		return false, ErrNotReady
	}

	// Check global ban first
	exists, err := r.client.SIsMember(ctx, PrefixBannedIP+"global", ip).Result()
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}

	return false, nil
}

// IsBannedIPForHost checks if an IP is banned for a specific host
func (r *RedisClient) IsBannedIPForHost(ctx context.Context, ip string, hostID string) (bool, error) {
	if !r.IsReady() {
		return false, ErrNotReady
	}

	// Check global ban
	globalKey := PrefixBannedIP + "global"
	exists, err := r.client.SIsMember(ctx, globalKey, ip).Result()
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}

	// Check host-specific ban
	if hostID != "" {
		hostKey := PrefixBannedIP + "host:" + hostID
		exists, err = r.client.SIsMember(ctx, hostKey, ip).Result()
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}

// AddBannedIP adds an IP to the banned set with optional TTL
func (r *RedisClient) AddBannedIP(ctx context.Context, ip string, hostID string, ttl time.Duration) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	key := PrefixBannedIP + "global"
	if hostID != "" {
		key = PrefixBannedIP + "host:" + hostID
	}

	pipe := r.client.Pipeline()
	pipe.SAdd(ctx, key, ip)

	// If TTL is set, track individual IP expiry
	if ttl > 0 {
		expiryKey := PrefixBannedIP + "expiry:" + ip
		pipe.Set(ctx, expiryKey, key, ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// RemoveBannedIP removes an IP from the banned set
func (r *RedisClient) RemoveBannedIP(ctx context.Context, ip string, hostID string) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	key := PrefixBannedIP + "global"
	if hostID != "" {
		key = PrefixBannedIP + "host:" + hostID
	}

	pipe := r.client.Pipeline()
	pipe.SRem(ctx, key, ip)
	pipe.Del(ctx, PrefixBannedIP+"expiry:"+ip)

	_, err := pipe.Exec(ctx)
	return err
}

// SyncBannedIPs syncs all banned IPs from database to cache
func (r *RedisClient) SyncBannedIPs(ctx context.Context, ips []BannedIPEntry) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	pipe := r.client.Pipeline()

	// Clear existing sets
	keys, _ := r.client.Keys(ctx, PrefixBannedIP+"*").Result()
	if len(keys) > 0 {
		pipe.Del(ctx, keys...)
	}

	// Add all banned IPs
	for _, entry := range ips {
		key := PrefixBannedIP + "global"
		if entry.HostID != "" {
			key = PrefixBannedIP + "host:" + entry.HostID
		}
		pipe.SAdd(ctx, key, entry.IP)

		// Set expiry tracking if applicable
		if entry.ExpiresAt != nil && entry.ExpiresAt.After(time.Now()) {
			ttl := time.Until(*entry.ExpiresAt)
			expiryKey := PrefixBannedIP + "expiry:" + entry.IP
			pipe.Set(ctx, expiryKey, key, ttl)
		}
	}

	_, err := pipe.Exec(ctx)
	return err
}

// BannedIPEntry represents a banned IP for cache sync
type BannedIPEntry struct {
	IP        string
	HostID    string
	ExpiresAt *time.Time
}

// ========================================
// Rate Limiting Operations
// ========================================

// RateLimitResult contains rate limit check result
type RateLimitResult struct {
	Allowed   bool
	Current   int64
	Limit     int64
	Remaining int64
	ResetAt   time.Time
}

// CheckRateLimit implements sliding window rate limiting
func (r *RedisClient) CheckRateLimit(ctx context.Context, key string, limit int64, window time.Duration) (*RateLimitResult, error) {
	if !r.IsReady() {
		return &RateLimitResult{Allowed: true}, ErrNotReady
	}

	now := time.Now()
	windowStart := now.Add(-window).UnixMilli()
	fullKey := PrefixRateLimit + key

	pipe := r.client.Pipeline()

	// Remove old entries outside window
	pipe.ZRemRangeByScore(ctx, fullKey, "0", strconv.FormatInt(windowStart, 10))

	// Count current entries
	countCmd := pipe.ZCard(ctx, fullKey)

	// Add current request
	pipe.ZAdd(ctx, fullKey, redis.Z{
		Score:  float64(now.UnixMilli()),
		Member: fmt.Sprintf("%d:%d", now.UnixNano(), now.UnixNano()%1000),
	})

	// Set TTL on the key
	pipe.Expire(ctx, fullKey, window+time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	current := countCmd.Val()
	allowed := current < limit

	return &RateLimitResult{
		Allowed:   allowed,
		Current:   current + 1, // Include current request
		Limit:     limit,
		Remaining: max(0, limit-current-1),
		ResetAt:   now.Add(window),
	}, nil
}

// IncrementCounter increments a counter with TTL
func (r *RedisClient) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if !r.IsReady() {
		return 0, ErrNotReady
	}

	fullKey := PrefixFail2ban + key

	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, fullKey)
	pipe.Expire(ctx, fullKey, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return incrCmd.Val(), nil
}

// GetCounter gets current counter value
func (r *RedisClient) GetCounter(ctx context.Context, key string) (int64, error) {
	if !r.IsReady() {
		return 0, ErrNotReady
	}

	val, err := r.client.Get(ctx, PrefixFail2ban+key).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return val, err
}

// ResetCounter deletes a counter
func (r *RedisClient) ResetCounter(ctx context.Context, key string) error {
	if !r.IsReady() {
		return ErrNotReady
	}
	return r.client.Del(ctx, PrefixFail2ban+key).Err()
}

// ========================================
// WAF Auto-Ban Counter Operations
// ========================================

// RecordWAFEvent records a WAF event for auto-ban tracking
func (r *RedisClient) RecordWAFEvent(ctx context.Context, ip string, hostID string, window time.Duration) (int64, error) {
	if !r.IsReady() {
		return 0, ErrNotReady
	}

	key := fmt.Sprintf("%s%s:%s", PrefixWAFCounter, hostID, ip)
	now := time.Now()
	windowStart := now.Add(-window).UnixMilli()

	pipe := r.client.Pipeline()

	// Remove old events
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))

	// Add current event
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixMilli()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	})

	// Count events
	countCmd := pipe.ZCard(ctx, key)

	// Set TTL
	pipe.Expire(ctx, key, window+time.Minute)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return countCmd.Val(), nil
}

// ========================================
// Generic Cache Operations
// ========================================

// Set stores a value with optional TTL
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixConfig+key, data, ttl).Err()
}

// Get retrieves a value
func (r *RedisClient) Get(ctx context.Context, key string, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixConfig+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// Delete removes a key
func (r *RedisClient) Delete(ctx context.Context, key string) error {
	if !r.IsReady() {
		return ErrNotReady
	}
	return r.client.Del(ctx, PrefixConfig+key).Err()
}

// ========================================
// Log Buffering with Redis Streams
// ========================================

// LogEntry represents a log entry for buffering
type LogEntry struct {
	LogType        string            `json:"log_type"`
	Timestamp      time.Time         `json:"timestamp"`
	Host           string            `json:"host,omitempty"`
	ClientIP       string            `json:"client_ip,omitempty"`
	Method         string            `json:"method,omitempty"`
	URI            string            `json:"uri,omitempty"`
	Protocol       string            `json:"protocol,omitempty"`
	StatusCode     int               `json:"status_code,omitempty"`
	BodyBytes      int64             `json:"body_bytes,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	Referer        string            `json:"referer,omitempty"`
	BlockReason    string            `json:"block_reason,omitempty"`
	BotCategory    string            `json:"bot_category,omitempty"`
	ExploitRule    string            `json:"exploit_rule,omitempty"`
	GeoCountry     string            `json:"geo_country,omitempty"`
	GeoCountryCode string            `json:"geo_country_code,omitempty"`
	GeoCity        string            `json:"geo_city,omitempty"`
	GeoASN         string            `json:"geo_asn,omitempty"`
	GeoOrg         string            `json:"geo_org,omitempty"`
	RequestTime          float64           `json:"request_time,omitempty"`
	XForwardedFor        string            `json:"x_forwarded_for,omitempty"`
	UpstreamResponseTime float64           `json:"upstream_response_time,omitempty"`
	Severity             string            `json:"severity,omitempty"`
	ErrorMessage         string            `json:"error_message,omitempty"`
	ProxyHostID          string            `json:"proxy_host_id,omitempty"`
	RawLog               string            `json:"raw_log,omitempty"`
	Extra                map[string]string `json:"extra,omitempty"`
}

// AddLogEntry adds a log entry to the buffer stream
func (r *RedisClient) AddLogEntry(ctx context.Context, entry *LogEntry) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return r.client.XAdd(ctx, &redis.XAddArgs{
		Stream: PrefixLogBuffer,
		MaxLen: 10000, // Keep last 10000 entries
		Approx: true,
		Values: map[string]interface{}{
			"data": data,
		},
	}).Err()
}

// ReadLogEntries reads and removes log entries from buffer
func (r *RedisClient) ReadLogEntries(ctx context.Context, count int64) ([]LogEntry, error) {
	if !r.IsReady() {
		return nil, ErrNotReady
	}

	// Read entries (limited to count at Redis level)
	messages, err := r.client.XRangeN(ctx, PrefixLogBuffer, "-", "+", count).Result()
	if err != nil {
		return nil, err
	}

	if len(messages) == 0 {
		return nil, nil
	}

	var entries []LogEntry
	var ids []string

	for _, msg := range messages {
		ids = append(ids, msg.ID)

		if data, ok := msg.Values["data"].(string); ok {
			var entry LogEntry
			if err := json.Unmarshal([]byte(data), &entry); err == nil {
				entries = append(entries, entry)
			}
		}
	}

	// Remove processed entries
	if len(ids) > 0 {
		r.client.XDel(ctx, PrefixLogBuffer, ids...)
	}

	return entries, nil
}

// GetLogBufferSize returns the number of entries in the log buffer
func (r *RedisClient) GetLogBufferSize(ctx context.Context) (int64, error) {
	if !r.IsReady() {
		return 0, ErrNotReady
	}

	return r.client.XLen(ctx, PrefixLogBuffer).Result()
}

// ========================================
// Health Check
// ========================================

// Health returns cache health status
func (r *RedisClient) Health(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	return r.client.Ping(ctx).Err()
}

// Stats returns cache statistics
func (r *RedisClient) Stats(ctx context.Context) (map[string]interface{}, error) {
	if !r.IsReady() {
		return map[string]interface{}{
			"status": "not_ready",
		}, nil
	}

	info, err := r.client.Info(ctx, "memory", "stats", "clients").Result()
	if err != nil {
		return nil, err
	}

	// Parse basic stats
	stats := map[string]interface{}{
		"status": "ready",
		"raw":    info,
	}

	// Count banned IPs
	globalBanned, _ := r.client.SCard(ctx, PrefixBannedIP+"global").Result()
	stats["banned_ips_global"] = globalBanned

	// Log buffer size
	logBufferSize, _ := r.GetLogBufferSize(ctx)
	stats["log_buffer_size"] = logBufferSize

	return stats, nil
}

// ========================================
// URI Block Cache Operations
// ========================================

// URIBlockEntry represents a cached URI block rule
type URIBlockEntry struct {
	HostID          string   `json:"host_id"`
	Enabled         bool     `json:"enabled"`
	AllowPrivateIPs bool     `json:"allow_private_ips"`
	ExceptionIPs    []string `json:"exception_ips"`
	Patterns        []URIBlockPattern `json:"patterns"`
}

// URIBlockPattern represents a URI block pattern
type URIBlockPattern struct {
	Pattern   string `json:"pattern"`
	MatchType string `json:"match_type"` // exact, prefix, regex
	Enabled   bool   `json:"enabled"`
}

// SetURIBlock caches URI block rules for a host
func (r *RedisClient) SetURIBlock(ctx context.Context, hostID string, entry *URIBlockEntry) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixURIBlock+hostID, data, 24*time.Hour).Err()
}

// GetURIBlock retrieves cached URI block rules for a host
func (r *RedisClient) GetURIBlock(ctx context.Context, hostID string) (*URIBlockEntry, error) {
	if !r.IsReady() {
		return nil, ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixURIBlock+hostID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}

	var entry URIBlockEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// DeleteURIBlock removes cached URI block rules for a host
func (r *RedisClient) DeleteURIBlock(ctx context.Context, hostID string) error {
	if !r.IsReady() {
		return ErrNotReady
	}
	return r.client.Del(ctx, PrefixURIBlock+hostID).Err()
}

// InvalidateAllURIBlocks removes all cached URI block rules
func (r *RedisClient) InvalidateAllURIBlocks(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	keys, err := r.client.Keys(ctx, PrefixURIBlock+"*").Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}
	return nil
}

// ========================================
// Dashboard Cache Operations
// ========================================

const (
	PrefixDashboard      = "dashboard:"
	PrefixGeoIP          = "geoip:"
	PrefixProxyHost      = "proxy_host:"
	PrefixJWTBlacklist   = "jwt_blacklist:"
	PrefixAPIRateLimit   = "api_rate:"
	PrefixSystemSettings = "system_settings:"
	PrefixGlobalSettings = "global_settings:"
	PrefixExploitRules   = "exploit_rules:"
	PrefixWAFExclusions  = "waf_exclusions:"
)

// DashboardCacheTTL is the default TTL for dashboard cache
const DashboardCacheTTL = 30 * time.Second

// SetDashboardSummary caches dashboard summary
func (r *RedisClient) SetDashboardSummary(ctx context.Context, summary interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixDashboard+"summary", data, DashboardCacheTTL).Err()
}

// GetDashboardSummary retrieves cached dashboard summary
func (r *RedisClient) GetDashboardSummary(ctx context.Context, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixDashboard+"summary").Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// SetGeoIPStats caches GeoIP statistics
func (r *RedisClient) SetGeoIPStats(ctx context.Context, hours int, stats interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(stats)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%sstats:%d", PrefixGeoIP, hours)
	return r.client.Set(ctx, key, data, time.Minute).Err()
}

// GetGeoIPStats retrieves cached GeoIP statistics
func (r *RedisClient) GetGeoIPStats(ctx context.Context, hours int, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	key := fmt.Sprintf("%sstats:%d", PrefixGeoIP, hours)
	data, err := r.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// ========================================
// GeoIP Lookup Cache Operations
// ========================================

// GeoIPResult represents cached GeoIP lookup result
type GeoIPResult struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	City        string `json:"city"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
}

// SetGeoIPLookup caches GeoIP lookup result for an IP
func (r *RedisClient) SetGeoIPLookup(ctx context.Context, ip string, result *GeoIPResult) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	// Cache for 1 hour
	return r.client.Set(ctx, PrefixGeoIP+"ip:"+ip, data, time.Hour).Err()
}

// GetGeoIPLookup retrieves cached GeoIP lookup result for an IP
func (r *RedisClient) GetGeoIPLookup(ctx context.Context, ip string) (*GeoIPResult, error) {
	if !r.IsReady() {
		return nil, ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixGeoIP+"ip:"+ip).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}

	var result GeoIPResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ========================================
// Proxy Host Config Cache Operations
// ========================================

// SetProxyHostConfig caches proxy host configuration
func (r *RedisClient) SetProxyHostConfig(ctx context.Context, hostID string, config interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// Cache for 5 minutes
	return r.client.Set(ctx, PrefixProxyHost+"config:"+hostID, data, 5*time.Minute).Err()
}

// GetProxyHostConfig retrieves cached proxy host configuration
func (r *RedisClient) GetProxyHostConfig(ctx context.Context, hostID string, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixProxyHost+"config:"+hostID).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// InvalidateProxyHostConfig removes cached proxy host configuration
func (r *RedisClient) InvalidateProxyHostConfig(ctx context.Context, hostID string) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	keys := []string{
		PrefixProxyHost + "config:" + hostID,
		PrefixProxyHost + "security:" + hostID,
	}
	return r.client.Del(ctx, keys...).Err()
}

// InvalidateAllProxyHostConfigs removes all cached proxy host configurations
func (r *RedisClient) InvalidateAllProxyHostConfigs(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	keys, err := r.client.Keys(ctx, PrefixProxyHost+"*").Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}
	return nil
}

// ========================================
// JWT Token Blacklist Operations
// ========================================

// BlacklistJWTToken adds a JWT token to the blacklist (for logout)
func (r *RedisClient) BlacklistJWTToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	// Calculate TTL until token would naturally expire
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	return r.client.Set(ctx, PrefixJWTBlacklist+tokenID, "1", ttl).Err()
}

// IsJWTTokenBlacklisted checks if a JWT token is blacklisted
func (r *RedisClient) IsJWTTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if !r.IsReady() {
		return false, ErrNotReady
	}

	exists, err := r.client.Exists(ctx, PrefixJWTBlacklist+tokenID).Result()
	if err != nil {
		return false, err
	}

	return exists > 0, nil
}

// ========================================
// API Rate Limiting Operations
// ========================================

// APIRateLimitResult contains API rate limit check result
type APIRateLimitResult struct {
	Allowed    bool
	Current    int64
	Limit      int64
	Remaining  int64
	ResetAt    time.Time
	RetryAfter time.Duration
}

// CheckAPIRateLimit checks API rate limit for a key (user ID, API token, or IP)
func (r *RedisClient) CheckAPIRateLimit(ctx context.Context, key string, limit int64, window time.Duration) (*APIRateLimitResult, error) {
	if !r.IsReady() {
		// If cache is not ready, allow the request
		return &APIRateLimitResult{Allowed: true, Limit: limit, Remaining: limit}, nil
	}

	now := time.Now()
	windowKey := fmt.Sprintf("%s%s:%d", PrefixAPIRateLimit, key, now.Unix()/int64(window.Seconds()))

	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, windowKey)
	pipe.Expire(ctx, windowKey, window+time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	current := incrCmd.Val()
	allowed := current <= limit
	remaining := limit - current
	if remaining < 0 {
		remaining = 0
	}

	resetAt := now.Truncate(window).Add(window)
	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = time.Until(resetAt)
	}

	return &APIRateLimitResult{
		Allowed:    allowed,
		Current:    current,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfter,
	}, nil
}

// ========================================
// Cache Statistics Operations
// ========================================

// GetCacheStats returns detailed cache statistics
func (r *RedisClient) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	if !r.IsReady() {
		return map[string]interface{}{
			"status": "not_ready",
		}, nil
	}

	stats := map[string]interface{}{
		"status": "ready",
	}

	// Get memory info
	memInfo, err := r.client.Info(ctx, "memory").Result()
	if err == nil {
		stats["memory_info"] = memInfo
	}

	// Count keys by prefix
	prefixes := []string{
		PrefixBannedIP, PrefixRateLimit, PrefixFail2ban, PrefixWAFCounter,
		PrefixConfig, PrefixSession, PrefixLogBuffer, PrefixURIBlock,
		PrefixDashboard, PrefixGeoIP, PrefixProxyHost, PrefixJWTBlacklist, PrefixAPIRateLimit,
	}

	keyCounts := make(map[string]int64)
	for _, prefix := range prefixes {
		keys, _ := r.client.Keys(ctx, prefix+"*").Result()
		keyCounts[prefix] = int64(len(keys))
	}
	stats["key_counts"] = keyCounts

	// Get total keys
	dbSize, _ := r.client.DBSize(ctx).Result()
	stats["total_keys"] = dbSize

	// Log buffer size
	logBufferSize, _ := r.GetLogBufferSize(ctx)
	stats["log_buffer_size"] = logBufferSize

	// Banned IPs count
	globalBanned, _ := r.client.SCard(ctx, PrefixBannedIP+"global").Result()
	stats["banned_ips_global"] = globalBanned

	return stats, nil
}

// Helper functions
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ParseIPFromRequest extracts the client IP considering proxies
func ParseIPFromRequest(remoteAddr string, xForwardedFor string, xRealIP string) string {
	// Prefer X-Real-IP if set
	if xRealIP != "" {
		return xRealIP
	}

	// Try X-Forwarded-For (first IP is the client)
	if xForwardedFor != "" {
		parts := strings.Split(xForwardedFor, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Fall back to remote address
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// Distributed Lock Operations

// AcquireLock attempts to acquire a distributed lock with the given key and TTL.
// Returns true if the lock was acquired, false if already held by another process.
// The lockValue should be a unique identifier (e.g., hostname + PID) for the lock holder.
func (r *RedisClient) AcquireLock(ctx context.Context, lockKey string, lockValue string, ttl time.Duration) (bool, error) {
	if !r.IsReady() {
		return false, ErrNotReady
	}

	key := PrefixLock + lockKey
	ok, err := r.client.SetNX(ctx, key, lockValue, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return ok, nil
}

// ReleaseLock releases a distributed lock only if the caller owns it.
// This uses a Lua script for atomic check-and-delete.
func (r *RedisClient) ReleaseLock(ctx context.Context, lockKey string, lockValue string) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	key := PrefixLock + lockKey

	// Lua script to atomically check value and delete
	script := redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`)

	_, err := script.Run(ctx, r.client, []string{key}, lockValue).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	return nil
}

// ExtendLock extends the TTL of a lock if the caller owns it.
func (r *RedisClient) ExtendLock(ctx context.Context, lockKey string, lockValue string, ttl time.Duration) (bool, error) {
	if !r.IsReady() {
		return false, ErrNotReady
	}

	key := PrefixLock + lockKey

	// Lua script to atomically check value and extend TTL
	script := redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("pexpire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`)

	result, err := script.Run(ctx, r.client, []string{key}, lockValue, ttl.Milliseconds()).Int()
	if err != nil && err != redis.Nil {
		return false, fmt.Errorf("failed to extend lock: %w", err)
	}

	return result == 1, nil
}

// ========================================
// System Settings Cache Operations
// ========================================

// SystemSettingsCacheTTL is the default TTL for system settings cache
const SystemSettingsCacheTTL = 5 * time.Minute

// SetSystemSettings caches system settings
func (r *RedisClient) SetSystemSettings(ctx context.Context, settings interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixSystemSettings+"main", data, SystemSettingsCacheTTL).Err()
}

// GetSystemSettings retrieves cached system settings
func (r *RedisClient) GetSystemSettings(ctx context.Context, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixSystemSettings+"main").Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// InvalidateSystemSettings removes cached system settings
func (r *RedisClient) InvalidateSystemSettings(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}
	return r.client.Del(ctx, PrefixSystemSettings+"main").Err()
}

// ========================================
// Global Settings Cache Operations
// ========================================

// GlobalSettingsCacheTTL is the default TTL for global settings cache
const GlobalSettingsCacheTTL = 5 * time.Minute

// SetGlobalSettings caches global nginx settings
func (r *RedisClient) SetGlobalSettings(ctx context.Context, settings interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixGlobalSettings+"main", data, GlobalSettingsCacheTTL).Err()
}

// GetGlobalSettings retrieves cached global nginx settings
func (r *RedisClient) GetGlobalSettings(ctx context.Context, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixGlobalSettings+"main").Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// InvalidateGlobalSettings removes cached global nginx settings
func (r *RedisClient) InvalidateGlobalSettings(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}
	return r.client.Del(ctx, PrefixGlobalSettings+"main").Err()
}

// ========================================
// Exploit Block Rules Cache Operations
// ========================================

// ExploitRulesCacheTTL is the default TTL for exploit rules cache
const ExploitRulesCacheTTL = 10 * time.Minute

// SetExploitRules caches all exploit blocking rules
func (r *RedisClient) SetExploitRules(ctx context.Context, rules interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixExploitRules+"all", data, ExploitRulesCacheTTL).Err()
}

// GetExploitRules retrieves cached exploit blocking rules
func (r *RedisClient) GetExploitRules(ctx context.Context, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixExploitRules+"all").Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// SetEnabledExploitRules caches only enabled exploit rules (for nginx config generation)
func (r *RedisClient) SetEnabledExploitRules(ctx context.Context, rules interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixExploitRules+"enabled", data, ExploitRulesCacheTTL).Err()
}

// GetEnabledExploitRules retrieves cached enabled exploit rules
func (r *RedisClient) GetEnabledExploitRules(ctx context.Context, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixExploitRules+"enabled").Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// InvalidateExploitRules removes all cached exploit rules
func (r *RedisClient) InvalidateExploitRules(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	keys := []string{
		PrefixExploitRules + "all",
		PrefixExploitRules + "enabled",
	}
	return r.client.Del(ctx, keys...).Err()
}

// ========================================
// WAF Exclusions Cache Operations
// ========================================

// WAFExclusionsCacheTTL is the default TTL for WAF exclusions cache
const WAFExclusionsCacheTTL = 10 * time.Minute

// SetGlobalExploitExclusions caches global exploit rule exclusions
func (r *RedisClient) SetGlobalExploitExclusions(ctx context.Context, exclusions interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(exclusions)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixWAFExclusions+"global", data, WAFExclusionsCacheTTL).Err()
}

// GetGlobalExploitExclusions retrieves cached global exploit rule exclusions
func (r *RedisClient) GetGlobalExploitExclusions(ctx context.Context, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixWAFExclusions+"global").Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// SetHostExploitExclusions caches per-host exploit rule exclusions
func (r *RedisClient) SetHostExploitExclusions(ctx context.Context, hostID string, exclusions interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := json.Marshal(exclusions)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, PrefixWAFExclusions+"host:"+hostID, data, WAFExclusionsCacheTTL).Err()
}

// GetHostExploitExclusions retrieves cached per-host exploit rule exclusions
func (r *RedisClient) GetHostExploitExclusions(ctx context.Context, hostID string, dest interface{}) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	data, err := r.client.Get(ctx, PrefixWAFExclusions+"host:"+hostID).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// InvalidateHostExploitExclusions removes cached per-host exploit exclusions
func (r *RedisClient) InvalidateHostExploitExclusions(ctx context.Context, hostID string) error {
	if !r.IsReady() {
		return ErrNotReady
	}
	return r.client.Del(ctx, PrefixWAFExclusions+"host:"+hostID).Err()
}

// InvalidateAllExploitExclusions removes all cached exploit exclusions
func (r *RedisClient) InvalidateAllExploitExclusions(ctx context.Context) error {
	if !r.IsReady() {
		return ErrNotReady
	}

	keys, err := r.client.Keys(ctx, PrefixWAFExclusions+"*").Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}
	return nil
}
