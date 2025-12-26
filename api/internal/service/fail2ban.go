package service

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// Fail2banService handles automatic IP banning based on HTTP error responses
type Fail2banService struct {
	db              *sql.DB
	rateLimitRepo   *repository.RateLimitRepository
	proxyHostRepo   *repository.ProxyHostRepository
	proxyHostService *ProxyHostService
	redisCache      *cache.RedisClient
	historyRepo     *repository.IPBanHistoryRepository

	// In-memory tracking of failed requests per IP per host (fallback when Redis unavailable)
	mu       sync.RWMutex
	ipEvents map[string]map[string][]time.Time // hostID -> IP -> list of fail timestamps

	// Cache of fail2ban configs per host
	configMu     sync.RWMutex
	configCache  map[string]*model.Fail2banConfig // hostID -> config
	lastConfigRefresh time.Time
}

// NewFail2banService creates a new Fail2ban service
func NewFail2banService(
	db *sql.DB,
	rateLimitRepo *repository.RateLimitRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	proxyHostService *ProxyHostService,
	redisCache *cache.RedisClient,
	historyRepo *repository.IPBanHistoryRepository,
) *Fail2banService {
	return &Fail2banService{
		db:               db,
		rateLimitRepo:    rateLimitRepo,
		proxyHostRepo:    proxyHostRepo,
		proxyHostService: proxyHostService,
		redisCache:       redisCache,
		historyRepo:      historyRepo,
		ipEvents:         make(map[string]map[string][]time.Time),
		configCache:      make(map[string]*model.Fail2banConfig),
	}
}

// Start begins the Fail2ban service background tasks
func (s *Fail2banService) Start(ctx context.Context) {
	// Load initial configs
	s.refreshConfigs(ctx)

	// Periodically refresh configs and cleanup old events
	configTicker := time.NewTicker(30 * time.Second)
	cleanupTicker := time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-ctx.Done():
				configTicker.Stop()
				cleanupTicker.Stop()
				return
			case <-configTicker.C:
				s.refreshConfigs(ctx)
			case <-cleanupTicker.C:
				s.cleanupOldEvents()
				s.cleanupExpiredBans(ctx)
			}
		}
	}()

	log.Println("[Fail2ban] Service started")
}

// refreshConfigs reloads fail2ban configs from database for all hosts
func (s *Fail2banService) refreshConfigs(ctx context.Context) {
	// Get all proxy hosts
	hosts, _, err := s.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
	if err != nil {
		log.Printf("[Fail2ban] Failed to list proxy hosts: %v", err)
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	// Clear old cache
	s.configCache = make(map[string]*model.Fail2banConfig)

	// Load config for each host
	for _, host := range hosts {
		if !host.Enabled {
			continue
		}
		config, err := s.rateLimitRepo.GetFail2banByProxyHostID(ctx, host.ID)
		if err != nil {
			continue
		}
		if config != nil && config.Enabled {
			s.configCache[host.ID] = config
		}
	}

	s.lastConfigRefresh = time.Now()
}

// getConfig returns the fail2ban config for a host (from cache)
func (s *Fail2banService) getConfig(hostID string) *model.Fail2banConfig {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.configCache[hostID]
}

// RecordFailedRequest records a failed request and checks if IP should be banned
func (s *Fail2banService) RecordFailedRequest(ctx context.Context, hostID string, clientIP string, statusCode int, uri string) {
	config := s.getConfig(hostID)
	if config == nil || !config.Enabled {
		return
	}

	// Check if status code is in fail_codes
	if !s.isFailCode(statusCode, config.FailCodes) {
		return
	}

	findTime := time.Duration(config.FindTime) * time.Second
	var eventCount int

	// Try Redis first for distributed counting
	if s.redisCache != nil && s.redisCache.IsReady() {
		key := fmt.Sprintf("fail2ban:%s:%s", hostID, clientIP)
		count, err := s.redisCache.IncrementCounter(ctx, key, findTime)
		if err == nil {
			eventCount = int(count)
		} else {
			// Fallback to in-memory on Redis error
			eventCount = s.recordFailedRequestInMemory(hostID, clientIP, findTime)
		}
	} else {
		// No Redis, use in-memory tracking
		eventCount = s.recordFailedRequestInMemory(hostID, clientIP, findTime)
	}

	// Check if threshold exceeded
	if eventCount >= config.MaxRetries {
		// Check if already banned (try cache first)
		if s.isIPBannedCached(ctx, clientIP, hostID) {
			return
		}

		// Get host domain for logging
		hostDomain := hostID
		host, err := s.proxyHostRepo.GetByID(ctx, hostID)
		if err == nil && host != nil && len(host.DomainNames) > 0 {
			hostDomain = host.DomainNames[0]
		}

		// Ban the IP
		reason := fmt.Sprintf("Fail2ban: %d failed requests (%d status) in %d seconds on %s",
			eventCount, statusCode, config.FindTime, hostDomain)

		if err := s.banIP(ctx, clientIP, hostID, reason, eventCount, config.BanTime, config.Action); err != nil {
			log.Printf("[Fail2ban] Failed to ban IP %s: %v", clientIP, err)
		} else {
			log.Printf("[Fail2ban] Banned IP %s on %s: %s", clientIP, hostDomain, reason)

			// Clear events for this IP after banning
			if s.redisCache != nil && s.redisCache.IsReady() {
				key := fmt.Sprintf("fail2ban:%s:%s", hostID, clientIP)
				s.redisCache.ResetCounter(ctx, key)
			}
			s.mu.Lock()
			delete(s.ipEvents[hostID], clientIP)
			s.mu.Unlock()
		}
	}
}

// recordFailedRequestInMemory is the fallback when Redis is unavailable
func (s *Fail2banService) recordFailedRequestInMemory(hostID string, clientIP string, findTime time.Duration) int {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Initialize host map if needed
	if s.ipEvents[hostID] == nil {
		s.ipEvents[hostID] = make(map[string][]time.Time)
	}

	// Add new event
	s.ipEvents[hostID][clientIP] = append(s.ipEvents[hostID][clientIP], now)

	// Filter to only events within the find_time window
	windowStart := now.Add(-findTime)
	var recentEvents []time.Time
	for _, t := range s.ipEvents[hostID][clientIP] {
		if t.After(windowStart) {
			recentEvents = append(recentEvents, t)
		}
	}
	s.ipEvents[hostID][clientIP] = recentEvents

	return len(recentEvents)
}

// isIPBannedCached checks ban status with cache first
func (s *Fail2banService) isIPBannedCached(ctx context.Context, ip string, hostID string) bool {
	// Try Redis cache first
	if s.redisCache != nil && s.redisCache.IsReady() {
		banned, err := s.redisCache.IsBannedIPForHost(ctx, ip, hostID)
		if err == nil {
			return banned
		}
		// Fall through to DB check on cache error
	}

	// Fallback to database
	return s.isIPBanned(ctx, ip, hostID)
}

// isFailCode checks if the status code is in the fail_codes list
func (s *Fail2banService) isFailCode(statusCode int, failCodes string) bool {
	codes := strings.Split(failCodes, ",")
	for _, code := range codes {
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}
		if c, err := strconv.Atoi(code); err == nil && c == statusCode {
			return true
		}
	}
	return false
}

// isIPBanned checks if an IP is already banned for a specific host
func (s *Fail2banService) isIPBanned(ctx context.Context, ip string, hostID string) bool {
	query := `
		SELECT COUNT(*) FROM banned_ips
		WHERE ip_address = $1
		AND (proxy_host_id = $2 OR proxy_host_id IS NULL)
		AND (expires_at IS NULL OR expires_at > NOW())
	`
	var count int
	err := s.db.QueryRowContext(ctx, query, ip, hostID).Scan(&count)
	if err != nil {
		log.Printf("[Fail2ban] Error checking banned IP: %v", err)
		return false
	}
	return count > 0
}

// banIP adds an IP to the banned list
func (s *Fail2banService) banIP(ctx context.Context, ip string, hostID string, reason string, failCount int, banTime int, action string) error {
	// If action is "log", just log and don't ban
	if action == "log" {
		log.Printf("[Fail2ban] Would ban IP %s (action=log): %s", ip, reason)
		return nil
	}

	id := uuid.New().String()
	now := time.Now()

	var expiresAt *time.Time
	isPermanent := false
	var ttl time.Duration

	if banTime > 0 {
		exp := now.Add(time.Duration(banTime) * time.Second)
		expiresAt = &exp
		ttl = time.Duration(banTime) * time.Second
	} else {
		isPermanent = true
		ttl = 0 // No TTL for permanent bans
	}

	// Fail2ban creates host-specific bans
	// Uses partial unique index idx_banned_ips_ip_host_unique
	// Note: fail_count is replaced, not accumulated to prevent unbounded growth
	query := `
		INSERT INTO banned_ips (id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, is_auto_banned, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $6)
		ON CONFLICT (ip_address, proxy_host_id) WHERE proxy_host_id IS NOT NULL DO UPDATE SET
			reason = EXCLUDED.reason,
			fail_count = EXCLUDED.fail_count,
			banned_at = EXCLUDED.banned_at,
			expires_at = EXCLUDED.expires_at,
			is_permanent = EXCLUDED.is_permanent,
			is_auto_banned = true
	`

	_, err := s.db.ExecContext(ctx, query, id, hostID, ip, reason, failCount, now, expiresAt, isPermanent)
	if err != nil {
		return fmt.Errorf("failed to insert banned IP: %w", err)
	}

	// Add to Redis cache for fast lookup
	if s.redisCache != nil && s.redisCache.IsReady() {
		if err := s.redisCache.AddBannedIP(ctx, ip, hostID, ttl); err != nil {
			log.Printf("[Fail2ban] Warning: Failed to add banned IP to cache: %v", err)
		}
	}

	// Record ban history
	if s.historyRepo != nil {
		domainName := ""
		host, err := s.proxyHostRepo.GetByID(ctx, hostID)
		if err == nil && host != nil && len(host.DomainNames) > 0 {
			domainName = host.DomainNames[0]
		}

		historyEvent := &model.IPBanHistory{
			EventType:   model.BanEventTypeBan,
			IPAddress:   ip,
			ProxyHostID: &hostID,
			DomainName:  domainName,
			Reason:      reason,
			Source:      model.BanSourceFail2ban,
			BanDuration: &banTime,
			ExpiresAt:   expiresAt,
			IsPermanent: isPermanent,
			IsAuto:      true,
			FailCount:   &failCount,
		}
		if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
			log.Printf("[Fail2ban] Warning: Failed to record ban history: %v", err)
		}
	}

	// Regenerate nginx config to apply the ban (async for speed)
	if s.proxyHostService != nil {
		go func() {
			bgCtx := context.Background()
			if _, err := s.proxyHostService.Update(bgCtx, hostID, &model.UpdateProxyHostRequest{}); err != nil {
				log.Printf("[Fail2ban] Warning: Failed to regenerate nginx config: %v", err)
			}
		}()
	}

	return nil
}

// cleanupOldEvents removes events outside the tracking window
func (s *Fail2banService) cleanupOldEvents() {
	s.configMu.RLock()
	configs := make(map[string]*model.Fail2banConfig)
	for k, v := range s.configCache {
		configs[k] = v
	}
	s.configMu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	for hostID, ipMap := range s.ipEvents {
		config := configs[hostID]
		if config == nil {
			// No config, cleanup all events for this host
			delete(s.ipEvents, hostID)
			continue
		}

		findTime := time.Duration(config.FindTime) * time.Second
		windowStart := time.Now().Add(-findTime)

		for ip, events := range ipMap {
			var recent []time.Time
			for _, t := range events {
				if t.After(windowStart) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(ipMap, ip)
			} else {
				ipMap[ip] = recent
			}
		}

		if len(ipMap) == 0 {
			delete(s.ipEvents, hostID)
		}
	}
}

// cleanupExpiredBans removes expired bans from the database
func (s *Fail2banService) cleanupExpiredBans(ctx context.Context) {
	// First, get all expired bans before deleting them (for history recording)
	selectQuery := `
		SELECT id, proxy_host_id, ip_address, reason
		FROM banned_ips
		WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_auto_banned = true
	`
	rows, err := s.db.QueryContext(ctx, selectQuery)
	if err != nil {
		log.Printf("[Fail2ban] Failed to query expired bans: %v", err)
		return
	}

	type expiredBan struct {
		id          string
		proxyHostID sql.NullString
		ipAddress   string
		reason      string
	}

	var expiredBans []expiredBan
	var affectedHostIDs []string
	affectedHostMap := make(map[string]bool)
	hasGlobalBan := false

	for rows.Next() {
		var ban expiredBan
		var reason sql.NullString
		if err := rows.Scan(&ban.id, &ban.proxyHostID, &ban.ipAddress, &reason); err != nil {
			continue
		}
		ban.reason = reason.String
		expiredBans = append(expiredBans, ban)

		if ban.proxyHostID.Valid && ban.proxyHostID.String != "" {
			if !affectedHostMap[ban.proxyHostID.String] {
				affectedHostMap[ban.proxyHostID.String] = true
				affectedHostIDs = append(affectedHostIDs, ban.proxyHostID.String)
			}
		} else {
			hasGlobalBan = true
		}
	}
	rows.Close()

	if len(expiredBans) == 0 {
		return // No expired bans
	}

	// Record unban history for each expired ban
	if s.historyRepo != nil {
		for _, ban := range expiredBans {
			var hostID *string
			if ban.proxyHostID.Valid {
				hostID = &ban.proxyHostID.String
			}
			historyEvent := &model.IPBanHistory{
				EventType:   model.BanEventTypeUnban,
				IPAddress:   ban.ipAddress,
				ProxyHostID: hostID,
				Reason:      "Ban expired",
				Source:      model.BanSourceExpired,
				IsAuto:      true,
			}
			if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
				log.Printf("[Fail2ban] Warning: Failed to record unban history for %s: %v", ban.ipAddress, err)
			}
		}
	}

	// Delete expired bans
	deleteQuery := `DELETE FROM banned_ips WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_auto_banned = true`
	result, err := s.db.ExecContext(ctx, deleteQuery)
	if err != nil {
		log.Printf("[Fail2ban] Failed to cleanup expired bans: %v", err)
		return
	}

	deletedRows, _ := result.RowsAffected()
	if deletedRows > 0 {
		log.Printf("[Fail2ban] Cleaned up %d expired bans", deletedRows)
	}

	// Regenerate nginx configs for affected hosts
	if s.proxyHostService == nil {
		return
	}

	if hasGlobalBan {
		// Global ban expired - need to regenerate all enabled proxy hosts
		hosts, _, err := s.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
		if err != nil {
			log.Printf("[Fail2ban] Failed to list proxy hosts for config regeneration: %v", err)
			return
		}
		for _, host := range hosts {
			if host.Enabled {
				if _, err := s.proxyHostService.Update(ctx, host.ID, &model.UpdateProxyHostRequest{}); err != nil {
					log.Printf("[Fail2ban] Warning: Failed to regenerate nginx config for host %s: %v", host.ID, err)
				}
			}
		}
		log.Printf("[Fail2ban] Regenerated nginx configs for all hosts after global ban expiry")
	} else {
		// Regenerate only affected hosts
		for _, hostID := range affectedHostIDs {
			if _, err := s.proxyHostService.Update(ctx, hostID, &model.UpdateProxyHostRequest{}); err != nil {
				log.Printf("[Fail2ban] Warning: Failed to regenerate nginx config for host %s: %v", hostID, err)
			}
		}
		if len(affectedHostIDs) > 0 {
			log.Printf("[Fail2ban] Regenerated nginx configs for %d affected hosts", len(affectedHostIDs))
		}
	}
}

// GetStats returns current fail2ban statistics
func (s *Fail2banService) GetStats() map[string]interface{} {
	s.configMu.RLock()
	enabledHosts := len(s.configCache)
	s.configMu.RUnlock()

	s.mu.RLock()
	trackedIPs := 0
	for _, ipMap := range s.ipEvents {
		trackedIPs += len(ipMap)
	}
	s.mu.RUnlock()

	return map[string]interface{}{
		"enabled_hosts": enabledHosts,
		"tracked_ips":   trackedIPs,
	}
}
