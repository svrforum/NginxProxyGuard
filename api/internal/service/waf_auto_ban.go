package service

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// WAFAutoBanService handles automatic IP banning based on WAF events
type WAFAutoBanService struct {
	db               *sql.DB
	systemSettingsRepo *repository.SystemSettingsRepository
	rateLimitRepo    *repository.RateLimitRepository
	proxyHostRepo    *repository.ProxyHostRepository
	proxyHostService *ProxyHostService
	historyRepo      *repository.IPBanHistoryRepository

	// In-memory tracking of WAF events per IP
	mu          sync.RWMutex
	ipEvents    map[string][]time.Time // IP -> list of event timestamps

	// Settings cache
	settingsMu      sync.RWMutex
	enabled         bool
	threshold       int
	windowSeconds   int
	durationSeconds int
	lastSettingsCheck time.Time
}

// NewWAFAutoBanService creates a new WAF auto-ban service
func NewWAFAutoBanService(
	db *sql.DB,
	systemSettingsRepo *repository.SystemSettingsRepository,
	rateLimitRepo *repository.RateLimitRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	proxyHostService *ProxyHostService,
	historyRepo *repository.IPBanHistoryRepository,
) *WAFAutoBanService {
	return &WAFAutoBanService{
		db:                 db,
		systemSettingsRepo: systemSettingsRepo,
		rateLimitRepo:      rateLimitRepo,
		proxyHostRepo:      proxyHostRepo,
		proxyHostService:   proxyHostService,
		historyRepo:        historyRepo,
		ipEvents:           make(map[string][]time.Time),
		threshold:          10,
		windowSeconds:      300,
		durationSeconds:    3600,
	}
}

// Start begins the auto-ban service background tasks
func (s *WAFAutoBanService) Start(ctx context.Context) {
	// Load initial settings
	s.refreshSettings(ctx)

	// Periodically refresh settings and cleanup old events
	ticker := time.NewTicker(30 * time.Second)
	cleanupTicker := time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				cleanupTicker.Stop()
				return
			case <-ticker.C:
				s.refreshSettings(ctx)
			case <-cleanupTicker.C:
				s.cleanupOldEvents()
				s.cleanupExpiredBans(ctx)
			}
		}
	}()

	log.Println("[WAF Auto-Ban] Service started")
}

// refreshSettings reloads settings from database
func (s *WAFAutoBanService) refreshSettings(ctx context.Context) {
	settings, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[WAF Auto-Ban] Failed to load settings: %v", err)
		return
	}

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	s.enabled = settings.WAFAutoBanEnabled
	s.threshold = settings.WAFAutoBanThreshold
	s.windowSeconds = settings.WAFAutoBanWindow
	s.durationSeconds = settings.WAFAutoBanDuration
	s.lastSettingsCheck = time.Now()

	if s.threshold < 1 {
		s.threshold = 10
	}
	if s.windowSeconds < 1 {
		s.windowSeconds = 300
	}
}

// RecordWAFEvent records a WAF event for an IP and checks if it should be banned
func (s *WAFAutoBanService) RecordWAFEvent(ctx context.Context, clientIP string, host string, ruleID int, ruleMessage string) {
	s.settingsMu.RLock()
	enabled := s.enabled
	threshold := s.threshold
	windowSeconds := s.windowSeconds
	durationSeconds := s.durationSeconds
	s.settingsMu.RUnlock()

	if !enabled {
		return
	}

	now := time.Now()
	windowStart := now.Add(-time.Duration(windowSeconds) * time.Second)

	s.mu.Lock()

	// Add new event
	s.ipEvents[clientIP] = append(s.ipEvents[clientIP], now)

	// Filter to only events within the window
	var recentEvents []time.Time
	for _, t := range s.ipEvents[clientIP] {
		if t.After(windowStart) {
			recentEvents = append(recentEvents, t)
		}
	}
	s.ipEvents[clientIP] = recentEvents
	eventCount := len(recentEvents)

	s.mu.Unlock()

	// Check if threshold exceeded
	if eventCount >= threshold {
		// Check if already banned
		if s.isIPBanned(ctx, clientIP) {
			return
		}

		// Ban the IP
		reason := fmt.Sprintf("Auto-banned: %d WAF events in %d seconds (last: rule %d - %s)",
			eventCount, windowSeconds, ruleID, truncateStringWithEllipsis(ruleMessage, 100))

		if err := s.banIP(ctx, clientIP, host, reason, eventCount, durationSeconds); err != nil {
			log.Printf("[WAF Auto-Ban] Failed to ban IP %s: %v", clientIP, err)
		} else {
			log.Printf("[WAF Auto-Ban] Banned IP %s: %s", clientIP, reason)

			// Clear events for this IP after banning
			s.mu.Lock()
			delete(s.ipEvents, clientIP)
			s.mu.Unlock()
		}
	}
}

// isIPBanned checks if an IP is already banned
func (s *WAFAutoBanService) isIPBanned(ctx context.Context, ip string) bool {
	query := `
		SELECT COUNT(*) FROM banned_ips
		WHERE ip_address = $1
		AND (expires_at IS NULL OR expires_at > NOW())
	`
	var count int
	err := s.db.QueryRowContext(ctx, query, ip).Scan(&count)
	if err != nil {
		log.Printf("[WAF Auto-Ban] Error checking banned IP: %v", err)
		return false
	}
	return count > 0
}

// banIP adds an IP to the banned list
func (s *WAFAutoBanService) banIP(ctx context.Context, ip string, host string, reason string, failCount int, durationSeconds int) error {
	id := uuid.New().String()
	now := time.Now()

	var expiresAt *time.Time
	isPermanent := false

	if durationSeconds > 0 {
		exp := now.Add(time.Duration(durationSeconds) * time.Second)
		expiresAt = &exp
	} else {
		isPermanent = true
	}

	// WAF auto-ban creates global bans (proxy_host_id = NULL)
	// Uses partial unique index idx_banned_ips_ip_global_unique
	query := `
		INSERT INTO banned_ips (id, ip_address, proxy_host_id, reason, fail_count, banned_at, expires_at, is_permanent, is_auto_banned, created_at)
		VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, true, $5)
		ON CONFLICT (ip_address) WHERE proxy_host_id IS NULL DO UPDATE SET
			reason = EXCLUDED.reason,
			fail_count = EXCLUDED.fail_count,
			banned_at = EXCLUDED.banned_at,
			expires_at = EXCLUDED.expires_at,
			is_permanent = EXCLUDED.is_permanent,
			is_auto_banned = true
	`

	_, err := s.db.ExecContext(ctx, query, id, ip, reason, failCount, now, expiresAt, isPermanent)
	if err != nil {
		return fmt.Errorf("failed to insert banned IP: %w", err)
	}

	// Record ban history
	if s.historyRepo != nil {
		historyEvent := &model.IPBanHistory{
			EventType:   model.BanEventTypeBan,
			IPAddress:   ip,
			DomainName:  host,
			Reason:      reason,
			Source:      model.BanSourceWAFAutoBan,
			BanDuration: &durationSeconds,
			ExpiresAt:   expiresAt,
			IsPermanent: isPermanent,
			IsAuto:      true,
			FailCount:   &failCount,
		}
		if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
			log.Printf("[WAF Auto-Ban] Warning: Failed to record ban history: %v", err)
		}
	}

	// Regenerate nginx configs for all enabled hosts (global ban)
	if s.proxyHostService != nil && s.proxyHostRepo != nil {
		hosts, _, err := s.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
		if err != nil {
			log.Printf("[WAF Auto-Ban] Warning: Failed to list proxy hosts: %v", err)
			return nil
		}

		for _, h := range hosts {
			if h.Enabled {
				if _, err := s.proxyHostService.Update(ctx, h.ID, nil); err != nil {
					log.Printf("[WAF Auto-Ban] Warning: Failed to regenerate nginx config for host %s: %v", h.ID, err)
				}
			}
		}
	}

	return nil
}

// updateNginxDenyList regenerates the nginx deny configuration
func (s *WAFAutoBanService) updateNginxDenyList(ctx context.Context) error {
	// Get all active banned IPs
	query := `
		SELECT ip_address FROM banned_ips
		WHERE expires_at IS NULL OR expires_at > NOW()
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	// Write to nginx deny list file
	// This will be picked up by nginx includes
	denyConf := "# Auto-generated banned IPs - DO NOT EDIT\n"
	for _, ip := range ips {
		denyConf += fmt.Sprintf("deny %s;\n", ip)
	}

	// Write to shared nginx config volume
	// Note: In production, this should use the nginx manager
	// For now, we'll rely on the rate_limit repository's existing mechanism

	return nil
}

// cleanupOldEvents removes events outside the tracking window
func (s *WAFAutoBanService) cleanupOldEvents() {
	s.settingsMu.RLock()
	windowSeconds := s.windowSeconds
	s.settingsMu.RUnlock()

	windowStart := time.Now().Add(-time.Duration(windowSeconds) * time.Second)

	s.mu.Lock()
	defer s.mu.Unlock()

	for ip, events := range s.ipEvents {
		var recent []time.Time
		for _, t := range events {
			if t.After(windowStart) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(s.ipEvents, ip)
		} else {
			s.ipEvents[ip] = recent
		}
	}
}

// cleanupExpiredBans removes expired bans from the database and regenerates nginx configs
// Note: This only handles bans with proxy_host_id IS NULL (global bans from WAF)
// Fail2ban service handles bans with specific proxy_host_id
func (s *WAFAutoBanService) cleanupExpiredBans(ctx context.Context) {
	// Get expired global bans before deleting (for history recording)
	selectQuery := `
		SELECT id, ip_address, reason FROM banned_ips
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
		AND proxy_host_id IS NULL
	`
	rows, err := s.db.QueryContext(ctx, selectQuery)
	if err != nil {
		log.Printf("[WAF Auto-Ban] Failed to query expired bans: %v", err)
		return
	}

	type expiredBan struct {
		id        string
		ipAddress string
		reason    string
	}
	var expiredBans []expiredBan

	for rows.Next() {
		var ban expiredBan
		var reason sql.NullString
		if err := rows.Scan(&ban.id, &ban.ipAddress, &reason); err != nil {
			continue
		}
		ban.reason = reason.String
		expiredBans = append(expiredBans, ban)
	}
	rows.Close()

	if len(expiredBans) == 0 {
		return // No expired global bans
	}

	// Record unban history for each expired ban
	if s.historyRepo != nil {
		for _, ban := range expiredBans {
			historyEvent := &model.IPBanHistory{
				EventType: model.BanEventTypeUnban,
				IPAddress: ban.ipAddress,
				Reason:    "Ban expired",
				Source:    model.BanSourceExpired,
				IsAuto:    true,
			}
			if err := s.historyRepo.RecordBanEvent(ctx, historyEvent); err != nil {
				log.Printf("[WAF Auto-Ban] Warning: Failed to record unban history for %s: %v", ban.ipAddress, err)
			}
		}
	}

	// Delete expired global bans
	deleteQuery := `
		DELETE FROM banned_ips
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
		AND proxy_host_id IS NULL
	`
	result, err := s.db.ExecContext(ctx, deleteQuery)
	if err != nil {
		log.Printf("[WAF Auto-Ban] Failed to cleanup expired bans: %v", err)
		return
	}

	deletedRows, _ := result.RowsAffected()
	if deletedRows > 0 {
		log.Printf("[WAF Auto-Ban] Cleaned up %d expired global bans", deletedRows)

		// Regenerate nginx configs for all enabled hosts
		if s.proxyHostService != nil && s.proxyHostRepo != nil {
			hosts, _, err := s.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
			if err != nil {
				log.Printf("[WAF Auto-Ban] Failed to list proxy hosts: %v", err)
				return
			}

			regeneratedCount := 0
			for _, host := range hosts {
				if host.Enabled {
					if _, err := s.proxyHostService.Update(ctx, host.ID, nil); err != nil {
						log.Printf("[WAF Auto-Ban] Warning: Failed to regenerate nginx config for host %s: %v", host.ID, err)
					} else {
						regeneratedCount++
					}
				}
			}
			log.Printf("[WAF Auto-Ban] Regenerated nginx configs for %d hosts after ban expiry", regeneratedCount)
		}
	}
}

// GetStats returns current auto-ban statistics
func (s *WAFAutoBanService) GetStats() map[string]interface{} {
	s.settingsMu.RLock()
	enabled := s.enabled
	threshold := s.threshold
	windowSeconds := s.windowSeconds
	durationSeconds := s.durationSeconds
	s.settingsMu.RUnlock()

	s.mu.RLock()
	trackedIPs := len(s.ipEvents)
	s.mu.RUnlock()

	return map[string]interface{}{
		"enabled":          enabled,
		"threshold":        threshold,
		"window_seconds":   windowSeconds,
		"duration_seconds": durationSeconds,
		"tracked_ips":      trackedIPs,
	}
}

func truncateStringWithEllipsis(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
