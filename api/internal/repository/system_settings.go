package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"
)

type SystemSettingsRepository struct {
	db    *sql.DB
	cache *cache.RedisClient
}

func NewSystemSettingsRepository(db *sql.DB) *SystemSettingsRepository {
	return &SystemSettingsRepository{db: db}
}

// SetCache sets the cache client for the repository
func (r *SystemSettingsRepository) SetCache(c *cache.RedisClient) {
	r.cache = c
}

// Get retrieves the system settings (there should only be one row)
func (r *SystemSettingsRepository) Get(ctx context.Context) (*model.SystemSettings, error) {
	// Try cache first
	if r.cache != nil {
		var cached model.SystemSettings
		if err := r.cache.GetSystemSettings(ctx, &cached); err == nil {
			return &cached, nil
		}
	}

	return r.getFromDB(ctx)
}

// getFromDB retrieves settings from database and caches the result
func (r *SystemSettingsRepository) getFromDB(ctx context.Context) (*model.SystemSettings, error) {
	query := `
		SELECT id, geoip_enabled, maxmind_license_key, maxmind_account_id,
		       geoip_auto_update, geoip_update_interval, geoip_last_updated, geoip_database_version,
		       acme_enabled, acme_email, acme_staging, acme_auto_renew, acme_renew_days_before,
		       acme_dns_provider, acme_dns_credentials,
		       notification_email, notify_cert_expiry, notify_cert_expiry_days,
		       notify_security_events, notify_backup_complete,
		       log_retention_days, stats_retention_days, backup_retention_count,
		       auto_backup_enabled, auto_backup_schedule,
		       COALESCE(access_log_retention_days, 1095) as access_log_retention_days,
		       COALESCE(waf_log_retention_days, 90) as waf_log_retention_days,
		       COALESCE(error_log_retention_days, 30) as error_log_retention_days,
		       COALESCE(system_log_retention_days, 30) as system_log_retention_days,
		       COALESCE(audit_log_retention_days, 1095) as audit_log_retention_days,
		       COALESCE(raw_log_enabled, false) as raw_log_enabled,
		       COALESCE(raw_log_retention_days, 7) as raw_log_retention_days,
		       COALESCE(raw_log_max_size_mb, 100) as raw_log_max_size_mb,
		       COALESCE(raw_log_rotate_count, 5) as raw_log_rotate_count,
		       COALESCE(raw_log_compress_rotated, true) as raw_log_compress_rotated,
		       COALESCE(bot_filter_default_enabled, false) as bot_filter_default_enabled,
		       COALESCE(bot_filter_default_block_bad_bots, true) as bot_filter_default_block_bad_bots,
		       COALESCE(bot_filter_default_block_ai_bots, false) as bot_filter_default_block_ai_bots,
		       COALESCE(bot_filter_default_allow_search_engines, true) as bot_filter_default_allow_search_engines,
		       COALESCE(bot_filter_default_block_suspicious_clients, false) as bot_filter_default_block_suspicious_clients,
		       COALESCE(bot_filter_default_challenge_suspicious, false) as bot_filter_default_challenge_suspicious,
		       COALESCE(bot_filter_default_custom_blocked_agents, '') as bot_filter_default_custom_blocked_agents,
		       COALESCE(bot_list_bad_bots, '') as bot_list_bad_bots,
		       COALESCE(bot_list_ai_bots, '') as bot_list_ai_bots,
		       COALESCE(bot_list_search_engines, '') as bot_list_search_engines,
		       COALESCE(bot_list_suspicious_clients, '') as bot_list_suspicious_clients,
		       COALESCE(waf_auto_ban_enabled, false) as waf_auto_ban_enabled,
		       COALESCE(waf_auto_ban_threshold, 10) as waf_auto_ban_threshold,
		       COALESCE(waf_auto_ban_window, 300) as waf_auto_ban_window,
		       COALESCE(waf_auto_ban_duration, 3600) as waf_auto_ban_duration,
		       COALESCE(global_block_exploits_exceptions, '^/wp-json/
^/api/v1/challenge/
^/wp-admin/admin-ajax.php
^/webapi/') as global_block_exploits_exceptions,
		       COALESCE(direct_ip_access_action, 'allow') as direct_ip_access_action,
		       COALESCE(ui_font_family, 'system') as ui_font_family,
		       COALESCE(system_logs_enabled, true) as system_logs_enabled,
		       COALESCE(system_logs_levels, '{"npg-proxy": "info", "npg-api": "info", "npg-db": "warn", "npg-ui": "warn"}'::jsonb) as system_logs_levels,
		       COALESCE(system_logs_exclude_patterns, ARRAY['/health', '/nginx_status', '/.well-known/', 'HEAD /']) as system_logs_exclude_patterns,
		       COALESCE(system_logs_stdout_excluded, ARRAY['npg-proxy']) as system_logs_stdout_excluded,
		       created_at, updated_at
		FROM system_settings
		LIMIT 1
	`

	var settings model.SystemSettings
	var maxmindLicenseKey, maxmindAccountID, geoipDatabaseVersion sql.NullString
	var geoipLastUpdated sql.NullTime
	var acmeEmail, acmeDNSProvider, notificationEmail, autoBackupSchedule sql.NullString
	var acmeDNSCredentials []byte

	err := r.db.QueryRowContext(ctx, query).Scan(
		&settings.ID,
		&settings.GeoIPEnabled,
		&maxmindLicenseKey,
		&maxmindAccountID,
		&settings.GeoIPAutoUpdate,
		&settings.GeoIPUpdateInterval,
		&geoipLastUpdated,
		&geoipDatabaseVersion,
		&settings.ACMEEnabled,
		&acmeEmail,
		&settings.ACMEStaging,
		&settings.ACMEAutoRenew,
		&settings.ACMERenewDaysBefore,
		&acmeDNSProvider,
		&acmeDNSCredentials,
		&notificationEmail,
		&settings.NotifyCertExpiry,
		&settings.NotifyCertExpiryDays,
		&settings.NotifySecurityEvents,
		&settings.NotifyBackupComplete,
		&settings.LogRetentionDays,
		&settings.StatsRetentionDays,
		&settings.BackupRetentionCount,
		&settings.AutoBackupEnabled,
		&autoBackupSchedule,
		&settings.AccessLogRetentionDays,
		&settings.WAFLogRetentionDays,
		&settings.ErrorLogRetentionDays,
		&settings.SystemLogRetentionDays,
		&settings.AuditLogRetentionDays,
		&settings.RawLogEnabled,
		&settings.RawLogRetentionDays,
		&settings.RawLogMaxSizeMB,
		&settings.RawLogRotateCount,
		&settings.RawLogCompressRotated,
		&settings.BotFilterDefaultEnabled,
		&settings.BotFilterDefaultBlockBadBots,
		&settings.BotFilterDefaultBlockAIBots,
		&settings.BotFilterDefaultAllowSearchEngines,
		&settings.BotFilterDefaultBlockSuspiciousClients,
		&settings.BotFilterDefaultChallengeSuspicious,
		&settings.BotFilterDefaultCustomBlockedAgents,
		&settings.BotListBadBots,
		&settings.BotListAIBots,
		&settings.BotListSearchEngines,
		&settings.BotListSuspiciousClients,
		&settings.WAFAutoBanEnabled,
		&settings.WAFAutoBanThreshold,
		&settings.WAFAutoBanWindow,
		&settings.WAFAutoBanDuration,
		&settings.GlobalBlockExploitsExceptions,
		&settings.DirectIPAccessAction,
		&settings.UIFontFamily,
		&settings.SystemLogsEnabled,
		&settings.SystemLogsLevels,
		pq.Array(&settings.SystemLogsExcludePatterns),
		pq.Array(&settings.SystemLogsStdoutExcluded),
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return r.createDefault(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get system settings: %w", err)
	}

	// Handle nullable fields
	if maxmindLicenseKey.Valid {
		settings.MaxmindLicenseKey = maxmindLicenseKey.String
	}
	if maxmindAccountID.Valid {
		settings.MaxmindAccountID = maxmindAccountID.String
	}
	if geoipLastUpdated.Valid {
		settings.GeoIPLastUpdated = &geoipLastUpdated.Time
	}
	if geoipDatabaseVersion.Valid {
		settings.GeoIPDatabaseVersion = geoipDatabaseVersion.String
	}
	if acmeEmail.Valid {
		settings.ACMEEmail = acmeEmail.String
	}
	if acmeDNSProvider.Valid {
		settings.ACMEDNSProvider = acmeDNSProvider.String
	}
	if notificationEmail.Valid {
		settings.NotificationEmail = notificationEmail.String
	}
	if autoBackupSchedule.Valid {
		settings.AutoBackupSchedule = autoBackupSchedule.String
	}
	if len(acmeDNSCredentials) > 0 {
		settings.ACMEDNSCredentials = acmeDNSCredentials
	} else {
		settings.ACMEDNSCredentials = json.RawMessage("{}")
	}

	// Cache the result
	if r.cache != nil {
		if err := r.cache.SetSystemSettings(ctx, &settings); err != nil {
			log.Printf("[Cache] Failed to cache system settings: %v", err)
		}
	}

	return &settings, nil
}

// createDefault creates default system settings
func (r *SystemSettingsRepository) createDefault(ctx context.Context) (*model.SystemSettings, error) {
	query := `
		INSERT INTO system_settings (
			geoip_enabled, geoip_auto_update, geoip_update_interval,
			acme_enabled, acme_staging, acme_auto_renew, acme_renew_days_before,
			notify_cert_expiry, notify_cert_expiry_days, notify_security_events,
			log_retention_days, stats_retention_days, backup_retention_count,
			acme_dns_credentials
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, created_at, updated_at
	`

	settings := &model.SystemSettings{
		GeoIPEnabled:         false,
		GeoIPAutoUpdate:      true,
		GeoIPUpdateInterval:  "7d",
		ACMEEnabled:          true,
		ACMEStaging:          false,
		ACMEAutoRenew:        true,
		ACMERenewDaysBefore:  30,
		NotifyCertExpiry:     true,
		NotifyCertExpiryDays: 14,
		NotifySecurityEvents: true,
		LogRetentionDays:     30,
		StatsRetentionDays:   90,
		BackupRetentionCount: 10,
		ACMEDNSCredentials:   json.RawMessage("{}"),
	}

	err := r.db.QueryRowContext(ctx, query,
		settings.GeoIPEnabled, settings.GeoIPAutoUpdate, settings.GeoIPUpdateInterval,
		settings.ACMEEnabled, settings.ACMEStaging, settings.ACMEAutoRenew, settings.ACMERenewDaysBefore,
		settings.NotifyCertExpiry, settings.NotifyCertExpiryDays, settings.NotifySecurityEvents,
		settings.LogRetentionDays, settings.StatsRetentionDays, settings.BackupRetentionCount,
		settings.ACMEDNSCredentials,
	).Scan(&settings.ID, &settings.CreatedAt, &settings.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create default system settings: %w", err)
	}

	return settings, nil
}

// Update updates system settings
func (r *SystemSettingsRepository) Update(ctx context.Context, req *model.UpdateSystemSettingsRequest) (*model.SystemSettings, error) {
	settings, err := r.Get(ctx)
	if err != nil {
		return nil, err
	}

	// Build dynamic update query
	var setClauses []string
	var args []interface{}
	argIndex := 1

	if req.GeoIPEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("geoip_enabled = $%d", argIndex))
		args = append(args, *req.GeoIPEnabled)
		argIndex++
	}
	if req.MaxmindLicenseKey != nil {
		setClauses = append(setClauses, fmt.Sprintf("maxmind_license_key = $%d", argIndex))
		args = append(args, *req.MaxmindLicenseKey)
		argIndex++
	}
	if req.MaxmindAccountID != nil {
		setClauses = append(setClauses, fmt.Sprintf("maxmind_account_id = $%d", argIndex))
		args = append(args, *req.MaxmindAccountID)
		argIndex++
	}
	if req.GeoIPAutoUpdate != nil {
		setClauses = append(setClauses, fmt.Sprintf("geoip_auto_update = $%d", argIndex))
		args = append(args, *req.GeoIPAutoUpdate)
		argIndex++
	}
	if req.GeoIPUpdateInterval != nil {
		setClauses = append(setClauses, fmt.Sprintf("geoip_update_interval = $%d", argIndex))
		args = append(args, *req.GeoIPUpdateInterval)
		argIndex++
	}

	if req.ACMEEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_enabled = $%d", argIndex))
		args = append(args, *req.ACMEEnabled)
		argIndex++
	}
	if req.ACMEEmail != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_email = $%d", argIndex))
		args = append(args, *req.ACMEEmail)
		argIndex++
	}
	if req.ACMEStaging != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_staging = $%d", argIndex))
		args = append(args, *req.ACMEStaging)
		argIndex++
	}
	if req.ACMEAutoRenew != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_auto_renew = $%d", argIndex))
		args = append(args, *req.ACMEAutoRenew)
		argIndex++
	}
	if req.ACMERenewDaysBefore != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_renew_days_before = $%d", argIndex))
		args = append(args, *req.ACMERenewDaysBefore)
		argIndex++
	}
	if req.ACMEDNSProvider != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_dns_provider = $%d", argIndex))
		args = append(args, *req.ACMEDNSProvider)
		argIndex++
	}
	if req.ACMEDNSCredentials != nil {
		setClauses = append(setClauses, fmt.Sprintf("acme_dns_credentials = $%d", argIndex))
		args = append(args, *req.ACMEDNSCredentials)
		argIndex++
	}

	if req.NotificationEmail != nil {
		setClauses = append(setClauses, fmt.Sprintf("notification_email = $%d", argIndex))
		args = append(args, *req.NotificationEmail)
		argIndex++
	}
	if req.NotifyCertExpiry != nil {
		setClauses = append(setClauses, fmt.Sprintf("notify_cert_expiry = $%d", argIndex))
		args = append(args, *req.NotifyCertExpiry)
		argIndex++
	}
	if req.NotifyCertExpiryDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("notify_cert_expiry_days = $%d", argIndex))
		args = append(args, *req.NotifyCertExpiryDays)
		argIndex++
	}
	if req.NotifySecurityEvents != nil {
		setClauses = append(setClauses, fmt.Sprintf("notify_security_events = $%d", argIndex))
		args = append(args, *req.NotifySecurityEvents)
		argIndex++
	}
	if req.NotifyBackupComplete != nil {
		setClauses = append(setClauses, fmt.Sprintf("notify_backup_complete = $%d", argIndex))
		args = append(args, *req.NotifyBackupComplete)
		argIndex++
	}

	if req.LogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("log_retention_days = $%d", argIndex))
		args = append(args, *req.LogRetentionDays)
		argIndex++
	}
	if req.StatsRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("stats_retention_days = $%d", argIndex))
		args = append(args, *req.StatsRetentionDays)
		argIndex++
	}
	if req.BackupRetentionCount != nil {
		setClauses = append(setClauses, fmt.Sprintf("backup_retention_count = $%d", argIndex))
		args = append(args, *req.BackupRetentionCount)
		argIndex++
	}
	if req.AutoBackupEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("auto_backup_enabled = $%d", argIndex))
		args = append(args, *req.AutoBackupEnabled)
		argIndex++
	}
	if req.AutoBackupSchedule != nil {
		setClauses = append(setClauses, fmt.Sprintf("auto_backup_schedule = $%d", argIndex))
		args = append(args, *req.AutoBackupSchedule)
		argIndex++
	}

	// Log Retention Settings (per log type)
	if req.AccessLogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("access_log_retention_days = $%d", argIndex))
		args = append(args, *req.AccessLogRetentionDays)
		argIndex++
	}
	if req.WAFLogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("waf_log_retention_days = $%d", argIndex))
		args = append(args, *req.WAFLogRetentionDays)
		argIndex++
	}
	if req.ErrorLogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("error_log_retention_days = $%d", argIndex))
		args = append(args, *req.ErrorLogRetentionDays)
		argIndex++
	}
	if req.SystemLogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("system_log_retention_days = $%d", argIndex))
		args = append(args, *req.SystemLogRetentionDays)
		argIndex++
	}
	if req.AuditLogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("audit_log_retention_days = $%d", argIndex))
		args = append(args, *req.AuditLogRetentionDays)
		argIndex++
	}

	// Raw Log File Settings
	if req.RawLogEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("raw_log_enabled = $%d", argIndex))
		args = append(args, *req.RawLogEnabled)
		argIndex++
	}
	if req.RawLogRetentionDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("raw_log_retention_days = $%d", argIndex))
		args = append(args, *req.RawLogRetentionDays)
		argIndex++
	}
	if req.RawLogMaxSizeMB != nil {
		setClauses = append(setClauses, fmt.Sprintf("raw_log_max_size_mb = $%d", argIndex))
		args = append(args, *req.RawLogMaxSizeMB)
		argIndex++
	}
	if req.RawLogRotateCount != nil {
		setClauses = append(setClauses, fmt.Sprintf("raw_log_rotate_count = $%d", argIndex))
		args = append(args, *req.RawLogRotateCount)
		argIndex++
	}
	if req.RawLogCompressRotated != nil {
		setClauses = append(setClauses, fmt.Sprintf("raw_log_compress_rotated = $%d", argIndex))
		args = append(args, *req.RawLogCompressRotated)
		argIndex++
	}

	// Bot Filter Default Settings
	if req.BotFilterDefaultEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_enabled = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultEnabled)
		argIndex++
	}
	if req.BotFilterDefaultBlockBadBots != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_block_bad_bots = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultBlockBadBots)
		argIndex++
	}
	if req.BotFilterDefaultBlockAIBots != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_block_ai_bots = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultBlockAIBots)
		argIndex++
	}
	if req.BotFilterDefaultAllowSearchEngines != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_allow_search_engines = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultAllowSearchEngines)
		argIndex++
	}
	if req.BotFilterDefaultBlockSuspiciousClients != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_block_suspicious_clients = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultBlockSuspiciousClients)
		argIndex++
	}
	if req.BotFilterDefaultChallengeSuspicious != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_challenge_suspicious = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultChallengeSuspicious)
		argIndex++
	}
	if req.BotFilterDefaultCustomBlockedAgents != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_filter_default_custom_blocked_agents = $%d", argIndex))
		args = append(args, *req.BotFilterDefaultCustomBlockedAgents)
		argIndex++
	}

	// Bot Lists
	if req.BotListBadBots != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_list_bad_bots = $%d", argIndex))
		args = append(args, *req.BotListBadBots)
		argIndex++
	}
	if req.BotListAIBots != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_list_ai_bots = $%d", argIndex))
		args = append(args, *req.BotListAIBots)
		argIndex++
	}
	if req.BotListSearchEngines != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_list_search_engines = $%d", argIndex))
		args = append(args, *req.BotListSearchEngines)
		argIndex++
	}
	if req.BotListSuspiciousClients != nil {
		setClauses = append(setClauses, fmt.Sprintf("bot_list_suspicious_clients = $%d", argIndex))
		args = append(args, *req.BotListSuspiciousClients)
		argIndex++
	}

	// WAF Auto-Ban Settings
	if req.WAFAutoBanEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("waf_auto_ban_enabled = $%d", argIndex))
		args = append(args, *req.WAFAutoBanEnabled)
		argIndex++
	}
	if req.WAFAutoBanThreshold != nil {
		setClauses = append(setClauses, fmt.Sprintf("waf_auto_ban_threshold = $%d", argIndex))
		args = append(args, *req.WAFAutoBanThreshold)
		argIndex++
	}
	if req.WAFAutoBanWindow != nil {
		setClauses = append(setClauses, fmt.Sprintf("waf_auto_ban_window = $%d", argIndex))
		args = append(args, *req.WAFAutoBanWindow)
		argIndex++
	}
	if req.WAFAutoBanDuration != nil {
		setClauses = append(setClauses, fmt.Sprintf("waf_auto_ban_duration = $%d", argIndex))
		args = append(args, *req.WAFAutoBanDuration)
		argIndex++
	}

	// Global Block Exploits Exceptions
	if req.GlobalBlockExploitsExceptions != nil {
		setClauses = append(setClauses, fmt.Sprintf("global_block_exploits_exceptions = $%d", argIndex))
		args = append(args, *req.GlobalBlockExploitsExceptions)
		argIndex++
	}

	// Direct IP Access Settings
	if req.DirectIPAccessAction != nil {
		setClauses = append(setClauses, fmt.Sprintf("direct_ip_access_action = $%d", argIndex))
		args = append(args, *req.DirectIPAccessAction)
		argIndex++
	}

	// UI Settings (global)
	if req.UIFontFamily != nil {
		setClauses = append(setClauses, fmt.Sprintf("ui_font_family = $%d", argIndex))
		args = append(args, *req.UIFontFamily)
		argIndex++
	}

	// System Log Settings
	if req.SystemLogsEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("system_logs_enabled = $%d", argIndex))
		args = append(args, *req.SystemLogsEnabled)
		argIndex++
	}
	if req.SystemLogsLevels != nil {
		setClauses = append(setClauses, fmt.Sprintf("system_logs_levels = $%d", argIndex))
		args = append(args, *req.SystemLogsLevels)
		argIndex++
	}
	if req.SystemLogsExcludePatterns != nil {
		setClauses = append(setClauses, fmt.Sprintf("system_logs_exclude_patterns = $%d", argIndex))
		args = append(args, pq.Array(*req.SystemLogsExcludePatterns))
		argIndex++
	}
	if req.SystemLogsStdoutExcluded != nil {
		setClauses = append(setClauses, fmt.Sprintf("system_logs_stdout_excluded = $%d", argIndex))
		args = append(args, pq.Array(*req.SystemLogsStdoutExcluded))
		argIndex++
	}

	if len(setClauses) == 0 {
		return settings, nil
	}

	// Add updated_at
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	// Add ID for WHERE clause
	args = append(args, settings.ID)

	query := fmt.Sprintf(`
		UPDATE system_settings
		SET %s
		WHERE id = $%d
	`, strings.Join(setClauses, ", "), argIndex)

	_, err = r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update system settings: %w", err)
	}

	// Invalidate cache
	if r.cache != nil {
		_ = r.cache.InvalidateSystemSettings(ctx)
	}

	return r.getFromDB(ctx)
}

// UpdateGeoIPStatus updates GeoIP-related fields after a database update
func (r *SystemSettingsRepository) UpdateGeoIPStatus(ctx context.Context, lastUpdated time.Time, version string) error {
	settings, err := r.Get(ctx)
	if err != nil {
		return err
	}

	query := `
		UPDATE system_settings
		SET geoip_last_updated = $1, geoip_database_version = $2, updated_at = $3
		WHERE id = $4
	`
	_, err = r.db.ExecContext(ctx, query, lastUpdated, version, time.Now(), settings.ID)
	if err != nil {
		return fmt.Errorf("failed to update GeoIP status: %w", err)
	}

	// Invalidate cache
	if r.cache != nil {
		_ = r.cache.InvalidateSystemSettings(ctx)
	}

	return nil
}

// GetGeoIPCredentials returns the raw MaxMind credentials (not masked)
func (r *SystemSettingsRepository) GetGeoIPCredentials(ctx context.Context) (licenseKey, accountID string, err error) {
	settings, err := r.Get(ctx)
	if err != nil {
		return "", "", err
	}
	return settings.MaxmindLicenseKey, settings.MaxmindAccountID, nil
}
