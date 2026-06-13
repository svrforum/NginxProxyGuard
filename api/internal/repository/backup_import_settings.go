package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

func (r *BackupRepository) importGlobalSettings(ctx context.Context, tx *sql.Tx, gs *model.GlobalSettingsExport) error {
	// Default ssl_ecdh_curve for old backups that don't have this field
	if gs.SSLECDHCurve == "" {
		gs.SSLECDHCurve = "X25519MLKEM768:X25519:secp256r1:secp384r1"
	}

	// Default enable_ipv6 for old backups that don't have this field
	enableIPv6 := true
	if gs.EnableIPv6 != nil {
		enableIPv6 = *gs.EnableIPv6
	}

	query := `
		UPDATE global_settings SET
			worker_processes = $1, worker_connections = $2, worker_rlimit_nofile = $3,
			multi_accept = $4, use_epoll = $5, sendfile = $6, tcp_nopush = $7, tcp_nodelay = $8,
			keepalive_timeout = $9, keepalive_requests = $10, types_hash_max_size = $11, server_tokens = $12,
			client_body_buffer_size = $13, client_header_buffer_size = $14, client_max_body_size = $15,
			large_client_header_buffers = $16, client_body_timeout = $17, client_header_timeout = $18,
			send_timeout = $19, proxy_connect_timeout = $20, proxy_send_timeout = $21, proxy_read_timeout = $22,
			gzip_enabled = $23, gzip_vary = $24, gzip_proxied = $25, gzip_comp_level = $26, gzip_buffers = $27,
			gzip_http_version = $28, gzip_min_length = $29, gzip_types = $30,
			ssl_protocols = $31, ssl_ciphers = $32, ssl_prefer_server_ciphers = $33, ssl_session_cache = $34,
			ssl_session_timeout = $35, ssl_session_tickets = $36, ssl_stapling = $37, ssl_stapling_verify = $38,
			ssl_ecdh_curve = $39,
			access_log_enabled = $40, error_log_level = $41, resolver = $42, resolver_timeout = $43,
			custom_http_config = $44, custom_stream_config = $45,
			enable_ipv6 = $46, updated_at = NOW()
	`

	_, err := tx.ExecContext(ctx, query,
		gs.WorkerProcesses, gs.WorkerConnections, gs.WorkerRlimitNofile,
		gs.MultiAccept, gs.UseEpoll, gs.Sendfile, gs.TCPNopush, gs.TCPNodelay,
		gs.KeepaliveTimeout, gs.KeepaliveRequests, gs.TypesHashMaxSize, gs.ServerTokens,
		gs.ClientBodyBufferSize, gs.ClientHeaderBufferSize, gs.ClientMaxBodySize,
		gs.LargeClientHeaderBuffers, gs.ClientBodyTimeout, gs.ClientHeaderTimeout,
		gs.SendTimeout, gs.ProxyConnectTimeout, gs.ProxySendTimeout, gs.ProxyReadTimeout,
		gs.GzipEnabled, gs.GzipVary, gs.GzipProxied, gs.GzipCompLevel, gs.GzipBuffers,
		gs.GzipHTTPVersion, gs.GzipMinLength, gs.GzipTypes,
		gs.SSLProtocols, gs.SSLCiphers, gs.SSLPreferServerCiphers, gs.SSLSessionCache,
		gs.SSLSessionTimeout, gs.SSLSessionTickets, gs.SSLStapling, gs.SSLStaplingVerify,
		gs.SSLECDHCurve,
		gs.AccessLogEnabled, gs.ErrorLogLevel, gs.Resolver, gs.ResolverTimeout,
		gs.CustomHTTPConfig, gs.CustomStreamConfig,
		enableIPv6,
	)
	return err
}

func (r *BackupRepository) importSystemSettings(ctx context.Context, tx *sql.Tx, ss *model.SystemSettingsExport) error {
	query := `
		UPDATE system_settings SET
			geoip_enabled = $1, geoip_auto_update = $2, geoip_update_interval = $3,
			maxmind_account_id = $4, maxmind_license_key = $5,
			acme_enabled = $6, acme_email = $7, acme_staging = $8, acme_auto_renew = $9, acme_renew_days_before = $10,
			notification_email = $11, notify_cert_expiry = $12, notify_cert_expiry_days = $13,
			notify_security_events = $14, notify_backup_complete = $15,
			log_retention_days = $16, stats_retention_days = $17, backup_retention_count = $18,
			auto_backup_enabled = $19, auto_backup_schedule = $20,
			access_log_retention_days = $21, waf_log_retention_days = $22, error_log_retention_days = $23,
			system_log_retention_days = $24, audit_log_retention_days = $25,
			raw_log_enabled = $26, raw_log_retention_days = $27, raw_log_max_size_mb = $28,
			raw_log_rotate_count = $29, raw_log_compress_rotated = $30,
			bot_filter_default_enabled = $31, bot_filter_default_block_bad_bots = $32,
			bot_filter_default_block_ai_bots = $33, bot_filter_default_allow_search_engines = $34,
			bot_filter_default_block_suspicious_clients = $35, bot_filter_default_challenge_suspicious = $36,
			bot_filter_default_custom_blocked_agents = $37,
			bot_list_bad_bots = $38, bot_list_ai_bots = $39, bot_list_search_engines = $40, bot_list_suspicious_clients = $41,
			waf_auto_ban_enabled = $42, waf_auto_ban_threshold = $43, waf_auto_ban_window = $44, waf_auto_ban_duration = $45,
			direct_ip_access_action = $46, system_logs_enabled = $47,
			ddns_check_interval_minutes = $48,
			global_trusted_ips = COALESCE($49, global_trusted_ips),
			global_block_exploits_exceptions = COALESCE($50, global_block_exploits_exceptions),
			ui_font_family = COALESCE($51, ui_font_family),
			ui_error_page_language = COALESCE($52, ui_error_page_language),
			system_logs_levels = COALESCE($53::jsonb, system_logs_levels),
			system_logs_exclude_patterns = COALESCE($54, system_logs_exclude_patterns),
			system_logs_stdout_excluded = COALESCE($55, system_logs_stdout_excluded),
			global_trusted_ips_bypass_waf = COALESCE($56, global_trusted_ips_bypass_waf),
			updated_at = NOW()
	`

	// 하위 버전 백업 호환: 구 버전 백업엔 이 필드가 없어 zero value(0)가 되므로
	// 최소 제약(>=1)을 위반하지 않도록 기본값 5로 보정.
	if ss.DDNSCheckIntervalMinutes < 1 {
		ss.DDNSCheckIntervalMinutes = 5
	}

	// 하위 버전 백업 호환: $49-$56 컬럼은 구 버전 백업엔 없어 nil이 된다.
	// nil이면 COALESCE가 기존 DB 값(신규 설치 기본값)을 유지한다 — 빈 값으로
	// 덮어쓰면 trusted IP 우회가 풀리고 기본 익스플로잇 예외가 사라지는 등
	// 동작이 조용히 바뀌기 때문. 새 백업은 항상 구체 값(빈 목록 포함)을 가진다.
	var systemLogsLevels interface{}
	if len(ss.SystemLogsLevels) > 0 {
		// jsonb 컬럼엔 []byte(bytea 인코딩)가 아닌 string으로 전달해야 한다.
		systemLogsLevels = string(ss.SystemLogsLevels)
	}
	var systemLogsExcludePatterns, systemLogsStdoutExcluded interface{}
	if ss.SystemLogsExcludePatterns != nil {
		systemLogsExcludePatterns = pq.Array(ss.SystemLogsExcludePatterns)
	}
	if ss.SystemLogsStdoutExcluded != nil {
		systemLogsStdoutExcluded = pq.Array(ss.SystemLogsStdoutExcluded)
	}

	_, err := tx.ExecContext(ctx, query,
		ss.GeoIPEnabled, ss.GeoIPAutoUpdate, ss.GeoIPUpdateInterval,
		ss.MaxmindAccountID, ss.MaxmindLicenseKey,
		ss.ACMEEnabled, ss.ACMEEmail, ss.ACMEStaging, ss.ACMEAutoRenew, ss.ACMERenewDaysBefore,
		ss.NotificationEmail, ss.NotifyCertExpiry, ss.NotifyCertExpiryDays,
		ss.NotifySecurityEvents, ss.NotifyBackupComplete,
		ss.LogRetentionDays, ss.StatsRetentionDays, ss.BackupRetentionCount,
		ss.AutoBackupEnabled, ss.AutoBackupSchedule,
		ss.AccessLogRetentionDays, ss.WAFLogRetentionDays, ss.ErrorLogRetentionDays,
		ss.SystemLogRetentionDays, ss.AuditLogRetentionDays,
		ss.RawLogEnabled, ss.RawLogRetentionDays, ss.RawLogMaxSizeMB,
		ss.RawLogRotateCount, ss.RawLogCompressRotated,
		ss.BotFilterDefaultEnabled, ss.BotFilterDefaultBlockBadBots,
		ss.BotFilterDefaultBlockAIBots, ss.BotFilterDefaultAllowSearchEngines,
		ss.BotFilterDefaultBlockSuspiciousClients, ss.BotFilterDefaultChallengeSuspicious,
		ss.BotFilterDefaultCustomBlockedAgents,
		ss.BotListBadBots, ss.BotListAIBots, ss.BotListSearchEngines, ss.BotListSuspiciousClients,
		ss.WAFAutoBanEnabled, ss.WAFAutoBanThreshold, ss.WAFAutoBanWindow, ss.WAFAutoBanDuration,
		ss.DirectIPAccessAction, ss.SystemLogsEnabled,
		ss.DDNSCheckIntervalMinutes,
		ss.GlobalTrustedIPs, ss.GlobalBlockExploitsExceptions,
		ss.UIFontFamily, ss.UIErrorPageLanguage,
		systemLogsLevels, systemLogsExcludePatterns, systemLogsStdoutExcluded,
		ss.GlobalTrustedIPsBypassWAF,
	)
	return err
}

// importLogSettings updates the singleton log_settings row. Only called when
// the backup contains the log_settings section; older backups (nil) keep the
// existing/default values.
func (r *BackupRepository) importLogSettings(ctx context.Context, tx *sql.Tx, ls *model.LogSettingsExport) error {
	// 하위 버전/손상 백업 호환: retention_days 0은 모든 로그 즉시 삭제를
	// 의미하게 되므로 기본값 30으로 보정.
	if ls.RetentionDays < 1 {
		ls.RetentionDays = 30
	}

	query := `
		UPDATE log_settings SET
			retention_days = $1, max_logs_per_type = $2, auto_cleanup_enabled = $3,
			updated_at = NOW()
	`
	res, err := tx.ExecContext(ctx, query, ls.RetentionDays, ls.MaxLogsPerType, ls.AutoCleanupEnabled)
	if err != nil {
		return err
	}

	// Fresh installs may not have the singleton row yet (it is lazily created
	// on first read) — insert it so the restored values are not lost.
	if n, _ := res.RowsAffected(); n == 0 {
		insertQuery := `
			INSERT INTO log_settings (retention_days, max_logs_per_type, auto_cleanup_enabled)
			VALUES ($1, $2, $3)
		`
		_, err = tx.ExecContext(ctx, insertQuery, ls.RetentionDays, ls.MaxLogsPerType, ls.AutoCleanupEnabled)
	}
	return err
}

func (r *BackupRepository) importFilterSubscription(ctx context.Context, tx *sql.Tx, fs *model.FilterSubscriptionExport, proxyHostIDMap map[string]string) error {
	// Insert subscription
	var subID string
	query := `
		INSERT INTO filter_subscriptions (name, description, url, format, type, enabled, exclude_private_ips, refresh_type, refresh_value, entry_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (url) DO NOTHING
		RETURNING id`

	err := tx.QueryRowContext(ctx, query,
		fs.Name, fs.Description, fs.URL, fs.Format, fs.Type,
		fs.Enabled, fs.ExcludePrivateIPs, fs.RefreshType, fs.RefreshValue, len(fs.Entries),
	).Scan(&subID)
	if err != nil {
		if err == sql.ErrNoRows {
			// URL already exists, skip
			return nil
		}
		return fmt.Errorf("failed to insert filter subscription: %w", err)
	}

	// Insert entries in batches
	for i := 0; i < len(fs.Entries); i += 500 {
		end := i + 500
		if end > len(fs.Entries) {
			end = len(fs.Entries)
		}
		batch := fs.Entries[i:end]

		valueStrings := make([]string, 0, len(batch))
		valueArgs := make([]interface{}, 0, len(batch)*3)
		for j, e := range batch {
			base := j*3 + 1
			valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d)", base, base+1, base+2))
			valueArgs = append(valueArgs, subID, e.Value, e.Reason)
		}

		entryQuery := fmt.Sprintf(
			`INSERT INTO filter_subscription_entries (subscription_id, value, reason) VALUES %s ON CONFLICT (subscription_id, value) DO NOTHING`,
			joinStrings(valueStrings, ", "),
		)
		if _, err := tx.ExecContext(ctx, entryQuery, valueArgs...); err != nil {
			return fmt.Errorf("failed to insert filter subscription entries: %w", err)
		}
	}

	// Insert exclusions with remapped proxy host IDs
	for _, oldHostID := range fs.Exclusions {
		newID, ok := proxyHostIDMap[oldHostID]
		if !ok {
			// Original proxy host not found in restored data, skip this exclusion
			continue
		}
		exclQuery := `INSERT INTO filter_subscription_host_exclusions (subscription_id, proxy_host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
		if _, err := tx.ExecContext(ctx, exclQuery, subID, newID); err != nil {
			return fmt.Errorf("failed to insert filter subscription exclusion: %w", err)
		}
	}

	// Insert entry exclusions
	entryExclQuery := `INSERT INTO filter_subscription_entry_exclusions (subscription_id, value) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	for _, excl := range fs.EntryExclusions {
		if _, err := tx.ExecContext(ctx, entryExclQuery, subID, excl.Value); err != nil {
			log.Printf("[Backup Import] Warning: failed to import entry exclusion %s: %v", excl.Value, err)
		}
	}

	return nil
}
