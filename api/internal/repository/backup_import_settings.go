package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"

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
			updated_at = NOW()
	`

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
	)
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
