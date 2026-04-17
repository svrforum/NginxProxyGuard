package repository

import (
	"context"
	"database/sql"
	"fmt"

	"nginx-proxy-guard/internal/model"
)

func (r *BackupRepository) exportGlobalSettings(ctx context.Context) (*model.GlobalSettingsExport, error) {
	query := `
		SELECT worker_processes, worker_connections, worker_rlimit_nofile,
		       multi_accept, use_epoll, sendfile, tcp_nopush, tcp_nodelay,
		       keepalive_timeout, keepalive_requests, types_hash_max_size, server_tokens,
		       client_body_buffer_size, client_header_buffer_size, client_max_body_size,
		       large_client_header_buffers, client_body_timeout, client_header_timeout,
		       send_timeout, proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
		       gzip_enabled, gzip_vary, gzip_proxied, gzip_comp_level, gzip_buffers,
		       gzip_http_version, gzip_min_length, gzip_types,
		       ssl_protocols, ssl_ciphers, ssl_prefer_server_ciphers, ssl_session_cache,
		       ssl_session_timeout, ssl_session_tickets, ssl_stapling, ssl_stapling_verify,
		       COALESCE(ssl_ecdh_curve, 'X25519MLKEM768:X25519:secp256r1:secp384r1') as ssl_ecdh_curve,
		       access_log_enabled, error_log_level, resolver, resolver_timeout,
		       custom_http_config, custom_stream_config,
		       COALESCE(enable_ipv6, true) as enable_ipv6
		FROM global_settings LIMIT 1
	`

	var gs model.GlobalSettingsExport
	var resolver, resolverTimeout, customHttp, customStream sql.NullString
	var customInt sql.NullInt64
	var enableIPv6 bool

	err := r.db.QueryRowContext(ctx, query).Scan(
		&gs.WorkerProcesses, &gs.WorkerConnections, &customInt,
		&gs.MultiAccept, &gs.UseEpoll, &gs.Sendfile, &gs.TCPNopush, &gs.TCPNodelay,
		&gs.KeepaliveTimeout, &gs.KeepaliveRequests, &gs.TypesHashMaxSize, &gs.ServerTokens,
		&gs.ClientBodyBufferSize, &gs.ClientHeaderBufferSize, &gs.ClientMaxBodySize,
		&gs.LargeClientHeaderBuffers, &gs.ClientBodyTimeout, &gs.ClientHeaderTimeout,
		&gs.SendTimeout, &gs.ProxyConnectTimeout, &gs.ProxySendTimeout, &gs.ProxyReadTimeout,
		&gs.GzipEnabled, &gs.GzipVary, &gs.GzipProxied, &gs.GzipCompLevel, &gs.GzipBuffers,
		&gs.GzipHTTPVersion, &gs.GzipMinLength, &gs.GzipTypes,
		&gs.SSLProtocols, &gs.SSLCiphers, &gs.SSLPreferServerCiphers, &gs.SSLSessionCache,
		&gs.SSLSessionTimeout, &gs.SSLSessionTickets, &gs.SSLStapling, &gs.SSLStaplingVerify,
		&gs.SSLECDHCurve,
		&gs.AccessLogEnabled, &gs.ErrorLogLevel, &resolver, &resolverTimeout,
		&customHttp, &customStream,
		&enableIPv6,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if customInt.Valid {
		v := int(customInt.Int64)
		gs.WorkerRlimitNofile = &v
	}
	gs.Resolver = resolver.String
	gs.ResolverTimeout = resolverTimeout.String
	gs.CustomHTTPConfig = customHttp.String
	gs.CustomStreamConfig = customStream.String
	gs.EnableIPv6 = &enableIPv6

	return &gs, nil
}

func (r *BackupRepository) exportSystemSettings(ctx context.Context) (*model.SystemSettingsExport, error) {
	query := `
		SELECT geoip_enabled, geoip_auto_update, geoip_update_interval,
		       COALESCE(maxmind_account_id, '') as maxmind_account_id,
		       COALESCE(maxmind_license_key, '') as maxmind_license_key,
		       acme_enabled, acme_email, acme_staging, acme_auto_renew, acme_renew_days_before,
		       notification_email, notify_cert_expiry, notify_cert_expiry_days,
		       notify_security_events, notify_backup_complete,
		       log_retention_days, stats_retention_days, backup_retention_count,
		       auto_backup_enabled, auto_backup_schedule,
		       access_log_retention_days, waf_log_retention_days, error_log_retention_days,
		       system_log_retention_days, audit_log_retention_days,
		       raw_log_enabled, raw_log_retention_days, raw_log_max_size_mb,
		       raw_log_rotate_count, raw_log_compress_rotated,
		       bot_filter_default_enabled, bot_filter_default_block_bad_bots,
		       bot_filter_default_block_ai_bots, bot_filter_default_allow_search_engines,
		       bot_filter_default_block_suspicious_clients, bot_filter_default_challenge_suspicious,
		       bot_filter_default_custom_blocked_agents,
		       bot_list_bad_bots, bot_list_ai_bots, bot_list_search_engines, bot_list_suspicious_clients,
		       waf_auto_ban_enabled, waf_auto_ban_threshold, waf_auto_ban_window, waf_auto_ban_duration,
		       direct_ip_access_action, system_logs_enabled
		FROM system_settings LIMIT 1
	`

	var ss model.SystemSettingsExport
	var acmeEmail, notificationEmail sql.NullString
	var geoipUpdateInterval, autoBackupSchedule, directIPAccessAction sql.NullString
	var maxmindAccountID, maxmindLicenseKey sql.NullString
	var botFilterDefaultCustomBlockedAgents sql.NullString
	var botListBadBots, botListAIBots, botListSearchEngines, botListSuspiciousClients sql.NullString

	err := r.db.QueryRowContext(ctx, query).Scan(
		&ss.GeoIPEnabled, &ss.GeoIPAutoUpdate, &geoipUpdateInterval,
		&maxmindAccountID, &maxmindLicenseKey,
		&ss.ACMEEnabled, &acmeEmail, &ss.ACMEStaging, &ss.ACMEAutoRenew, &ss.ACMERenewDaysBefore,
		&notificationEmail, &ss.NotifyCertExpiry, &ss.NotifyCertExpiryDays,
		&ss.NotifySecurityEvents, &ss.NotifyBackupComplete,
		&ss.LogRetentionDays, &ss.StatsRetentionDays, &ss.BackupRetentionCount,
		&ss.AutoBackupEnabled, &autoBackupSchedule,
		&ss.AccessLogRetentionDays, &ss.WAFLogRetentionDays, &ss.ErrorLogRetentionDays,
		&ss.SystemLogRetentionDays, &ss.AuditLogRetentionDays,
		&ss.RawLogEnabled, &ss.RawLogRetentionDays, &ss.RawLogMaxSizeMB,
		&ss.RawLogRotateCount, &ss.RawLogCompressRotated,
		&ss.BotFilterDefaultEnabled, &ss.BotFilterDefaultBlockBadBots,
		&ss.BotFilterDefaultBlockAIBots, &ss.BotFilterDefaultAllowSearchEngines,
		&ss.BotFilterDefaultBlockSuspiciousClients, &ss.BotFilterDefaultChallengeSuspicious,
		&botFilterDefaultCustomBlockedAgents,
		&botListBadBots, &botListAIBots, &botListSearchEngines, &botListSuspiciousClients,
		&ss.WAFAutoBanEnabled, &ss.WAFAutoBanThreshold, &ss.WAFAutoBanWindow, &ss.WAFAutoBanDuration,
		&directIPAccessAction, &ss.SystemLogsEnabled,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ss.GeoIPUpdateInterval = geoipUpdateInterval.String
	ss.MaxmindAccountID = maxmindAccountID.String
	ss.MaxmindLicenseKey = maxmindLicenseKey.String
	ss.ACMEEmail = acmeEmail.String
	ss.NotificationEmail = notificationEmail.String
	ss.AutoBackupSchedule = autoBackupSchedule.String
	ss.DirectIPAccessAction = directIPAccessAction.String
	ss.BotFilterDefaultCustomBlockedAgents = botFilterDefaultCustomBlockedAgents.String
	ss.BotListBadBots = botListBadBots.String
	ss.BotListAIBots = botListAIBots.String
	ss.BotListSearchEngines = botListSearchEngines.String
	ss.BotListSuspiciousClients = botListSuspiciousClients.String

	return &ss, nil
}

func (r *BackupRepository) exportFilterSubscriptions(ctx context.Context) ([]model.FilterSubscriptionExport, error) {
	query := `
		SELECT id, name, COALESCE(description, '') as description, url, format, type,
		       enabled, COALESCE(exclude_private_ips, false), refresh_type, refresh_value
		FROM filter_subscriptions
		ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query filter subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []model.FilterSubscriptionExport
	for rows.Next() {
		var sub model.FilterSubscriptionExport
		var id string
		if err := rows.Scan(&id, &sub.Name, &sub.Description, &sub.URL, &sub.Format, &sub.Type,
			&sub.Enabled, &sub.ExcludePrivateIPs, &sub.RefreshType, &sub.RefreshValue); err != nil {
			return nil, fmt.Errorf("failed to scan filter subscription: %w", err)
		}

		// Export entries
		entryQuery := `SELECT value, COALESCE(reason, '') FROM filter_subscription_entries WHERE subscription_id = $1 ORDER BY created_at`
		entryRows, err := r.db.QueryContext(ctx, entryQuery, id)
		if err != nil {
			return nil, fmt.Errorf("failed to export entries for subscription %s: %w", sub.Name, err)
		}
		for entryRows.Next() {
			var e model.FilterSubscriptionEntryExport
			if err := entryRows.Scan(&e.Value, &e.Reason); err != nil {
				entryRows.Close()
				return nil, err
			}
			sub.Entries = append(sub.Entries, e)
		}
		if err := entryRows.Err(); err != nil {
			entryRows.Close()
			return nil, fmt.Errorf("error iterating entries for subscription %s: %w", sub.Name, err)
		}
		entryRows.Close()

		// Export exclusions (as proxy_host_id list)
		exclQuery := `SELECT proxy_host_id FROM filter_subscription_host_exclusions WHERE subscription_id = $1`
		exclRows, err := r.db.QueryContext(ctx, exclQuery, id)
		if err != nil {
			return nil, fmt.Errorf("failed to export exclusions for subscription %s: %w", sub.Name, err)
		}
		for exclRows.Next() {
			var hostID string
			if err := exclRows.Scan(&hostID); err != nil {
				exclRows.Close()
				return nil, err
			}
			sub.Exclusions = append(sub.Exclusions, hostID)
		}
		if err := exclRows.Err(); err != nil {
			exclRows.Close()
			return nil, fmt.Errorf("error iterating exclusions for subscription %s: %w", sub.Name, err)
		}
		exclRows.Close()

		// Export entry exclusions
		entryExclQuery := `SELECT value FROM filter_subscription_entry_exclusions WHERE subscription_id = $1`
		entryExclRows, err := r.db.QueryContext(ctx, entryExclQuery, id)
		if err != nil {
			return nil, fmt.Errorf("failed to export entry exclusions for subscription %s: %w", sub.Name, err)
		}
		for entryExclRows.Next() {
			var excl model.FilterSubscriptionEntryExclusionExport
			if err := entryExclRows.Scan(&excl.Value); err != nil {
				entryExclRows.Close()
				return nil, err
			}
			sub.EntryExclusions = append(sub.EntryExclusions, excl)
		}
		if err := entryExclRows.Err(); err != nil {
			entryExclRows.Close()
			return nil, fmt.Errorf("error iterating entry exclusions for subscription %s: %w", sub.Name, err)
		}
		entryExclRows.Close()

		subs = append(subs, sub)
	}
	return subs, rows.Err()
}
