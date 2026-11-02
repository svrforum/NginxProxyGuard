package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/dnsentry"
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

	// A fresh install has no global_settings row until settings are first
	// saved, and the UPDATE below changes nothing without one: a backup
	// restored onto a new server reported success and dropped every global
	// setting. Create the row the way GlobalSettingsRepository.Update does.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_settings (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM global_settings LIMIT 1)`); err != nil {
		return err
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
			enable_ipv6 = $46, access_log_strip_query = $47, worker_shutdown_timeout = $48,
			updated_at = NOW()
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
		gs.AccessLogStripQuery,
		gs.WorkerShutdownTimeout,
	)
	return err
}

// importSystemSettings updates the system settings from a backup and returns
// the domain names of the global trusted IPs it restored (#320).
func (r *BackupRepository) importSystemSettings(ctx context.Context, tx *sql.Tx, ss *model.SystemSettingsExport) ([]string, error) {
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
			trusted_proxy_cidrs = COALESCE($57, trusted_proxy_cidrs),
			trusted_proxy_preset = COALESCE($58, trusted_proxy_preset),
			real_ip_header = COALESCE($59, real_ip_header),
			raw_log_archive_enabled = COALESCE($60, raw_log_archive_enabled),
			raw_log_archive_retention_days = COALESCE($61, raw_log_archive_retention_days),
			dns_entry_settings = COALESCE($62::jsonb, dns_entry_settings),
			global_trusted_hostnames = $63,
			updated_at = NOW()
	`

	// 하위 버전 백업 호환: 구 버전 백업엔 이 필드가 없어 zero value(0)가 되므로
	// 최소 제약(>=1)을 위반하지 않도록 기본값 5로 보정.
	if ss.DDNSCheckIntervalMinutes < 1 {
		ss.DDNSCheckIntervalMinutes = 5
	}

	// 원본 로그 설정: 구 버전/손상 백업의 0 값은 기본값으로 보정한다
	// (보존 0일은 logrotate에서 "삭제 안 함", 회전 개수 0은 구버전에서 전부 삭제).
	// 보관 디렉터리 필드가 없는 백업(일 단위 보존 이전)은 업그레이드와 같은
	// 보존 인계 규칙을 받는다 — 복원 대상 설치의 created_at 기준.
	var installedAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT created_at FROM system_settings LIMIT 1`).Scan(&installedAt); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("read install date: %w", err)
	}
	model.CoerceRawLogImport(ss, installedAt, time.Now())

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

	// An out-of-allowlist value in a hand-edited backup must not reach
	// nginx.conf. Coerce rather than fail the whole restore.
	trustedProxyPreset := coerceBackupString(ss.TrustedProxyPreset, model.NormalizeTrustedProxyPreset)
	realIPHeader := coerceBackupString(ss.RealIPHeader, model.NormalizeRealIPHeader)
	// The CIDR list needs the same guard as the two above. Without it a
	// hand-edited backup restores 0.0.0.0/0 — which the API's own write path
	// refuses — and the restore then regenerates nginx.conf and reloads,
	// leaving the forwarded-address header forgeable by any client.
	trustedProxyCIDRs := coerceBackupString(ss.TrustedProxyCIDRs, func(v string) (string, error) {
		if err := model.ValidateTrustedProxyCIDRs(v); err != nil {
			return "", err
		}
		return v, nil
	})

	// Domain entry tunables (#320): nil (an older backup) keeps the live value.
	dnsEntrySettings := dnsEntrySettingsFromBackup(ss.DNSEntrySettings)
	// The trusted IPs' domain names (#320) are not kept that way: nil (an
	// older backup) restores none, next to the backup's global_trusted_ips.
	var trustedHostnames []string
	if ss.GlobalTrustedHostnames != nil {
		trustedHostnames = *ss.GlobalTrustedHostnames
	}
	trustedHostnames = restorableDNSNames("the global trusted IPs", trustedHostnames)

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
		trustedProxyCIDRs, trustedProxyPreset, realIPHeader,
		ss.RawLogArchiveEnabled, ss.RawLogArchiveRetentionDays,
		dnsEntrySettings,
		pq.Array(trustedHostnames),
	)
	if err != nil {
		return nil, err
	}
	return trustedHostnames, nil
}

// dnsEntrySettingsFromBackup is the dns_entry_settings value a restore writes
// (#320): the backup's object read as the API reads the column (a missing key
// takes its default, a number out of range is clamped, an unreadable value
// gives the defaults), passed as a JSON string because a jsonb parameter must
// not be []byte. nil — keep the live value — when the backup predates the
// field or holds null there (the decoder keeps a JSON null as the four
// bytes null).
func dnsEntrySettingsFromBackup(raw json.RawMessage) interface{} {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	b, err := json.Marshal(model.ParseDNSEntrySettings(raw))
	if err != nil {
		return nil
	}
	return string(b)
}

// importDNSEntryStates merges the backup's domain entry state records into
// dns_entry_states (#320), in the import's transaction, after every list
// section. names are the domain names the restored access lists use; a
// record for any other name is ignored. Each record goes through
// dnsentry.MergeRestored with the live row, read FOR UPDATE, and the merged
// row is written whole: a review is kept or added, never dropped, the live
// pin and published history win over the backup's, and nothing is
// published.
func (r *BackupRepository) importDNSEntryStates(ctx context.Context, tx *sql.Tx, states []model.DNSEntryStateExport, names []string) error {
	// A record's hostname, review_reason (with the status needs_review),
	// canonical_name and last_applied reach the row only through
	// MergeRestored and the state repository's UpsertState
	// (backup_sync_test.go looks for these column names here).
	return mergeRestoredDNSEntryStates(ctx, newDNSEntryTx(tx), states, names, model.DefaultAddressPolicy(), time.Now())
}

// mergeRestoredDNSEntryStates is importDNSEntryStates on any DNSEntryTx, with
// the address policy and the clock passed in for tests.
func mergeRestoredDNSEntryStates(ctx context.Context, store DNSEntryTx, states []model.DNSEntryStateExport, names []string,
	policy *model.AddressPolicy, now time.Time) error {
	used := make(map[string]bool, len(names))
	for _, name := range names {
		used[name] = true
	}
	var records []model.DNSEntryStateExport
	var keys []string
	seen := make(map[string]bool)
	for _, rec := range states {
		name := model.NormalizeDNSName(rec.Hostname)
		if !used[name] {
			continue
		}
		rec.Hostname = name
		records = append(records, rec)
		if !seen[name] {
			seen[name] = true
			keys = append(keys, name)
		}
	}
	if len(records) == 0 {
		return nil
	}
	sort.Strings(keys)

	live, err := store.GetStates(ctx, keys)
	if err != nil {
		return err
	}
	// Records merge in file order; a second record for a name merges into
	// the first one's result, so a review in either stays.
	merged := make(map[string]model.DNSEntryState, len(keys))
	for _, rec := range records {
		var existing *model.DNSEntryState
		if st, ok := merged[rec.Hostname]; ok {
			existing = &st
		} else if st, ok := live[rec.Hostname]; ok {
			existing = &st
		}
		st, ok := dnsentry.MergeRestored(existing, rec, policy, now)
		if !ok {
			log.Printf("[Backup] Skipped the domain entry state of %.60q: not a domain name this version accepts.", rec.Hostname)
			continue
		}
		merged[rec.Hostname] = st
	}
	for _, name := range keys {
		if st, ok := merged[name]; ok {
			if err := store.UpsertState(ctx, st); err != nil {
				return err
			}
		}
	}
	return nil
}

// RestoredDNSEntries reads, after an import, the domain names the lists use
// (the access lists, the exception lists and the global trusted IPs: every
// source of the DNS checks' references) and which of them wait for review
// (#320), for the restore audit. It reads the merged rows, not what the
// backup said.
func (r *BackupRepository) RestoredDNSEntries(ctx context.Context) (model.DNSRestoreSummary, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT n.hostname, COALESCE(s.status, '') = $1
		FROM (SELECT DISTINCT refs.hostname FROM (`+dnsReferenceSources+`
		) AS refs(scope, hostname, owner_id, owner_name)) n
		LEFT JOIN dns_entry_states s ON s.hostname = n.hostname
		ORDER BY n.hostname
	`, model.DNSStatusNeedsReview)
	if err != nil {
		return model.DNSRestoreSummary{}, err
	}
	defer rows.Close()

	var out model.DNSRestoreSummary
	for rows.Next() {
		var name string
		var needsReview bool
		if err := rows.Scan(&name, &needsReview); err != nil {
			return model.DNSRestoreSummary{}, err
		}
		out.Names = append(out.Names, name)
		if needsReview {
			out.NeedsReview = append(out.NeedsReview, name)
		}
	}
	return out, rows.Err()
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

// importRoles restores RBAC roles and their permissions (#222).
//
// Upsert by name rather than delete-then-insert: users.role_id references roles
// with ON DELETE RESTRICT, and import runs inside one transaction, so clearing
// the table while accounts still point at it would abort the whole restore. This
// also means the built-in roles seeded by the migration are updated in place
// instead of being duplicated.
//
// Role ASSIGNMENTS are not restored — user rows are not part of a backup at all
// (see model.RoleExport), so an administrator re-assigns roles afterwards.
func (r *BackupRepository) importRoles(ctx context.Context, tx *sql.Tx, roles []model.RoleExport) error {
	for _, e := range roles {
		var id string
		err := tx.QueryRowContext(ctx, `
			INSERT INTO roles (name, description, is_superuser, is_builtin)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (lower((name)::text)) DO UPDATE
			   SET description = EXCLUDED.description,
			       is_superuser = EXCLUDED.is_superuser,
			       is_builtin = EXCLUDED.is_builtin,
			       updated_at = now()
			RETURNING id`, e.Name, e.Description, e.IsSuperuser, e.IsBuiltin).Scan(&id)
		if err != nil {
			return fmt.Errorf("role %s: %w", e.Name, err)
		}

		// Replace the permission set wholesale: the backup is authoritative for
		// what the role grants, and role_permissions has no inbound references.
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id); err != nil {
			return fmt.Errorf("role %s: clearing permissions: %w", e.Name, err)
		}
		for _, perm := range e.Permissions {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)
				ON CONFLICT (role_id, permission) DO NOTHING`, id, perm); err != nil {
				return fmt.Errorf("role %s permission %s: %w", e.Name, perm, err)
			}
		}
	}
	return nil
}

// importSSOProviders restores the OIDC provider registry (#227).
//
// Upsert by slug, like importRoles upserts by name, so a restore over a live
// install updates providers in place instead of colliding. Roles are resolved by
// NAME: a backup carries no uuids that mean anything here. A provider whose role
// is missing is imported with no default role and JIT forced off — silently
// provisioning accounts with the wrong role would be worse than a provider the
// administrator has to finish configuring.
func (r *BackupRepository) importSSOProviders(ctx context.Context, tx *sql.Tx, providers []model.SSOProviderExport) error {
	var present bool
	if err := tx.QueryRowContext(ctx,
		`SELECT to_regclass('public.sso_providers') IS NOT NULL`).Scan(&present); err != nil || !present {
		if len(providers) > 0 {
			log.Printf("Backup import: skipping %d SSO providers — the sso_providers table is missing", len(providers))
		}
		return nil
	}

	roleID := func(name string) *string {
		if name == "" {
			return nil
		}
		var id string
		if err := tx.QueryRowContext(ctx,
			`SELECT id FROM roles WHERE lower(name) = lower($1)`, name).Scan(&id); err != nil {
			return nil
		}
		return &id
	}

	for _, e := range providers {
		defaultRole := roleID(e.DefaultRoleName)
		allowJIT := e.AllowJIT
		if allowJIT && defaultRole == nil {
			log.Printf("Backup import: SSO provider %q wanted role %q, which does not exist — importing with automatic account creation off",
				e.Slug, e.DefaultRoleName)
			allowJIT = false
		}

		mappings := make([]model.GroupRoleMapping, 0, len(e.GroupRoleMappings))
		for _, m := range e.GroupRoleMappings {
			if id := roleID(m.RoleName); id != nil {
				mappings = append(mappings, model.GroupRoleMapping{Group: m.Group, RoleID: *id})
			} else {
				log.Printf("Backup import: SSO provider %q drops the mapping for group %q — role %q does not exist",
					e.Slug, m.Group, m.RoleName)
			}
		}
		encoded, err := json.Marshal(mappings)
		if err != nil {
			return fmt.Errorf("sso provider %s: %w", e.Slug, err)
		}

		scopes := e.Scopes
		if scopes == "" {
			scopes = "openid profile email"
		}
		groupClaim := e.GroupClaim
		if groupClaim == "" {
			groupClaim = "groups"
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sso_providers (slug, name, issuer_url, client_id, client_secret, scopes,
				callback_base_url, enabled, allow_jit, trust_provider_email, allowed_email_domains, allowed_emails,
				group_claim, required_group, default_role_id, group_role_mappings)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12,$13,NULLIF($14,''),$15,$16)
			ON CONFLICT (lower((slug)::text)) DO UPDATE SET
				name = EXCLUDED.name, issuer_url = EXCLUDED.issuer_url,
				client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret,
				scopes = EXCLUDED.scopes, callback_base_url = EXCLUDED.callback_base_url,
				enabled = EXCLUDED.enabled, allow_jit = EXCLUDED.allow_jit,
				trust_provider_email = EXCLUDED.trust_provider_email,
				allowed_email_domains = EXCLUDED.allowed_email_domains,
				allowed_emails = EXCLUDED.allowed_emails, group_claim = EXCLUDED.group_claim,
				required_group = EXCLUDED.required_group, default_role_id = EXCLUDED.default_role_id,
				group_role_mappings = EXCLUDED.group_role_mappings, updated_at = now()`,
			e.Slug, e.Name, e.IssuerURL, e.ClientID, e.ClientSecret, scopes,
			e.CallbackBaseURL, e.Enabled, allowJIT, e.TrustProviderEmail, pq.Array(e.AllowedEmailDomains), pq.Array(e.AllowedEmails),
			groupClaim, e.RequiredGroup, defaultRole, encoded); err != nil {
			return fmt.Errorf("sso provider %s: %w", e.Slug, err)
		}
	}
	return nil
}

// importCloudflareTunnel restores the singleton Cloudflare Tunnel setting
// (Phase 1 token mode). Delete-then-insert so the singleton stays unique.
// Defaults mode to "token" so a pre-Phase-2 backup with an empty mode cannot
// fail the column CHECK.
func (r *BackupRepository) importCloudflareTunnel(ctx context.Context, tx *sql.Tx, e *model.CloudflareTunnelExport) error {
	_, _ = tx.ExecContext(ctx, "DELETE FROM cloudflare_tunnel")

	mode := e.Mode
	if mode == "" {
		mode = "token"
	}
	query := `
		INSERT INTO cloudflare_tunnel (enabled, token, mode, api_token, catchall_enabled, catchall_applied_service)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	// Older backups leave the managed fields zero-valued, which is exactly the
	// pre-#267 state. Stored tokens are re-validated at every point of use
	// (service Update / converge), so no validation is needed here.
	_, err := tx.ExecContext(ctx, query, e.Enabled, e.Token, mode,
		e.APIToken, e.CatchallEnabled, e.CatchallAppliedService)
	return err
}

// coerceBackupString runs a restored value through its normalizer, dropping it
// to nil (keep the live value) when the backup holds something unsupported.
func coerceBackupString(v *string, normalize func(string) (string, error)) interface{} {
	if v == nil {
		return nil
	}
	normalized, err := normalize(*v)
	if err != nil {
		return nil
	}
	return normalized
}
