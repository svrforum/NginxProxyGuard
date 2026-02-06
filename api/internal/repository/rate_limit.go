package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

type RateLimitRepository struct {
	db *sql.DB
}

func NewRateLimitRepository(db *sql.DB) *RateLimitRepository {
	return &RateLimitRepository{db: db}
}

// RateLimit operations

func (r *RateLimitRepository) GetByProxyHostID(ctx context.Context, proxyHostID string) (*model.RateLimit, error) {
	query := `
		SELECT id, proxy_host_id, enabled, requests_per_second, burst_size,
		       zone_size, limit_by, limit_response, whitelist_ips, created_at, updated_at
		FROM rate_limits
		WHERE proxy_host_id = $1
	`

	var rl model.RateLimit
	var whitelistIPs sql.NullString

	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&rl.ID, &rl.ProxyHostID, &rl.Enabled, &rl.RequestsPerSecond, &rl.BurstSize,
		&rl.ZoneSize, &rl.LimitBy, &rl.LimitResponse, &whitelistIPs, &rl.CreatedAt, &rl.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	rl.WhitelistIPs = whitelistIPs.String
	return &rl, nil
}

func (r *RateLimitRepository) Upsert(ctx context.Context, proxyHostID string, req *model.CreateRateLimitRequest) (*model.RateLimit, error) {
	query := `
		INSERT INTO rate_limits (proxy_host_id, enabled, requests_per_second, burst_size,
		                         zone_size, limit_by, limit_response, whitelist_ips)
		VALUES ($1, COALESCE($2, TRUE), COALESCE(NULLIF($3, 0), 50), COALESCE(NULLIF($4, 0), 100),
		        COALESCE(NULLIF($5, ''), '10m'), COALESCE(NULLIF($6, ''), 'ip'), COALESCE(NULLIF($7, 0), 429), $8)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			enabled = COALESCE($2, rate_limits.enabled),
			requests_per_second = CASE WHEN $3 > 0 THEN $3 ELSE rate_limits.requests_per_second END,
			burst_size = CASE WHEN $4 > 0 THEN $4 ELSE rate_limits.burst_size END,
			zone_size = CASE WHEN $5 != '' THEN $5 ELSE rate_limits.zone_size END,
			limit_by = CASE WHEN $6 != '' THEN $6 ELSE rate_limits.limit_by END,
			limit_response = CASE WHEN $7 > 0 THEN $7 ELSE rate_limits.limit_response END,
			whitelist_ips = COALESCE($8, rate_limits.whitelist_ips),
			updated_at = NOW()
		RETURNING id, proxy_host_id, enabled, requests_per_second, burst_size,
		          zone_size, limit_by, limit_response, whitelist_ips, created_at, updated_at
	`

	var rl model.RateLimit
	var whitelistIPs sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		proxyHostID, req.Enabled, req.RequestsPerSecond, req.BurstSize,
		req.ZoneSize, req.LimitBy, req.LimitResponse, sql.NullString{String: req.WhitelistIPs, Valid: req.WhitelistIPs != ""},
	).Scan(
		&rl.ID, &rl.ProxyHostID, &rl.Enabled, &rl.RequestsPerSecond, &rl.BurstSize,
		&rl.ZoneSize, &rl.LimitBy, &rl.LimitResponse, &whitelistIPs, &rl.CreatedAt, &rl.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	rl.WhitelistIPs = whitelistIPs.String
	return &rl, nil
}

func (r *RateLimitRepository) Delete(ctx context.Context, proxyHostID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM rate_limits WHERE proxy_host_id = $1", proxyHostID)
	return err
}

// Fail2ban operations

func (r *RateLimitRepository) GetFail2banByProxyHostID(ctx context.Context, proxyHostID string) (*model.Fail2banConfig, error) {
	query := `
		SELECT id, proxy_host_id, enabled, max_retries, find_time, ban_time,
		       fail_codes, action, created_at, updated_at
		FROM fail2ban_configs
		WHERE proxy_host_id = $1
	`

	var f model.Fail2banConfig
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&f.ID, &f.ProxyHostID, &f.Enabled, &f.MaxRetries, &f.FindTime, &f.BanTime,
		&f.FailCodes, &f.Action, &f.CreatedAt, &f.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &f, nil
}

func (r *RateLimitRepository) UpsertFail2ban(ctx context.Context, proxyHostID string, req *model.CreateFail2banRequest) (*model.Fail2banConfig, error) {
	query := `
		INSERT INTO fail2ban_configs (proxy_host_id, enabled, max_retries, find_time, ban_time, fail_codes, action)
		VALUES ($1, COALESCE($2, TRUE), COALESCE(NULLIF($3, 0), 5), COALESCE(NULLIF($4, 0), 600),
		        COALESCE(NULLIF($5, 0), 3600), COALESCE(NULLIF($6, ''), '401,403'), COALESCE(NULLIF($7, ''), 'block'))
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			enabled = COALESCE($2, fail2ban_configs.enabled),
			max_retries = CASE WHEN $3 > 0 THEN $3 ELSE fail2ban_configs.max_retries END,
			find_time = CASE WHEN $4 > 0 THEN $4 ELSE fail2ban_configs.find_time END,
			ban_time = CASE WHEN $5 >= 0 THEN $5 ELSE fail2ban_configs.ban_time END,
			fail_codes = CASE WHEN $6 != '' THEN $6 ELSE fail2ban_configs.fail_codes END,
			action = CASE WHEN $7 != '' THEN $7 ELSE fail2ban_configs.action END,
			updated_at = NOW()
		RETURNING id, proxy_host_id, enabled, max_retries, find_time, ban_time, fail_codes, action, created_at, updated_at
	`

	var f model.Fail2banConfig
	err := r.db.QueryRowContext(ctx, query,
		proxyHostID, req.Enabled, req.MaxRetries, req.FindTime, req.BanTime, req.FailCodes, req.Action,
	).Scan(
		&f.ID, &f.ProxyHostID, &f.Enabled, &f.MaxRetries, &f.FindTime, &f.BanTime,
		&f.FailCodes, &f.Action, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &f, nil
}

func (r *RateLimitRepository) DeleteFail2ban(ctx context.Context, proxyHostID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM fail2ban_configs WHERE proxy_host_id = $1", proxyHostID)
	return err
}

// BannedIP operations

func (r *RateLimitRepository) ListBannedIPs(ctx context.Context, proxyHostID *string, page, perPage int) (*model.BannedIPListResponse, error) {
	var countQuery, listQuery string
	var args []interface{}

	// Only show active bans (permanent or not yet expired)
	activeCondition := "(is_permanent = TRUE OR expires_at > NOW())"

	if proxyHostID != nil {
		countQuery = "SELECT COUNT(*) FROM banned_ips WHERE proxy_host_id = $1 AND " + activeCondition
		listQuery = `
			SELECT id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, COALESCE(is_auto_banned, false), created_at
			FROM banned_ips
			WHERE proxy_host_id = $1 AND ` + activeCondition + `
			ORDER BY banned_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []interface{}{*proxyHostID, perPage, (page - 1) * perPage}
	} else {
		countQuery = "SELECT COUNT(*) FROM banned_ips WHERE " + activeCondition
		listQuery = `
			SELECT id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, COALESCE(is_auto_banned, false), created_at
			FROM banned_ips
			WHERE ` + activeCondition + `
			ORDER BY banned_at DESC
			LIMIT $1 OFFSET $2
		`
		args = []interface{}{perPage, (page - 1) * perPage}
	}

	var total int
	if proxyHostID != nil {
		err := r.db.QueryRowContext(ctx, countQuery, *proxyHostID).Scan(&total)
		if err != nil {
			return nil, err
		}
	} else {
		err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
		if err != nil {
			return nil, err
		}
	}

	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bannedIPs []model.BannedIP
	for rows.Next() {
		var b model.BannedIP
		var proxyHostID sql.NullString
		var reason sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(&b.ID, &proxyHostID, &b.IPAddress, &reason, &b.FailCount,
			&b.BannedAt, &expiresAt, &b.IsPermanent, &b.IsAutoBanned, &b.CreatedAt)
		if err != nil {
			return nil, err
		}

		if proxyHostID.Valid {
			b.ProxyHostID = &proxyHostID.String
		}
		b.Reason = reason.String
		if expiresAt.Valid {
			b.ExpiresAt = &expiresAt.Time
		}

		bannedIPs = append(bannedIPs, b)
	}

	totalPages := (total + perPage - 1) / perPage
	return &model.BannedIPListResponse{
		Data:       bannedIPs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// ListGlobalBannedIPs returns only banned IPs where proxy_host_id IS NULL (global bans)
func (r *RateLimitRepository) ListGlobalBannedIPs(ctx context.Context, page, perPage int) (*model.BannedIPListResponse, error) {
	activeCondition := "(is_permanent = TRUE OR expires_at > NOW())"

	countQuery := "SELECT COUNT(*) FROM banned_ips WHERE proxy_host_id IS NULL AND " + activeCondition
	listQuery := `
		SELECT id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, COALESCE(is_auto_banned, false), created_at
		FROM banned_ips
		WHERE proxy_host_id IS NULL AND ` + activeCondition + `
		ORDER BY banned_at DESC
		LIMIT $1 OFFSET $2
	`

	var total int
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, err
	}

	rows, err := r.db.QueryContext(ctx, listQuery, perPage, (page-1)*perPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bannedIPs []model.BannedIP
	for rows.Next() {
		var b model.BannedIP
		var proxyHostID sql.NullString
		var reason sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(&b.ID, &proxyHostID, &b.IPAddress, &reason, &b.FailCount,
			&b.BannedAt, &expiresAt, &b.IsPermanent, &b.IsAutoBanned, &b.CreatedAt)
		if err != nil {
			return nil, err
		}

		if proxyHostID.Valid {
			b.ProxyHostID = &proxyHostID.String
		}
		b.Reason = reason.String
		if expiresAt.Valid {
			b.ExpiresAt = &expiresAt.Time
		}

		bannedIPs = append(bannedIPs, b)
	}

	totalPages := (total + perPage - 1) / perPage
	return &model.BannedIPListResponse{
		Data:       bannedIPs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// ListHostBannedIPs returns only banned IPs where proxy_host_id IS NOT NULL (per-host bans)
func (r *RateLimitRepository) ListHostBannedIPs(ctx context.Context, page, perPage int) (*model.BannedIPListResponse, error) {
	activeCondition := "(is_permanent = TRUE OR expires_at > NOW())"

	countQuery := "SELECT COUNT(*) FROM banned_ips WHERE proxy_host_id IS NOT NULL AND " + activeCondition
	listQuery := `
		SELECT id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, COALESCE(is_auto_banned, false), created_at
		FROM banned_ips
		WHERE proxy_host_id IS NOT NULL AND ` + activeCondition + `
		ORDER BY banned_at DESC
		LIMIT $1 OFFSET $2
	`

	var total int
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, err
	}

	rows, err := r.db.QueryContext(ctx, listQuery, perPage, (page-1)*perPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bannedIPs []model.BannedIP
	for rows.Next() {
		var b model.BannedIP
		var proxyHostID sql.NullString
		var reason sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(&b.ID, &proxyHostID, &b.IPAddress, &reason, &b.FailCount,
			&b.BannedAt, &expiresAt, &b.IsPermanent, &b.IsAutoBanned, &b.CreatedAt)
		if err != nil {
			return nil, err
		}

		if proxyHostID.Valid {
			b.ProxyHostID = &proxyHostID.String
		}
		b.Reason = reason.String
		if expiresAt.Valid {
			b.ExpiresAt = &expiresAt.Time
		}

		bannedIPs = append(bannedIPs, b)
	}

	totalPages := (total + perPage - 1) / perPage
	return &model.BannedIPListResponse{
		Data:       bannedIPs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

func (r *RateLimitRepository) BanIP(ctx context.Context, proxyHostID *string, ip, reason string, banTime int) (*model.BannedIP, error) {
	var expiresAt *time.Time
	isPermanent := banTime == 0

	if !isPermanent {
		t := time.Now().Add(time.Duration(banTime) * time.Second)
		expiresAt = &t
	}

	// First delete any existing ban for this IP (for the same proxy host or global)
	if proxyHostID != nil {
		r.db.ExecContext(ctx, "DELETE FROM banned_ips WHERE ip_address = $1 AND proxy_host_id = $2", ip, *proxyHostID)
	} else {
		r.db.ExecContext(ctx, "DELETE FROM banned_ips WHERE ip_address = $1 AND proxy_host_id IS NULL", ip)
	}

	query := `
		INSERT INTO banned_ips (proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent)
		VALUES ($1, $2, $3, 1, NOW(), $4, $5)
		RETURNING id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, created_at
	`

	var b model.BannedIP
	var phID sql.NullString
	var reasonOut sql.NullString
	var expiresAtOut sql.NullTime

	err := r.db.QueryRowContext(ctx, query, proxyHostID, ip, reason, expiresAt, isPermanent).Scan(
		&b.ID, &phID, &b.IPAddress, &reasonOut, &b.FailCount, &b.BannedAt, &expiresAtOut, &b.IsPermanent, &b.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if phID.Valid {
		b.ProxyHostID = &phID.String
	}
	b.Reason = reasonOut.String
	if expiresAtOut.Valid {
		b.ExpiresAt = &expiresAtOut.Time
	}

	return &b, nil
}

func (r *RateLimitRepository) GetBannedIPByID(ctx context.Context, id string) (*model.BannedIP, error) {
	query := `
		SELECT id, proxy_host_id, ip_address, reason, fail_count, banned_at, expires_at, is_permanent, created_at
		FROM banned_ips WHERE id = $1
	`

	var b model.BannedIP
	var phID sql.NullString
	var reason sql.NullString
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&b.ID, &phID, &b.IPAddress, &reason, &b.FailCount, &b.BannedAt, &expiresAt, &b.IsPermanent, &b.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if phID.Valid {
		b.ProxyHostID = &phID.String
	}
	b.Reason = reason.String
	if expiresAt.Valid {
		b.ExpiresAt = &expiresAt.Time
	}

	return &b, nil
}

func (r *RateLimitRepository) UnbanIP(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM banned_ips WHERE id = $1", id)
	return err
}

func (r *RateLimitRepository) UnbanIPByAddress(ctx context.Context, ip string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM banned_ips WHERE ip_address = $1", ip)
	return err
}

func (r *RateLimitRepository) CleanExpiredBans(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, "DELETE FROM banned_ips WHERE expires_at < NOW() AND is_permanent = FALSE")
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *RateLimitRepository) IsIPBanned(ctx context.Context, proxyHostID *string, ip string) (bool, error) {
	var query string
	var args []interface{}

	if proxyHostID != nil {
		query = `
			SELECT EXISTS(
				SELECT 1 FROM banned_ips
				WHERE ip_address = $1
				AND (proxy_host_id = $2 OR proxy_host_id IS NULL)
				AND (expires_at > NOW() OR is_permanent = TRUE)
			)
		`
		args = []interface{}{ip, *proxyHostID}
	} else {
		query = `
			SELECT EXISTS(
				SELECT 1 FROM banned_ips
				WHERE ip_address = $1
				AND (expires_at > NOW() OR is_permanent = TRUE)
			)
		`
		args = []interface{}{ip}
	}

	var exists bool
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	return exists, err
}

// GetActiveBannedIPSet returns the set of IPs from the given list that are currently actively banned.
func (r *RateLimitRepository) GetActiveBannedIPSet(ctx context.Context, ips []string) (map[string]bool, error) {
	result := make(map[string]bool)
	if len(ips) == 0 {
		return result, nil
	}

	query := `
		SELECT DISTINCT ip_address FROM banned_ips
		WHERE ip_address = ANY($1) AND (is_permanent = TRUE OR expires_at > NOW())
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ips))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		result[ip] = true
	}

	return result, rows.Err()
}
