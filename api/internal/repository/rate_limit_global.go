package repository

import (
	"context"
	"database/sql"

	"nginx-proxy-guard/internal/model"
)

// GlobalRateLimitRepository manages the singleton global_rate_limits row — the
// global rate-limit default hosts inherit unless they override or opt out
// (#198 slice 5). The nginx zone stays per-host; only values are inherited.
type GlobalRateLimitRepository struct {
	db *sql.DB
}

func NewGlobalRateLimitRepository(db *sql.DB) *GlobalRateLimitRepository {
	return &GlobalRateLimitRepository{db: db}
}

func defaultGlobalRateLimit() *model.GlobalRateLimit {
	return &model.GlobalRateLimit{
		Enabled: false, RequestsPerSecond: 50, BurstSize: 100,
		ZoneSize: "10m", LimitBy: "ip", LimitResponse: 429,
	}
}

// GetGlobal returns the singleton global rate-limit default, or a zero-value
// disabled default when no row exists.
func (r *GlobalRateLimitRepository) GetGlobal(ctx context.Context) (*model.GlobalRateLimit, error) {
	var g model.GlobalRateLimit
	var whitelist sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, enabled, requests_per_second, burst_size, zone_size, limit_by, limit_response, whitelist_ips, created_at, updated_at
		FROM global_rate_limits LIMIT 1
	`).Scan(&g.ID, &g.Enabled, &g.RequestsPerSecond, &g.BurstSize, &g.ZoneSize, &g.LimitBy, &g.LimitResponse, &whitelist, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return defaultGlobalRateLimit(), nil
	}
	if err != nil {
		return nil, err
	}
	g.WhitelistIPs = whitelist.String
	return &g, nil
}

// Upsert applies a partial update to the singleton, creating it if absent.
func (r *GlobalRateLimitRepository) Upsert(ctx context.Context, req *model.UpdateGlobalRateLimitRequest) (*model.GlobalRateLimit, error) {
	cur, err := r.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	if req.RequestsPerSecond > 0 {
		cur.RequestsPerSecond = req.RequestsPerSecond
	}
	if req.BurstSize > 0 {
		cur.BurstSize = req.BurstSize
	}
	if req.ZoneSize != "" {
		cur.ZoneSize = req.ZoneSize
	}
	if req.LimitBy != "" {
		cur.LimitBy = req.LimitBy
	}
	if req.LimitResponse > 0 {
		cur.LimitResponse = req.LimitResponse
	}
	// Whitelist can legitimately be cleared to empty.
	cur.WhitelistIPs = req.WhitelistIPs

	whitelist := sql.NullString{String: cur.WhitelistIPs, Valid: cur.WhitelistIPs != ""}
	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO global_rate_limits (enabled, requests_per_second, burst_size, zone_size, limit_by, limit_response, whitelist_ips)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, cur.Enabled, cur.RequestsPerSecond, cur.BurstSize, cur.ZoneSize, cur.LimitBy, cur.LimitResponse, whitelist)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE global_rate_limits
			SET enabled=$1, requests_per_second=$2, burst_size=$3, zone_size=$4, limit_by=$5, limit_response=$6, whitelist_ips=$7, updated_at=NOW()
			WHERE id=$8
		`, cur.Enabled, cur.RequestsPerSecond, cur.BurstSize, cur.ZoneSize, cur.LimitBy, cur.LimitResponse, whitelist, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetGlobal(ctx)
}
