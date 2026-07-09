package repository

import (
	"context"
	"database/sql"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// GlobalGeoRepository manages the singleton global_geo_restrictions row — the
// global geo default that hosts inherit unless they override or opt out.
// Mirrors the URIBlockRepository global-singleton pattern.
type GlobalGeoRepository struct {
	db *database.DB
}

func NewGlobalGeoRepository(db *database.DB) *GlobalGeoRepository {
	return &GlobalGeoRepository{db: db}
}

// GetGlobal returns the singleton global geo default. When no row exists it
// returns a zero-value, disabled default (mirrors GetGlobalURIBlock) so callers
// never special-case "not configured yet".
func (r *GlobalGeoRepository) GetGlobal(ctx context.Context) (*model.GlobalGeoRestriction, error) {
	var g model.GlobalGeoRestriction
	var countries pq.StringArray
	var allowedIPs pq.StringArray
	err := r.db.QueryRowContext(ctx, `
		SELECT id, enabled, mode, countries, COALESCE(allowed_ips, '{}'),
		       allow_private_ips, allow_search_bots, challenge_mode, created_at, updated_at
		FROM global_geo_restrictions LIMIT 1
	`).Scan(&g.ID, &g.Enabled, &g.Mode, &countries, &allowedIPs,
		&g.AllowPrivateIPs, &g.AllowSearchBots, &g.ChallengeMode, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return &model.GlobalGeoRestriction{
			Enabled:         false,
			Mode:            "blacklist",
			Countries:       []string{},
			AllowedIPs:      []string{},
			AllowPrivateIPs: true,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	g.Countries = []string(countries)
	g.AllowedIPs = []string(allowedIPs)
	return &g, nil
}

// Upsert applies a partial update to the singleton, creating it if absent.
func (r *GlobalGeoRepository) Upsert(ctx context.Context, req *model.UpdateGlobalGeoRestrictionRequest) (*model.GlobalGeoRestriction, error) {
	cur, err := r.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	if req.Mode != nil {
		cur.Mode = *req.Mode
	}
	if req.Countries != nil {
		cur.Countries = req.Countries
	}
	if req.AllowedIPs != nil {
		cur.AllowedIPs = req.AllowedIPs
	}
	if req.AllowPrivateIPs != nil {
		cur.AllowPrivateIPs = *req.AllowPrivateIPs
	}
	if req.AllowSearchBots != nil {
		cur.AllowSearchBots = *req.AllowSearchBots
	}
	if req.ChallengeMode != nil {
		cur.ChallengeMode = *req.ChallengeMode
	}

	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO global_geo_restrictions (enabled, mode, countries, allowed_ips, allow_private_ips, allow_search_bots, challenge_mode)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, cur.Enabled, cur.Mode, pq.Array(cur.Countries), pq.Array(cur.AllowedIPs), cur.AllowPrivateIPs, cur.AllowSearchBots, cur.ChallengeMode)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE global_geo_restrictions
			SET enabled=$1, mode=$2, countries=$3, allowed_ips=$4, allow_private_ips=$5, allow_search_bots=$6, challenge_mode=$7, updated_at=NOW()
			WHERE id=$8
		`, cur.Enabled, cur.Mode, pq.Array(cur.Countries), pq.Array(cur.AllowedIPs), cur.AllowPrivateIPs, cur.AllowSearchBots, cur.ChallengeMode, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetGlobal(ctx)
}
