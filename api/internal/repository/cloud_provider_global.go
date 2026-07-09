package repository

import (
	"context"
	"database/sql"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// GlobalCloudProvidersRepository manages the singleton global_cloud_providers
// row — the global cloud-provider blocking default hosts inherit unless they
// override or opt out (#198 slice 4).
type GlobalCloudProvidersRepository struct {
	db *sql.DB
}

func NewGlobalCloudProvidersRepository(db *sql.DB) *GlobalCloudProvidersRepository {
	return &GlobalCloudProvidersRepository{db: db}
}

// GetGlobal returns the singleton global cloud-provider default, or a zero-value
// (empty blocked list) default when no row exists.
func (r *GlobalCloudProvidersRepository) GetGlobal(ctx context.Context) (*model.GlobalCloudProviders, error) {
	var g model.GlobalCloudProviders
	err := r.db.QueryRowContext(ctx, `
		SELECT id, COALESCE(blocked_providers, '{}'), challenge_mode, allow_search_bots, created_at, updated_at
		FROM global_cloud_providers LIMIT 1
	`).Scan(&g.ID, pq.Array(&g.BlockedProviders), &g.ChallengeMode, &g.AllowSearchBots, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return &model.GlobalCloudProviders{BlockedProviders: []string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	if g.BlockedProviders == nil {
		g.BlockedProviders = []string{}
	}
	return &g, nil
}

// Upsert replaces the singleton, creating it if absent.
func (r *GlobalCloudProvidersRepository) Upsert(ctx context.Context, req *model.UpdateGlobalCloudProvidersRequest) (*model.GlobalCloudProviders, error) {
	cur, err := r.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	providers := req.BlockedProviders
	if providers == nil {
		providers = []string{}
	}
	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO global_cloud_providers (blocked_providers, challenge_mode, allow_search_bots)
			VALUES ($1, $2, $3)
		`, pq.Array(providers), req.ChallengeMode, req.AllowSearchBots)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE global_cloud_providers
			SET blocked_providers=$1, challenge_mode=$2, allow_search_bots=$3, updated_at=NOW()
			WHERE id=$4
		`, pq.Array(providers), req.ChallengeMode, req.AllowSearchBots, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetGlobal(ctx)
}
