package repository

import (
	"context"
	"database/sql"

	"nginx-proxy-guard/internal/model"
)

// CloudflareTunnelRepository manages the singleton cloudflare_tunnel row
// (Cloudflare Tunnel Phase 1 token mode).
type CloudflareTunnelRepository struct {
	db *sql.DB
}

func NewCloudflareTunnelRepository(db *sql.DB) *CloudflareTunnelRepository {
	return &CloudflareTunnelRepository{db: db}
}

func defaultCloudflareTunnel() *model.CloudflareTunnel {
	return &model.CloudflareTunnel{Enabled: false, Mode: "token"}
}

// GetSingleton returns the singleton row, or a disabled default when absent.
func (r *CloudflareTunnelRepository) GetSingleton(ctx context.Context) (*model.CloudflareTunnel, error) {
	var t model.CloudflareTunnel
	err := r.db.QueryRowContext(ctx, `
		SELECT id, enabled, token, mode, created_at, updated_at
		FROM cloudflare_tunnel LIMIT 1
	`).Scan(&t.ID, &t.Enabled, &t.Token, &t.Mode, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return defaultCloudflareTunnel(), nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Upsert applies a partial update to the singleton, creating it if absent.
// Token: nil keeps the stored token; non-nil replaces it.
func (r *CloudflareTunnelRepository) Upsert(ctx context.Context, req *model.UpdateCloudflareTunnelRequest) (*model.CloudflareTunnel, error) {
	cur, err := r.GetSingleton(ctx)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	if req.Token != nil {
		cur.Token = *req.Token
	}

	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO cloudflare_tunnel (enabled, token, mode)
			VALUES ($1, $2, $3)
		`, cur.Enabled, cur.Token, cur.Mode)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE cloudflare_tunnel
			SET enabled=$1, token=$2, updated_at=NOW()
			WHERE id=$3
		`, cur.Enabled, cur.Token, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetSingleton(ctx)
}
