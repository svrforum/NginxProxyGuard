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
		SELECT id, enabled, token, mode, api_token, catchall_enabled, catchall_applied_service, created_at, updated_at
		FROM cloudflare_tunnel LIMIT 1
	`).Scan(&t.ID, &t.Enabled, &t.Token, &t.Mode, &t.APIToken, &t.CatchallEnabled, &t.CatchallAppliedService, &t.CreatedAt, &t.UpdatedAt)
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
	if req.Mode != nil {
		cur.Mode = *req.Mode
	}
	if req.APIToken != nil {
		cur.APIToken = *req.APIToken
	}
	if req.CatchallEnabled != nil {
		cur.CatchallEnabled = *req.CatchallEnabled
	}

	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO cloudflare_tunnel (enabled, token, mode, api_token, catchall_enabled, catchall_applied_service)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, cur.Enabled, cur.Token, cur.Mode, cur.APIToken, cur.CatchallEnabled, cur.CatchallAppliedService)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE cloudflare_tunnel
			SET enabled=$1, token=$2, mode=$3, api_token=$4, catchall_enabled=$5, updated_at=NOW()
			WHERE id=$6
		`, cur.Enabled, cur.Token, cur.Mode, cur.APIToken, cur.CatchallEnabled, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetSingleton(ctx)
}

// SetCatchallAppliedService records the exact service URL NPG last wrote into
// the tunnel's catch-all rule ("" = NPG's rule is no longer in place). Written
// only after a successful Cloudflare API call, so it always trails reality.
func (r *CloudflareTunnelRepository) SetCatchallAppliedService(ctx context.Context, service string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE cloudflare_tunnel SET catchall_applied_service=$1, updated_at=NOW()
	`, service)
	return err
}
