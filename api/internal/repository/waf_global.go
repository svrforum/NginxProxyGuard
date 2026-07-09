package repository

import (
	"context"
	"database/sql"

	"nginx-proxy-guard/internal/model"
)

// GlobalWAFRepository manages the singleton global_waf row — the global WAF
// default hosts inherit when waf_use_global=true (#198 slice 6).
type GlobalWAFRepository struct {
	db *sql.DB
}

func NewGlobalWAFRepository(db *sql.DB) *GlobalWAFRepository {
	return &GlobalWAFRepository{db: db}
}

func defaultGlobalWAF() *model.GlobalWAF {
	return &model.GlobalWAF{
		Enabled: false, Mode: "detection", ParanoiaLevel: 1, AnomalyThreshold: 5,
	}
}

// GetGlobal returns the singleton global WAF default, or a zero-value disabled
// default when no row exists.
func (r *GlobalWAFRepository) GetGlobal(ctx context.Context) (*model.GlobalWAF, error) {
	var g model.GlobalWAF
	err := r.db.QueryRowContext(ctx, `
		SELECT id, enabled, mode, paranoia_level, anomaly_threshold, created_at, updated_at
		FROM global_waf LIMIT 1
	`).Scan(&g.ID, &g.Enabled, &g.Mode, &g.ParanoiaLevel, &g.AnomalyThreshold, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return defaultGlobalWAF(), nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// Upsert applies a partial update to the singleton, creating it if absent.
func (r *GlobalWAFRepository) Upsert(ctx context.Context, req *model.UpdateGlobalWAFRequest) (*model.GlobalWAF, error) {
	cur, err := r.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	if req.Mode != "" {
		cur.Mode = req.Mode
	}
	if req.ParanoiaLevel > 0 {
		cur.ParanoiaLevel = req.ParanoiaLevel
	}
	if req.AnomalyThreshold > 0 {
		cur.AnomalyThreshold = req.AnomalyThreshold
	}

	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO global_waf (enabled, mode, paranoia_level, anomaly_threshold)
			VALUES ($1, $2, $3, $4)
		`, cur.Enabled, cur.Mode, cur.ParanoiaLevel, cur.AnomalyThreshold)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE global_waf
			SET enabled=$1, mode=$2, paranoia_level=$3, anomaly_threshold=$4, updated_at=NOW()
			WHERE id=$5
		`, cur.Enabled, cur.Mode, cur.ParanoiaLevel, cur.AnomalyThreshold, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetGlobal(ctx)
}
