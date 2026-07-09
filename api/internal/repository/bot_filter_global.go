package repository

import (
	"context"
	"database/sql"

	"nginx-proxy-guard/internal/model"
)

// GlobalBotFilterRepository manages the singleton global_bot_filters row — the
// global bot-filter default hosts inherit unless they override or opt out (#198).
type GlobalBotFilterRepository struct {
	db *sql.DB
}

func NewGlobalBotFilterRepository(db *sql.DB) *GlobalBotFilterRepository {
	return &GlobalBotFilterRepository{db: db}
}

// GetGlobal returns the singleton global bot-filter default, or a zero-value
// disabled default when no row exists.
func (r *GlobalBotFilterRepository) GetGlobal(ctx context.Context) (*model.GlobalBotFilter, error) {
	var g model.GlobalBotFilter
	var customBlocked, customAllowed sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, enabled, block_bad_bots, block_ai_bots, allow_search_engines, block_suspicious_clients,
		       custom_blocked_agents, custom_allowed_agents, challenge_suspicious, created_at, updated_at
		FROM global_bot_filters LIMIT 1
	`).Scan(&g.ID, &g.Enabled, &g.BlockBadBots, &g.BlockAIBots, &g.AllowSearchEngines, &g.BlockSuspiciousClients,
		&customBlocked, &customAllowed, &g.ChallengeSuspicious, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return &model.GlobalBotFilter{Enabled: false, BlockBadBots: true, AllowSearchEngines: true}, nil
	}
	if err != nil {
		return nil, err
	}
	g.CustomBlockedAgents = customBlocked.String
	g.CustomAllowedAgents = customAllowed.String
	return &g, nil
}

// Upsert applies a partial update to the singleton, creating it if absent.
func (r *GlobalBotFilterRepository) Upsert(ctx context.Context, req *model.UpdateGlobalBotFilterRequest) (*model.GlobalBotFilter, error) {
	cur, err := r.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	if req.BlockBadBots != nil {
		cur.BlockBadBots = *req.BlockBadBots
	}
	if req.BlockAIBots != nil {
		cur.BlockAIBots = *req.BlockAIBots
	}
	if req.AllowSearchEngines != nil {
		cur.AllowSearchEngines = *req.AllowSearchEngines
	}
	if req.BlockSuspiciousClients != nil {
		cur.BlockSuspiciousClients = *req.BlockSuspiciousClients
	}
	if req.CustomBlockedAgents != nil {
		cur.CustomBlockedAgents = *req.CustomBlockedAgents
	}
	if req.CustomAllowedAgents != nil {
		cur.CustomAllowedAgents = *req.CustomAllowedAgents
	}
	if req.ChallengeSuspicious != nil {
		cur.ChallengeSuspicious = *req.ChallengeSuspicious
	}

	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO global_bot_filters (enabled, block_bad_bots, block_ai_bots, allow_search_engines, block_suspicious_clients, custom_blocked_agents, custom_allowed_agents, challenge_suspicious)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, cur.Enabled, cur.BlockBadBots, cur.BlockAIBots, cur.AllowSearchEngines, cur.BlockSuspiciousClients, cur.CustomBlockedAgents, cur.CustomAllowedAgents, cur.ChallengeSuspicious)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE global_bot_filters
			SET enabled=$1, block_bad_bots=$2, block_ai_bots=$3, allow_search_engines=$4, block_suspicious_clients=$5, custom_blocked_agents=$6, custom_allowed_agents=$7, challenge_suspicious=$8, updated_at=NOW()
			WHERE id=$9
		`, cur.Enabled, cur.BlockBadBots, cur.BlockAIBots, cur.AllowSearchEngines, cur.BlockSuspiciousClients, cur.CustomBlockedAgents, cur.CustomAllowedAgents, cur.ChallengeSuspicious, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetGlobal(ctx)
}
