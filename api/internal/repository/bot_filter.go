package repository

import (
	"context"
	"database/sql"
	"log"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"
)

type BotFilterRepository struct {
	db    *sql.DB
	cache *cache.RedisClient
}

func NewBotFilterRepository(db *sql.DB) *BotFilterRepository {
	return &BotFilterRepository{db: db}
}

// SetCache wires Valkey caching for GetByProxyHostID, the hot lookup during
// nginx config generation. Cache is invalidated on per-host writes.
func (r *BotFilterRepository) SetCache(c *cache.RedisClient) {
	r.cache = c
}

const botFilterCacheTTL = 60 * time.Second

func (r *BotFilterRepository) cacheKey(proxyHostID string) string {
	return "bot_filter:host:" + proxyHostID
}

func (r *BotFilterRepository) invalidateHost(ctx context.Context, proxyHostID string) {
	if r.cache == nil {
		return
	}
	_ = r.cache.Delete(ctx, r.cacheKey(proxyHostID))
}

func (r *BotFilterRepository) GetByProxyHostID(ctx context.Context, proxyHostID string) (*model.BotFilter, error) {
	key := r.cacheKey(proxyHostID)
	if r.cache != nil {
		var cached model.BotFilter
		if err := r.cache.Get(ctx, key, &cached); err == nil {
			// Empty ID encodes a cached "no row" — return (nil, nil) so callers
			// retain the same contract as the underlying SQL.
			if cached.ID == "" {
				return nil, nil
			}
			return &cached, nil
		}
	}

	query := `
		SELECT id, proxy_host_id, enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		       COALESCE(block_suspicious_clients, FALSE) as block_suspicious_clients,
		       custom_blocked_agents, custom_allowed_agents, challenge_suspicious, created_at, updated_at
		FROM bot_filters
		WHERE proxy_host_id = $1
	`

	var bf model.BotFilter
	var customBlocked, customAllowed sql.NullString

	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&bf.ID, &bf.ProxyHostID, &bf.Enabled, &bf.BlockBadBots, &bf.BlockAIBots, &bf.AllowSearchEngines,
		&bf.BlockSuspiciousClients, &customBlocked, &customAllowed, &bf.ChallengeSuspicious, &bf.CreatedAt, &bf.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		if r.cache != nil {
			_ = r.cache.Set(ctx, key, model.BotFilter{}, botFilterCacheTTL)
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	bf.CustomBlockedAgents = customBlocked.String
	bf.CustomAllowedAgents = customAllowed.String

	if r.cache != nil {
		if err := r.cache.Set(ctx, key, bf, botFilterCacheTTL); err != nil {
			log.Printf("[Cache] Failed to cache bot filter for host %s: %v", proxyHostID, err)
		}
	}
	return &bf, nil
}

func (r *BotFilterRepository) Upsert(ctx context.Context, proxyHostID string, req *model.CreateBotFilterRequest) (*model.BotFilter, error) {
	query := `
		INSERT INTO bot_filters (proxy_host_id, enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		                         block_suspicious_clients, custom_blocked_agents, custom_allowed_agents, challenge_suspicious)
		VALUES ($1, COALESCE($2, TRUE), COALESCE($3, TRUE), COALESCE($4, FALSE), COALESCE($5, TRUE),
		        COALESCE($6, FALSE), $7, $8, COALESCE($9, FALSE))
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			enabled = COALESCE($2, bot_filters.enabled),
			block_bad_bots = COALESCE($3, bot_filters.block_bad_bots),
			block_ai_bots = COALESCE($4, bot_filters.block_ai_bots),
			allow_search_engines = COALESCE($5, bot_filters.allow_search_engines),
			block_suspicious_clients = COALESCE($6, bot_filters.block_suspicious_clients),
			custom_blocked_agents = $7,
			custom_allowed_agents = $8,
			challenge_suspicious = COALESCE($9, bot_filters.challenge_suspicious),
			updated_at = NOW()
		RETURNING id, proxy_host_id, enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		          COALESCE(block_suspicious_clients, FALSE) as block_suspicious_clients,
		          custom_blocked_agents, custom_allowed_agents, challenge_suspicious, created_at, updated_at
	`

	var bf model.BotFilter
	var customBlocked, customAllowed sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		proxyHostID, req.Enabled, req.BlockBadBots, req.BlockAIBots, req.AllowSearchEngines,
		req.BlockSuspiciousClients,
		req.CustomBlockedAgents,
		req.CustomAllowedAgents,
		req.ChallengeSuspicious,
	).Scan(
		&bf.ID, &bf.ProxyHostID, &bf.Enabled, &bf.BlockBadBots, &bf.BlockAIBots, &bf.AllowSearchEngines,
		&bf.BlockSuspiciousClients, &customBlocked, &customAllowed, &bf.ChallengeSuspicious, &bf.CreatedAt, &bf.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	bf.CustomBlockedAgents = customBlocked.String
	bf.CustomAllowedAgents = customAllowed.String
	r.invalidateHost(ctx, proxyHostID)
	return &bf, nil
}

func (r *BotFilterRepository) Delete(ctx context.Context, proxyHostID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM bot_filters WHERE proxy_host_id = $1", proxyHostID)
	if err != nil {
		return err
	}
	r.invalidateHost(ctx, proxyHostID)
	return nil
}

func (r *BotFilterRepository) List(ctx context.Context) ([]model.BotFilter, error) {
	query := `
		SELECT id, proxy_host_id, enabled, block_bad_bots, block_ai_bots, allow_search_engines,
		       COALESCE(block_suspicious_clients, FALSE) as block_suspicious_clients,
		       custom_blocked_agents, custom_allowed_agents, challenge_suspicious, created_at, updated_at
		FROM bot_filters
		WHERE enabled = TRUE
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var filters []model.BotFilter
	for rows.Next() {
		var bf model.BotFilter
		var customBlocked, customAllowed sql.NullString

		err := rows.Scan(
			&bf.ID, &bf.ProxyHostID, &bf.Enabled, &bf.BlockBadBots, &bf.BlockAIBots, &bf.AllowSearchEngines,
			&bf.BlockSuspiciousClients, &customBlocked, &customAllowed, &bf.ChallengeSuspicious, &bf.CreatedAt, &bf.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		bf.CustomBlockedAgents = customBlocked.String
		bf.CustomAllowedAgents = customAllowed.String
		filters = append(filters, bf)
	}

	return filters, nil
}
