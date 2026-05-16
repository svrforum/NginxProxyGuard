package repository

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"
)

type GeoRepository struct {
	db    *database.DB
	cache *cache.RedisClient
}

func NewGeoRepository(db *database.DB) *GeoRepository {
	return &GeoRepository{db: db}
}

// SetCache wires Valkey caching for GetByProxyHostID, the hot lookup during
// nginx config generation. Per-host TTL invalidation runs on every write.
func (r *GeoRepository) SetCache(c *cache.RedisClient) {
	r.cache = c
}

const geoCacheTTL = 60 * time.Second

func (r *GeoRepository) cacheKey(proxyHostID string) string {
	return "geo:host:" + proxyHostID
}

func (r *GeoRepository) invalidateHost(ctx context.Context, proxyHostID string) {
	if r.cache == nil {
		return
	}
	if err := r.cache.Delete(ctx, r.cacheKey(proxyHostID)); err != nil {
		log.Printf("[Cache] geo invalidate failed for host %s: %v", proxyHostID, err)
	}
}

// InvalidateHost is the exported form used by sibling repositories that
// write to the geo_restrictions table directly (e.g. CloudProviderRepository
// updating blocked_cloud_providers). Without this cross-repo invalidation a
// per-host geo cache entry would stay stale until TTL.
func (r *GeoRepository) InvalidateHost(ctx context.Context, proxyHostID string) {
	r.invalidateHost(ctx, proxyHostID)
}

// fetchByProxyHostID is the uncached SQL path. GetByProxyHostID layers caching
// on top; Update() uses this directly so its read-modify-write sequence never
// merges a stale row back over a concurrent write from another repository.
func (r *GeoRepository) fetchByProxyHostID(ctx context.Context, proxyHostID string) (*model.GeoRestriction, error) {
	var geo model.GeoRestriction
	var countries pq.StringArray
	var allowedIPs pq.StringArray
	var challengeMode sql.NullBool
	var allowPrivateIPs sql.NullBool
	var allowSearchBots sql.NullBool

	err := r.db.QueryRowContext(ctx, `
		SELECT id, proxy_host_id, mode, countries, COALESCE(allowed_ips, '{}'), enabled,
		       COALESCE(challenge_mode, false), COALESCE(allow_private_ips, true),
		       COALESCE(allow_search_bots, false), created_at, updated_at
		FROM geo_restrictions WHERE proxy_host_id = $1
	`, proxyHostID).Scan(
		&geo.ID, &geo.ProxyHostID, &geo.Mode, &countries, &allowedIPs, &geo.Enabled,
		&challengeMode, &allowPrivateIPs, &allowSearchBots, &geo.CreatedAt, &geo.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	geo.Countries = []string(countries)
	geo.AllowedIPs = []string(allowedIPs)
	geo.ChallengeMode = challengeMode.Bool
	geo.AllowPrivateIPs = allowPrivateIPs.Bool
	geo.AllowSearchBots = allowSearchBots.Bool
	return &geo, nil
}

func (r *GeoRepository) GetByProxyHostID(ctx context.Context, proxyHostID string) (*model.GeoRestriction, error) {
	key := r.cacheKey(proxyHostID)
	if r.cache != nil {
		var cached model.GeoRestriction
		if err := r.cache.Get(ctx, key, &cached); err == nil {
			if cached.ID == "" {
				return nil, nil
			}
			return &cached, nil
		}
	}

	var geo model.GeoRestriction
	var countries pq.StringArray
	var allowedIPs pq.StringArray
	var challengeMode sql.NullBool
	var allowPrivateIPs sql.NullBool
	var allowSearchBots sql.NullBool

	err := r.db.QueryRowContext(ctx, `
		SELECT id, proxy_host_id, mode, countries, COALESCE(allowed_ips, '{}'), enabled,
		       COALESCE(challenge_mode, false), COALESCE(allow_private_ips, true),
		       COALESCE(allow_search_bots, false), created_at, updated_at
		FROM geo_restrictions WHERE proxy_host_id = $1
	`, proxyHostID).Scan(
		&geo.ID, &geo.ProxyHostID, &geo.Mode, &countries, &allowedIPs, &geo.Enabled,
		&challengeMode, &allowPrivateIPs, &allowSearchBots, &geo.CreatedAt, &geo.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		if r.cache != nil {
			// Cache the "no restriction" miss so the next host without geo
			// rules during SyncAllConfigs doesn't re-hit the DB.
			_ = r.cache.Set(ctx, key, model.GeoRestriction{}, geoCacheTTL)
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	geo.Countries = []string(countries)
	geo.AllowedIPs = []string(allowedIPs)
	geo.ChallengeMode = challengeMode.Bool
	geo.AllowPrivateIPs = allowPrivateIPs.Bool
	geo.AllowSearchBots = allowSearchBots.Bool

	if r.cache != nil {
		if err := r.cache.Set(ctx, key, geo, geoCacheTTL); err != nil {
			log.Printf("[Cache] Failed to cache geo restriction for host %s: %v", proxyHostID, err)
		}
	}
	return &geo, nil
}

func (r *GeoRepository) Upsert(ctx context.Context, proxyHostID string, req *model.CreateGeoRestrictionRequest) (*model.GeoRestriction, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	challengeMode := false
	if req.ChallengeMode != nil {
		challengeMode = *req.ChallengeMode
	}

	allowPrivateIPs := true
	if req.AllowPrivateIPs != nil {
		allowPrivateIPs = *req.AllowPrivateIPs
	}

	allowSearchBots := false
	if req.AllowSearchBots != nil {
		allowSearchBots = *req.AllowSearchBots
	}

	allowedIPs := req.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}

	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO geo_restrictions (proxy_host_id, mode, countries, allowed_ips, enabled, challenge_mode, allow_private_ips, allow_search_bots)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			mode = EXCLUDED.mode,
			countries = EXCLUDED.countries,
			allowed_ips = EXCLUDED.allowed_ips,
			enabled = EXCLUDED.enabled,
			challenge_mode = EXCLUDED.challenge_mode,
			allow_private_ips = EXCLUDED.allow_private_ips,
			allow_search_bots = EXCLUDED.allow_search_bots,
			updated_at = NOW()
		RETURNING id
	`, proxyHostID, req.Mode, pq.Array(req.Countries), pq.Array(allowedIPs), enabled, challengeMode, allowPrivateIPs, allowSearchBots).Scan(&id)
	if err != nil {
		return nil, err
	}

	r.invalidateHost(ctx, proxyHostID)
	return r.GetByProxyHostID(ctx, proxyHostID)
}

func (r *GeoRepository) Update(ctx context.Context, proxyHostID string, req *model.UpdateGeoRestrictionRequest) (*model.GeoRestriction, error) {
	// Use the uncached SQL read here. This is read-modify-write — pulling a
	// stale cached row would silently revert columns written by sibling
	// repositories (e.g. CloudProviderRepository.SetBlockedCloudProviders)
	// because the merge below writes the full row back. Cost is one extra
	// SQL round-trip per geo restriction save; this path is admin-rare.
	existing, err := r.fetchByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}

	// Apply updates
	if req.Mode != nil {
		existing.Mode = *req.Mode
	}
	if len(req.Countries) > 0 {
		existing.Countries = req.Countries
	}
	if req.AllowedIPs != nil {
		existing.AllowedIPs = req.AllowedIPs
	}
	if req.AllowPrivateIPs != nil {
		existing.AllowPrivateIPs = *req.AllowPrivateIPs
	}
	if req.AllowSearchBots != nil {
		existing.AllowSearchBots = *req.AllowSearchBots
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.ChallengeMode != nil {
		existing.ChallengeMode = *req.ChallengeMode
	}

	_, err = r.db.ExecContext(ctx, `
		UPDATE geo_restrictions SET
			mode = $1, countries = $2, allowed_ips = $3, enabled = $4, challenge_mode = $5, allow_private_ips = $6, allow_search_bots = $7, updated_at = $8
		WHERE proxy_host_id = $9
	`, existing.Mode, pq.Array(existing.Countries), pq.Array(existing.AllowedIPs), existing.Enabled, existing.ChallengeMode, existing.AllowPrivateIPs, existing.AllowSearchBots, time.Now(), proxyHostID)
	if err != nil {
		return nil, err
	}

	r.invalidateHost(ctx, proxyHostID)
	return r.GetByProxyHostID(ctx, proxyHostID)
}

func (r *GeoRepository) Delete(ctx context.Context, proxyHostID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM geo_restrictions WHERE proxy_host_id = $1`, proxyHostID)
	if err != nil {
		return err
	}
	r.invalidateHost(ctx, proxyHostID)
	return nil
}
