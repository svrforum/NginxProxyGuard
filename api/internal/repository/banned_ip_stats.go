package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"nginx-proxy-guard/internal/model"
)

// BannedIPStatsRepository answers the per-IP summary behind a banned address.
//
// It reads two sources with very different costs: ip_ban_history is small and
// indexed, while logs_partitioned is a compressed hypertable where a client_ip
// lookup cannot use the btree inside compressed chunks — every chunk in range
// is scanned. That is why the traffic side is one query over a bounded window
// rather than several convenient ones. (#242)
type BannedIPStatsRepository struct {
	db *sql.DB
}

func NewBannedIPStatsRepository(db *sql.DB) *BannedIPStatsRepository {
	return &BannedIPStatsRepository{db: db}
}

// One CTE, read four ways. The CTE is MATERIALIZED on purpose: without it the
// planner inlines the scan into each branch and the address is scanned four
// times, which on a large hypertable is the difference between one slow query
// and four.
const bannedIPTrafficQuery = `
WITH scoped AS MATERIALIZED (
    SELECT host, request_uri, block_reason, geo_country, geo_country_code, timestamp
    FROM logs_partitioned
    WHERE client_ip = $1::inet
      AND timestamp > now() - make_interval(days => $2)
      AND ` + canaryURIExclusion + `
),
totals AS (
    SELECT count(*)                                        AS total,
           count(*) FILTER (WHERE block_reason <> 'none')  AS blocked,
           min(timestamp)                                  AS first_seen,
           max(timestamp)                                  AS last_seen
    FROM scoped
),
country AS (
    SELECT geo_country, geo_country_code
    FROM scoped
    WHERE geo_country_code IS NOT NULL AND geo_country_code <> ''
    GROUP BY 1, 2
    ORDER BY count(*) DESC
    LIMIT 1
),
hosts AS (
    SELECT json_agg(t) AS items FROM (
        SELECT host AS name, count(*) AS count
        FROM scoped WHERE host IS NOT NULL AND host <> ''
        GROUP BY 1 ORDER BY 2 DESC LIMIT 3
    ) t
),
uris AS (
    SELECT json_agg(t) AS items FROM (
        SELECT request_uri AS name, count(*) AS count
        FROM scoped WHERE request_uri IS NOT NULL AND request_uri <> ''
        GROUP BY 1 ORDER BY 2 DESC LIMIT 5
    ) t
)
SELECT t.total, t.blocked, t.first_seen, t.last_seen,
       c.geo_country, c.geo_country_code, h.items, u.items
FROM totals t
LEFT JOIN country c ON true
LEFT JOIN hosts   h ON true
LEFT JOIN uris    u ON true`

// GetStats returns the summary for one address over the given window.
//
// A malformed address would make PostgreSQL reject the ::inet cast with a
// 500; callers validate before reaching here.
func (r *BannedIPStatsRepository) GetStats(ctx context.Context, ip string, windowDays int) (*model.BannedIPStats, error) {
	stats := &model.BannedIPStats{
		IPAddress:  ip,
		WindowDays: windowDays,
		TopHosts:   []model.BannedIPTarget{},
		TopURIs:    []model.BannedIPTarget{},
	}

	var country, countryCode sql.NullString
	var hostsJSON, urisJSON []byte
	err := r.db.QueryRowContext(ctx, bannedIPTrafficQuery, ip, windowDays).Scan(
		&stats.TotalRequests, &stats.BlockedRequests, &stats.FirstSeen, &stats.LastSeen,
		&country, &countryCode, &hostsJSON, &urisJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to read traffic stats for banned IP: %w", err)
	}
	if country.Valid {
		stats.Country = country.String
	}
	if countryCode.Valid {
		stats.CountryCode = countryCode.String
	}
	if err := unmarshalTargets(hostsJSON, &stats.TopHosts); err != nil {
		return nil, err
	}
	if err := unmarshalTargets(urisJSON, &stats.TopURIs); err != nil {
		return nil, err
	}

	// Ban history is deliberately not windowed — the whole point of the number
	// is that this address has been back before.
	const banQuery = `
        SELECT count(*) FILTER (WHERE event_type = 'ban'),
               min(created_at) FILTER (WHERE event_type = 'ban'),
               max(created_at) FILTER (WHERE event_type = 'ban')
        FROM ip_ban_history WHERE ip_address = $1`
	if err := r.db.QueryRowContext(ctx, banQuery, ip).Scan(
		&stats.BanCount, &stats.FirstBanAt, &stats.LastBanAt,
	); err != nil {
		return nil, fmt.Errorf("failed to read ban history for banned IP: %w", err)
	}

	return stats, nil
}

// json_agg returns SQL NULL rather than an empty array when nothing grouped,
// which is the ordinary case for an address the ban is already keeping out.
func unmarshalTargets(raw []byte, dst *[]model.BannedIPTarget) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("failed to decode banned IP targets: %w", err)
	}
	return nil
}
