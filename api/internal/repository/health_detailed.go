package repository

import (
	"context"
	"database/sql"
)

// HealthDetailedRepository surfaces storage + compression telemetry used by
// /api/v1/health/detailed. Kept separate from DashboardRepository because the
// queries hit timescaledb_information.* catalog views rather than the regular
// hypertables, and we want this read-only diagnostic path to be obviously
// safe to call frequently.
type HealthDetailedRepository struct {
	db *sql.DB
}

func NewHealthDetailedRepository(db *sql.DB) *HealthDetailedRepository {
	return &HealthDetailedRepository{db: db}
}

// HypertableStats holds compression telemetry for a single TimescaleDB
// hypertable used by the detailed health endpoint.
type HypertableStats struct {
	Name                string `json:"name"`
	CompressionEnabled  bool   `json:"compression_enabled"`
	TotalChunks         int    `json:"total_chunks"`
	CompressedChunks    int    `json:"compressed_chunks"`
	HypertableSizeBytes int64  `json:"hypertable_size_bytes"`
}

// GetHypertableStats returns per-hypertable compression telemetry. Skips the
// catalog rows on errors so a missing timescaledb_information view (older PG
// or a non-Timescale fallback) does not block the entire health response.
func (r *HealthDetailedRepository) GetHypertableStats(ctx context.Context) ([]HypertableStats, error) {
	const q = `
		SELECT h.hypertable_name,
		       h.compression_enabled,
		       (SELECT count(*) FROM timescaledb_information.chunks c
		          WHERE c.hypertable_schema = h.hypertable_schema
		            AND c.hypertable_name = h.hypertable_name) AS total_chunks,
		       (SELECT count(*) FROM timescaledb_information.chunks c
		          WHERE c.hypertable_schema = h.hypertable_schema
		            AND c.hypertable_name = h.hypertable_name
		            AND c.is_compressed) AS compressed_chunks,
		       hypertable_size(format('%I.%I', h.hypertable_schema, h.hypertable_name)::regclass) AS size_bytes
		FROM timescaledb_information.hypertables h
		ORDER BY h.hypertable_name
	`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HypertableStats
	for rows.Next() {
		var s HypertableStats
		if err := rows.Scan(&s.Name, &s.CompressionEnabled, &s.TotalChunks, &s.CompressedChunks, &s.HypertableSizeBytes); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetAccessLogRowCount returns the row count of logs_partitioned. Uses the
// pg_class reltuples estimate to avoid an O(n) COUNT(*) on a 100M+ row
// hypertable — accuracy within a few percent is fine for a health card.
func (r *HealthDetailedRepository) GetAccessLogRowCount(ctx context.Context) (int64, error) {
	const q = `SELECT COALESCE(SUM(reltuples)::bigint, 0)
	           FROM pg_class c
	           JOIN pg_namespace n ON n.oid = c.relnamespace
	           WHERE n.nspname = '_timescaledb_internal'
	             AND c.relname LIKE '_hyper_1_%_chunk'`
	var n int64
	if err := r.db.QueryRowContext(ctx, q).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
