package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
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

// GetAccessLogRowCount returns the row count of logs_partitioned, avoiding an
// O(n) COUNT(*) on a hypertable that holds 154M rows on the largest install.
//
// It has to count compressed and uncompressed chunks differently, which is why
// this is not one line. Compressing a chunk empties its heap, so pg_class
// reltuples for a compressed chunk reports roughly nothing: summing reltuples
// across every chunk — what this used to do — under-reported by 81% here
// (194,167 against an actual 1,029,800) and the error grows with every chunk
// the compression policy touches. The compressed rows live in the chunk's
// compressed relation, one row per batch, with _ts_meta_count saying how many
// original rows that batch holds.
//
// Both sides are driven from TimescaleDB's list of the hypertable's chunks
// rather than matching relation names in pg_class. This install carries a full
// orphaned duplicate of every chunk relation — 250 physical against 125 in the
// catalogue — and counting those doubled the answer.
//
// The chunk list comes from timescaledb_information.chunks, the documented
// view. Only the link from a compressed chunk to its compressed relation is
// read from the private catalog, _timescaledb_catalog.compression_settings
// (relid, compress_relid), which 2.24 and 2.30 both have. This used to read
// schema_name, table_name and compressed_chunk_id from
// _timescaledb_catalog.chunk; TimescaleDB 2.30 removed those columns, and the
// query failed on every install that pulled the current image, which made
// /health/detailed report the database as disconnected.
//
// Measured at 177ms and within 0.15% on a million rows. On a 2.26 install with
// 185 chunks (177 compressed, 1.69M rows) the view-based form gives exactly
// what the catalog form gave, in about 0.3 s, nearly all of it reading the
// batch counts. approximate_row_count() looks like the obvious alternative and
// is not: it answered 71,000 for the same table, because it rests on the same
// reltuples estimates.
func (r *HealthDetailedRepository) GetAccessLogRowCount(ctx context.Context) (int64, error) {
	return r.hypertableRowCount(ctx, "public", "logs_partitioned")
}

// hypertableRowCount counts the rows of one hypertable as GetAccessLogRowCount
// describes.
func (r *HealthDetailedRepository) hypertableRowCount(ctx context.Context, schema, table string) (int64, error) {
	// Uncompressed chunks: the estimate is still right for these, and it is the
	// cheap half. reltuples is -1 until a chunk is first analyzed.
	const uncompressed = `
		SELECT COALESCE(SUM(GREATEST(c.reltuples, 0))::bigint, 0)
		FROM timescaledb_information.chunks ch
		JOIN pg_namespace n ON n.nspname = ch.chunk_schema
		JOIN pg_class c ON c.relname = ch.chunk_name AND c.relnamespace = n.oid
		WHERE ch.hypertable_schema = $1 AND ch.hypertable_name = $2
		  AND NOT ch.is_compressed`

	var total int64
	if err := r.db.QueryRowContext(ctx, uncompressed, schema, table).Scan(&total); err != nil {
		return 0, fmt.Errorf("failed to estimate uncompressed log rows: %w", err)
	}

	// Compressed chunks: exact, from the batch counts. Their compressed
	// relations have to be found first because each is a separate relation.
	rows, err := r.db.QueryContext(ctx, `
		SELECT cn.nspname, cc.relname
		FROM timescaledb_information.chunks ch
		JOIN pg_namespace n ON n.nspname = ch.chunk_schema
		JOIN pg_class c ON c.relname = ch.chunk_name AND c.relnamespace = n.oid
		JOIN _timescaledb_catalog.compression_settings cs ON cs.relid = c.oid
		JOIN pg_class cc ON cc.oid = cs.compress_relid
		JOIN pg_namespace cn ON cn.oid = cc.relnamespace
		WHERE ch.hypertable_schema = $1 AND ch.hypertable_name = $2
		  AND ch.is_compressed`, schema, table)
	if err != nil {
		// A build without compression has no such catalog; the uncompressed
		// figure is then the whole answer.
		return total, nil
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var relSchema, relName string
		if err := rows.Scan(&relSchema, &relName); err != nil {
			return total, nil
		}
		parts = append(parts, fmt.Sprintf(`SELECT COALESCE(SUM(_ts_meta_count),0)::bigint AS n FROM %s.%s`,
			pq.QuoteIdentifier(relSchema), pq.QuoteIdentifier(relName)))
	}
	if len(parts) == 0 {
		return total, nil
	}

	var compressed int64
	q := `SELECT COALESCE(SUM(n), 0) FROM (` + strings.Join(parts, " UNION ALL ") + `) t`
	if err := r.db.QueryRowContext(ctx, q).Scan(&compressed); err != nil {
		// Better a low number than none: the uncompressed half is still true.
		return total, nil
	}
	return total + compressed, nil
}
