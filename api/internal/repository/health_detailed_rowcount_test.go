package repository

import (
	"context"
	"os"
	"regexp"
	"testing"
)

// TimescaleDB 2.30 removed schema_name, table_name and compressed_chunk_id from
// _timescaledb_catalog.chunk. The row count read them, so on any install that
// pulled the current image it failed and /health/detailed reported the
// database as disconnected. Chunks are listed from the documented view now.
func TestAccessLogRowCountAvoidsTheRemovedChunkCatalogColumns(t *testing.T) {
	src, err := os.ReadFile("health_detailed.go")
	if err != nil {
		t.Fatalf("read health_detailed.go: %v", err)
	}
	code := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(string(src), "") // comments may name them
	for _, banned := range []string{`ch\.schema_name`, `ch\.table_name`, `compressed_chunk_id`, `_timescaledb_catalog\.chunk\b`} {
		if regexp.MustCompile(banned).MatchString(code) {
			t.Errorf("health_detailed.go reads %s, which TimescaleDB 2.30 no longer has", banned)
		}
	}
}

// Against a real hypertable with compressed and uncompressed chunks, the
// count is exact once the uncompressed chunks are analyzed: compressed chunks
// from their batch counts, uncompressed ones from reltuples, nothing twice.
func TestHypertableRowCountCountsCompressedAndUncompressedChunks(t *testing.T) {
	db, schema := openSchemaTestDB(t)
	var hasTimescale bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTimescale); err != nil {
		t.Fatalf("check for TimescaleDB: %v", err)
	}
	if !hasTimescale {
		t.Skip("TimescaleDB is not installed in the test database")
	}
	// Drop the hypertable itself before its schema goes: TimescaleDB 2.30
	// leaves the compressed chunk relations behind when only the schema is
	// dropped. Schema-qualified, so a fixture that failed before creating it
	// can never reach the database's own logs_partitioned.
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP TABLE IF EXISTS ` + schema + `.logs_partitioned`); err != nil {
			t.Logf("drop test hypertable: %v", err)
		}
	})
	mustExec(t, db,
		`CREATE TABLE logs_partitioned (created_at timestamptz NOT NULL, host text, v integer)`,
		`SELECT create_hypertable('`+schema+`.logs_partitioned', by_range('created_at', INTERVAL '1 day'))`,
		`ALTER TABLE logs_partitioned SET (timescaledb.compress, timescaledb.compress_segmentby = 'host', timescaledb.compress_orderby = 'created_at DESC')`,
		// Four days: 1000, 2000 and 1500 rows on the three old ones, 700 today.
		`INSERT INTO logs_partitioned (created_at, host, v)
		 SELECT date_trunc('day', now()) - make_interval(days => d) + make_interval(secs => i * 60), 'h' || (i % 3), i
		 FROM (VALUES (3, 1000), (2, 2000), (1, 1500)) AS days(d, n), generate_series(1, n) AS i`,
		`INSERT INTO logs_partitioned (created_at, host, v)
		 SELECT date_trunc('day', now()) + make_interval(secs => i), 'h' || (i % 3), i FROM generate_series(1, 700) AS i`,
		`SELECT compress_chunk(c) FROM show_chunks('`+schema+`.logs_partitioned', older_than => INTERVAL '1 day') AS c`,
		`ANALYZE logs_partitioned`,
	)
	var compressed, uncompressed int
	if err := db.QueryRow(`
		SELECT count(*) FILTER (WHERE is_compressed), count(*) FILTER (WHERE NOT is_compressed)
		FROM timescaledb_information.chunks WHERE hypertable_schema = $1 AND hypertable_name = 'logs_partitioned'`, schema).Scan(&compressed, &uncompressed); err != nil {
		t.Fatalf("list chunks: %v", err)
	}
	if compressed == 0 || uncompressed == 0 {
		t.Fatalf("fixture has %d compressed and %d uncompressed chunks, want both", compressed, uncompressed)
	}

	var exact int64
	if err := db.QueryRow(`SELECT count(*) FROM logs_partitioned`).Scan(&exact); err != nil {
		t.Fatalf("count: %v", err)
	}
	repo := NewHealthDetailedRepository(db)
	got, err := repo.hypertableRowCount(context.Background(), schema, "logs_partitioned")
	if err != nil {
		t.Fatalf("hypertableRowCount: %v", err)
	}
	if got != exact || exact != 5200 {
		t.Errorf("row count = %d, want the exact %d (5200)", got, exact)
	}
}
