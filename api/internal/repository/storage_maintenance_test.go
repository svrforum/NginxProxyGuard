package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// openMaintenanceTestDB opens NPG_TEST_DATABASE_URL as an ordinary pool — the
// lock tests need two sessions at once — with a new, empty schema for the
// test's hypertable. The queries under test read TimescaleDB's catalog views,
// not tables by name, so no search_path is needed. Skipped without the
// variable, as in CI, and without TimescaleDB.
func openMaintenanceTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed storage maintenance test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("ping test database: %v", err)
	}
	var hasTimescale bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTimescale); err != nil || !hasTimescale {
		db.Close()
		t.Skip("TimescaleDB is not installed in the test database")
	}
	schema := fmt.Sprintf("npg_test_dg_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		db.Close()
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		// The hypertable first: TimescaleDB 2.30 leaves compressed chunk
		// relations behind when only the schema is dropped.
		_, _ = db.Exec(`DROP TABLE IF EXISTS ` + schema + `.npg_dg_test`)
		if _, err := db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
		db.Close()
	})
	return db, schema
}

func TestStorageMaintenanceAgainstTimescale(t *testing.T) {
	db, schema := openMaintenanceTestDB(t)
	ctx := context.Background()
	table := schema + ".npg_dg_test"
	mustExec(t, db,
		`CREATE TABLE `+table+` (host text, payload text, created_at timestamptz NOT NULL DEFAULT now())`,
		`SELECT create_hypertable('`+table+`', by_range('created_at', INTERVAL '1 day'))`,
		`ALTER TABLE `+table+` SET (timescaledb.compress, timescaledb.compress_segmentby = 'host', timescaledb.compress_orderby = 'created_at DESC')`,
		// Two closed days and the current one; ~10 MB per closed day.
		`INSERT INTO `+table+` (host, payload, created_at)
		 SELECT 'h' || (g % 5), repeat(md5(g::text), 8), date_trunc('day', now()) - (d || ' days')::interval + (g % 80000) * interval '1 second'
		 FROM generate_series(1, 2) d, generate_series(1, 30000) g`,
		`INSERT INTO `+table+` (host, payload) VALUES ('h1', 'now')`,
	)
	r := NewStorageMaintenanceRepository(db)

	cands, err := r.CompressionCandidates(ctx, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var mine []ChunkCandidate
	for _, c := range cands {
		if c.Hypertable == "npg_dg_test" {
			mine = append(mine, c)
		}
	}
	if len(mine) != 2 {
		t.Fatalf("want the 2 closed chunks, got %d: %#v", len(mine), mine)
	}
	for _, c := range mine {
		if c.RangeEnd.After(time.Now()) {
			t.Fatalf("the open chunk was offered: %#v", c)
		}
	}
	for i := 1; i < len(cands); i++ {
		if cands[i].Bytes < cands[i-1].Bytes {
			t.Fatal("candidates are not smallest-first")
		}
	}

	if running, err := r.CompressionPolicyRunning(ctx); err != nil || running {
		t.Fatalf("policy running = %v, %v", running, err)
	}
	// CompressionPolicyRunning finds the policy by proc_name; make sure this
	// TimescaleDB still names it that way (2.18 renamed the user-facing API
	// to "columnstore").
	mustExec(t, db, `SELECT add_compression_policy('`+table+`', INTERVAL '30 days')`)
	var proc string
	if err := db.QueryRow(`SELECT proc_name FROM timescaledb_information.jobs WHERE hypertable_schema = $1 AND hypertable_name = 'npg_dg_test'`, schema).Scan(&proc); err != nil || proc != "policy_compression" {
		t.Fatalf("compression policy proc_name = %q, %v; CompressionPolicyRunning would never see it run", proc, err)
	}
	if dir, err := r.DataDirectory(ctx); err != nil || !filepath.IsAbs(dir) {
		t.Fatalf("data_directory = %q, %v", dir, err)
	}

	// Two passes at once: exactly one gets the lock.
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	gate := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := r.WithMaintenanceLock(ctx, func(ctx context.Context, _ ChunkCompressor) error {
				<-gate
				return nil
			})
			if err != nil {
				t.Error(err)
			}
			results <- ok
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d passes acquired the lock, want 1", n)
	}

	// The raw_log reclaim job (C6) takes the same key per chunk on its own
	// pinned connection; while it holds it, an emergency pass stands aside.
	reclaim, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reclaim.Close()
	if got, err := TryMaintenanceLock(ctx, reclaim); err != nil || !got {
		t.Fatalf("TryMaintenanceLock = %v, %v", got, err)
	}
	if ok, err := r.WithMaintenanceLock(ctx, func(context.Context, ChunkCompressor) error { return nil }); ok || err != nil {
		t.Fatalf("an emergency pass ran while the reclaim job held the lock: %v %v", ok, err)
	}
	if err := ReleaseMaintenanceLock(reclaim); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseMaintenanceLock(reclaim); err == nil {
		t.Fatal("releasing a lock the session does not hold must say so")
	}

	// A chunk another session holds: lock_timeout, classified as such.
	hold, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hold.ExecContext(ctx, `LOCK TABLE `+mine[0].Schema+`.`+mine[0].Name+` IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	_, err = r.WithMaintenanceLock(ctx, func(ctx context.Context, c ChunkCompressor) error {
		return c.CompressChunk(ctx, mine[0].Schema, mine[0].Name)
	})
	_ = hold.Rollback()
	if !IsLockTimeout(err) || IsDiskFull(err) {
		t.Fatalf("want a lock timeout, got %v", err)
	}

	// Then it compresses, and the session settings do not leak.
	_, err = r.WithMaintenanceLock(ctx, func(ctx context.Context, c ChunkCompressor) error {
		for _, ch := range mine {
			if err := c.CompressChunk(ctx, ch.Schema, ch.Name); err != nil {
				return err
			}
		}
		// Compressing an already compressed chunk is a no-op, not an error.
		return c.CompressChunk(ctx, mine[0].Schema, mine[0].Name)
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // whichever pooled session ran the pass
		var lt string
		if err := db.QueryRow(`SHOW lock_timeout`).Scan(&lt); err != nil || lt != "0" {
			t.Fatalf("lock_timeout leaked into the pool: %q %v", lt, err)
		}
	}
	ratios, err := r.CompressionRatios(ctx)
	if err != nil || ratios["npg_dg_test"] <= 1 {
		t.Fatalf("ratios = %v, %v", ratios, err)
	}
	cands, err = r.CompressionCandidates(ctx, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Hypertable == "npg_dg_test" {
			t.Fatalf("a compressed chunk is still a candidate: %#v", c)
		}
	}
}
