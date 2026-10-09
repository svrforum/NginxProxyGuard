package database

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// openTimescaleTestDB opens NPG_TEST_DATABASE_URL for a test that needs
// TimescaleDB. Skipped without the variable (as in CI) or the extension.
func openTimescaleTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed test")
	}
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	var hasTimescale bool
	if err := sqlDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTimescale); err != nil {
		t.Fatalf("check for TimescaleDB: %v", err)
	}
	if !hasTimescale {
		t.Skip("TimescaleDB is not installed in the test database")
	}
	return &DB{DB: sqlDB}
}

// The side tables' compression policy used to be added only in the pass that
// first enabled compression, so a table whose policy went missing afterwards
// was never compressed again. setupTableCompression runs on every boot and
// must put the policy back, once.
func TestSetupTableCompressionRestoresAMissingPolicy(t *testing.T) {
	db := openTimescaleTestDB(t)
	for _, compressed := range []bool{true, false} {
		name := "compression already enabled, policy missing"
		if !compressed {
			name = "compression never enabled"
		}
		t.Run(name, func(t *testing.T) {
			table := fmt.Sprintf("npg_test_compress_%d", time.Now().UnixNano())
			t.Cleanup(func() {
				if _, err := db.Exec(`DROP TABLE IF EXISTS public.` + table + ` CASCADE`); err != nil {
					t.Logf("drop %s: %v", table, err)
				}
			})
			stmts := []string{
				`CREATE TABLE public.` + table + ` (id uuid DEFAULT gen_random_uuid(), action text, created_at timestamptz NOT NULL DEFAULT now())`,
				`SELECT create_hypertable('public.` + table + `', by_range('created_at', INTERVAL '1 day'))`,
			}
			if compressed {
				stmts = append(stmts, `ALTER TABLE public.`+table+` SET (timescaledb.compress, timescaledb.compress_segmentby = 'action', timescaledb.compress_orderby = 'created_at DESC')`)
			}
			for _, s := range stmts {
				if _, err := db.Exec(s); err != nil {
					t.Fatalf("exec %q: %v", s, err)
				}
			}

			policies := func() (int, string) {
				t.Helper()
				var n int
				var after sql.NullString
				if err := db.QueryRow(`
					SELECT count(*), max(config->>'compress_after')
					FROM timescaledb_information.jobs
					WHERE proc_name = 'policy_compression'
					  AND hypertable_schema = 'public' AND hypertable_name = $1`, table).Scan(&n, &after); err != nil {
					t.Fatalf("count policies: %v", err)
				}
				return n, after.String
			}
			if n, _ := policies(); n != 0 {
				t.Fatalf("fixture has %d policies, want none", n)
			}

			db.setupTableCompression(table, "action")
			if n, after := policies(); n != 1 || after != "7 days" {
				t.Fatalf("after setup: %d policies compressing after %q, want 1 at \"7 days\"", n, after)
			}
			var enabled bool
			if err := db.QueryRow(`SELECT compression_enabled FROM timescaledb_information.hypertables WHERE hypertable_name = $1`, table).Scan(&enabled); err != nil || !enabled {
				t.Fatalf("compression enabled = %v (%v), want true", enabled, err)
			}

			// The next boot finds the policy and leaves it alone.
			db.setupTableCompression(table, "action")
			if n, _ := policies(); n != 1 {
				t.Fatalf("after a second setup: %d policies, want still 1", n)
			}
		})
	}
}
