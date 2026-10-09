package repository

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// openSchemaTestDB opens NPG_TEST_DATABASE_URL on a single connection whose
// search_path starts with a new, empty schema that is dropped when the test
// ends. The repository's SQL names its tables without a schema, so a test can
// create just the tables a query reads, with the columns and types it needs,
// without touching the database's own tables. Skipped without the variable,
// as in CI.
func openSchemaTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	// One connection, so the session's search_path applies to every query the
	// code under test sends through this pool.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("ping test database: %v", err)
	}
	schema := fmt.Sprintf("npg_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		db.Close()
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
		db.Close()
	})
	if _, err := db.Exec(`SET search_path TO ` + schema + `, public`); err != nil {
		t.Fatalf("set search_path: %v", err)
	}
	return db, schema
}

// mustExec runs each statement and fails the test on the first error.
func mustExec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}
