package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// challenge_logs had no retention. It follows the access-log retention: chunks
// are dropped where it is a hypertable, rows deleted where it is not.
func TestEnforceRetentionAppliesAccessRetentionToChallengeLogs(t *testing.T) {
	src, err := os.ReadFile("partition.go")
	if err != nil {
		t.Fatalf("read partition.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "partition.go", src, 0)
	if err != nil {
		t.Fatalf("parse partition.go: %v", err)
	}
	var body string
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "enforceRetention" {
			body = string(src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
		}
	}
	for _, want := range []string{
		`s.dropOldChunks(ctx, "challenge_logs", settings.AccessLogRetentionDays)`,
		`s.cleanupChallengeLogs(ctx, settings.AccessLogRetentionDays)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("enforceRetention no longer calls %s", want)
		}
	}
}

// Where challenge_logs is a plain table, rows older than the retention are
// deleted in batches and everything newer stays.
func TestCleanupChallengeLogsDeletesOnlyRowsPastRetention(t *testing.T) {
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	// One connection, so the search_path below reaches the code under test.
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("npg_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
		db.Close()
	})
	for _, stmt := range []string{
		`CREATE SCHEMA ` + schema,
		`SET search_path TO ` + schema + `, public`,
		`CREATE TABLE challenge_logs (
			id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
			proxy_host_id uuid,
			client_ip character varying(45) NOT NULL,
			user_agent text,
			result character varying(20) NOT NULL,
			trigger_reason character varying(255),
			captcha_score numeric(3,2),
			solve_time integer,
			created_at timestamp with time zone DEFAULT now()
		)`,
		// More than two batches past a 30-day retention.
		`INSERT INTO challenge_logs (client_ip, result, created_at)
		 SELECT '192.0.2.1', 'passed', now() - interval '40 days' - make_interval(secs => i)
		 FROM generate_series(1, 25000) i`,
		`INSERT INTO challenge_logs (client_ip, result, created_at)
		 SELECT '192.0.2.2', 'failed', now() - interval '10 days' FROM generate_series(1, 10) i`,
		`INSERT INTO challenge_logs (client_ip, result, created_at)
		 SELECT '192.0.2.3', 'passed', NULL FROM generate_series(1, 5) i`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
	s := &PartitionScheduler{db: db}
	rows := func() (n int) {
		t.Helper()
		if err := db.QueryRow(`SELECT count(*) FROM challenge_logs`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	s.cleanupChallengeLogs(context.Background(), 0)
	if n := rows(); n != 25015 {
		t.Fatalf("an unset retention deleted rows: %d left, want 25015", n)
	}

	s.cleanupChallengeLogs(context.Background(), 30)
	if n := rows(); n != 15 {
		t.Fatalf("%d rows left, want the 15 inside the retention (or without a time)", n)
	}
}
