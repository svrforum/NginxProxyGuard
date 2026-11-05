package database

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// A clone copied its source's upstream name (#362), so an install that cloned
// such a host carries two upstream blocks with one name into the upgrade, and
// nginx refuses every config. The repair in `upgrades` renames every holder
// of a name but the oldest, and changes nothing on the next boot.
func TestUpgradeRenamesDuplicateUpstreamNames(t *testing.T) {
	entries := upgradeEntriesContaining(t, "replace(u.proxy_host_id::text, '-', '')")
	if len(entries) != 1 {
		t.Fatalf("found %d upgrade entries renaming duplicate upstream names, want 1", len(entries))
	}

	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	schema := fmt.Sprintf("npg_test_upstreams_%d", time.Now().UnixNano())
	if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
	})
	repair := strings.ReplaceAll(entries[0], "public.", schema+".")

	for _, stmt := range []string{
		`CREATE TABLE ` + schema + `.upstreams (
			id uuid PRIMARY KEY,
			proxy_host_id uuid NOT NULL UNIQUE,
			name character varying(255) NOT NULL,
			created_at timestamp with time zone,
			updated_at timestamp with time zone
		)`,
		`INSERT INTO ` + schema + `.upstreams (id, proxy_host_id, name, created_at) VALUES
			('00000000-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 'upstream_aaaaaaaa', '2026-01-01'),
			('00000000-0000-4000-8000-0000000000a2', 'cccccccc-0000-4000-8000-000000000002', 'upstream_aaaaaaaa', '2026-02-01'),
			('00000000-0000-4000-8000-0000000000a3', 'dddddddd-0000-4000-8000-000000000003', 'pool', '2026-01-01'),
			('00000000-0000-4000-8000-0000000000a4', 'eeeeeeee-0000-4000-8000-000000000004', 'pool', NULL),
			('00000000-0000-4000-8000-0000000000a5', 'ffffffff-0000-4000-8000-000000000005', 'upstream_ffffffff', '2026-01-01')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("set up: %v", err)
		}
	}

	if _, err := db.Exec(repair); err != nil {
		t.Fatalf("repair: %v", err)
	}
	want := map[string]string{
		"aaaaaaaa-0000-4000-8000-000000000001": "upstream_aaaaaaaa", // the source keeps its name
		"cccccccc-0000-4000-8000-000000000002": "upstream_cccccccc000040008000000000000002",
		"dddddddd-0000-4000-8000-000000000003": "upstream_dddddddd000040008000000000000003",
		"eeeeeeee-0000-4000-8000-000000000004": "pool", // no created_at counts as the oldest
		"ffffffff-0000-4000-8000-000000000005": "upstream_ffffffff",
	}
	rows, err := db.Query(`SELECT proxy_host_id, name FROM ` + schema + `.upstreams`)
	if err != nil {
		t.Fatalf("read names: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var host, name string
		if err := rows.Scan(&host, &name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name != want[host] {
			t.Errorf("host %s: name = %q, want %q", host, name, want[host])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	res, err := db.Exec(repair)
	if err != nil {
		t.Fatalf("second repair: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("second boot renamed %d rows, want 0", n)
	}
}
