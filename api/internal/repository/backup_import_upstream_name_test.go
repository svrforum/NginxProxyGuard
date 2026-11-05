package repository

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A backup taken before the #362 fix can hold two upstreams with one name;
// restored as they are, nginx refuses every host's config until the next
// restart. As in the upgrade repair, an enabled host keeps the name over a
// disabled one and otherwise the one restored first keeps it, and nginx's
// case-blind comparison counts.
func TestRestoreKeepsUpstreamNamesApart(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db, `CREATE TABLE proxy_hosts (
		id uuid PRIMARY KEY,
		enabled boolean DEFAULT true NOT NULL
	)`, `CREATE TABLE upstreams (
		id uuid DEFAULT gen_random_uuid() NOT NULL,
		proxy_host_id uuid NOT NULL UNIQUE,
		name character varying(255) NOT NULL,
		scheme character varying(10) DEFAULT 'http'::character varying NOT NULL,
		servers jsonb DEFAULT '[]'::jsonb NOT NULL,
		load_balance character varying(20) DEFAULT 'round_robin'::character varying,
		health_check_enabled boolean DEFAULT false,
		health_check_interval integer DEFAULT 30,
		health_check_timeout integer DEFAULT 5,
		health_check_path character varying(255) DEFAULT '/'::character varying,
		health_check_expected_status integer DEFAULT 200,
		keepalive integer DEFAULT 32,
		is_healthy boolean DEFAULT true,
		last_check_at timestamp with time zone,
		created_at timestamp with time zone DEFAULT now(),
		updated_at timestamp with time zone DEFAULT now()
	)`)
	repo := NewBackupRepository(db)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	up := func(name string) *model.UpstreamExport {
		return &model.UpstreamExport{
			Name:        name,
			Servers:     []interface{}{map[string]any{"address": "192.0.2.10", "port": 8080}},
			LoadBalance: "round_robin",
		}
	}
	restored := []struct {
		host    string
		enabled bool
		name    string
		want    string
	}{
		{"aaaaaaaa-0000-4000-8000-000000000001", true, "upstream_aaaaaaaa", "upstream_aaaaaaaa"},
		{"bbbbbbbb-0000-4000-8000-000000000002", true, "upstream_aaaaaaaa", "upstream_bbbbbbbb000040008000000000000002"}, // the clone's copy
		{"cccccccc-0000-4000-8000-000000000003", true, "UPSTREAM_AAAAAAAA", "upstream_cccccccc000040008000000000000003"},
		{"dddddddd-0000-4000-8000-000000000004", true, "pool_d", "pool_d"},
		{"eeeeeeee-0000-4000-8000-000000000005", false, "pool_x", "upstream_eeeeeeee000040008000000000000005"}, // disabled: gives way
		{"ffffffff-0000-4000-8000-000000000006", true, "pool_x", "pool_x"},
	}
	for _, r := range restored {
		// The restore writes each host before its upstream.
		if _, err := tx.ExecContext(ctx, `INSERT INTO proxy_hosts (id, enabled) VALUES ($1, $2)`, r.host, r.enabled); err != nil {
			t.Fatal(err)
		}
		if err := repo.importUpstream(ctx, tx, r.host, up(r.name)); err != nil {
			t.Fatalf("restore %s: %v", r.host, err)
		}
	}
	for _, r := range restored {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM upstreams WHERE proxy_host_id = $1`, r.host).Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name != r.want {
			t.Errorf("host %s restored as %q, want %q", r.host, name, r.want)
		}
	}
}
