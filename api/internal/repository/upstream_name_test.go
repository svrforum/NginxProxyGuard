package repository

import (
	"context"
	"errors"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// nginx refuses two upstream blocks with one name, and then every config at
// once (#362): a clone copied its source's name. Upsert now keeps each name
// to one proxy host.
func TestUpsertKeepsAnUpstreamNameToOneProxyHost(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db, `CREATE TABLE upstreams (
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
	repo := NewUpstreamRepository(db)
	ctx := context.Background()
	servers := []model.CreateUpstreamServerRequest{{Address: "192.0.2.10", Port: 8080}}

	// Two ids that share their first 8 characters, and a third that does not.
	const (
		source = "aaaaaaaa-0000-4000-8000-000000000001"
		twin   = "aaaaaaaa-0000-4000-8000-000000000002"
		other  = "bbbbbbbb-0000-4000-8000-000000000003"
	)

	up, err := repo.Upsert(ctx, source, &model.CreateUpstreamRequest{Servers: servers})
	if err != nil {
		t.Fatalf("source upstream: %v", err)
	}
	if up.Name != "upstream_aaaaaaaa" {
		t.Fatalf("source name = %q, want upstream_aaaaaaaa", up.Name)
	}

	// What a clone used to send: the source's name for another host.
	if _, err := repo.Upsert(ctx, other, &model.CreateUpstreamRequest{Name: up.Name, Servers: servers}); !errors.Is(err, model.ErrUpstreamNameTaken) {
		t.Fatalf("another host taking the source's name: err = %v, want ErrUpstreamNameTaken", err)
	}

	// The derived name repeats the source's: the whole id stands in.
	twinUp, err := repo.Upsert(ctx, twin, &model.CreateUpstreamRequest{Servers: servers})
	if err != nil {
		t.Fatalf("twin upstream: %v", err)
	}
	if twinUp.Name != "upstream_aaaaaaaa000040008000000000000002" {
		t.Fatalf("twin name = %q, want the whole id", twinUp.Name)
	}

	// A host saving its own name again is not a conflict.
	if _, err := repo.Upsert(ctx, source, &model.CreateUpstreamRequest{Name: up.Name, Servers: servers}); err != nil {
		t.Fatalf("source saving its own name: %v", err)
	}
	if _, err := repo.Upsert(ctx, other, &model.CreateUpstreamRequest{Name: "pool_b", Servers: servers}); err != nil {
		t.Fatalf("a free custom name: %v", err)
	}
}
