package repository

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A list cut short by the entry limit looked like a display error: 188,000
// listed entries showed as the 25,000 kept (#361). The subscription now keeps
// what the list had next to what it kept.
func TestSubscriptionKeepsWhatItsListHad(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db, `CREATE TABLE filter_subscriptions (
		id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
		name text NOT NULL,
		description text,
		url text NOT NULL UNIQUE,
		format character varying(20) NOT NULL DEFAULT 'npg-json',
		type character varying(20) NOT NULL,
		enabled boolean DEFAULT true,
		refresh_type character varying(20) NOT NULL DEFAULT 'interval',
		refresh_value character varying(50) NOT NULL DEFAULT '24h',
		last_fetched_at timestamp with time zone,
		last_success_at timestamp with time zone,
		last_error text,
		entry_count integer DEFAULT 0,
		exclude_private_ips boolean DEFAULT false,
		created_at timestamp with time zone DEFAULT now(),
		updated_at timestamp with time zone DEFAULT now(),
		source_entry_count integer DEFAULT 0 NOT NULL
	)`)
	repo := NewFilterSubscriptionRepository(db)
	ctx := context.Background()

	created, err := repo.Create(ctx, &model.FilterSubscription{
		Name: "big list", URL: "https://lists.example.com/big.txt", Format: "plain", Type: "ip",
		RefreshType: "interval", RefreshValue: "24h", EntryCount: 100000, SourceEntryCount: 188000,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, created.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.EntryCount != 100000 || got.SourceEntryCount != 188000 {
		t.Fatalf("after create: kept %d of %d, want 100000 of 188000", got.EntryCount, got.SourceEntryCount)
	}

	// The next fetch finds a shorter list that fits.
	if err := repo.UpdateFetchStatus(ctx, created.ID, true, 90000, 90000, ""); err != nil {
		t.Fatalf("update fetch status: %v", err)
	}
	list, err := repo.List(ctx, 1, 10)
	if err != nil || len(list.Data) != 1 {
		t.Fatalf("list: %v (%+v)", err, list)
	}
	if list.Data[0].EntryCount != 90000 || list.Data[0].SourceEntryCount != 90000 {
		t.Fatalf("after refresh: kept %d of %d, want 90000 of 90000", list.Data[0].EntryCount, list.Data[0].SourceEntryCount)
	}

	// A failed fetch leaves both counts alone.
	if err := repo.UpdateFetchStatus(ctx, created.ID, false, 90000, 90000, "fetch failed"); err != nil {
		t.Fatalf("record a failed fetch: %v", err)
	}
	if got, _ := repo.GetByID(ctx, created.ID); got.SourceEntryCount != 90000 {
		t.Fatalf("after a failed fetch: listed %d, want 90000", got.SourceEntryCount)
	}
}
