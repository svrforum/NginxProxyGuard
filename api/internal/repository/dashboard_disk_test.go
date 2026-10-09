package repository

import (
	"context"
	"testing"
	"time"
)

// DiskGuard's growth estimate reads yesterday's usage from system_health. The
// row must be the disk's own (by path), else the same-size disk's (the day
// after an upgrade moved the path from "/"), and the one closest in time.
func TestDiskUsedNearPicksTheDisksClosestRow(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE system_health (recorded_at timestamptz NOT NULL, disk_total bigint DEFAULT 0, disk_used bigint DEFAULT 0, disk_path varchar(255) DEFAULT '/')`,
		`CREATE INDEX ON system_health (recorded_at)`,
	)
	r := NewDashboardRepository(db)
	ctx := context.Background()
	at := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	const total = int64(200) << 30
	ins := func(offset time.Duration, used int64, path string, size int64) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO system_health (recorded_at, disk_total, disk_used, disk_path) VALUES ($1, $2, $3, $4)`,
			at.Add(offset), size, used, path); err != nil {
			t.Fatal(err)
		}
	}

	// Only the "/" rows of the day before the upgrade: matched by size.
	ins(-30*time.Minute, 100, "/", total)
	ins(10*time.Minute, 101, "/", total)
	ins(5*time.Minute, 999, "/", 50<<30) // another disk's size: never matched
	used, rec, ok, err := r.DiskUsedNear(ctx, "npg-db:/var/lib/postgresql/data", uint64(total), at, time.Hour)
	if err != nil || !ok || used != 101 || !rec.Equal(at.Add(10*time.Minute)) {
		t.Fatalf("by size: used=%d at=%v ok=%v err=%v", used, rec, ok, err)
	}

	// A row of the disk's own path wins over a closer one matched by size.
	ins(-50*time.Minute, 90, "npg-db:/var/lib/postgresql/data", total)
	if used, _, ok, _ := r.DiskUsedNear(ctx, "npg-db:/var/lib/postgresql/data", uint64(total), at, time.Hour); !ok || used != 90 {
		t.Fatalf("by path: used=%d ok=%v", used, ok)
	}

	// Nothing inside the window: no estimate rather than a wrong one.
	if _, _, ok, err := r.DiskUsedNear(ctx, "x", uint64(total), at.Add(-5*time.Hour), time.Hour); ok || err != nil {
		t.Fatalf("outside the window: ok=%v err=%v", ok, err)
	}
}
