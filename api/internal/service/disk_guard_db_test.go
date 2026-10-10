package service

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// openNotificationDB returns a database of its own on the server
// NPG_TEST_DATABASE_URL names, holding the notification tables as a fresh
// install creates them. Skipped without the variable, as in CI.
func openNotificationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed disk alert test")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping test database: %v", err)
	}
	name := fmt.Sprintf("npg_test_dg_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		admin.Close()
		t.Skipf("cannot create a test database: %v", err)
	}
	db, err := sql.Open("postgres", withDatabase(dsn, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Logf("drop database %s: %v", name, err)
		}
		admin.Close()
	})
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{
		`(?s)CREATE TABLE IF NOT EXISTS public\.notification_channels \(.*?\n\);`,
		`(?s)CREATE TABLE IF NOT EXISTS public\.notification_state \(.*?\n\);`,
		`(?s)CREATE TABLE IF NOT EXISTS public\.notification_outbox \(.*?\n\);`,
		`ALTER TABLE ONLY public\.notification_state\s+ADD CONSTRAINT notification_state_pkey PRIMARY KEY \(event_key, subject\);`,
	} {
		m := regexp.MustCompile(re).FindString(string(b))
		if m == "" {
			t.Fatalf("001_init.sql has no %s", re)
		}
		execAll(t, db, m)
	}
	return db
}

// The quiet close of a vanished disk's alert, recorded in the database and
// read back by a guard started afterwards, does not hold the warning for a
// disk that comes back still full; a recovery does.
func TestDiskGuardQuietCloseAgainstTheDatabase(t *testing.T) {
	db := openNotificationDB(t)
	repo := repository.NewNotificationRepository(&database.DB{DB: db})
	svc := NewNotificationService(repo)
	ctx := context.Background()
	u := &fakeDiskUsage{pct: map[string]float64{}, roles: map[string][]DiskRole{"db": {DiskRoleDB}, "backups": {DiskRoleBackups}}}
	// notification_state.since is the database's now(): the guard's clock
	// starts there.
	c := &diskClock{t: time.Now()}
	guard := func() *DiskGuard {
		return NewDiskGuard(u, svc, repo, nil, DiskGuardOptions{ConfirmSamples: 2, Cooldown: 6 * time.Hour, Now: c.now})
	}
	low := func() model.NotificationState {
		t.Helper()
		s, err := repo.StateRecord(ctx, eventDiskLow, "backups")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ticks := func(g *DiskGuard, n int) {
		for i := 0; i < n; i++ {
			diskTickAt(g, u, c, 50)
		}
	}

	g := guard()
	u.pct["backups"] = 87
	ticks(g, 2)
	if s := low(); s.State != stateFailing {
		t.Fatalf("warning not recorded: %+v", s)
	}
	delete(u.pct, "backups")
	ticks(g, 12)
	if s := low(); !isQuietlyResolved(s) {
		t.Fatalf("the vanished disk's alert was not closed quietly: %+v", s)
	}

	// Back still at 87%, after a restart: recorded at once.
	g = guard()
	u.pct["backups"] = 87
	ticks(g, 2)
	if s := low(); s.State != stateFailing {
		t.Fatalf("a disk back after a quiet close was held: %+v", s)
	}

	// A recovery holds the next warning for the cooldown, across a restart.
	u.pct["backups"] = 79
	ticks(g, 2)
	if s := low(); s.State != stateOK || isQuietlyResolved(s) {
		t.Fatalf("recovery recorded as %+v", s)
	}
	g = guard()
	u.pct["backups"] = 87
	ticks(g, 2)
	if s := low(); s.State != stateOK {
		t.Fatalf("a warning inside the cooldown after a recovery was not held: %+v", s)
	}
}
