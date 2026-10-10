package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// The raw log reclaim against a real TimescaleDB: NPG_TEST_DATABASE_URL names
// a server where the test may create databases (skipped without it, as in
// CI). The service reads public.logs_partitioned, so each test gets a
// database of its own rather than a schema.

func openReclaimServiceDB(t *testing.T) (*sql.DB, *repository.RawLogReclaimRepository) {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed raw log reclaim test")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping test database: %v", err)
	}
	name := fmt.Sprintf("npg_test_rrs_%d_%d", os.Getpid(), time.Now().UnixNano())
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
	if _, err := db.Exec(`CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		t.Skipf("TimescaleDB is not available: %v", err)
	}

	// The two state tables as a fresh install creates them.
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"raw_log_reclaim_job", "raw_log_reclaim_chunks"} {
		m := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.` + table + ` \(.*?\n\);`).FindString(string(b))
		if m == "" {
			t.Fatalf("no CREATE TABLE for %s in 001_init.sql", table)
		}
		execAll(t, db, m)
	}
	// Two closed days, five and four days back, compressed as production
	// compresses them (segmentby host, log_type).
	execAll(t, db,
		`CREATE TYPE log_type AS ENUM ('access', 'error', 'modsec')`,
		`CREATE TABLE logs_partitioned (
		    id uuid NOT NULL DEFAULT gen_random_uuid(),
		    log_type log_type NOT NULL,
		    "timestamp" timestamptz NOT NULL,
		    host text,
		    client_ip inet,
		    request_uri text,
		    status_code integer,
		    raw_log text,
		    created_at timestamptz NOT NULL)`,
		`SELECT create_hypertable('logs_partitioned', by_range('created_at', INTERVAL '1 day'))`,
		`ALTER TABLE logs_partitioned SET (timescaledb.compress, timescaledb.compress_segmentby = 'host, log_type', timescaledb.compress_orderby = 'created_at DESC')`,
		`INSERT INTO logs_partitioned (log_type, "timestamp", host, client_ip, request_uri, status_code, raw_log, created_at)
		 SELECT (ARRAY['access', 'access', 'access', 'error', 'modsec'])[1 + g % 5]::log_type,
		        d + g * interval '2 seconds', 'h' || (g % 3) || '.example.com', ('192.0.2.' || (g % 250))::inet, '/p/' || g,
		        200 + (g % 5), repeat(md5(g::text), 15), d + g * interval '2 seconds'
		   FROM generate_series(4, 5) back,
		        LATERAL (SELECT date_trunc('day', now(), 'UTC') - back * interval '1 day' AS d) s,
		        generate_series(1, 10000) g`,
		`SELECT compress_chunk(c) FROM show_chunks('logs_partitioned', older_than => now() - interval '3 days') c`,
	)
	return db, repository.NewRawLogReclaimRepository(db)
}

func withDatabase(dsn, name string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		u.Path = "/" + name
		return u.String()
	}
	return dsn + " dbname=" + name // key=value: the last dbname wins
}

func execAll(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}

// dbReclaimService is the service on the real repository, with plenty of
// room, no pause between days and its waits cut short.
func dbReclaimService(t *testing.T, repo *repository.RawLogReclaimRepository) *RawLogReclaimService {
	s := NewRawLogReclaimService(repo, RawLogReclaimOptions{Pause: 0, ResumeDelay: time.Millisecond})
	s.SetDiskProbe(plenty())
	s.sleep = func(ctx context.Context, d time.Duration) { sleepCtx(ctx, min(d, 20*time.Millisecond)) }
	t.Cleanup(s.Shutdown)
	return s
}

// waitingBackends returns the backends of this database whose query starts
// with prefix and that wait for a lock.
func waitingBackends(t *testing.T, db *sql.DB, prefix string) []int {
	t.Helper()
	rows, err := db.Query(`SELECT pid FROM pg_stat_activity
		 WHERE datname = current_database() AND wait_event_type = 'Lock' AND ltrim(query, E' \t\r\n') LIKE $1 || '%'`, prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var pids []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, pid)
	}
	return pids
}

// holdLocks keeps the tables locked in mode from a session of its own until
// the returned function is called. In ACCESS SHARE mode the session holds no
// snapshot or transaction id meanwhile, so a run's horizon check does not
// wait for it (ACCESS EXCLUSIVE takes a transaction id: for tests where no
// run follows).
func holdLocks(t *testing.T, db *sql.DB, mode string, tables ...string) (release func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`BEGIN`, `LOCK TABLE ` + strings.Join(tables, ", ") + ` IN ` + mode + ` MODE`} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if mode == "ACCESS SHARE" {
		var held bool
		if err := db.QueryRow(`SELECT backend_xmin IS NOT NULL OR backend_xid IS NOT NULL FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&held); err != nil || held {
			t.Fatalf("the lock holder keeps a snapshot or a transaction id (%v, %v): the reclaim would wait for it", held, err)
		}
	}
	return func() {
		_, _ = conn.ExecContext(ctx, `COMMIT`)
		conn.Close()
	}
}

// A database connection lost in the middle of a day — the runner's session
// terminated while its VACUUM FULL waits for a lock — stops the run but does
// not count against the day: three in a row leave it to be finished, and the
// next run finishes it.
func TestRawReclaimDBConnectionLossKeepsTheDay(t *testing.T) {
	db, repo := openReclaimServiceDB(t)
	ctx := context.Background()
	infos, err := repo.ListChunks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, c := range infos {
		if c.SkipReason() == "" {
			rels = append(rels, c.CompressedRel)
		}
	}
	if len(rels) != 2 {
		t.Fatalf("days that qualify: %+v; want the two old ones", infos)
	}
	s := dbReclaimService(t, repo)

	var worked string
	for run := 1; run <= rawReclaimFailAfter; run++ {
		release := holdLocks(t, db, "ACCESS SHARE", rels...)
		if _, err := s.Start(ctx, "admin", nil); err != nil {
			release()
			t.Fatalf("run %d: %v", run, err)
		}
		// Every VACUUM FULL that waits loses its session.
		s.mu.Lock()
		done := s.done
		s.mu.Unlock()
		killed := 0
	wait:
		for {
			select {
			case <-done:
				break wait
			case <-time.After(20 * time.Millisecond):
			}
			for _, pid := range waitingBackends(t, db, "VACUUM FULL") {
				if _, err := db.Exec(`SELECT pg_terminate_backend($1)`, pid); err != nil {
					t.Fatal(err)
				}
				killed++
			}
		}
		release()
		job, err := repo.LoadJob(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if killed == 0 || job.Status != model.RawReclaimFailed || !strings.Contains(job.LastError, "connection to the database was lost while compacting") {
			t.Fatalf("run %d: %d session(s) ended, job %+v; want failed on the lost connection", run, killed, job)
		}
		rows, err := repo.ListChunkRows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.WorkedAt != nil {
				if worked != "" && worked != r.Name {
					t.Fatalf("run %d worked on %s, not %s", run, r.Name, worked)
				}
				worked = r.Name
				if r.State != "nulled" || r.Attempts != 0 {
					t.Fatalf("run %d: the day = %+v; want nulled with no attempt counted", run, r)
				}
			}
		}
		if worked == "" {
			t.Fatalf("run %d worked on no day: %+v", run, rows)
		}
	}

	// Nothing in the way: the next run finishes both days.
	if _, err := s.Start(ctx, "admin", nil); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s)
	rows, err := repo.ListChunkRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.State != "done" || r.BytesAfter >= r.BytesBefore {
			t.Fatalf("day after the last run = %+v; want done and smaller", r)
		}
	}
	if job, _ := repo.LoadJob(ctx); job.Status != model.RawReclaimDone {
		t.Fatalf("job = %+v", job)
	}
}

// An API stop while a resumed run waits in its planning (here, for a lock on
// the day table) leaves the job running for the next start, instead of
// recording "planning the reclaim failed: context canceled".
func TestRawReclaimDBShutdownWhileAResumePlansKeepsTheJob(t *testing.T) {
	db, repo := openReclaimServiceDB(t)
	ctx := context.Background()
	if _, err := repo.BeginJob(ctx, "admin", nil); err != nil {
		t.Fatal(err)
	}
	release := holdLocks(t, db, "ACCESS EXCLUSIVE", "raw_log_reclaim_chunks")
	defer release()
	s := dbReclaimService(t, repo)
	done := make(chan struct{})
	go func() { s.ResumeIfRunning(ctx); close(done) }()
	for deadline := time.Now().Add(10 * time.Second); len(waitingBackends(t, db, "UPDATE raw_log_reclaim_chunks SET state = 'gone'")) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the resume never reached its planning")
		}
	}
	s.Shutdown()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the resume did not end with the API")
	}
	release()
	job, err := repo.LoadJob(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != model.RawReclaimRunning || job.LastError != "" {
		t.Fatalf("job = %+v; want still running, to be resumed after the next start", job)
	}
}
