package repository

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// openReclaimTestDB opens NPG_TEST_DATABASE_URL as a pool whose sessions all
// start their search_path with a new, empty schema: the reclaim's state
// tables are named without a schema, and the runner pins one session while
// other queries go through the pool. Skipped without the variable (as in CI)
// and without TimescaleDB.
func openReclaimTestDB(t *testing.T) (*sql.DB, string) {
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
	var hasTimescale bool
	if err := admin.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTimescale); err != nil || !hasTimescale {
		admin.Close()
		t.Skip("TimescaleDB is not installed in the test database")
	}
	schema := fmt.Sprintf("npg_test_rr_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatalf("create schema %s: %v", schema, err)
	}
	db, err := sql.Open("postgres", withSearchPath(dsn, schema))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		// The hypertable first: TimescaleDB 2.30 leaves compressed chunk
		// relations behind when only the schema is dropped.
		_, _ = admin.Exec(`DROP TABLE IF EXISTS ` + schema + `.logs_partitioned`)
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
		admin.Close()
	})
	return db, schema
}

func withSearchPath(dsn, schema string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + "search_path=" + url.QueryEscape(schema+",public")
	}
	return dsn + " search_path=" + schema + ",public"
}

// createReclaimStateTables creates the two state tables in schema from the
// DDL a fresh install runs, so the test exercises the shipped definition.
func createReclaimStateTables(t *testing.T, db *sql.DB, schema string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"raw_log_reclaim_job", "raw_log_reclaim_chunks"} {
		m := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.` + table + ` \(.*?\n\);`).FindString(string(b))
		if m == "" {
			t.Fatalf("no CREATE TABLE for %s in 001_init.sql", table)
		}
		mustExec(t, db, strings.Replace(m, "public."+table, schema+"."+table, 1))
	}
}

// buildReclaimHypertable builds a small logs_partitioned with the production
// compression layout (segmentby host, log_type) in schema: two closed days
// five and four days back, compressed, and today's rows, not.
func buildReclaimHypertable(t *testing.T, db *sql.DB, schema string) (dayA, dayB time.Time) {
	t.Helper()
	ht := schema + ".logs_partitioned"
	mustExec(t, db,
		`CREATE TYPE `+schema+`.log_type AS ENUM ('access', 'error', 'modsec')`,
		`CREATE TABLE `+ht+` (
		    id uuid NOT NULL DEFAULT gen_random_uuid(),
		    log_type `+schema+`.log_type NOT NULL,
		    "timestamp" timestamptz NOT NULL,
		    host text,
		    client_ip inet,
		    request_uri text,
		    status_code integer,
		    rule_id bigint,
		    http_user_agent text,
		    raw_log text,
		    created_at timestamptz NOT NULL)`,
		`SELECT create_hypertable('`+ht+`', by_range('created_at', INTERVAL '1 day'))`,
		`ALTER TABLE `+ht+` SET (timescaledb.compress, timescaledb.compress_segmentby = 'host, log_type', timescaledb.compress_orderby = 'created_at DESC')`,
		// ~480-byte access/error lines and ~5 KB ModSecurity records, as
		// production stores them; md5 keeps them from compressing to nothing.
		`INSERT INTO `+ht+` (log_type, "timestamp", host, client_ip, request_uri, status_code, rule_id, http_user_agent, raw_log, created_at)
		 SELECT (ARRAY['access', 'access', 'access', 'access', 'access', 'access', 'error', 'error', 'modsec', 'access'])[1 + g % 10]::`+schema+`.log_type,
		        d + g * interval '2 seconds', 'h' || (g % 3) || '.example.com', ('192.0.2.' || (g % 250))::inet, '/p/' || g,
		        200 + (g % 5), CASE WHEN g % 10 = 8 THEN 942100 + g % 7 END, 'ua-' || (g % 11),
		        CASE WHEN g % 10 = 8 THEN repeat(md5(g::text || 'm'), 160) ELSE repeat(md5(g::text), 15) END,
		        d + g * interval '2 seconds'
		   FROM generate_series(4, 5) back,
		        LATERAL (SELECT date_trunc('day', now(), 'UTC') - back * interval '1 day' AS d) s,
		        generate_series(1, 20000) g`,
		`INSERT INTO `+ht+` (log_type, "timestamp", host, raw_log, created_at) VALUES ('access', now(), 'h1.example.com', 'today', now())`,
		`SELECT compress_chunk(c) FROM show_chunks('`+ht+`', older_than => now() - interval '3 days') c`,
	)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	return today.AddDate(0, 0, -5), today.AddDate(0, 0, -4)
}

type reclaimFingerprint struct {
	rows          int64
	noRaw         string // md5 over every column but raw_log
	modsecRaw     string // md5 over ModSecurity raw_log
	nonModsecRaw  int64  // access/error rows that still carry raw_log
	modsecWithRaw int64
}

func fingerprintDay(t *testing.T, db *sql.DB, from time.Time) reclaimFingerprint {
	t.Helper()
	var f reclaimFingerprint
	var modsec sql.NullString
	err := db.QueryRow(`
		SELECT count(*),
		       md5(string_agg(md5(row(id, log_type, "timestamp", host, client_ip, request_uri, status_code,
		                              rule_id, http_user_agent, created_at)::text), ',' ORDER BY id)),
		       md5(string_agg(md5(raw_log), ',' ORDER BY id) FILTER (WHERE log_type = 'modsec')),
		       count(*) FILTER (WHERE log_type <> 'modsec' AND raw_log IS NOT NULL),
		       count(*) FILTER (WHERE log_type = 'modsec' AND raw_log IS NOT NULL)
		  FROM logs_partitioned WHERE created_at >= $1 AND created_at < $2`,
		from, from.AddDate(0, 0, 1)).Scan(&f.rows, &f.noRaw, &modsec, &f.nonModsecRaw, &f.modsecWithRaw)
	if err != nil {
		t.Fatal(err)
	}
	f.modsecRaw = modsec.String
	return f
}

// waitNoOlderSnapshots polls the horizon: other test packages may hold a
// snapshot for a moment.
func waitNoOlderSnapshots(t *testing.T, r *RawLogReclaimRepository, xid int64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		b, err := r.OlderSnapshots(context.Background(), xid)
		if err != nil {
			t.Fatal(err)
		}
		if b.Count == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still %d older snapshot(s) after 60s: %+v", b.Count, b)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func chunkStatus(t *testing.T, db *sql.DB, chunk string) int {
	t.Helper()
	var st int
	if err := db.QueryRow(`SELECT _timescaledb_functions.chunk_status($1::regclass)`, chunk).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRawLogReclaimMethodOneAgainstTimescale(t *testing.T) {
	db, schema := openReclaimTestDB(t)
	ctx := context.Background()
	dayA, dayB := buildReclaimHypertable(t, db, schema)
	r := NewRawLogReclaimRepository(db)
	r.schema = schema

	if ok, reason, err := r.Support(ctx); err != nil || !ok {
		t.Fatalf("Support = %v %q %v", ok, reason, err)
	}
	infos, err := r.ListChunks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var target, other *ReclaimChunkInfo
	recent := 0
	for i := range infos {
		c := &infos[i]
		switch {
		case c.RangeStart.Equal(dayA):
			target = c
		case c.RangeStart.Equal(dayB):
			other = c
		default:
			recent++
			if c.SkipReason() == "" {
				t.Errorf("today's uncompressed chunk qualifies: %+v", c)
			}
		}
	}
	if target == nil || other == nil || recent != 1 {
		t.Fatalf("chunks %+v; want the two old days and today's", infos)
	}
	if reason := target.SkipReason(); reason != "" || !ValidReclaimRelation(target.CompressedRel) || target.Bytes <= 0 {
		t.Fatalf("old day does not qualify (%q): %+v", reason, target)
	}
	if got, err := r.LookupChunk(ctx, target.Name); err != nil || got == nil || got.CompressedRel != target.CompressedRel {
		t.Fatalf("LookupChunk = %+v, %v", got, err)
	}
	if got, err := r.LookupChunk(ctx, "_timescaledb_internal._hyper_999999_1_chunk"); err != nil || got != nil {
		t.Fatalf("LookupChunk of a missing chunk = %+v, %v", got, err)
	}

	before := fingerprintDay(t, db, dayA)
	otherBefore := fingerprintDay(t, db, dayB)
	statusBefore := chunkStatus(t, db, target.Name)
	st, err := r.RawLogStats(ctx, target.CompressedRel)
	if err != nil {
		t.Fatal(err)
	}
	if st.RawBytes <= 0 || st.ModSecBytes <= 0 || st.PendingBatches <= 0 || before.nonModsecRaw == 0 || before.modsecWithRaw == 0 {
		t.Fatalf("stats %+v, fingerprint %+v: the fixture has no raw_log to reclaim", st, before)
	}

	sess, err := r.OpenSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if got, err := sess.TryJobLock(ctx); err != nil || !got {
		t.Fatalf("job lock: %v %v", got, err)
	}
	rival, err := r.OpenSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rival.TryJobLock(ctx); err != nil || got {
		t.Fatalf("a second runner took the job lock: %v %v", got, err)
	}
	// The emergency compression's lock is taken only around the rewrite.
	if got, err := sess.TrySharedLock(ctx); err != nil || !got {
		t.Fatalf("shared lock: %v %v", got, err)
	}
	if got, err := rival.TrySharedLock(ctx); err != nil || got {
		t.Fatalf("the shared lock was not exclusive: %v %v", got, err)
	}
	batches, xid, err := sess.NullRawLog(ctx, target.CompressedRel)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.ReleaseSharedLock(); err != nil {
		t.Fatal(err)
	}
	if got, err := rival.TrySharedLock(ctx); err != nil || !got {
		t.Fatalf("the shared lock stayed held after the UPDATE: %v %v", got, err)
	}
	if err := rival.ReleaseSharedLock(); err != nil {
		t.Fatal(err)
	}
	if batches != st.PendingBatches || xid <= 0 {
		t.Fatalf("UPDATE changed %d batches (want %d), xid %d", batches, st.PendingBatches, xid)
	}
	mid, err := r.RawLogStats(ctx, target.CompressedRel)
	if err != nil || mid.PendingBatches != 0 || mid.RawBytes != 0 || mid.ModSecBytes != st.ModSecBytes {
		t.Fatalf("after the UPDATE: %+v, %v", mid, err)
	}

	waitNoOlderSnapshots(t, r, xid)
	if got, err := sess.TrySharedLock(ctx); err != nil || !got {
		t.Fatalf("shared lock: %v %v", got, err)
	}
	after, err := sess.VacuumFull(ctx, target.CompressedRel)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.ReleaseSharedLock(); err != nil {
		t.Fatal(err)
	}
	if after >= target.Bytes || after > target.Bytes-st.RawBytes/2 {
		t.Fatalf("size %d -> %d with %d bytes of raw_log removed: VACUUM FULL returned too little", target.Bytes, after, st.RawBytes)
	}
	t.Logf("compressed day %d -> %d bytes (raw_log %d, ModSecurity raw_log kept %d, %d batches)", target.Bytes, after, st.RawBytes, st.ModSecBytes, batches)

	got := fingerprintDay(t, db, dayA)
	if got.rows != before.rows || got.noRaw != before.noRaw {
		t.Fatalf("columns other than raw_log changed: %+v -> %+v", before, got)
	}
	if got.modsecRaw != before.modsecRaw || got.modsecWithRaw != before.modsecWithRaw {
		t.Fatalf("ModSecurity raw_log changed: %+v -> %+v", before, got)
	}
	if got.nonModsecRaw != 0 {
		t.Fatalf("%d access/error rows still carry raw_log", got.nonModsecRaw)
	}
	if s := chunkStatus(t, db, target.Name); s != statusBefore {
		t.Fatalf("chunk status %d -> %d", statusBefore, s)
	}
	if o := fingerprintDay(t, db, dayB); o != otherBefore {
		t.Fatalf("the other day changed: %+v -> %+v", otherBefore, o)
	}

	// The session's settings went back, and closing it frees the job lock at
	// once instead of carrying it into the pool.
	_ = rival.Close()
	_ = sess.Close()
	var free bool
	if err := db.QueryRow(`SELECT pg_try_advisory_lock($1)`, RawLogReclaimJobLockKey).Scan(&free); err != nil || !free {
		t.Fatalf("job lock after Close: %v %v", free, err)
	}
	if _, err := db.Exec(`SELECT pg_advisory_unlock_all()`); err != nil {
		t.Fatal(err)
	}
}

func TestRawLogReclaimHorizonSeesOlderSnapshots(t *testing.T) {
	db, _ := openReclaimTestDB(t)
	ctx := context.Background()
	r := NewRawLogReclaimRepository(db)

	reader, err := db.Conn(ctx) // a REPEATABLE READ snapshot taken before the UPDATE
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	writer, err := db.Conn(ctx) // a transaction with an xid, idle between statements
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	mustConnExec(t, reader, `BEGIN ISOLATION LEVEL REPEATABLE READ`, `SELECT 1`)
	mustConnExec(t, writer, `BEGIN`, `SELECT pg_current_xact_id()`)

	// The "UPDATE": a committed transaction newer than both.
	var xid int64
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT xid(pg_current_xact_id())::text::bigint`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	b, err := r.OlderSnapshots(ctx, xid)
	if err != nil {
		t.Fatal(err)
	}
	if b.Count < 2 || b.Since == nil {
		t.Fatalf("blockers %+v; want the open snapshot and the open transaction", b)
	}
	mustConnExec(t, reader, `COMMIT`)
	b, err = r.OlderSnapshots(ctx, xid)
	if err != nil || b.Count < 1 {
		t.Fatalf("after the reader ended: %+v, %v; the writer's xid still blocks", b, err)
	}
	mustConnExec(t, writer, `COMMIT`)
	waitNoOlderSnapshots(t, r, xid)

	// A snapshot taken after the UPDATE does not hold it back.
	mustConnExec(t, reader, `BEGIN ISOLATION LEVEL REPEATABLE READ`, `SELECT 1`)
	waitNoOlderSnapshots(t, r, xid)
	mustConnExec(t, reader, `COMMIT`)

	// The stand-in horizon for a lost xid is at or after every committed one.
	now, err := r.HorizonNow(ctx)
	if err != nil || now < xid {
		t.Fatalf("HorizonNow = %d, %v; want >= %d", now, err, xid)
	}
}

func mustConnExec(t *testing.T, c *sql.Conn, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := c.ExecContext(context.Background(), s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}

func TestRawLogReclaimStateTables(t *testing.T) {
	db, schema := openReclaimTestDB(t)
	ctx := context.Background()
	createReclaimStateTables(t, db, schema)
	r := NewRawLogReclaimRepository(db)

	if j, err := r.LoadJob(ctx); err != nil || j.Status != "idle" {
		t.Fatalf("LoadJob on an empty table = %+v, %v", j, err)
	}
	two := 2
	j, err := r.BeginJob(ctx, "admin", &two)
	if err != nil || j.Status != "running" || j.MaxChunks == nil || *j.MaxChunks != 2 || j.RequestedBy != "admin" || j.RequestedAt == nil || j.FinishedAt != nil {
		t.Fatalf("BeginJob = %+v, %v", j, err)
	}
	if j, found, err := r.ResumeJob(ctx); err != nil || !found || j.StartedAt == nil {
		t.Fatalf("ResumeJob while running = %+v %v %v", j, found, err)
	}

	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a, b := "_timescaledb_internal._hyper_999999_1_chunk", "_timescaledb_internal._hyper_999999_2_chunk"
	for _, p := range []ReclaimPlanRow{
		{Name: a, RangeStart: day, RangeEnd: day.AddDate(0, 0, 1), BytesBefore: 1000, RawBytes: 400},
		{Name: b, RangeStart: day.AddDate(0, 0, 1), RangeEnd: day.AddDate(0, 0, 2), BytesBefore: 900, RawBytes: 300},
	} {
		if err := r.PlanChunk(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// Planning again leaves a recorded day alone.
	if err := r.PlanChunk(ctx, ReclaimPlanRow{Name: a, RangeStart: day, RangeEnd: day.AddDate(0, 0, 1), BytesBefore: 1, RawBytes: 1}); err != nil {
		t.Fatal(err)
	}
	rows := func() map[string]ReclaimChunk {
		t.Helper()
		list, err := r.ListChunkRows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]ReclaimChunk{}
		for _, c := range list {
			m[c.Name] = c
		}
		return m
	}
	if got := rows()[a]; got.State != "pending" || got.BytesBefore != 1000 || got.RawBytes != 400 {
		t.Fatalf("a = %+v", got)
	}

	if err := r.MarkWorked(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkNulled(ctx, a, 1000, 400, 12, 4242); err != nil {
		t.Fatal(err)
	}
	got := rows()[a]
	if got.State != "nulled" || got.UpdateXID == nil || *got.UpdateXID != 4242 || got.WorkedAt == nil {
		t.Fatalf("a after MarkNulled = %+v", got)
	}
	// A skipped day comes back as it was: nulled (it still needs VACUUM
	// FULL), or pending with fresh sizes.
	if err := r.MarkSkipped(ctx, a, ReclaimSkipPartial); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkSkipped(ctx, b, ReclaimSkipPartial); err != nil {
		t.Fatal(err)
	}
	if got := rows()[b]; got.State != "skipped" || got.LastError != "skipped: "+ReclaimSkipPartial {
		t.Fatalf("b skipped = %+v", got)
	}
	for _, p := range []ReclaimPlanRow{
		{Name: a, RangeStart: day, RangeEnd: day.AddDate(0, 0, 1), BytesBefore: 5, RawBytes: 5},
		{Name: b, RangeStart: day.AddDate(0, 0, 1), RangeEnd: day.AddDate(0, 0, 2), BytesBefore: 800, RawBytes: 250},
	} {
		if err := r.PlanChunk(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	m := rows()
	if m[a].State != "nulled" || m[a].BytesBefore != 1000 || m[a].RawBytes != 400 || m[a].LastError != "" {
		t.Fatalf("a back from skipped = %+v", m[a])
	}
	if m[b].State != "pending" || m[b].BytesBefore != 800 || m[b].RawBytes != 250 {
		t.Fatalf("b back from skipped = %+v", m[b])
	}

	if err := r.MarkVacuumIneffective(ctx, a, 990, "kept"); err != nil {
		t.Fatal(err)
	}
	if got := rows()[a]; got.Attempts != 1 || got.BytesAfter != 990 || got.State != "nulled" {
		t.Fatalf("a after an ineffective VACUUM FULL = %+v", got)
	}
	// Errors: not counted, counted, and the third counted one fails the day.
	if st, err := r.NoteChunkError(ctx, b, "busy", false, 3); err != nil || st != "pending" {
		t.Fatalf("NoteChunkError = %q %v", st, err)
	}
	for i, want := range []string{"pending", "pending", "failed"} {
		st, err := r.NoteChunkError(ctx, b, "boom: pq: relation \"x\" does not exist (42P01)", true, 3)
		if err != nil || st != want {
			t.Fatalf("error %d: state %q, %v; want %s", i+1, st, err, want)
		}
	}
	if got := rows()[b]; got.Attempts != 3 || got.LastError != "boom: A database error occurred" {
		t.Fatalf("b = %+v; the stored error must not carry driver text", got)
	}
	// Planning again leaves failed days failed, with their errors. A run that
	// gets to one brings it back with its attempts and its error: nulled with
	// its sizes when an UPDATE is on record, else pending. One more counted
	// error fails it again.
	for i := 0; i < 2; i++ {
		if _, err := r.NoteChunkError(ctx, a, "boom", true, 3); err != nil {
			t.Fatal(err)
		}
	}
	if got := rows()[a]; got.State != "failed" || got.Attempts != 3 {
		t.Fatalf("a = %+v; want failed", got)
	}
	for _, p := range []ReclaimPlanRow{
		{Name: a, RangeStart: day, RangeEnd: day.AddDate(0, 0, 1), BytesBefore: 5, RawBytes: 5},
		{Name: b, RangeStart: day.AddDate(0, 0, 1), RangeEnd: day.AddDate(0, 0, 2), BytesBefore: 700, RawBytes: 200},
	} {
		if err := r.PlanChunk(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	m = rows()
	if m[a].State != "failed" || m[a].Attempts != 3 || m[a].LastError != "boom" {
		t.Fatalf("a planned again = %+v; want still failed, with its error", m[a])
	}
	if m[b].State != "failed" || m[b].Attempts != 3 || m[b].LastError != "boom: A database error occurred" {
		t.Fatalf("b planned again = %+v; want still failed, with its error", m[b])
	}
	if st, err := r.ReviveChunk(ctx, a); err != nil || st != "nulled" {
		t.Fatalf("ReviveChunk(a) = %q, %v; want nulled", st, err)
	}
	if st, err := r.ReviveChunk(ctx, b); err != nil || st != "pending" {
		t.Fatalf("ReviveChunk(b) = %q, %v; want pending", st, err)
	}
	if st, err := r.ReviveChunk(ctx, b); err != nil || st != "" {
		t.Fatalf("ReviveChunk of a day that is not failed = %q, %v; want nothing", st, err)
	}
	m = rows()
	if m[a].State != "nulled" || m[a].BytesBefore != 1000 || m[a].RawBytes != 400 || m[a].Attempts != 3 || m[a].LastError != "boom" {
		t.Fatalf("a back from failed = %+v; want nulled with its sizes, attempts and error", m[a])
	}
	if m[b].State != "pending" || m[b].BytesBefore != 800 || m[b].RawBytes != 250 || m[b].Attempts != 3 || m[b].LastError == "" {
		t.Fatalf("b back from failed = %+v; want pending with its sizes, attempts and error", m[b])
	}
	if st, err := r.NoteChunkError(ctx, b, "boom", true, 3); err != nil || st != "failed" {
		t.Fatalf("one more error on a retried day: %q, %v; want failed", st, err)
	}

	if err := r.MarkDone(ctx, a, 1000, 600, 400); err != nil {
		t.Fatal(err)
	}
	// Neither chunk exists: unfinished days are retired, finished ones kept.
	if err := r.MarkGoneChunks(ctx); err != nil {
		t.Fatal(err)
	}
	m = rows()
	if m[a].State != "done" || m[a].BytesAfter != 600 || m[b].State != "gone" {
		t.Fatalf("after MarkGoneChunks: a %+v, b %+v", m[a], m[b])
	}

	if err := r.FinishJob(ctx, "failed", "reclaiming 2026-09-01 failed: pq: could not extend file (53100)"); err != nil {
		t.Fatal(err)
	}
	j, err = r.LoadJob(ctx)
	if err != nil || j.Status != "failed" || j.FinishedAt == nil || j.LastError != "reclaiming 2026-09-01 failed: A database error occurred" {
		t.Fatalf("job = %+v, %v", j, err)
	}
	if _, found, err := r.ResumeJob(ctx); err != nil || found {
		t.Fatalf("ResumeJob of a failed job: found %v, %v", found, err)
	}
	// A new request clears the old end and error.
	j, err = r.BeginJob(ctx, "", nil)
	if err != nil || j.Status != "running" || j.MaxChunks != nil || j.LastError != "" || j.FinishedAt != nil || j.RequestedBy != "" {
		t.Fatalf("second BeginJob = %+v, %v", j, err)
	}
	// max_chunks is an integer column: the service refuses anything larger.
	most, over := math.MaxInt32, math.MaxInt32+1
	if j, err := r.BeginJob(ctx, "admin", &most); err != nil || j.MaxChunks == nil || *j.MaxChunks != most {
		t.Fatalf("BeginJob with max_chunks %d = %+v, %v", most, j, err)
	}
	if _, err := r.BeginJob(ctx, "admin", &over); SQLState(err) != "22003" {
		t.Fatalf("BeginJob with max_chunks %d: %v; want numeric_value_out_of_range", over, err)
	}
}

func TestValidReclaimRelation(t *testing.T) {
	for _, ok := range []string{"_timescaledb_internal.compress_hyper_2_3_chunk", "_timescaledb_internal._hyper_1_42_chunk_compressed"} {
		if !ValidReclaimRelation(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "compress_hyper_2_3_chunk", `"Weird".x`, "a.b; DROP TABLE x", "a.b.c", "A.b", "a .b"} {
		if ValidReclaimRelation(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	// The SQL never gets a refused name.
	r := &RawLogReclaimRepository{}
	if _, err := r.RawLogStats(context.Background(), "a.b; DROP TABLE x"); err == nil {
		t.Fatal("RawLogStats accepted an unexpected name")
	}
	s := &reclaimSession{}
	if _, _, err := s.NullRawLog(context.Background(), "x"); err == nil {
		t.Fatal("NullRawLog accepted an unexpected name")
	}
	if _, err := s.VacuumFull(context.Background(), "x"); err == nil {
		t.Fatal("VacuumFull accepted an unexpected name")
	}
}

// A lazy VACUUM (manual or autovacuum) running since before the UPDATE does
// not hold the space: the server leaves such backends' xmin out of the
// horizon, so VACUUM FULL can return the space and the wait must not count
// it. A snapshot taken by anything else still counts (above).
func TestRawLogReclaimHorizonIgnoresLazyVacuum(t *testing.T) {
	db, schema := openReclaimTestDB(t)
	ctx := context.Background()
	r := NewRawLogReclaimRepository(db)
	big, upd := schema+".big_t", schema+".upd_t"
	mustExec(t, db,
		`CREATE TABLE `+big+` (id int, pad text) WITH (autovacuum_enabled = off)`,
		`INSERT INTO `+big+` SELECT g, repeat('x', 200) FROM generate_series(1, 20000) g`,
		`DELETE FROM `+big+` WHERE id % 2 = 0`,
		`CREATE TABLE `+upd+` (id int, pad text) WITH (autovacuum_enabled = off)`,
		`INSERT INTO `+upd+` SELECT g, md5(g::text) || repeat('y', 400) FROM generate_series(1, 20000) g`)

	// A lazy VACUUM throttled to about ten pages a second: a minute or more.
	vac, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer vac.Close()
	var vacPID int
	if err := vac.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&vacPID); err != nil {
		t.Fatal(err)
	}
	mustConnExec(t, vac, `SET vacuum_cost_delay = 100`, `SET vacuum_cost_limit = 1`)
	vacDone := make(chan error, 1)
	go func() {
		_, err := vac.ExecContext(ctx, `VACUUM `+big)
		vacDone <- err
	}()
	defer func() {
		_, _ = db.Exec(`SELECT pg_cancel_backend($1)`, vacPID)
		<-vacDone
	}()
	vacuuming := func() bool {
		var running bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_stat_progress_vacuum WHERE pid = $1)
		       AND (SELECT backend_xmin IS NOT NULL FROM pg_stat_activity WHERE pid = $1)`, vacPID).Scan(&running); err != nil {
			t.Fatal(err)
		}
		return running
	}
	for deadline := time.Now().Add(10 * time.Second); !vacuuming(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the VACUUM never showed up in pg_stat_progress_vacuum with a snapshot")
		}
	}

	// The "UPDATE": a committed transaction newer than the vacuum's snapshot
	// that removes most of upd_t.
	var xid int64
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM ` + upd + ` WHERE id > 1000`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT xid(pg_current_xact_id())::text::bigint`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var older bool
	if err := db.QueryRow(`SELECT age(backend_xmin) >= age($2::text::xid) FROM pg_stat_activity WHERE pid = $1`, vacPID, fmt.Sprint(xid)).Scan(&older); err != nil || !older {
		t.Fatalf("the vacuum's snapshot is not older than the UPDATE (%v, %v): the test proves nothing", older, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		b, err := r.OlderSnapshots(ctx, xid)
		if err != nil {
			t.Fatal(err)
		}
		if b.Count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lazy VACUUM (pid %d) is counted as holding the space: %+v", vacPID, b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// And the space really comes back while that VACUUM still runs: the
	// server ignored its snapshot, as the check did.
	var before, after int64
	if err := db.QueryRow(`SELECT pg_total_relation_size($1::regclass)`, upd).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `VACUUM FULL `+upd)
	if err := db.QueryRow(`SELECT pg_total_relation_size($1::regclass)`, upd).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after > before/4 {
		t.Fatalf("VACUUM FULL kept the removed rows (%d -> %d bytes): the lazy VACUUM did hold the horizon", before, after)
	}
	t.Logf("VACUUM FULL during a lazy VACUUM: %d -> %d bytes", before, after)
	if !vacuuming() {
		t.Fatal("the VACUUM ended before the check: run it on a bigger table")
	}
}

// A parallel VACUUM runs its index passes in parallel workers: backends of
// type 'parallel worker' whose leader_pid is the VACUUM, with its snapshot,
// that pg_stat_progress_vacuum does not list (it lists the leader). The
// server leaves them out of the horizon with their leader, so VACUUM FULL
// returns the space all the same, and the wait must not count them either.
func TestRawLogReclaimHorizonIgnoresParallelVacuumWorkers(t *testing.T) {
	db, schema := openReclaimTestDB(t)
	ctx := context.Background()
	r := NewRawLogReclaimRepository(db)
	big, upd := schema+".pv_big", schema+".pv_upd"
	mustExec(t, db,
		`CREATE TABLE `+big+` (id int, a text, b text, c text) WITH (autovacuum_enabled = off)`,
		`INSERT INTO `+big+` SELECT g, md5(g::text), md5((g + 1)::text), md5((g + 2)::text) FROM generate_series(1, 200000) g`,
		`CREATE INDEX ON `+big+` (a)`,
		`CREATE INDEX ON `+big+` (b)`,
		`CREATE INDEX ON `+big+` (c)`,
		`CREATE TABLE `+upd+` (id int, pad text) WITH (autovacuum_enabled = off)`,
		`INSERT INTO `+upd+` SELECT g, md5(g::text) || repeat('y', 400) FROM generate_series(1, 20000) g`)
	// All-visible first, so the throttled VACUUM below skips the heap and
	// spends its time in the indexes, in parallel workers. A transaction
	// another test package has open at the moment keeps pages from being
	// marked, hence the retries.
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		mustExec(t, db, `VACUUM `+big)
		var visible bool
		if err := db.QueryRow(`SELECT relallvisible >= relpages * 0.99 FROM pg_class WHERE oid = $1::regclass`, big).Scan(&visible); err != nil {
			t.Fatal(err)
		}
		if visible {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the table never became all-visible")
		}
	}
	// Dead rows the VACUUM can remove: nothing older than their DELETE open.
	var delXID int64
	dtx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dtx.Exec(`DELETE FROM ` + big + ` WHERE id <= 3000`); err != nil {
		t.Fatal(err)
	}
	if err := dtx.QueryRow(`SELECT xid(pg_current_xact_id())::text::bigint`).Scan(&delXID); err != nil {
		t.Fatal(err)
	}
	if err := dtx.Commit(); err != nil {
		t.Fatal(err)
	}
	waitNoOlderSnapshots(t, r, delXID)

	vac, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer vac.Close()
	var vacPID int
	if err := vac.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&vacPID); err != nil {
		t.Fatal(err)
	}
	mustConnExec(t, vac, `SET max_parallel_maintenance_workers = 2`, `SET min_parallel_index_scan_size = 0`,
		`SET vacuum_cost_delay = 10`, `SET vacuum_cost_limit = 1`)
	vacDone := make(chan error, 1)
	go func() {
		_, err := vac.ExecContext(ctx, `VACUUM (PARALLEL 2, INDEX_CLEANUP ON) `+big)
		vacDone <- err
	}()
	defer func() {
		_, _ = db.Exec(`SELECT pg_cancel_backend($1)`, vacPID)
		<-vacDone
	}()
	workers := func() int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity
		       WHERE leader_pid = $1 AND pid <> $1 AND backend_xmin IS NOT NULL
		         AND pid NOT IN (SELECT pid FROM pg_stat_progress_vacuum)`, vacPID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for deadline := time.Now().Add(30 * time.Second); workers() == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the VACUUM never started parallel workers with a snapshot")
		}
	}

	// The "UPDATE": a committed transaction newer than the workers' snapshot
	// that removes most of upd_t.
	var xid int64
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM ` + upd + ` WHERE id > 1000`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT xid(pg_current_xact_id())::text::bigint`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var older int
	if err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity
	       WHERE leader_pid = $1 AND pid <> $1 AND age(backend_xmin) >= age($2::text::xid)`, vacPID, fmt.Sprint(xid)).Scan(&older); err != nil || older == 0 {
		t.Fatalf("no worker holds a snapshot older than the UPDATE (%d, %v): the test proves nothing", older, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := r.OlderSnapshots(ctx, xid)
		if err != nil {
			t.Fatal(err)
		}
		if b.Count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the parallel VACUUM's workers are counted as holding the space: %+v", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// And the space really comes back while those workers still run: the
	// server ignored their snapshot, as the check did.
	var before, after int64
	if err := db.QueryRow(`SELECT pg_total_relation_size($1::regclass)`, upd).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `VACUUM FULL `+upd)
	if err := db.QueryRow(`SELECT pg_total_relation_size($1::regclass)`, upd).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after > before/4 {
		t.Fatalf("VACUUM FULL kept the removed rows (%d -> %d bytes): the parallel workers did hold the horizon", before, after)
	}
	t.Logf("VACUUM FULL during a parallel VACUUM: %d -> %d bytes", before, after)
	if workers() == 0 {
		t.Fatal("the parallel workers ended before the check: give the VACUUM more index pages")
	}
}
