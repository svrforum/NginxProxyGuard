package repository

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"
)

func trafficTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestTrafficQueriesAcrossPartialAndFullHours(t *testing.T) {
	db := openRollupTestDB(t)
	const a = "11111111-1111-4111-8111-111111111111"
	const b = "22222222-2222-4222-8222-222222222222"
	mustExec(t, db,
		`INSERT INTO proxy_hosts (id, domain_names) VALUES
		('`+a+`', ARRAY['a.example.com']), ('`+b+`', ARRAY['b.example.com'])`,
		`INSERT INTO logs_partitioned (log_type, host, proxy_host_id, request_uri, body_bytes_sent, created_at) VALUES
		('access', 'a.example.com', '`+a+`', '/start', 10, '2026-10-08 10:30:00+00'),
		('access', 'a.example.com', '`+a+`', '/middle', 20, '2026-10-08 11:10:00+00'),
		('access', 'b.example.com', '`+b+`', '/middle', 30, '2026-10-08 11:20:00+00'),
		('access', 'unknown.example.com', NULL, '/middle', 40, '2026-10-08 11:30:00+00'),
		('access', 'b.example.com', '`+b+`', '/end', 50, '2026-10-08 12:10:00+00'),
		('access', 'a.example.com', '`+a+`', '/early', 999, '2026-10-07 10:29:59+00'),
		('access', 'b.example.com', '`+b+`', '/late', 999, '2026-10-08 12:30:00+00'),
		('access', 'b.example.com', '`+b+`', '/__npg_canary?x=1', 999, '2026-10-08 11:20:00+00')`,
	)
	repo := NewDashboardRepository(db)
	ctx := context.Background()
	if _, err := repo.RecomputeHourlyRollup(ctx, trafficTime(t, "2026-10-08T10:00:00Z"), trafficTime(t, "2026-10-08T13:00:00Z")); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	for _, tc := range []struct {
		name, start, end string
	}{
		{"raw", "2026-10-08T10:30:00Z", "2026-10-08T12:30:00Z"},
		{"historical", "2026-10-07T10:30:00Z", "2026-10-08T12:30:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, end := trafficTime(t, tc.start), trafficTime(t, tc.end)
			summary, err := repo.GetTrafficSummary(ctx, start, end)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Bytes != 150 || summary.Requests != 5 {
				t.Fatalf("global %+v, want 150 bytes / 5 requests", summary)
			}
			got := map[string]TrafficHost{}
			for _, h := range summary.Hosts {
				got[h.ID] = h
			}
			for id, bytes := range map[string]int64{a: 30, b: 80, "unclassified": 40} {
				if got[id].Bytes != bytes {
					t.Errorf("host %s got %+v, want %d bytes", id, got[id], bytes)
				}
			}
			for id, expected := range map[string]int64{"": 150, a: 30, b: 80, "unclassified": 40} {
				series, err := repo.GetTrafficSeries(ctx, start, end, id, false)
				if err != nil {
					t.Errorf("series for %s: %v", id, err)
					continue
				}
				var bytes int64
				for _, point := range series {
					bytes += point.Bytes
				}
				if bytes != expected {
					t.Errorf("series for %s got %d bytes, want %d", id, bytes, expected)
				}
			}
		})
	}
	// A rerun must be idempotent, even after a source request disappears.
	mustExec(t, db, `DELETE FROM logs_partitioned WHERE request_uri = '/middle' AND proxy_host_id = '`+b+`'`)
	if _, err := repo.RecomputeHourlyRollup(ctx, trafficTime(t, "2026-10-08T11:00:00Z"), trafficTime(t, "2026-10-08T12:00:00Z")); err != nil {
		t.Fatal(err)
	}
	summary, err := repo.GetTrafficSummary(ctx, trafficTime(t, "2026-10-07T10:30:00Z"), trafficTime(t, "2026-10-08T12:30:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Bytes != 120 || summary.Requests != 4 {
		t.Errorf("after replay got %d bytes / %d requests, want 120 / 4", summary.Bytes, summary.Requests)
	}
}

func TestTrafficHourlyBackfillResumesAfterRestartAndKeepsGlobalHistory(t *testing.T) {
	db := openRollupTestDB(t)
	const host = "11111111-1111-4111-8111-111111111111"
	mustExec(t, db,
		`INSERT INTO proxy_hosts (id, domain_names) VALUES ('`+host+`', ARRAY['a.example.com'])`,
		`INSERT INTO logs_partitioned (log_type, host, proxy_host_id, request_uri, body_bytes_sent, created_at) VALUES
		('access', 'a.example.com', '`+host+`', '/first', 10, '2026-10-30 03:10:00+00'),
		('access', 'a.example.com', '`+host+`', '/second', 20, '2026-10-30 09:15:00+00'),
		('access', 'a.example.com', '`+host+`', '/__npg_canary', 999, '2026-10-30 09:20:00+00'),
		('access', 'a.example.com', '`+host+`', '/recent', 100, '2026-10-30 12:10:00+00')`,
		`INSERT INTO dashboard_stats_hourly (hour_bucket, total_requests, bytes_sent) VALUES
		('2026-10-30 03:00:00+00', 9, 900),
		('2026-10-30 09:00:00+00', 8, 800)`,
	)
	now := trafficTime(t, "2026-10-31T12:30:00Z") // cutoff: October 30, 11:00 UTC
	ctx := context.Background()
	repo := NewDashboardRepository(db)
	from, to, complete, err := repo.BackfillTrafficHourly(ctx, now)
	if err != nil || complete || !from.Equal(trafficTime(t, "2026-10-30T03:00:00Z")) ||
		!to.Equal(trafficTime(t, "2026-10-30T09:00:00Z")) {
		t.Fatalf("first backfill: from=%s to=%s complete=%v err=%v", from, to, complete, err)
	}
	// A fresh repository uses the persisted checkpoint, without double-counting.
	repo = NewDashboardRepository(db)
	from, to, complete, err = repo.BackfillTrafficHourly(ctx, now)
	if err != nil || complete || !from.Equal(trafficTime(t, "2026-10-30T09:00:00Z")) ||
		!to.Equal(trafficTime(t, "2026-10-30T11:00:00Z")) {
		t.Fatalf("resumed backfill: from=%s to=%s complete=%v err=%v", from, to, complete, err)
	}
	_, _, complete, err = repo.BackfillTrafficHourly(ctx, now)
	if err != nil || !complete {
		t.Fatalf("backfill completion: complete=%v err=%v", complete, err)
	}
	var hostRequests, hostBytes int64
	if err := db.QueryRow(`SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(bytes_sent), 0)
		FROM dashboard_stats_hourly WHERE proxy_host_id = $1`, host).Scan(&hostRequests, &hostBytes); err != nil {
		t.Fatal(err)
	}
	if hostRequests != 2 || hostBytes != 30 {
		t.Errorf("host backfill got %d requests, %d bytes; want 2/30", hostRequests, hostBytes)
	}
	var globalBytes int64
	if err := db.QueryRow(`SELECT SUM(bytes_sent) FROM dashboard_stats_hourly WHERE proxy_host_id IS NULL`).Scan(&globalBytes); err != nil {
		t.Fatal(err)
	}
	if globalBytes != 1700 {
		t.Errorf("historical global totals changed: got %d, want 1700", globalBytes)
	}
	// Repeated calls after completion cannot change either the cursor or totals.
	_, _, complete, err = repo.BackfillTrafficHourly(ctx, now)
	if err != nil || !complete {
		t.Fatalf("repeated completion: complete=%v err=%v", complete, err)
	}
}

func TestTrafficHourlyBackfillRetriesFailedBatch(t *testing.T) {
	db := openRollupTestDB(t)
	const host = "11111111-1111-4111-8111-111111111111"
	mustExec(t, db,
		`INSERT INTO proxy_hosts (id, domain_names) VALUES ('`+host+`', ARRAY['a.example.com'])`,
		`INSERT INTO logs_partitioned (log_type, host, proxy_host_id, body_bytes_sent, created_at) VALUES
		('access', 'a.example.com', '`+host+`', 42, '2026-10-30 03:10:00+00')`,
	)
	now := trafficTime(t, "2026-10-31T12:30:00Z")
	// Force a real SQL error after cursor initialization. Renaming a column
	// ensures the query fails even if a public.proxy_hosts table exists outside
	// the test schema (PostgreSQL may fall back to it after DROP TABLE).
	// The failed transaction must roll back the cursor and aggregate writes.
	mustExec(t, db, `ALTER TABLE logs_partitioned RENAME COLUMN body_bytes_sent TO missing_body_bytes_sent`)
	_, _, _, err := NewDashboardRepository(db).BackfillTrafficHourly(context.Background(), now)
	if err == nil {
		t.Fatal("expected backfill SQL error")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM traffic_hourly_backfill`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed batch persisted a cursor: count=%d err=%v", count, err)
	}
	mustExec(t, db, `ALTER TABLE logs_partitioned RENAME COLUMN missing_body_bytes_sent TO body_bytes_sent`)
	from, _, _, err := NewDashboardRepository(db).BackfillTrafficHourly(context.Background(), now)
	if err != nil || !from.Equal(trafficTime(t, "2026-10-30T03:00:00Z")) {
		t.Fatalf("retry: from=%s err=%v", from, err)
	}
}

func TestTrafficHourlyBackfillWithNoHistoricalLogs(t *testing.T) {
	db := openRollupTestDB(t)
	from, to, complete, err := NewDashboardRepository(db).BackfillTrafficHourly(
		context.Background(), trafficTime(t, "2026-10-31T12:30:00Z"))
	if err != nil || !complete || !from.Equal(to) {
		t.Fatalf("empty backfill: from=%s to=%s complete=%v err=%v", from, to, complete, err)
	}
}

func TestTrafficRateExactWindowAndEmptySummary(t *testing.T) {
	db := openRollupTestDB(t)
	repo := NewDashboardRepository(db)
	start, end := trafficTime(t, "2026-10-08T10:00:00Z"), trafficTime(t, "2026-10-08T10:00:30Z")
	summary, err := repo.GetTrafficSummary(context.Background(), start, end)
	if err != nil || summary.Requests != 0 || summary.Bytes != 0 {
		t.Fatalf("empty summary: %+v, %v", summary, err)
	}
	mustExec(t, db, `INSERT INTO logs_partitioned (log_type, host, request_uri, body_bytes_sent, created_at) VALUES
		('access', 'unknown.example.com', '/', 100, '2026-10-08 10:00:00+00'),
		('access', 'unknown.example.com', '/', 200, '2026-10-08 10:00:29.999+00'),
		('access', 'unknown.example.com', '/', 999, '2026-10-08 10:00:30+00')`)
	requests, bytes, err := repo.GetTrafficRate(context.Background(), start, end, "unclassified")
	if err != nil || requests != 2 || bytes != 300 {
		t.Errorf("rate interval got %d requests, %d bytes, %v; want 2/300", requests, bytes, err)
	}
}

func TestTrafficRealtimeTenSecondBoundaries(t *testing.T) {
	db := openRollupTestDB(t)
	const host = "11111111-1111-4111-8111-111111111111"
	mustExec(t, db,
		`INSERT INTO proxy_hosts (id, domain_names) VALUES ('`+host+`', ARRAY['a.example.com'])`,
		`INSERT INTO logs_partitioned (log_type, host, proxy_host_id, body_bytes_sent, created_at) VALUES
		('access', 'a.example.com', '`+host+`', 10, '2026-10-08 10:00:00+00'),
		('access', 'a.example.com', '`+host+`', 20, '2026-10-08 10:00:09.999+00'),
		('access', 'a.example.com', '`+host+`', 30, '2026-10-08 10:00:10+00'),
		('access', 'a.example.com', '`+host+`', 40, '2026-10-08 10:00:19.999+00'),
		('access', 'a.example.com', '`+host+`', 999, '2026-10-08 10:00:20+00'),
		('access', 'unknown.example.com', NULL, 50, '2026-10-08 10:00:10+00')`,
	)
	start := trafficTime(t, "2026-10-08T10:00:00Z")
	end := trafficTime(t, "2026-10-08T10:00:20Z")
	repo := NewDashboardRepository(db)
	for _, tc := range []struct {
		name, hostID string
		bytes        []int64
		requests     []int64
	}{
		{"all", "", []int64{30, 120}, []int64{2, 3}},
		{"host", host, []int64{30, 70}, []int64{2, 2}},
		{"unclassified", "unclassified", []int64{50}, []int64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.GetTrafficSeries(context.Background(), start, end, tc.hostID, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.bytes) {
				t.Fatalf("got %d buckets: %+v", len(got), got)
			}
			for i, point := range got {
				if point.Bytes != tc.bytes[i] || point.Requests != tc.requests[i] {
					t.Errorf("bucket %d: got %+v, want %d bytes and %d requests", i, point, tc.bytes[i], tc.requests[i])
				}
				if want := start.Add(time.Duration(i) * 10 * time.Second); tc.hostID != "unclassified" && !point.Timestamp.Equal(want) {
					t.Errorf("bucket %d starts at %s, want %s", i, point.Timestamp, want)
				}
			}
		})
	}
}

// Two independent DB connections must claim distinct backfill batches. A
// single-connection pool would serialize the calls before reaching FOR UPDATE
// and would not exercise cross-process concurrency.
func TestTrafficHourlyBackfillConcurrentWorkers(t *testing.T) {
	db := openRollupTestDB(t)
	var schema string
	if err := db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db,
		`INSERT INTO proxy_hosts VALUES ('11111111-1111-4111-8111-111111111111', ARRAY['a.example.com'])`,
		`INSERT INTO logs_partitioned (log_type, host, proxy_host_id, body_bytes_sent, created_at) VALUES
		('access', 'a.example.com', '11111111-1111-4111-8111-111111111111', 10, '2026-10-30 03:10:00+00'),
		('access', 'a.example.com', '11111111-1111-4111-8111-111111111111', 20, '2026-10-30 09:10:00+00')`,
	)
	other, err := sql.Open("postgres", os.Getenv("NPG_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetMaxOpenConns(1)
	if _, err := other.Exec(`SET search_path TO ` + schema + `, public`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	now := trafficTime(t, "2026-10-31T12:30:00Z")
	type result struct {
		from, to time.Time
		complete bool
		err      error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, conn := range []*sql.DB{db, other} {
		wg.Add(1)
		go func(conn *sql.DB) {
			defer wg.Done()
			<-start
			from, to, done, err := NewDashboardRepository(conn).BackfillTrafficHourly(ctx, now)
			results <- result{from, to, done, err}
		}(conn)
	}
	close(start)
	wg.Wait()
	close(results)
	seen := make(map[string]bool)
	for r := range results {
		if r.err != nil || r.complete {
			t.Fatalf("concurrent backfill: %+v", r)
		}
		key := r.from.Format(time.RFC3339)
		if seen[key] {
			t.Errorf("duplicate batch started at %s", key)
		}
		seen[key] = true
	}
	if len(seen) != 2 || !seen["2026-10-30T03:00:00Z"] || !seen["2026-10-30T09:00:00Z"] {
		t.Errorf("claimed ranges: %+v", seen)
	}
	var requests, bytes int64
	if err := db.QueryRow(`SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(bytes_sent), 0)
		FROM dashboard_stats_hourly WHERE proxy_host_id IS NOT NULL`).Scan(&requests, &bytes); err != nil || requests != 2 || bytes != 30 {
		t.Errorf("aggregated %d requests and %d bytes, err=%v; want 2/30", requests, bytes, err)
	}
}
