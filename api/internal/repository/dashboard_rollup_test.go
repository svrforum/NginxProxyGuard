package repository

import (
	"context"
	"database/sql"
	"math"
	"strings"
	"testing"
	"time"
)

// The hourly rollup overwrites (=) what the logs hold; it never adds (+=) to
// what a row already says, which is how the old rollup double counted.
func TestHourlyRollupOverwritesAndFiltersLikeTheDashboard(t *testing.T) {
	for _, want := range []string{
		canaryURIExclusion,
		"status_code IS DISTINCT FROM 101",
		"ON CONFLICT (hour_bucket) WHERE proxy_host_id IS NULL",
		// The average and the count that weights it cover the same requests,
		// which leave out the ones held open past a minute (#324).
		"avg(request_time) FILTER (WHERE " + averagedRequestFilter + ")",
		"count(request_time) FILTER (WHERE " + averagedRequestFilter + ")",
		"request_time <= 60",
	} {
		if !strings.Contains(hourlyRollupRecomputeSQL, want) {
			t.Errorf("hourlyRollupRecomputeSQL lost %q", want)
		}
	}
	for _, col := range []string{"total_requests", "status_2xx", "status_3xx", "status_4xx", "status_5xx",
		"avg_response_time", "timed_requests", "bytes_sent", "waf_blocked", "rate_limited", "bot_blocked"} {
		if !strings.Contains(hourlyRollupRecomputeSQL, "= EXCLUDED."+col) {
			t.Errorf("hourlyRollupRecomputeSQL does not overwrite %s", col)
		}
		if strings.Contains(hourlyRollupRecomputeSQL, "dashboard_stats_hourly."+col+" +") {
			t.Errorf("hourlyRollupRecomputeSQL adds to %s instead of overwriting it", col)
		}
	}
}

type hourlyRow struct {
	total, s2, s3, s4, s5, bytes, waf, rl, bot, timed int64
	avgMs                                             float64
}

// openRollupTestDB returns a test database with the columns the hourly rollup
// reads and writes.
func openRollupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TYPE log_type AS ENUM ('access', 'error', 'modsec')`,
		`CREATE TYPE block_reason AS ENUM ('none', 'waf', 'bot_filter', 'rate_limit', 'geo_block')`,
		`CREATE TABLE logs_partitioned (
			log_type log_type NOT NULL, host text, request_uri text, status_code integer,
			request_time double precision, body_bytes_sent bigint,
			block_reason block_reason DEFAULT 'none', created_at timestamptz NOT NULL)`,
		`CREATE TABLE dashboard_stats_hourly (
			id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
			proxy_host_id uuid,
			hour_bucket timestamp with time zone NOT NULL,
			total_requests bigint DEFAULT 0 NOT NULL,
			status_2xx bigint DEFAULT 0 NOT NULL,
			status_3xx bigint DEFAULT 0 NOT NULL,
			status_4xx bigint DEFAULT 0 NOT NULL,
			status_5xx bigint DEFAULT 0 NOT NULL,
			avg_response_time double precision DEFAULT 0,
			timed_requests bigint DEFAULT 0 NOT NULL,
			bytes_sent bigint DEFAULT 0 NOT NULL,
			bytes_received bigint DEFAULT 0 NOT NULL,
			waf_blocked bigint DEFAULT 0 NOT NULL,
			rate_limited bigint DEFAULT 0 NOT NULL,
			bot_blocked bigint DEFAULT 0 NOT NULL,
			created_at timestamp with time zone DEFAULT now() NOT NULL,
			UNIQUE (proxy_host_id, hour_bucket))`,
		`CREATE UNIQUE INDEX idx_dashboard_stats_hourly_null_host_bucket ON dashboard_stats_hourly (hour_bucket) WHERE proxy_host_id IS NULL`,
	)
	return db
}

// One recompute over a fixed window: the counts match what the logs hold,
// NULL fields count, NPG's own and internal requests do not, the latency
// average leaves out WebSocket upgrades and requests without a time, a wrong
// row is overwritten, an hour without requests is zeroed, and hours outside
// the window and per-host rows are left alone. A second run changes nothing.
func TestRecomputeHourlyRollup(t *testing.T) {
	db := openRollupTestDB(t)
	mustExec(t, db,

		// 10:00 UTC: nine requests that count.
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, block_reason, created_at) VALUES
			('access', 'a.example.com', '/ok',     200, 0.100, 1000,  'none',       '2026-10-08 10:01:00+00'),
			('access', 'a.example.com', '/fast',   200, NULL,  500,   'none',       '2026-10-08 10:02:00+00'),
			('access', 'a.example.com', '/moved',  302, 0.300, NULL,  'none',       '2026-10-08 10:03:00+00'),
			('access', 'a.example.com', '/ws',     101, 1178.9, 21606, 'none',      '2026-10-08 10:04:00+00'),
			('access', 'a.example.com', '/attack', 403, NULL,  0,     'waf',        '2026-10-08 10:05:00+00'),
			('access', 'a.example.com', '/burst',  429, 0.200, 10,    'rate_limit', '2026-10-08 10:06:00+00'),
			('access', 'a.example.com', '/bot',    403, NULL,  10,    'bot_filter', '2026-10-08 10:07:00+00'),
			('access', 'a.example.com', '/broken', 502, 0.400, 20,    'none',       '2026-10-08 10:08:00+00'),
			('access', 'a.example.com', NULL,      200, 0.200, 100,   'none',       '2026-10-08 10:59:59.999+00')`,
		// 10:00 UTC: rows that do not count.
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at) VALUES
			('access', 'a.example.com', '/__npg_canary?n=1', 200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', 'a.example.com', '/health',           200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', 'a.example.com', '/nginx_status',     200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', 'a.example.com', '/.well-known/acme-challenge/x', 200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', 'localhost',      '/x', 200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', 'localhost:8080', '/x', 200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', '_',              '/x', 200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('access', NULL,             '/x', 200, 0.1, 1, '2026-10-08 10:10:00+00'),
			('error',  'a.example.com',  '/x', NULL, NULL, NULL, '2026-10-08 10:10:00+00'),
			('modsec', 'a.example.com',  '/x', 403, NULL, NULL, '2026-10-08 10:10:00+00')`,
		// 11:00 UTC: two requests. 09:00 and 13:00 are outside the window.
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at) VALUES
			('access', 'b.example.com', '/', 200, 0.050, 10, '2026-10-08 11:00:00+00'),
			('access', 'b.example.com', '/', 404, 0.150, 30, '2026-10-08 11:30:00+00'),
			('access', 'b.example.com', '/', 200, 0.050, 10, '2026-10-08 09:59:59+00'),
			('access', 'b.example.com', '/', 200, 0.050, 10, '2026-10-08 13:00:00+00')`,
		// What the old rollup left behind: a wrong 10:00, a stale 12:00 whose
		// requests are gone, 13:00 outside the window, and a per-host row.
		`INSERT INTO dashboard_stats_hourly (proxy_host_id, hour_bucket, total_requests, status_2xx) VALUES
			(NULL, '2026-10-08 10:00:00+00', 999999, 999999),
			(NULL, '2026-10-08 12:00:00+00', 999, 999),
			(NULL, '2026-10-08 13:00:00+00', 777, 777),
			('0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0', '2026-10-08 10:00:00+00', 5, 5)`,
	)

	read := func() map[string]hourlyRow {
		t.Helper()
		rows, err := db.Query(`
			SELECT to_char(hour_bucket AT TIME ZONE 'UTC', 'HH24:MI') || CASE WHEN proxy_host_id IS NULL THEN '' ELSE ' host' END,
			       total_requests, status_2xx, status_3xx, status_4xx, status_5xx, avg_response_time,
			       bytes_sent, waf_blocked, rate_limited, bot_blocked, timed_requests
			FROM dashboard_stats_hourly`)
		if err != nil {
			t.Fatalf("read rollup: %v", err)
		}
		defer rows.Close()
		got := map[string]hourlyRow{}
		for rows.Next() {
			var k string
			var r hourlyRow
			if err := rows.Scan(&k, &r.total, &r.s2, &r.s3, &r.s4, &r.s5, &r.avgMs, &r.bytes, &r.waf, &r.rl, &r.bot, &r.timed); err != nil {
				t.Fatalf("scan rollup: %v", err)
			}
			r.avgMs = float64(int64(r.avgMs*1000+0.5)) / 1000 // compare to the microsecond
			got[k] = r
		}
		return got
	}

	repo := NewDashboardRepository(db)
	ctx := context.Background()
	// from is truncated to its hour; to is exclusive.
	from := time.Date(2026, 10, 8, 10, 20, 0, 0, time.UTC)
	to := time.Date(2026, 10, 8, 13, 0, 0, 0, time.UTC)

	n, err := repo.RecomputeHourlyRollup(ctx, from, to)
	if err != nil {
		t.Fatalf("RecomputeHourlyRollup: %v", err)
	}
	if n != 3 {
		t.Errorf("wrote %d hourly rows, want 3 (10:00, 11:00, 12:00)", n)
	}
	want := map[string]hourlyRow{
		// 9 requests: 2xx /ok /fast and the NULL URI, 3xx /moved, 4xx three,
		// 5xx one; the 101 counts as a request but in no class. Latency
		// averages 0.1, 0.3, 0.2, 0.4 and 0.2 s: not the 101, not the NULLs.
		"10:00":      {total: 9, s2: 3, s3: 1, s4: 3, s5: 1, avgMs: 240, timed: 5, bytes: 23246, waf: 1, rl: 1, bot: 1},
		"11:00":      {total: 2, s2: 1, s4: 1, avgMs: 100, timed: 2, bytes: 40},
		"12:00":      {},
		"13:00":      {total: 777, s2: 777},
		"10:00 host": {total: 5, s2: 5},
	}
	got := read()
	if len(got) != len(want) {
		t.Errorf("rollup has %d rows, want %d: %+v", len(got), len(want), got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("hour %s = %+v, want %+v", k, got[k], w)
		}
	}

	if _, err := repo.RecomputeHourlyRollup(ctx, from, to); err != nil {
		t.Fatalf("second RecomputeHourlyRollup: %v", err)
	}
	again := read()
	for k, w := range got {
		if again[k] != w {
			t.Errorf("a second run changed hour %s from %+v to %+v", k, w, again[k])
		}
	}
}

// The dashboard's 24h response time is the average over the requests that
// have a measured time, whichever hours they fall in. The hourly rows keep
// each hour's average; the 24h figure weights them by timed_requests. It
// weighted them by total_requests, which also counts the instant answers
// (blocked scanners, redirects: stored without a time), so an hour of those
// multiplied the time of its few measured requests: here 367.6 ms instead of
// 72.7.
func TestDashboardResponseTimeAveragesTimedRequests(t *testing.T) {
	db := openRollupTestDB(t)
	mustExec(t, db,
		// 21:00 UTC: 2,000 instant answers, 20 proxied requests at 400 ms and a
		// WebSocket upgrade (its time is the connection's lifetime).
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, block_reason, created_at)
		 SELECT 'access', 'a.example.com', '/scan', 403, NULL, 0, 'bot_filter', '2026-10-08 21:00:00+00'::timestamptz + g * interval '1 second'
		 FROM generate_series(1, 2000) g`,
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at)
		 SELECT 'access', 'a.example.com', '/app', 200, 0.400, 100, '2026-10-08 21:40:00+00'::timestamptz + g * interval '1 second'
		 FROM generate_series(1, 20) g`,
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at) VALUES
			('access', 'a.example.com', '/ws', 101, 3600.0, 10, '2026-10-08 21:50:00+00')`,
		// 22:00 UTC: 200 requests at 40 ms, none instant.
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at)
		 SELECT 'access', 'a.example.com', '/app', 200, 0.040, 100, '2026-10-08 22:00:00+00'::timestamptz + g * interval '1 second'
		 FROM generate_series(1, 200) g`,
	)
	repo := NewDashboardRepository(db)
	ctx := context.Background()
	if _, err := repo.RecomputeHourlyRollup(ctx, time.Date(2026, 10, 8, 21, 0, 0, 0, time.UTC), time.Date(2026, 10, 8, 23, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RecomputeHourlyRollup: %v", err)
	}
	var total, bandwidth, errorsN, forRate int64
	var avgMs float64
	since := time.Date(2026, 10, 8, 20, 30, 0, 0, time.UTC)
	if err := db.QueryRowContext(ctx, dashboardSummary24hSQL, since).Scan(&total, &bandwidth, &avgMs, &errorsN, &forRate); err != nil {
		t.Fatalf("24h summary: %v", err)
	}
	// (20 x 400 ms + 200 x 40 ms) / 220 timed requests
	if want := 16000.0 / 220; math.Abs(avgMs-want) > 0.01 {
		t.Errorf("24h average response time %.1f ms, want %.1f (the mean over the 220 timed requests)", avgMs, want)
	}
	if total != 2221 || errorsN != 2000 {
		t.Errorf("24h totals: %d requests and %d errors, want 2221 and 2000", total, errorsN)
	}

	// Hours without a timed request do not pull the average to 0.
	mustExec(t, db, `INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at)
		 SELECT 'access', 'a.example.com', '/scan', 403, NULL, 0, '2026-10-08 23:00:00+00'::timestamptz + g * interval '1 second'
		 FROM generate_series(1, 500) g`)
	if _, err := repo.RecomputeHourlyRollup(ctx, time.Date(2026, 10, 8, 23, 0, 0, 0, time.UTC), time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RecomputeHourlyRollup 23:00: %v", err)
	}
	if err := db.QueryRowContext(ctx, dashboardSummary24hSQL, since).Scan(&total, &bandwidth, &avgMs, &errorsN, &forRate); err != nil {
		t.Fatalf("24h summary: %v", err)
	}
	if want := 16000.0 / 220; math.Abs(avgMs-want) > 0.01 || total != 2721 {
		t.Errorf("with an hour of instant answers only: %.1f ms over %d requests, want %.1f ms over 2721", avgMs, total, want)
	}
}

// An event stream or a long poll holds its request open for minutes on
// purpose: its time is how long the client stayed connected, not how fast the
// server answered. It still counts as a request (in the totals, its status
// class and its bytes), but not in the average response time, nor in
// timed_requests, by which the 24h figure weights each hour. One five-minute
// event stream among twenty 50 ms requests put the hour at 14.3 s (#324). A
// request that took a minute or less is averaged as before, and a WebSocket
// upgrade is left out however short it was (#148).
func TestAverageResponseTimeLeavesOutLongRequests(t *testing.T) {
	db := openRollupTestDB(t)
	repo := NewDashboardRepository(db)
	ctx := context.Background()

	hour := func(bucket string) hourlyRow {
		t.Helper()
		var r hourlyRow
		if err := db.QueryRowContext(ctx, `
			SELECT total_requests, status_2xx, status_5xx, bytes_sent, timed_requests, avg_response_time
			FROM dashboard_stats_hourly
			WHERE proxy_host_id IS NULL AND hour_bucket = $1::timestamptz`, bucket).
			Scan(&r.total, &r.s2, &r.s5, &r.bytes, &r.timed, &r.avgMs); err != nil {
			t.Fatalf("read hour %s: %v", bucket, err)
		}
		r.avgMs = float64(int64(r.avgMs*1000+0.5)) / 1000 // compare to the microsecond
		return r
	}

	// 14:00 UTC: twenty requests at 50 ms, an event stream held open for five
	// minutes and a WebSocket that lasted 30 seconds.
	mustExec(t, db,
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at)
		 SELECT 'access', 'a.example.com', '/api', 200, 0.050, 100, '2026-10-08 14:00:00+00'::timestamptz + g * interval '1 second'
		 FROM generate_series(1, 20) g`,
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at) VALUES
			('access', 'a.example.com', '/events', 200, 300.0, 5000, '2026-10-08 14:30:00+00'),
			('access', 'a.example.com', '/ws',     101, 30.0,  10,   '2026-10-08 14:40:00+00')`,
	)
	if _, err := repo.RecomputeHourlyRollup(ctx, time.Date(2026, 10, 8, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 8, 15, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RecomputeHourlyRollup 14:00: %v", err)
	}
	// All 22 requests count (the 101 in no status class); the average and
	// timed_requests cover the twenty 50 ms answers only.
	if got, want := hour("2026-10-08 14:00:00+00"), (hourlyRow{total: 22, s2: 21, bytes: 7010, timed: 20, avgMs: 50}); got != want {
		t.Errorf("14:00 = %+v, want %+v", got, want)
	}
	var total, bandwidth, errorsN, forRate int64
	var avgMs float64
	if err := db.QueryRowContext(ctx, dashboardSummary24hSQL, time.Date(2026, 10, 8, 13, 30, 0, 0, time.UTC)).
		Scan(&total, &bandwidth, &avgMs, &errorsN, &forRate); err != nil {
		t.Fatalf("24h summary: %v", err)
	}
	if math.Abs(avgMs-50) > 0.01 || total != 22 || bandwidth != 7010 {
		t.Errorf("24h: %.1f ms over %d requests and %d bytes, want 50.0 ms over 22 requests and 7010 bytes", avgMs, total, bandwidth)
	}

	// 15:00 UTC: one request answered in exactly a minute, one just over it.
	mustExec(t, db,
		`INSERT INTO logs_partitioned (log_type, host, request_uri, status_code, request_time, body_bytes_sent, created_at) VALUES
			('access', 'a.example.com', '/report', 200, 60.0, 100, '2026-10-08 15:10:00+00'),
			('access', 'a.example.com', '/report', 200, 60.5, 100, '2026-10-08 15:20:00+00')`,
	)
	if _, err := repo.RecomputeHourlyRollup(ctx, time.Date(2026, 10, 8, 15, 0, 0, 0, time.UTC), time.Date(2026, 10, 8, 16, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RecomputeHourlyRollup 15:00: %v", err)
	}
	if got, want := hour("2026-10-08 15:00:00+00"), (hourlyRow{total: 2, s2: 2, bytes: 200, timed: 1, avgMs: 60000}); got != want {
		t.Errorf("15:00 = %+v, want %+v (a minute is averaged, anything longer is not)", got, want)
	}
}
