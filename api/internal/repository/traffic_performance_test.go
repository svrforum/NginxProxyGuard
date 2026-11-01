package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in synthetic measurement, never run against a production database.
// openRollupTestDB creates and removes a private schema. The fixture models
// only rollup-relevant columns, daily partitions and the relevant log indexes;
// it is deliberately not a claim about Timescale compression or live load.
func TestTrafficPerformance(t *testing.T) {
	if os.Getenv("NPG_TRAFFIC_PERF") != "1" {
		t.Skip("set NPG_TRAFFIC_PERF=1 on an isolated test database")
	}
	db := openRollupTestDB(t)
	mustExec(t, db, `DROP TABLE logs_partitioned`, `CREATE TABLE logs_partitioned (
		log_type log_type NOT NULL, host text, proxy_host_id uuid, request_uri text, status_code integer,
		request_time double precision, body_bytes_sent bigint, block_reason block_reason DEFAULT 'none',
		created_at timestamptz NOT NULL, timestamp timestamptz NOT NULL, raw_log text
	) PARTITION BY RANGE(created_at)`)
	for day := 28; day <= 30; day++ {
		mustExec(t, db, fmt.Sprintf(`CREATE TABLE logs_day_%d PARTITION OF logs_partitioned
		FOR VALUES FROM ('2026-10-%d 00:00:00+00') TO ('2026-10-%d 00:00:00+00')`, day, day, day+1))
	}
	mustExec(t, db,
		`CREATE INDEX ON logs_partitioned(created_at DESC)`,
		`CREATE INDEX ON logs_partitioned(log_type, created_at DESC)`,
		`CREATE INDEX ON logs_partitioned(proxy_host_id, timestamp DESC) WHERE proxy_host_id IS NOT NULL`,
		`CREATE INDEX ON dashboard_stats_hourly(hour_bucket)`,
		`INSERT INTO proxy_hosts SELECT md5(i::text)::uuid, ARRAY['host-' || i || '.example.test'] FROM generate_series(1,200) i`,
		`INSERT INTO logs_partitioned
		 SELECT 'access', 'host-' || (i % 200 + 1) || '.example.test',
		 CASE WHEN i % 20 = 0 THEN NULL ELSE md5((i % 200 + 1)::text)::uuid END,
		 CASE WHEN i % 100 = 0 THEN '/health' ELSE '/asset' END,
		 CASE WHEN i % 13 = 0 THEN 404 ELSE 200 END, 0.025, 1024 + i % 65536, 'none',
		 '2026-10-28 00:00:00+00'::timestamptz + (i * interval '0.0864 seconds'),
		 '2026-10-28 00:00:00+00'::timestamptz + (i * interval '0.0864 seconds'), repeat('x',180)
		 FROM generate_series(0,2999999) i`,
		`ANALYZE logs_partitioned`, `ANALYZE proxy_hosts`)
	var version, settings string
	var size int64
	if err := db.QueryRow(`SELECT version(), current_setting('shared_buffers') || ' shared_buffers, ' ||
		current_setting('work_mem') || ' work_mem, ' || current_setting('max_parallel_workers_per_gather') || ' parallel workers',
		(SELECT sum(pg_total_relation_size(inhrelid)) FROM pg_inherits WHERE inhparent = 'logs_partitioned'::regclass)`).Scan(&version, &settings, &size); err != nil {
		t.Fatal(err)
	}
	t.Logf("Environment: %s; %s; log table+indexes=%d bytes; 3,000,000 rows / 72h / 200 configured hosts / 190 active classified hosts", version, settings, size)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	measure := func(name, query string, args ...any) {
		t.Helper()
		var plan json.RawMessage
		if err := db.QueryRowContext(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, args...).Scan(&plan); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var parsed []struct {
			Execution float64        `json:"Execution Time"`
			Planning  float64        `json:"Planning Time"`
			Plan      map[string]any `json:"Plan"`
		}
		if err := json.Unmarshal(plan, &parsed); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: planning=%.3fms execution=%.3fms shared-hit=%v read=%v temp-read=%v temp-written=%v", name, parsed[0].Planning, parsed[0].Execution, parsed[0].Plan["Shared Hit Blocks"], parsed[0].Plan["Shared Read Blocks"], parsed[0].Plan["Temp Read Blocks"], parsed[0].Plan["Temp Written Blocks"])
		if dir := os.Getenv("NPG_TRAFFIC_PERF_OUTPUT"); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".json"), plan, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, hours := range []int{1, 2, 26} {
		end := trafficTime(t, "2026-10-31T00:00:00Z")
		start := end.Add(-time.Duration(hours) * time.Hour)
		for repeat := 1; repeat <= 3; repeat++ {
			prefix := fmt.Sprintf("%dh-run%d", hours, repeat)
			measure(prefix+"-global", hourlyRollupRecomputeSQL, start, end)
			measure(prefix+"-host", hourlyHostRollupSQL, start, end)
			// Original PR cleanup, retained only for a paired comparison on
			// the same fixture, indexes, connection and PostgreSQL settings.
			measure(prefix+"-legacy-cleanup", `DELETE FROM dashboard_stats_hourly d
			WHERE d.proxy_host_id IS NOT NULL
			AND d.hour_bucket >= date_trunc('hour', $1::timestamptz, 'UTC') AND d.hour_bucket < $2::timestamptz
			AND NOT EXISTS (SELECT 1 FROM logs_partitioned l WHERE l.proxy_host_id = d.proxy_host_id
			 AND l.created_at >= d.hour_bucket AND l.created_at < d.hour_bucket + interval '1 hour'
			 AND `+trafficAccessFilter+`)`, start, end)
			measure(prefix+"-cleanup", hourlyHostRollupCleanupSQL, start, end)
		}
	}
	// 24h summary: compare raw scan to the complete-hours + partial-hours path.
	start, end := trafficTime(t, "2026-10-29T23:30:00Z"), trafficTime(t, "2026-10-30T23:30:00Z")
	fullStart, fullEnd := trafficFullHours(start, end)
	for repeat := 1; repeat <= 3; repeat++ {
		measure(fmt.Sprintf("24h-run%d-raw-summary", repeat), trafficSummarySQL(false), start, end)
		measure(fmt.Sprintf("24h-run%d-hybrid-summary", repeat), trafficSummarySQL(true), start, end, fullStart, fullEnd)
		measure(fmt.Sprintf("24h-run%d-raw-chart", repeat), `SELECT to_timestamp(floor(extract(epoch from created_at)/300)*300), count(*), sum(body_bytes_sent)
		FROM logs_partitioned WHERE created_at >= $1 AND created_at < $2 AND `+trafficAccessFilter+` GROUP BY 1 ORDER BY 1`, start, end)
		query, args := trafficSeriesQuery(start, end, "", false)
		measure(fmt.Sprintf("24h-run%d-hybrid-chart", repeat), query, args...)
	}
	for _, id := range []string{"", "unclassified"} {
		before := time.Now()
		points, err := NewDashboardRepository(db).GetTrafficSeries(ctx, start, end, id, false)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("24h repository chart host=%q: %s (%d buckets)", id, time.Since(before), len(points))
	}
}
