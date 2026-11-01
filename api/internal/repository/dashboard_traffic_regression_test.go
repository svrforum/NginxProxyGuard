package repository

import (
	"context"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

// Host rollups combine every alias under a proxy host. TopHosts must retain
// the requested hostname, including domains that have no registered host.
func TestDashboardTopHostsPreservesRawHostnamesWithHostRollups(t *testing.T) {
	db := openRollupTestDB(t)
	const hostID = "11111111-1111-4111-8111-111111111111"
	mustExec(t, db,
		`INSERT INTO proxy_hosts VALUES ('`+hostID+`', ARRAY['primary.example.com', 'alias.example.com'])`,
		`INSERT INTO logs_partitioned (log_type, proxy_host_id, host, request_uri, created_at)
		 SELECT 'access', '`+hostID+`', 'primary.example.com', '/', '2026-10-08 10:10:00+00'
		 FROM generate_series(1, 2)`,
		`INSERT INTO logs_partitioned (log_type, proxy_host_id, host, request_uri, created_at)
		 SELECT 'access', '`+hostID+`', 'alias.example.com', '/', '2026-10-08 10:15:00+00'
		 FROM generate_series(1, 3)`,
		`INSERT INTO logs_partitioned (log_type, host, request_uri, created_at)
		 SELECT 'access', 'unregistered.example.com', '/', '2026-10-08 10:20:00+00'
		 FROM generate_series(1, 4)`,
		// These must not change the counts or appear in the ranking.
		`INSERT INTO logs_partitioned (log_type, proxy_host_id, host, request_uri, created_at) VALUES
		 ('access', '`+hostID+`', 'alias.example.com', '/__npg_canary?probe=1', '2026-10-08 10:30:00+00'),
		 ('error', '`+hostID+`', 'alias.example.com', '/', '2026-10-08 10:30:00+00'),
		 ('access', '`+hostID+`', 'alias.example.com', '/', '2026-10-08 09:59:59+00'),
		 ('access', NULL, 'localhost', '/', '2026-10-08 10:30:00+00'),
		 ('access', NULL, '192.0.2.1', '/', '2026-10-08 10:30:00+00'),
		 ('access', NULL, '', '/', '2026-10-08 10:30:00+00'),
		 ('access', NULL, NULL, '/', '2026-10-08 10:30:00+00')`,
	)
	repo := NewDashboardRepository(db)
	since := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	want := []model.HostStat{
		{Domain: "unregistered.example.com", Requests: 4},
		{HostID: hostID, Domain: "alias.example.com", Requests: 3},
		{HostID: hostID, Domain: "primary.example.com", Requests: 2},
	}
	for _, withRollups := range []bool{false, true} {
		if withRollups {
			mustExec(t, db, `INSERT INTO dashboard_stats_hourly (proxy_host_id, hour_bucket, total_requests) VALUES
			 (NULL, '2026-10-08 10:00:00+00', 9),
			 ('`+hostID+`', '2026-10-08 10:00:00+00', 5)`)
		}
		if got := repo.getTopHosts(context.Background(), since); !reflect.DeepEqual(got, want) {
			t.Errorf("TopHosts with host rollups=%t: got %+v, want %+v", withRollups, got, want)
		}
	}

	// A retained hourly row cannot invent hostname data once raw logs expire.
	mustExec(t, db, `DELETE FROM logs_partitioned`)
	if got := repo.getTopHosts(context.Background(), since); len(got) != 0 {
		t.Errorf("TopHosts without raw logs: got %+v, want no hostname ranking", got)
	}
}

func TestDashboardGetHourlyStatsSeparatesGlobalAndHostRows(t *testing.T) {
	db := openRollupTestDB(t)
	// The shared rollup fixture only declares columns needed by recomputation;
	// add the remaining columns read by the hourly repository API locally.
	mustExec(t, db,
		`ALTER TABLE dashboard_stats_hourly
		 ADD COLUMN max_response_time double precision DEFAULT 0,
		 ADD COLUMN min_response_time double precision DEFAULT 0,
		 ADD COLUMN p95_response_time double precision DEFAULT 0,
		 ADD COLUMN p99_response_time double precision DEFAULT 0,
		 ADD COLUMN waf_detected bigint DEFAULT 0 NOT NULL,
		 ADD COLUMN top_countries jsonb DEFAULT '[]'::jsonb,
		 ADD COLUMN top_paths jsonb DEFAULT '[]'::jsonb,
		 ADD COLUMN top_ips jsonb DEFAULT '[]'::jsonb`,
		`INSERT INTO dashboard_stats_hourly (proxy_host_id, hour_bucket, total_requests, bytes_sent) VALUES
		 (NULL, '2026-10-08 09:00:00+00', 999, 9990),
		 (NULL, '2026-10-08 10:00:00+00', 100, 1000),
		 (NULL, '2026-10-08 11:00:00+00', 200, 2000),
		 (NULL, '2026-10-08 13:00:00+00', 999, 9990),
		 ('11111111-1111-4111-8111-111111111111', '2026-10-08 09:00:00+00', 999, 9990),
		 ('11111111-1111-4111-8111-111111111111', '2026-10-08 10:00:00+00', 10, 100),
		 ('11111111-1111-4111-8111-111111111111', '2026-10-08 11:00:00+00', 20, 200),
		 ('11111111-1111-4111-8111-111111111111', '2026-10-08 12:00:00+00', 30, 300),
		 ('11111111-1111-4111-8111-111111111111', '2026-10-08 13:00:00+00', 999, 9990),
		 ('22222222-2222-4222-8222-222222222222', '2026-10-08 10:00:00+00', 40, 400)`,
	)
	repo := NewDashboardRepository(db)
	for _, tc := range []struct {
		name   string
		hostID string
		hours  []int
		totals []int64
	}{
		{name: "default global", hours: []int{11, 10}, totals: []int64{200, 100}},
		{name: "explicit host", hostID: "11111111-1111-4111-8111-111111111111", hours: []int{12, 11, 10}, totals: []int64{30, 20, 10}},
		{name: "other host", hostID: "22222222-2222-4222-8222-222222222222", hours: []int{10}, totals: []int64{40}},
		{name: "unknown host", hostID: "33333333-3333-4333-8333-333333333333"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.GetHourlyStats(context.Background(), &model.DashboardQueryParams{
				ProxyHostID: tc.hostID,
				StartTime:   time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC),
				EndTime:     time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatalf("GetHourlyStats: %v", err)
			}
			if len(got) != len(tc.hours) {
				t.Fatalf("got %d rows, want %d: %+v", len(got), len(tc.hours), got)
			}
			for i, row := range got {
				wantHour := time.Date(2026, 10, 8, tc.hours[i], 0, 0, 0, time.UTC)
				if !row.HourBucket.Equal(wantHour) || row.TotalRequests != tc.totals[i] || row.BytesSent != tc.totals[i]*10 {
					t.Errorf("row %d = %+v, want hour %v, requests %d, bytes %d", i, row, wantHour, tc.totals[i], tc.totals[i]*10)
				}
				if tc.hostID == "" {
					if row.ProxyHostID != nil {
						t.Errorf("global row contains host ID %s", *row.ProxyHostID)
					}
				} else if row.ProxyHostID == nil || *row.ProxyHostID != tc.hostID {
					t.Errorf("row host ID = %v, want %s", row.ProxyHostID, tc.hostID)
				}
			}
		})
	}
}

// Execute each init.sql checkpoint definition independently, without running
// the full initial schema or touching public tables used by other tests.
func TestDashboardTrafficBackfillDDLExecutesOnPostgres(t *testing.T) {
	src, err := os.ReadFile("../database/migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.SplitN(string(src), "-- UPGRADE SECTION", 2)
	if len(sections) != 2 {
		t.Fatal("missing UPGRADE SECTION")
	}
	definition := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.traffic_hourly_backfill \(.*?;`)
	for i, name := range []string{"initial schema", "upgrade section"} {
		t.Run(name, func(t *testing.T) {
			db := openRollupTestDB(t)
			ddl := definition.FindString(sections[i])
			if ddl == "" {
				t.Fatal("missing traffic_hourly_backfill definition")
			}
			// Only change schema qualification so the actual DDL runs in the
			// fixture's isolated search_path rather than in public.
			ddl = strings.Replace(ddl, "public.traffic_hourly_backfill", "traffic_hourly_backfill", 1)
			mustExec(t, db, `DROP TABLE traffic_hourly_backfill`, ddl, ddl)
			nextHour := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
			var next, updated time.Time
			if err := db.QueryRow(`INSERT INTO traffic_hourly_backfill (id, next_hour) VALUES (1, $1)
			 RETURNING next_hour, updated_at`, nextHour).Scan(&next, &updated); err != nil {
				t.Fatalf("insert checkpoint with default updated_at: %v", err)
			}
			if !next.Equal(nextHour) || updated.IsZero() {
				t.Errorf("checkpoint next_hour=%v updated_at=%v, want %v and a default timestamp", next, updated, nextHour)
			}
			for _, tc := range []struct {
				name, sql, state string
			}{
				{"singleton check", `INSERT INTO traffic_hourly_backfill (id, next_hour) VALUES (2, now())`, "23514"},
				{"primary key", `INSERT INTO traffic_hourly_backfill (id, next_hour) VALUES (1, now())`, "23505"},
				{"required next_hour", `UPDATE traffic_hourly_backfill SET next_hour = NULL WHERE id = 1`, "23502"},
				{"required updated_at", `UPDATE traffic_hourly_backfill SET updated_at = NULL WHERE id = 1`, "23502"},
			} {
				_, err := db.Exec(tc.sql)
				var pgErr *pq.Error
				if !errors.As(err, &pgErr) || string(pgErr.Code) != tc.state {
					t.Errorf("%s: got %v, want SQLSTATE %s", tc.name, err, tc.state)
				}
			}
		})
	}
}
