package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// The time sort reads each page from a created_at window (requestTimeOrder).
// Walked page by page, it must return every row once, in request order, even
// with rows stored seconds after their requests, one stored minutes late and
// one whose request time is ahead of its insert time (#373). Runs against the
// Postgres NPG_TEST_DATABASE_URL names, in a temporary table of its own.
func TestListTimeSortReadsEveryRowInRequestOrder(t *testing.T) {
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed time sort test")
	}
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sqlDB.Close()
	sqlDB.SetMaxOpenConns(1) // the temporary table lives in one session
	ctx := context.Background()
	if _, err := sqlDB.ExecContext(ctx, `CREATE TEMP TABLE logs_partitioned (
		id uuid PRIMARY KEY, log_type text, timestamp timestamptz NOT NULL, host text, client_ip inet,
		geo_country text, geo_country_code text, geo_org text,
		request_method text, request_uri text, status_code int,
		body_bytes_sent bigint, request_time double precision,
		upstream_addr text, upstream_status text, http_user_agent text,
		severity text, error_message text, rule_id bigint, rule_message text, action_taken text,
		block_reason text, bot_category text, exploit_rule text,
		created_at timestamptz NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	type row struct {
		id     string
		ts, ca time.Time
	}
	base := time.Date(2026, 11, 9, 13, 13, 0, 0, time.UTC)
	var rows []row
	add := func(ts time.Time, lag time.Duration) {
		rows = append(rows, row{fmt.Sprintf("00000000-0000-4000-8000-%012d", len(rows)), ts, ts.Add(lag)})
	}
	for i := 0; i < 60; i++ {
		ts := base.Add(time.Duration(i/3) * time.Second) // three requests a second
		add(ts, time.Duration((i*7)%6)*time.Second+time.Duration(i%5)*200*time.Millisecond)
	}
	add(base.Add(5*time.Second), 26*time.Second) // a WAF event, stored late
	add(base.Add(8*time.Second), 3*time.Minute)  // a backlog
	add(base.Add(30*time.Second), -1*time.Hour)  // a request clock an hour ahead
	add(base.Add(12*time.Second), 0)             // same second as others
	add(base.Add(12*time.Second), 2*time.Second) //
	for _, r := range rows {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO logs_partitioned (id, log_type, timestamp, request_uri, created_at)
			VALUES ($1, 'access', $2, '/', $3)`, r.id, r.ts, r.ca); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	repo := &LogRepository{db: &database.DB{DB: sqlDB}}
	// Stored while the pages are read: a new request, and an old one stored late.
	laterIDs := []string{"10000000-0000-4000-8000-00000000000a", "10000000-0000-4000-8000-00000000000b"}
	for _, order := range []string{"desc", "asc"} {
		t.Run(order, func(t *testing.T) {
			key := func(r row) time.Time { // as requestTimeOrder defines it
				if order == "asc" {
					if floor := r.ca.Add(-time.Minute); r.ts.Before(floor) {
						return floor
					}
					return r.ts
				}
				if r.ca.Before(r.ts) {
					return r.ca
				}
				return r.ts
			}
			want := append([]row(nil), rows...)
			sort.Slice(want, func(i, j int) bool {
				a, b := want[i], want[j]
				if !key(a).Equal(key(b)) {
					return key(a).After(key(b)) == (order == "desc")
				}
				if !a.ca.Equal(b.ca) {
					return a.ca.After(b.ca) == (order == "desc")
				}
				return (a.id > b.id) == (order == "desc")
			})

			for _, perPage := range []int{1, 7, 50, 100} {
				var got []string
				var asOf *time.Time
				for page := 1; ; page++ {
					sortBy, sortOrder := "timestamp", order
					res, err := repo.List(ctx, &model.LogFilter{SortBy: &sortBy, SortOrder: &sortOrder, AsOf: asOf}, page, perPage)
					if err != nil {
						t.Fatalf("List page %d: %v", page, err)
					}
					if res.NextCursor != "" {
						t.Fatalf("page %d minted a created_at cursor for the time sort", page)
					}
					if res.AsOf == nil || (asOf != nil && !res.AsOf.Equal(*asOf)) {
						t.Fatalf("page %d as_of = %v, want page 1's %v", page, res.AsOf, asOf)
					}
					if page == 1 {
						// Logs stored after page 1 must not shift the pages after it.
						asOf = res.AsOf
						if _, err := sqlDB.ExecContext(ctx, `INSERT INTO logs_partitioned (id, log_type, timestamp, request_uri, created_at) VALUES
							($1, 'access', clock_timestamp(), '/', clock_timestamp()),
							($2, 'access', $3, '/', clock_timestamp())`, laterIDs[0], laterIDs[1], base.Add(10*time.Second)); err != nil {
							t.Fatalf("insert later rows: %v", err)
						}
					}
					for _, l := range res.Logs {
						got = append(got, l.ID)
					}
					if res.Total <= page*perPage {
						break
					}
				}
				if _, err := sqlDB.ExecContext(ctx, `DELETE FROM logs_partitioned WHERE id = ANY($1)`, pq.Array(laterIDs)); err != nil {
					t.Fatalf("delete later rows: %v", err)
				}
				if len(got) != len(want) {
					t.Fatalf("perPage %d: read %d rows, want %d", perPage, len(got), len(want))
				}
				for i := range want {
					if got[i] != want[i].id {
						t.Fatalf("perPage %d: row %d is %s, want %s", perPage, i, got[i], want[i].id)
					}
				}
			}

			// What #373 saw: the rows stored within seconds come back in
			// request order.
			var last time.Time
			for _, r := range want {
				if r.ca.Sub(r.ts) > 30*time.Second || r.ca.Before(r.ts) {
					continue
				}
				if !last.IsZero() && (order == "desc" && r.ts.After(last) || order == "asc" && r.ts.Before(last)) {
					t.Fatalf("request time %s after %s out of %s order", r.ts, last, order)
				}
				last = r.ts
			}
		})
	}
}
