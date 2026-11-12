package repository

import (
	"context"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// The log list's time sort (sort_by=timestamp) orders by request time inside a
// created_at window (requestTimeOrder), and pages by OFFSET: a created_at
// cursor does not fit it (#373). The default sort keeps created_at and its
// cursor, the caller's filter is not rewritten, and other sorts are unchanged.
func TestListTimeSortShape(t *testing.T) {
	cursor, err := encodeLogCursor(logCursor{CreatedAt: time.Now().Add(-time.Hour), ID: "11111111-2222-4333-8444-555555555555"})
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	for _, tc := range []struct {
		sortBy, sortOrder string
		cursor            string
		orderBy           string
		keyset            bool   // the page is read with (created_at, id) < cursor
		nextCursor        bool   // a cursor for the next page is minted
		window            string // the created_at window the page is read from
		asOf              bool   // the request sends back page 1's as_of
	}{
		{"timestamp", "desc", cursor, "ORDER BY LEAST(timestamp, created_at) DESC, created_at DESC, id DESC", false, false,
			"created_at >= (SELECT min(LEAST(timestamp, created_at)) FROM (SELECT timestamp, created_at FROM logs_partitioned WHERE ", false},
		{"timestamp", "desc", "", "ORDER BY LEAST(timestamp, created_at) DESC, created_at DESC, id DESC", false, false,
			"created_at >= (SELECT min(LEAST(timestamp, created_at)) FROM (SELECT timestamp, created_at FROM logs_partitioned WHERE ", false},
		{"timestamp", "desc", "", "ORDER BY LEAST(timestamp, created_at) DESC, created_at DESC, id DESC", false, false,
			"created_at >= (SELECT min(LEAST(timestamp, created_at)) FROM (SELECT timestamp, created_at FROM logs_partitioned WHERE ", true},
		{"timestamp", "asc", cursor, "ORDER BY GREATEST(timestamp, created_at - interval '1 minute') ASC, created_at ASC, id ASC", false, false,
			"created_at <= (SELECT max(GREATEST(timestamp, created_at - interval '1 minute')) FROM (SELECT timestamp, created_at FROM logs_partitioned WHERE ", false},
		{"created_at", "desc", cursor, "ORDER BY created_at DESC, id DESC", true, true, "", false},
		{"status_code", "desc", cursor, "ORDER BY status_code DESC", false, false, "", false},
	} {
		name := fmt.Sprintf("%s %s cursor=%v as_of=%v", tc.sortBy, tc.sortOrder, tc.cursor != "", tc.asOf)
		t.Run(name, func(t *testing.T) {
			sqlDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer sqlDB.Close()
			repo := &LogRepository{db: &database.DB{DB: sqlDB}}

			sortBy, sortOrder := tc.sortBy, tc.sortOrder
			filter := &model.LogFilter{SortBy: &sortBy, SortOrder: &sortOrder}
			if tc.cursor != "" {
				c := tc.cursor
				filter.Cursor = &c
			}
			pinned := time.Date(2026, 10, 9, 12, 0, 5, 0, time.UTC)
			if tc.asOf {
				filter.AsOf = &pinned
			}

			cols := []string{"id", "log_type", "timestamp", "host", "client_ip", "geo_country", "geo_country_code", "geo_org",
				"request_method", "request_uri", "status_code", "body_bytes_sent", "request_time", "upstream_addr", "upstream_status",
				"http_user_agent", "severity", "error_message", "rule_id", "rule_message", "action_taken",
				"block_reason", "bot_category", "exploit_rule", "created_at"}
			rows := sqlmock.NewRows(cols)
			now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
			for i := 0; i < 3; i++ { // perPage 2 + 1: there is a next page
				at := now.Add(-time.Duration(i) * time.Second)
				vals := make([]driver.Value, len(cols))
				vals[0] = fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i)
				vals[1] = "access"
				vals[2] = at
				vals[24] = at
				rows.AddRow(vals...)
			}

			keyset := `\(created_at, id\) < \(\$\d+, \$\d+::uuid\) `
			order := strings.ReplaceAll(regexp.QuoteMeta(tc.orderBy), " ", `\s+`)
			pattern := `FROM logs_partitioned WHERE .*` + order + `\s+LIMIT`
			if tc.keyset {
				pattern = `FROM logs_partitioned WHERE .*` + keyset + order + `\s+LIMIT`
			}
			if tc.window != "" {
				// Pinned to as_of, inside the window as well as outside it.
				pinnedTo := `created_at <= \$\d+ AND `
				pattern = `FROM logs_partitioned WHERE .* ` + pinnedTo + regexp.QuoteMeta(tc.window) + `.* created_at <= \$\d+ ORDER BY created_at .*\) w\)[^(]*` + order + `\s+LIMIT`
				if !tc.asOf {
					mock.ExpectQuery(`^SELECT now\(\)$`).WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(pinned))
				}
			}
			mock.ExpectQuery(pattern).WillReturnRows(rows)

			res, err := repo.List(context.Background(), filter, 1, 2)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("query did not order by %q (keyset %v): %v", tc.orderBy, tc.keyset, err)
			}
			if got := res.NextCursor != ""; got != tc.nextCursor {
				t.Errorf("next cursor minted = %v, want %v", got, tc.nextCursor)
			}
			if got := res.AsOf != nil && res.AsOf.Equal(pinned); got != (tc.window != "") {
				t.Errorf("as_of returned = %v (%v), want %v", got, res.AsOf, tc.window != "")
			}
			if *filter.SortBy != tc.sortBy {
				t.Errorf("List rewrote the caller's sort_by to %q", *filter.SortBy)
			}
		})
	}
}
