package repository

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// The log list's time sort (sort_by=timestamp) is served by the created_at
// ordering: idx_logs_part_timestamp is retired, and ordering by timestamp
// sorted the whole window. It keeps cursor paging like the default sort, and
// the caller's filter is not rewritten. Other sorts are unchanged.
func TestListServesTheTimeSortFromCreatedAt(t *testing.T) {
	cursor, err := encodeLogCursor(logCursor{CreatedAt: time.Now().Add(-time.Hour), ID: "11111111-2222-4333-8444-555555555555"})
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	for _, tc := range []struct {
		sortBy, sortOrder string
		cursor            string
		orderBy           string
		keyset            bool // the page is read with (created_at, id) < cursor
		nextCursor        bool // a cursor for the next page is minted
	}{
		{"timestamp", "desc", cursor, "ORDER BY created_at DESC, id DESC", true, true},
		{"timestamp", "desc", "", "ORDER BY created_at DESC, id DESC", false, true},
		{"timestamp", "asc", cursor, "ORDER BY created_at ASC, id ASC", false, false},
		{"created_at", "desc", cursor, "ORDER BY created_at DESC, id DESC", true, true},
		{"status_code", "desc", cursor, "ORDER BY status_code DESC", false, false},
	} {
		name := fmt.Sprintf("%s %s cursor=%v", tc.sortBy, tc.sortOrder, tc.cursor != "")
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
			pattern := `FROM logs_partitioned WHERE .*` + strings.ReplaceAll(tc.orderBy, " ", `\s+`) + `\s+LIMIT`
			if tc.keyset {
				pattern = `FROM logs_partitioned WHERE .*` + keyset + strings.ReplaceAll(tc.orderBy, " ", `\s+`) + `\s+LIMIT`
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
			if *filter.SortBy != tc.sortBy {
				t.Errorf("List rewrote the caller's sort_by to %q", *filter.SortBy)
			}
		})
	}
}
