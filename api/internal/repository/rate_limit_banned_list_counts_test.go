package repository

import (
	"context"
	"database/sql/driver"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
)

// The banned-IP screen's statistics cards and host filter show these counts.
// They used to be counted from the 50-row page, so the permanent card read 50
// however many permanent bans there were (#319). Every list must take them
// from one aggregate over exactly the WHERE its page uses — the page rows below
// are two temporary manual bans, so any count derived from them is wrong.
func TestBannedIPListCountsComeFromTheAggregateOverTheListPredicate(t *testing.T) {
	const active = "(is_permanent = TRUE OR expires_at > NOW())"
	hostA := "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	hostB := "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	ctx := context.Background()

	cases := []struct {
		name      string
		list      func(*RateLimitRepository) (*model.BannedIPListResponse, error)
		where     string
		countArgs []driver.Value
		listArgs  []driver.Value
		pageHost  driver.Value
		groups    [][]driver.Value // proxy_host_id, count, permanent, auto
		want      model.BannedIPListResponse
	}{
		{
			name: "global tab",
			list: func(r *RateLimitRepository) (*model.BannedIPListResponse, error) {
				return r.ListGlobalBannedIPs(ctx, 1, 50)
			},
			where:    "proxy_host_id IS NULL AND " + active,
			listArgs: []driver.Value{50, 0},
			groups:   [][]driver.Value{{nil, 120, 70, 30}},
			want:     model.BannedIPListResponse{Total: 120, TotalPages: 3, PermanentCount: 70, AutoCount: 30, HostCounts: map[string]int{}},
		},
		{
			name: "hosts tab, every host",
			list: func(r *RateLimitRepository) (*model.BannedIPListResponse, error) {
				return r.ListHostBannedIPs(ctx, 1, 50)
			},
			where:    "proxy_host_id IS NOT NULL AND " + active,
			listArgs: []driver.Value{50, 0},
			pageHost: hostA,
			groups:   [][]driver.Value{{hostA, 80, 60, 10}, {hostB, 5, 0, 5}},
			want:     model.BannedIPListResponse{Total: 85, TotalPages: 2, PermanentCount: 60, AutoCount: 15, HostCounts: map[string]int{hostA: 80, hostB: 5}},
		},
		{
			name: "hosts tab, one host, second page",
			list: func(r *RateLimitRepository) (*model.BannedIPListResponse, error) {
				return r.ListBannedIPs(ctx, &hostA, 2, 50)
			},
			where:     "proxy_host_id = $1 AND " + active,
			countArgs: []driver.Value{hostA},
			listArgs:  []driver.Value{hostA, 50, 50},
			pageHost:  hostA,
			groups:    [][]driver.Value{{hostA, 73, 73, 0}},
			want:      model.BannedIPListResponse{Total: 73, TotalPages: 2, PermanentCount: 73, AutoCount: 0, HostCounts: map[string]int{hostA: 73}},
		},
		{
			name: "no filter",
			list: func(r *RateLimitRepository) (*model.BannedIPListResponse, error) {
				return r.ListBannedIPs(ctx, nil, 1, 50)
			},
			where:    active,
			listArgs: []driver.Value{50, 0},
			// Global bans count towards the totals but have no host entry.
			groups: [][]driver.Value{{nil, 3, 1, 0}, {hostA, 60, 2, 60}},
			want:   model.BannedIPListResponse{Total: 63, TotalPages: 2, PermanentCount: 3, AutoCount: 60, HostCounts: map[string]int{hostA: 60}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()
			repo := &RateLimitRepository{db: db}

			// sqlmock collapses whitespace before matching, so single spaces
			// stand for the query's line breaks. Both patterns pin the text
			// between WHERE and the next clause to the same predicate.
			where := regexp.QuoteMeta(tc.where)
			groups := sqlmock.NewRows([]string{"proxy_host_id", "count", "permanent", "auto"})
			for _, g := range tc.groups {
				groups.AddRow(g...)
			}
			count := mock.ExpectQuery(`^SELECT proxy_host_id, COUNT\(\*\), COUNT\(\*\) FILTER \(WHERE is_permanent\), COUNT\(\*\) FILTER \(WHERE is_auto_banned\) FROM banned_ips WHERE ` + where + ` GROUP BY proxy_host_id$`)
			if tc.countArgs == nil {
				count.WithoutArgs()
			} else {
				count.WithArgs(tc.countArgs...)
			}
			count.WillReturnRows(groups)

			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			page := sqlmock.NewRows([]string{"id", "proxy_host_id", "ip_address", "reason", "fail_count", "banned_at", "expires_at", "is_permanent", "is_auto_banned", "created_at"}).
				AddRow("ban-1", tc.pageHost, "192.0.2.10", "manual", 1, now, now.Add(time.Hour), false, false, now).
				AddRow("ban-2", tc.pageHost, "198.51.100.20", "manual", 1, now, now.Add(time.Hour), false, false, now)
			mock.ExpectQuery(`^SELECT id, proxy_host_id, ip_address, .* FROM banned_ips WHERE ` + where + ` ORDER BY banned_at DESC LIMIT \$\d OFFSET \$\d$`).
				WithArgs(tc.listArgs...).
				WillReturnRows(page)

			got, err := tc.list(repo)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("sql expectations: %v", err)
			}
			if len(got.Data) != 2 {
				t.Fatalf("page rows = %d, want 2", len(got.Data))
			}
			if got.Total != tc.want.Total || got.TotalPages != tc.want.TotalPages {
				t.Errorf("total = %d (%d pages), want %d (%d pages)", got.Total, got.TotalPages, tc.want.Total, tc.want.TotalPages)
			}
			if got.PermanentCount != tc.want.PermanentCount || got.AutoCount != tc.want.AutoCount {
				t.Errorf("permanent/auto = %d/%d, want %d/%d", got.PermanentCount, got.AutoCount, tc.want.PermanentCount, tc.want.AutoCount)
			}
			// Never nil: the field is sent as {} rather than null.
			if !reflect.DeepEqual(got.HostCounts, tc.want.HostCounts) {
				t.Errorf("host counts = %#v, want %#v", got.HostCounts, tc.want.HostCounts)
			}
		})
	}
}
