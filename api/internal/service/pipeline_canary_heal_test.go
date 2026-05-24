package service

import (
	"testing"
	"time"
)

func TestCanHeal(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	fresh := now.Add(-time.Minute) // window still open
	old := now.Add(-31 * time.Minute)

	cases := []struct {
		name        string
		stage       string
		attempts    int
		windowStart time.Time
		want        bool
	}{
		{"nginx_write within budget", "nginx_write", 0, fresh, true},
		{"nginx_write at budget edge", "nginx_write", 2, fresh, true},
		{"nginx_write exhausted", "nginx_write", 3, fresh, false},
		{"exhausted but window elapsed", "nginx_write", 3, old, true},
		{"path_mismatch healable", "path_mismatch", 0, fresh, true},
		{"tail_stalled healable", "tail_stalled", 1, fresh, true},
		{"db_insert not healable", "db_insert", 0, fresh, false},
		{"nginx_unreachable not healable", "nginx_unreachable", 0, fresh, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canHeal(tc.stage, tc.attempts, tc.windowStart, now); got != tc.want {
				t.Errorf("canHeal(%q, %d, ...) = %v, want %v", tc.stage, tc.attempts, got, tc.want)
			}
		})
	}
}
