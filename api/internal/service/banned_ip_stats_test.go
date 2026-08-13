package service

import (
	"context"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// The address is interpolated into SQL as ::inet and the window into
// make_interval. Both are rejected here, before the query is built — a value
// that reaches PostgreSQL malformed comes back as a 500 rather than the 400 the
// caller earned. (#242)
func TestGetBannedIPStatsRejectsBadInputBeforeQuerying(t *testing.T) {
	// A nil repository is the point: every case below must fail validation and
	// return before anything tries to use it.
	s := &SecurityService{}

	for _, tc := range []struct {
		name string
		ip   string
		days int
	}{
		{"not an address", "not-an-ip", 7},
		{"sql in the address", "1'; DROP TABLE users;--", 7},
		{"empty address", "", 7},
		{"window not offered", "192.0.2.1", 999},
		{"zero window", "192.0.2.1", 0},
		{"negative window", "192.0.2.1", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.GetBannedIPStats(context.Background(), tc.ip, tc.days)
			if err == nil {
				t.Fatalf("accepted ip=%q days=%d", tc.ip, tc.days)
			}
			// The handler maps on this word to answer 400 instead of 500.
			if !strings.Contains(err.Error(), "invalid") {
				t.Errorf("error must say what was invalid so the handler can answer 400; got %q", err)
			}
		})
	}
}

// Valid input must get past validation and reach the repository — otherwise the
// checks above could pass by rejecting everything.
func TestGetBannedIPStatsAcceptsValidInput(t *testing.T) {
	s := &SecurityService{}
	for _, ip := range []string{"192.0.2.1", "::1", "2001:db8::1"} {
		for _, days := range model.BannedIPStatsWindowDays {
			_, err := s.GetBannedIPStats(context.Background(), ip, days)
			if err == nil || !strings.Contains(err.Error(), "not initialized") {
				t.Errorf("ip=%q days=%d stopped at validation (%v); it should have reached the repository", ip, days, err)
			}
		}
	}
}
