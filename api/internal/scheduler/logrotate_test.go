package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"nginx-proxy-guard/internal/nginx"
)

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("time zone %s not available: %v", name, err)
	}
	return loc
}

func TestNextRotationTick(t *testing.T) {
	utc := time.UTC
	seoul := mustLoad(t, "Asia/Seoul")
	kolkata := mustLoad(t, "Asia/Kolkata")
	newYork := mustLoad(t, "America/New_York")
	santiago := mustLoad(t, "America/Santiago")

	cases := []struct {
		name       string
		now        time.Time
		wantLocal  string // in now's zone
		wantForced bool
	}{
		{"one second before midnight", time.Date(2026, 10, 9, 23, 59, 59, 0, utc), "2026-10-10 00:00", true},
		{"afternoon in Seoul", time.Date(2026, 10, 10, 13, 20, 0, 0, seoul), "2026-10-10 14:00", false},
		// +05:30: the next local top of the hour, not :30.
		{"half-hour zone", time.Date(2026, 10, 10, 9, 10, 0, 0, kolkata), "2026-10-10 10:00", false},
		{"half-hour zone before midnight", time.Date(2026, 10, 10, 23, 45, 0, 0, kolkata), "2026-10-11 00:00", true},
		// 2026-03-08 02:00 does not exist in New York; the run lands at 03:00.
		{"spring forward", time.Date(2026, 3, 8, 1, 30, 0, 0, newYork), "2026-03-08 03:00", false},
		{"exactly on the hour", time.Date(2026, 10, 10, 14, 0, 0, 0, utc), "2026-10-10 15:00", false},
		{"exactly midnight", time.Date(2026, 10, 10, 0, 0, 0, 0, utc), "2026-10-10 01:00", false},
		{"year end", time.Date(2026, 12, 31, 23, 0, 1, 0, utc), "2027-01-01 00:00", true},
		// Chile moves its clocks at midnight: 2026-09-06 00:00 does not exist,
		// so the day's forced run happens at its first hour, 01:00.
		{"midnight skipped by DST", time.Date(2026, 9, 5, 23, 30, 0, 0, santiago), "2026-09-06 01:00", true},
	}
	for _, tc := range cases {
		next, forced := nextRotationTick(tc.now)
		if got := next.In(tc.now.Location()).Format("2006-01-02 15:04"); got != tc.wantLocal || forced != tc.wantForced {
			t.Errorf("%s: nextRotationTick(%s) = %s forced=%v, want %s forced=%v",
				tc.name, tc.now.Format(time.RFC3339), got, forced, tc.wantLocal, tc.wantForced)
		}
		if !next.After(tc.now) {
			t.Errorf("%s: next tick %s is not after now %s", tc.name, next, tc.now)
		}
		if gap := next.Sub(tc.now); gap > time.Hour {
			t.Errorf("%s: waits %v, more than an hour", tc.name, gap)
		}
	}

	// Across both New York transitions every run is at most an hour after the
	// previous one, and never before it.
	for _, start := range []time.Time{
		time.Date(2026, 3, 7, 22, 30, 0, 0, newYork),
		time.Date(2026, 10, 31, 22, 30, 0, 0, newYork),
	} {
		now := start
		for i := 0; i < 8; i++ {
			next, _ := nextRotationTick(now)
			if gap := next.Sub(now); gap <= 0 || gap > time.Hour {
				t.Fatalf("DST: from %s to %s is %v", now.Format(time.RFC3339), next.Format(time.RFC3339), gap)
			}
			if next.Minute() != 0 || next.Second() != 0 {
				t.Fatalf("DST: %s is not on a local hour", next.Format(time.RFC3339))
			}
			now = next.Add(time.Minute)
		}
	}
}

type fakeRotator struct {
	forced  []bool
	rotated bool
	err     error
}

func (f *fakeRotator) RotateLogsScheduled(_ context.Context, force bool) (bool, error) {
	f.forced = append(f.forced, force)
	return f.rotated, f.err
}

// Every hourly run wakes the raw log archiver, whatever the outcome, and
// passes the forced flag through.
func TestLogRotateRunOnceWakesAfterEveryRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		rot  *fakeRotator
	}{
		{"rotated", &fakeRotator{rotated: true}},
		{"not due", &fakeRotator{}},
		{"empty", &fakeRotator{err: nginx.ErrLogrotateNothingToRotate}},
		{"no config", &fakeRotator{err: nginx.ErrLogrotateConfigMissing}},
		{"busy", &fakeRotator{err: nginx.ErrLogrotateBusy}},
		{"failure", &fakeRotator{err: errors.New("docker: no such container")}},
	} {
		woken := 0
		s := &LogRotateScheduler{stopCh: make(chan struct{}), nginx: tc.rot, afterRotate: func() { woken++ }}
		s.runOnce(context.Background(), true)
		s.runOnce(context.Background(), false)
		if woken != 2 {
			t.Errorf("%s: afterRotate ran %d times for 2 runs", tc.name, woken)
		}
		if len(tc.rot.forced) != 2 || !tc.rot.forced[0] || tc.rot.forced[1] {
			t.Errorf("%s: forced flags passed = %v, want [true false]", tc.name, tc.rot.forced)
		}
	}

	// No nginx manager: still wakes, never panics.
	woken := false
	s := NewLogRotateScheduler(nil, func() { woken = true })
	s.runOnce(context.Background(), false)
	if !woken {
		t.Error("afterRotate did not run without an nginx manager")
	}
	s.Stop()
	s.Stop() // idempotent
}
