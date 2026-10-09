package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Which hours each rebuild covers: the last 25 hours until the first rebuild
// after boot succeeds, then the current hour, plus the previous one for the
// first ten minutes of an hour (rows of a batch that began before the hour
// turned commit after it).
func TestRollupWindow(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 9, h, m, 30, 0, time.UTC) }
	hour := func(h int) time.Time { return time.Date(2026, 10, 9, h, 0, 0, 0, time.UTC) }
	for _, tc := range []struct {
		name     string
		now      time.Time
		swept    bool
		from, to time.Time
	}{
		{"boot sweep", at(13, 25), false, hour(13).Add(-25 * time.Hour), hour(14)},
		{"boot sweep early in an hour", at(13, 2), false, hour(13).Add(-25 * time.Hour), hour(14)},
		{"current hour", at(13, 25), true, hour(13), hour(14)},
		{"previous hour too, early in an hour", at(13, 9), true, hour(12), hour(14)},
		{"previous hour no longer after ten minutes", at(13, 10), true, hour(13), hour(14)},
	} {
		from, to := rollupWindow(tc.now, tc.swept)
		if !from.Equal(tc.from) || !to.Equal(tc.to) {
			t.Errorf("%s: window [%s, %s), want [%s, %s)", tc.name, from, to, tc.from, tc.to)
		}
	}
}

type fakeRollup struct {
	calls []time.Duration // span of each window asked for
	err   error
}

func (f *fakeRollup) RecomputeHourlyRollup(ctx context.Context, from, to time.Time) (int64, error) {
	f.calls = append(f.calls, to.Sub(from))
	if _, ok := ctx.Deadline(); !ok {
		return 0, errors.New("no deadline")
	}
	return int64(to.Sub(from) / time.Hour), f.err
}

// The collector rebuilds at most once a minute, sweeps the last 25 hours
// first, and keeps sweeping until a sweep succeeds.
func TestRecomputeRollupSweepsOnceThenEveryMinute(t *testing.T) {
	f := &fakeRollup{err: errors.New("database is starting up")}
	sc := NewStatsCollector(nil, "", "")
	sc.SetRollupRepo(f)

	sc.recomputeRollup() // the boot sweep fails
	sc.recomputeRollup() // too soon to try again
	if len(f.calls) != 1 || f.calls[0] != 26*time.Hour {
		t.Fatalf("calls = %v, want one 26-hour sweep (25 hours back, through the current hour)", f.calls)
	}

	f.err = nil
	sc.rollupLastAttempt = time.Now().Add(-rollupInterval)
	sc.recomputeRollup() // the sweep is tried again, and succeeds
	if len(f.calls) != 2 || f.calls[1] != 26*time.Hour {
		t.Fatalf("calls = %v, want the failed sweep retried", f.calls)
	}

	sc.rollupLastAttempt = time.Now().Add(-rollupInterval)
	sc.recomputeRollup() // from now on the current hour, or two early in an hour
	if len(f.calls) != 3 || f.calls[2] > 2*time.Hour {
		t.Fatalf("calls = %v, want a one- or two-hour rebuild after the sweep", f.calls)
	}
}

// Without the repository wired, the collector records system health only.
func TestRecomputeRollupWithoutRepository(t *testing.T) {
	sc := NewStatsCollector(nil, "", "")
	sc.recomputeRollup()
}
