package service

import (
	"context"
	"sync/atomic"
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

func TestAttemptHeal_BudgetLimit(t *testing.T) {
	p := &PipelineCanary{}
	var calls int32
	p.SetHealer(func(ctx context.Context, stage string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	for i := 0; i < 5; i++ {
		p.attemptHeal(context.Background(), "nginx_write")
	}
	if got := atomic.LoadInt32(&calls); got != int32(healMaxAttempts) {
		t.Errorf("budget: expected %d heal calls, got %d", healMaxAttempts, got)
	}
}

func TestAttemptHeal_InFlightGuard(t *testing.T) {
	p := &PipelineCanary{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	p.SetHealer(func(ctx context.Context, stage string) error {
		atomic.AddInt32(&calls, 1)
		close(entered) // first heal is now in progress (holds healMu)
		<-release
		return nil
	})
	go p.attemptHeal(context.Background(), "nginx_write")
	<-entered
	// second concurrent attempt must be rejected by healMu.TryLock (no 2nd call)
	p.attemptHeal(context.Background(), "nginx_write")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("in-flight guard: expected 1 heal call, got %d", got)
	}
	close(release)
	time.Sleep(20 * time.Millisecond) // let the first goroutine finish cleanly
}

func TestAttemptHeal_NotHealableStageDoesNotConsumeBudget(t *testing.T) {
	p := &PipelineCanary{}
	var calls int32
	p.SetHealer(func(ctx context.Context, stage string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	p.attemptHeal(context.Background(), "db_insert")
	p.attemptHeal(context.Background(), "nginx_unreachable")
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("non-healable stages must not call healer, got %d", got)
	}
}
