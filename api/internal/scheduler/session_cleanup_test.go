package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"nginx-proxy-guard/internal/config"
)

type fakeTokenCleaner struct {
	calls    int
	removed  int
	err      error
	deadline time.Duration // time left on the context when called
	block    bool          // wait for the context to end, like a long sweep
}

func (f *fakeTokenCleaner) CleanupExpiredTokens(ctx context.Context) (int, error) {
	f.calls++
	if dl, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(dl)
	}
	if f.block {
		<-ctx.Done()
		return f.removed, ctx.Err()
	}
	return f.removed, f.err
}

// Expired challenge tokens are deleted with the sessions, once per sweep, on a
// deadline long enough for a first run over a large backlog; a failure is
// logged and does not end the sweep.
func TestSessionCleanupPrunesChallengeTokens(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"removes expired tokens", nil},
		{"tolerates a failure", errors.New("connection reset")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeTokenCleaner{removed: 42, err: tc.err}
			s := NewSessionCleanupScheduler(nil, nil)
			s.SetChallengeService(f)

			s.cleanup()

			if f.calls != 1 {
				t.Fatalf("challenge token cleanup ran %d times in one sweep, want 1", f.calls)
			}
			if f.deadline <= config.ContextTimeout {
				t.Errorf("challenge token cleanup got %v, want its own deadline longer than the %v sessions get", f.deadline, config.ContextTimeout)
			}
		})
	}
}

// Without a challenge service the sweep still runs and skips that step.
func TestSessionCleanupWithoutChallengeService(t *testing.T) {
	s := NewSessionCleanupScheduler(nil, nil)
	s.cleanup()
}

// Stopping the scheduler ends a sweep that is still deleting.
func TestSessionCleanupStopEndsAChallengeTokenSweep(t *testing.T) {
	f := &fakeTokenCleaner{block: true}
	s := NewSessionCleanupScheduler(nil, nil)
	s.SetChallengeService(f)
	s.running = true // as after Start, without its two-minute first delay

	done := make(chan struct{})
	go func() {
		s.cleanupChallengeTokens()
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	s.Stop()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the challenge token sweep kept running after Stop")
	}
}
