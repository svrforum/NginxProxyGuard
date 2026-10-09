package scheduler

import (
	"context"
	"testing"
	"time"
)

// NPG_DISK_GUARD_INTERVAL is clamped to its 15-second minimum, and an unset
// interval is the 1-minute default.
func TestDiskGuardSchedulerInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for in, want := range map[time.Duration]time.Duration{
		0: time.Minute, 5 * time.Second: 15 * time.Second, 15 * time.Second: 15 * time.Second, 2 * time.Minute: 2 * time.Minute,
	} {
		if got := NewDiskGuardScheduler(ctx, cancel, nil, in).interval; got != want {
			t.Errorf("interval %v -> %v, want %v", in, got, want)
		}
	}
}
