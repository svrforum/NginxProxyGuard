package service

import (
	"context"
	"testing"
	"time"
)

// A replayed audit line counts at the time it happened, not when a reconnect
// delivered it. The threshold is high so nothing reaches the database.
func TestRecordWAFEvent_UsesEventTime(t *testing.T) {
	s := &WAFAutoBanService{ipEvents: map[string][]time.Time{}, enabled: true, threshold: 1000, windowSeconds: 300}
	ctx := context.Background()
	const ip = "192.0.2.10"
	now := time.Now()

	s.RecordWAFEvent(ctx, ip, "waf.example.com", 942100, "m", now.Add(-10*time.Minute))
	if n := len(s.ipEvents[ip]); n != 0 {
		t.Fatalf("an event older than the window was counted (%d)", n)
	}

	at := now.Add(-time.Minute)
	s.RecordWAFEvent(ctx, ip, "waf.example.com", 942100, "m", at)
	if ev := s.ipEvents[ip]; len(ev) != 1 || !ev[0].Equal(at) {
		t.Fatalf("an in-window replayed event was not recorded at its own time: %v", ev)
	}

	s.RecordWAFEvent(ctx, ip, "waf.example.com", 942100, "m", time.Time{})
	s.RecordWAFEvent(ctx, ip, "waf.example.com", 942100, "m", now.Add(time.Hour)) // clock skew
	ev := s.ipEvents[ip]
	if len(ev) != 3 {
		t.Fatalf("zero and future times must count (as now): %v", ev)
	}
	for _, e := range ev[1:] {
		if e.Before(now) || e.After(time.Now()) {
			t.Fatalf("zero/future time not counted as now: %v", e)
		}
	}
}

// The window still slides over events recorded out of order (a replay
// followed by live events).
func TestRecordWAFEvent_OutOfOrderEventsLeaveTheWindow(t *testing.T) {
	s := &WAFAutoBanService{ipEvents: map[string][]time.Time{}, enabled: true, threshold: 1000, windowSeconds: 60}
	ctx := context.Background()
	const ip = "192.0.2.11"
	now := time.Now()
	s.RecordWAFEvent(ctx, ip, "h", 1, "m", now)
	s.RecordWAFEvent(ctx, ip, "h", 1, "m", now.Add(-59*time.Second))
	if n := len(s.ipEvents[ip]); n != 2 {
		t.Fatalf("got %d events, want 2", n)
	}
	s.windowSeconds = 30 // the next call filters with the shorter window
	s.RecordWAFEvent(ctx, ip, "h", 1, "m", now)
	if n := len(s.ipEvents[ip]); n != 2 {
		t.Fatalf("got %d events after the window moved past the replayed one, want 2", n)
	}
}
