package service

import (
	"testing"
	"time"
)

func TestRestartTail_NonBlockingAndCoalesces(t *testing.T) {
	c := &LogCollector{restartTail: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		c.RestartTail()
		c.RestartTail() // second call must not block when one is already pending
		c.RestartTail()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RestartTail blocked")
	}
	if len(c.restartTail) != 1 {
		t.Errorf("expected exactly 1 coalesced signal buffered, got %d", len(c.restartTail))
	}
}
