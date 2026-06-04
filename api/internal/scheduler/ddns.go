package scheduler

import (
	"context"
	"log"
	"os"
	"time"
)

// ddnsSyncer is the narrow service dep (DDNSService satisfies it).
type ddnsSyncer interface {
	SyncAll(ctx context.Context)
}

// DDNSScheduler periodically syncs enabled DDNS records to the public IP. (#154)
//
// The interval is resolved dynamically each cycle via intervalFn so changes to
// the configured DDNS check interval (system_settings) take effect on the next
// cycle without a restart. (#157)
type DDNSScheduler struct {
	svc        ddnsSyncer
	intervalFn func() time.Duration
	stopChan   chan struct{}
	running    bool
}

// NewDDNSScheduler constructs (but does not start) the scheduler. intervalFn is
// consulted at the start of every cycle; a non-positive result is clamped to 1
// minute so a misconfiguration can never busy-loop the syncer. A nil intervalFn
// defaults to a fixed 5 minutes. (#157)
func NewDDNSScheduler(svc ddnsSyncer, intervalFn func() time.Duration) *DDNSScheduler {
	if intervalFn == nil {
		intervalFn = func() time.Duration { return 5 * time.Minute }
	}
	return &DDNSScheduler{svc: svc, intervalFn: intervalFn, stopChan: make(chan struct{})}
}

// currentInterval resolves and clamps the configured interval for one cycle.
func (s *DDNSScheduler) currentInterval() time.Duration {
	d := s.intervalFn()
	if d < time.Minute {
		d = time.Minute
	}
	return d
}

// Start launches the sync loop. It is a no-op when already running. When the
// environment variable NPG_DDNS_DISABLED is "1" or "true" the scheduler is
// fully disabled (kill switch for operators who manage DDNS externally).
func (s *DDNSScheduler) Start() {
	if s.running {
		return
	}
	if v := os.Getenv("NPG_DDNS_DISABLED"); v == "1" || v == "true" {
		log.Printf("[DDNS] scheduler DISABLED via NPG_DDNS_DISABLED")
		return
	}
	s.running = true
	go s.run()
	log.Printf("[DDNS] scheduler started (interval: %v)", s.currentInterval())
}

// Stop signals the sync loop to exit.
func (s *DDNSScheduler) Stop() {
	if s.running {
		close(s.stopChan)
		s.running = false
	}
}

func (s *DDNSScheduler) run() {
	s.svc.SyncAll(context.Background()) // run once at startup
	for {
		// Re-read the interval each cycle so config changes apply next tick. (#157)
		t := time.NewTimer(s.currentInterval())
		select {
		case <-s.stopChan:
			t.Stop()
			return
		case <-t.C:
			s.svc.SyncAll(context.Background())
		}
	}
}
