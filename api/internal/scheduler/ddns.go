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
type DDNSScheduler struct {
	svc      ddnsSyncer
	interval time.Duration
	stopChan chan struct{}
	running  bool
}

// NewDDNSScheduler constructs (but does not start) the scheduler. A non-positive
// interval defaults to 5 minutes.
func NewDDNSScheduler(svc ddnsSyncer, interval time.Duration) *DDNSScheduler {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &DDNSScheduler{svc: svc, interval: interval, stopChan: make(chan struct{})}
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
	log.Printf("[DDNS] scheduler started (interval: %v)", s.interval)
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
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopChan:
			return
		case <-t.C:
			s.svc.SyncAll(context.Background())
		}
	}
}
