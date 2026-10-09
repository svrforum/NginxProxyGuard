package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/service"
)

const (
	// diskGuardStartDelay: boot runs migrations and a full config sync first,
	// and a disk does not fill in 45 seconds.
	diskGuardStartDelay = 45 * time.Second
	// diskGuardTickTimeout bounds one tick. Every statfs in it has its own 3 s
	// timeout and every docker call 5 s, so a tick normally takes well under a
	// second.
	diskGuardTickTimeout = 50 * time.Second
	diskGuardMinInterval = 15 * time.Second
)

// DiskGuardScheduler ticks DiskGuard (D1-D4) every minute. One worker: the
// alert state machine assumes a single caller.
type DiskGuardScheduler struct {
	guard    *service.DiskGuard
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
	running  bool
	mu       sync.Mutex
}

// NewDiskGuardScheduler takes the context everything DiskGuard starts is tied
// to, so Stop also ends work it left running.
func NewDiskGuardScheduler(ctx context.Context, cancel context.CancelFunc, g *service.DiskGuard, interval time.Duration) *DiskGuardScheduler {
	if interval < diskGuardMinInterval {
		interval = time.Minute
	}
	return &DiskGuardScheduler{guard: g, interval: interval, ctx: ctx, cancel: cancel}
}

func (s *DiskGuardScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.guard == nil {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] Disk guard started (interval: %v)", s.interval)
}

func (s *DiskGuardScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.stopOnce.Do(s.cancel)
	s.running = false
	log.Println("[Scheduler] Disk guard stopped")
}

func (s *DiskGuardScheduler) run() {
	select {
	case <-time.After(diskGuardStartDelay):
	case <-s.ctx.Done():
		return
	}
	s.tick()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.tick()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *DiskGuardScheduler) tick() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in disk guard: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, diskGuardTickTimeout)
	defer cancel()
	s.guard.Tick(ctx)
}
