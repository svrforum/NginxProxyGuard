package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/service"
)

// NotificationDigestScheduler queues the daily summary for channels whose hour
// has come. (#221)
//
// It ticks hourly rather than sleeping until the next due hour, because the
// operator can change digest_hour at any time and a sleeping goroutine would
// not notice. Idempotency comes from last_digest_on, not from the tick.
type NotificationDigestScheduler struct {
	digest   *service.NotificationDigestService
	interval time.Duration
	stopChan chan struct{}
	stopOnce sync.Once
	running  bool
	mu       sync.Mutex
}

func NewNotificationDigestScheduler(d *service.NotificationDigestService) *NotificationDigestScheduler {
	return &NotificationDigestScheduler{
		digest:   d,
		interval: time.Hour,
		stopChan: make(chan struct{}),
	}
}

func (s *NotificationDigestScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] Notification digest scheduler started (interval: %v)", s.interval)
}

func (s *NotificationDigestScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.stopOnce.Do(func() { close(s.stopChan) })
	s.running = false
	log.Println("[Scheduler] Notification digest scheduler stopped")
}

func (s *NotificationDigestScheduler) run() {
	// A minute after boot, so a restart at the digest hour still delivers.
	select {
	case <-time.After(time.Minute):
	case <-s.stopChan:
		return
	}
	s.tick()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.tick()
		case <-s.stopChan:
			return
		}
	}
}

func (s *NotificationDigestScheduler) tick() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in notification digest: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()
	if n, err := s.digest.SendDue(ctx, time.Now()); err != nil {
		log.Printf("[Scheduler] Notification digest failed: %v", err)
	} else if n > 0 {
		log.Printf("[Scheduler] Queued the daily digest for %d channel(s)", n)
	}
}
