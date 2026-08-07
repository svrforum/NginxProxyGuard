package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/service"
)

// NotificationDispatchScheduler drains the notification outbox, closes the
// batching window and prunes old rows. (#221)
//
// One worker, deliberately. Delivery has a retry budget and a per-channel health
// counter, and both are only enforceable if a single place is doing the sending.
type NotificationDispatchScheduler struct {
	dispatcher *service.NotificationDispatcher
	interval   time.Duration
	stopChan   chan struct{}
	stopOnce   sync.Once
	running    bool
	mu         sync.Mutex
}

func NewNotificationDispatchScheduler(d *service.NotificationDispatcher) *NotificationDispatchScheduler {
	return &NotificationDispatchScheduler{
		dispatcher: d,
		interval:   config.NotificationDispatchInterval,
		stopChan:   make(chan struct{}),
	}
}

func (s *NotificationDispatchScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] Notification dispatcher started (interval: %v)", s.interval)
}

func (s *NotificationDispatchScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.stopOnce.Do(func() { close(s.stopChan) })
	s.running = false
	log.Println("[Scheduler] Notification dispatcher stopped")
}

func (s *NotificationDispatchScheduler) run() {
	// A short delay before the first pass: boot already does migrations and a
	// config sync, and nothing here is urgent.
	select {
	case <-time.After(30 * time.Second):
	case <-s.stopChan:
		return
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	batchTicker := time.NewTicker(config.NotificationBatchWindow)
	defer batchTicker.Stop()
	pruneTicker := time.NewTicker(time.Hour)
	defer pruneTicker.Stop()

	s.dispatch()
	for {
		select {
		case <-ticker.C:
			s.dispatch()
		case <-batchTicker.C:
			s.flush()
		case <-pruneTicker.C:
			s.prune()
		case <-s.stopChan:
			// A burst arriving in the last minutes of the process is held in
			// memory waiting for the batch window; without this it dies with
			// the container on every restart and upgrade. Flushing writes it to
			// the outbox, so the next boot delivers it.
			s.flush()
			// And dispatch what that flush just queued, so a clean shutdown
			// does not itself delay the alert by a whole boot cycle.
			s.dispatch()
			return
		}
	}
}

func (s *NotificationDispatchScheduler) dispatch() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in notification dispatch: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()
	if n, err := s.dispatcher.DispatchOnce(ctx); err != nil {
		log.Printf("[Scheduler] Notification dispatch failed: %v", err)
	} else if n > 0 {
		log.Printf("[Scheduler] Delivered %d notification(s)", n)
	}
}

func (s *NotificationDispatchScheduler) flush() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in notification flush: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()
	s.dispatcher.FlushBatches(ctx)
}

func (s *NotificationDispatchScheduler) prune() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in notification prune: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()
	s.dispatcher.Prune(ctx)
}
