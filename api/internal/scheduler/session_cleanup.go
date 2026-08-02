package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/service"
)

// SessionCleanupScheduler prunes expired sessions and old login attempts.
//
// AuthService.CleanupSessions existed with no caller, so auth_sessions and
// login_attempts grew without bound. That matters more with several accounts:
// login_attempts is now keyed per (account, IP) for the lockout, so it
// accumulates faster, and it is the table an operator looks at after a
// brute-force attempt. (#222)
type SessionCleanupScheduler struct {
	service  *service.AuthService
	sso      *service.SSOService
	interval time.Duration
	stopChan chan struct{}
	stopOnce sync.Once
	running  bool
	mu       sync.Mutex
}

func NewSessionCleanupScheduler(svc *service.AuthService, sso *service.SSOService) *SessionCleanupScheduler {
	return &SessionCleanupScheduler{
		service:  svc,
		sso:      sso,
		interval: config.SessionCleanupInterval,
		stopChan: make(chan struct{}),
	}
}

func (s *SessionCleanupScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] Session cleanup scheduler started (interval: %v)", s.interval)
}

func (s *SessionCleanupScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.stopOnce.Do(func() { close(s.stopChan) })
	s.running = false
	log.Println("[Scheduler] Session cleanup scheduler stopped")
}

func (s *SessionCleanupScheduler) run() {
	// Deliberate delay before the first sweep: boot already does migrations and
	// a config sync, and this is never urgent.
	select {
	case <-time.After(2 * time.Minute):
	case <-s.stopChan:
		return
	}
	s.cleanup()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopChan:
			return
		}
	}
}

func (s *SessionCleanupScheduler) cleanup() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in session cleanup: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
	defer cancel()
	if err := s.service.CleanupSessions(ctx); err != nil {
		log.Printf("[Scheduler] Session cleanup failed: %v", err)
	}
	// Half-finished SSO sign-ins leave a state row behind; they expire in ten
	// minutes but nothing would delete them. (#227)
	if s.sso != nil {
		if n, err := s.sso.CleanupLoginStates(ctx); err != nil {
			log.Printf("[Scheduler] SSO login-state cleanup failed: %v", err)
		} else if n > 0 {
			log.Printf("[Scheduler] Removed %d expired SSO login states", n)
		}
	}
}
