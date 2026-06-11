package scheduler

import (
	"context"
	"log"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// RenewalScheduler handles automatic certificate renewals
type RenewalScheduler struct {
	certRepo    *repository.CertificateRepository
	certService *service.CertificateService
	interval    time.Duration
	daysBuffer  int // Renew certificates expiring within this many days
	stopChan    chan struct{}
	running     bool
}

// NewRenewalScheduler creates a new renewal scheduler
func NewRenewalScheduler(
	certRepo *repository.CertificateRepository,
	certService *service.CertificateService,
	interval time.Duration,
	daysBuffer int,
) *RenewalScheduler {
	if interval == 0 {
		interval = 24 * time.Hour // Default to once per day
	}
	if daysBuffer == 0 {
		daysBuffer = 30 // Default to 30 days before expiry
	}

	return &RenewalScheduler{
		certRepo:    certRepo,
		certService: certService,
		interval:    interval,
		daysBuffer:  daysBuffer,
		stopChan:    make(chan struct{}),
	}
}

// Start begins the renewal scheduler
func (s *RenewalScheduler) Start() {
	if s.running {
		return
	}
	s.running = true

	go s.run()
	log.Printf("[Scheduler] Certificate renewal scheduler started (interval: %v, buffer: %d days)", s.interval, s.daysBuffer)
}

// Stop stops the renewal scheduler
func (s *RenewalScheduler) Stop() {
	if !s.running {
		return
	}
	close(s.stopChan)
	s.running = false
	log.Println("[Scheduler] Certificate renewal scheduler stopped")
}

func (s *RenewalScheduler) run() {
	// Run immediately on start
	s.checkAndRenew()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndRenew()
		case <-s.stopChan:
			return
		}
	}
}

func (s *RenewalScheduler) checkAndRenew() {
	ctx := context.Background()

	log.Println("[Scheduler] Checking for certificates needing renewal...")

	// Get certificates expiring soon with auto_renew enabled
	certs, err := s.certRepo.GetExpiringSoon(ctx, s.daysBuffer)
	if err != nil {
		log.Printf("[Scheduler] Error getting expiring certificates: %v", err)
		return
	}

	if len(certs) == 0 {
		log.Println("[Scheduler] No certificates need renewal")
		return
	}

	log.Printf("[Scheduler] Found %d certificate(s) needing renewal", len(certs))

	for _, cert := range certs {
		// Skip if already renewing
		if cert.Status == model.CertStatusRenewing {
			log.Printf("[Scheduler] Certificate %s is already renewing, skipping", cert.ID)
			continue
		}

		// Skip custom uploaded certificates (they can't be auto-renewed)
		if cert.Provider == model.CertProviderCustom {
			log.Printf("[Scheduler] Certificate %s is a custom upload, cannot auto-renew", cert.ID)
			continue
		}

		// Back off failing renewals: when the last attempt errored within the
		// past 24h, skip this cycle unless expiry is within 7 days. Without
		// this, a permanently-failing cert (e.g. domain no longer resolving)
		// hammers the ACME endpoint every cycle and burns Let's Encrypt rate
		// limits. In the final week before expiry every cycle retries.
		if cert.ErrorMessage != nil && *cert.ErrorMessage != "" &&
			cert.RenewalAttemptedAt != nil && time.Since(*cert.RenewalAttemptedAt) < 24*time.Hour &&
			cert.ExpiresAt != nil && time.Until(*cert.ExpiresAt) > 7*24*time.Hour {
			log.Printf("[Scheduler] Certificate %s last renewal failed %.0fh ago, backing off (expires %s)",
				cert.ID, time.Since(*cert.RenewalAttemptedAt).Hours(), cert.ExpiresAt.Format("2006-01-02"))
			continue
		}

		// Attempt renewal
		log.Printf("[Scheduler] Renewing certificate %s for domains: %v", cert.ID, cert.DomainNames)

		if err := s.certService.Renew(ctx, cert.ID); err != nil {
			log.Printf("[Scheduler] Failed to renew certificate %s: %v", cert.ID, err)
			continue
		}

		log.Printf("[Scheduler] Successfully initiated renewal for certificate %s", cert.ID)
	}
}

// CheckNow triggers an immediate renewal check
func (s *RenewalScheduler) CheckNow() {
	go s.checkAndRenew()
}
