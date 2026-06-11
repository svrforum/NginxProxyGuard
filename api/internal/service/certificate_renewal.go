package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/acme"

	"github.com/google/uuid"
)

// Renew renews a certificate
func (s *CertificateService) Renew(ctx context.Context, id string) error {
	cert, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}
	if cert == nil {
		return model.ErrNotFound
	}

	// Try to acquire distributed lock to prevent concurrent renewals
	lockKey := "cert:renewal:" + id
	lockValue := uuid.New().String()

	if s.redisCache != nil && s.redisCache.IsReady() {
		acquired, err := s.redisCache.AcquireLock(ctx, lockKey, lockValue, certRenewalLockTTL)
		if err != nil {
			log.Printf("[Certificate] Warning: Failed to acquire lock for cert %s: %v", id, err)
			// Continue without lock if Redis fails - single instance fallback
		} else if !acquired {
			log.Printf("[Certificate] Renewal already in progress for cert %s, skipping", id)
			return fmt.Errorf("renewal already in progress for certificate %s", id)
		}
	}

	// Mark as renewing
	cert.Status = model.CertStatusRenewing
	now := time.Now()
	cert.RenewalAttemptedAt = &now
	if err := s.repo.Update(ctx, cert); err != nil {
		// Release lock on failure
		if s.redisCache != nil && s.redisCache.IsReady() {
			s.redisCache.ReleaseLock(ctx, lockKey, lockValue)
		}
		return fmt.Errorf("failed to update certificate status: %w", err)
	}

	// Clear previous logs before starting renewal (do this before goroutine)
	s.clearCertLogs(id)

	// Run renewal in background with lock info
	go s.renewCertificateWithLock(cert, lockKey, lockValue)

	return nil
}

// renewCertificateWithLock wraps renewCertificate with lock release
func (s *CertificateService) renewCertificateWithLock(cert *model.Certificate, lockKey, lockValue string) {
	defer func() {
		// Always release the lock when done
		if s.redisCache != nil && s.redisCache.IsReady() {
			ctx := context.Background()
			if err := s.redisCache.ReleaseLock(ctx, lockKey, lockValue); err != nil {
				log.Printf("[Certificate] Warning: Failed to release lock for cert %s: %v", cert.ID, err)
			}
		}
	}()

	s.renewCertificate(cert)
}

func (s *CertificateService) renewCertificate(cert *model.Certificate) {
	ctx := context.Background()

	switch cert.Provider {
	case model.CertProviderLetsEncrypt:
		s.renewLetsEncrypt(ctx, cert)
	case model.CertProviderSelfSigned:
		// For self-signed, just regenerate
		validityDays := 365
		if cert.ExpiresAt != nil && cert.IssuedAt != nil {
			validityDays = int(cert.ExpiresAt.Sub(*cert.IssuedAt).Hours() / 24)
		}
		s.generateSelfSignedCert(cert.ID, []string(cert.DomainNames), validityDays)
	default:
		s.updateCertError(ctx, cert.ID, "cannot renew custom certificates")
	}
}

func (s *CertificateService) renewLetsEncrypt(ctx context.Context, cert *model.Certificate) {
	// Add logging for renewal process (logs are already cleared in Renew())
	s.addCertLog(cert.ID, "info", fmt.Sprintf("Starting renewal for domains: %v", []string(cert.DomainNames)), "init")

	// Get ACME service with current settings from database
	// This ensures staging/production changes take effect immediately
	acmeService, acmeEmail := s.getACMEService(ctx)

	// Reconstruct ACME user
	var user acme.ACMEUser
	var hasValidUser bool
	if len(cert.AcmeAccount) > 2 { // More than just "{}"
		if err := user.FromJSON(cert.AcmeAccount); err != nil {
			s.addCertLog(cert.ID, "warn", fmt.Sprintf("Failed to restore ACME account: %v, will create new account", err), "init")
		} else if user.GetPrivateKey() != nil {
			hasValidUser = true
			s.addCertLog(cert.ID, "info", "Restored existing ACME account", "init")
		}
	}

	var result *acme.CertificateResult
	var newUser *acme.ACMEUser
	var renewErr error

	if cert.DNSProviderID != nil {
		// Use DNS-01 challenge for renewal
		dnsProvider, err := s.dnsRepo.GetByID(ctx, *cert.DNSProviderID)
		if err != nil || dnsProvider == nil {
			s.updateRenewalError(ctx, cert.ID, "DNS provider not found")
			return
		}

		s.addCertLog(cert.ID, "info", fmt.Sprintf("Using DNS-01 challenge with provider: %s", dnsProvider.Name), "challenge")

		if hasValidUser {
			// Try renewal with existing account
			s.addCertLog(cert.ID, "info", "Attempting certificate renewal...", "acme")
			result, renewErr = acmeService.RenewCertificate(cert.CertificatePEM, cert.PrivateKeyPEM, dnsProvider, &user)
		}

		// If renewal failed or no valid user, obtain new certificate.
		// Reuse the stored ACME account when we have one — registering a fresh
		// account on every failed attempt burns Let's Encrypt rate limits.
		if !hasValidUser || renewErr != nil {
			var existingUser *acme.ACMEUser
			if hasValidUser {
				existingUser = &user
			}
			if renewErr != nil {
				s.addCertLog(cert.ID, "warn", fmt.Sprintf("Renewal failed: %v, obtaining new certificate", renewErr), "acme")
			} else {
				s.addCertLog(cert.ID, "info", "No valid ACME account, obtaining new certificate", "acme")
			}
			result, newUser, renewErr = acmeService.ObtainCertificate(acmeEmail, []string(cert.DomainNames), dnsProvider, existingUser)
		}

		if renewErr != nil {
			s.updateRenewalError(ctx, cert.ID, diagnoseDNS01Error(renewErr))
			return
		}
	} else {
		// Use HTTP-01 challenge for renewal (no DNS provider)
		s.addCertLog(cert.ID, "info", "Using HTTP-01 challenge", "challenge")

		if hasValidUser {
			// Try renewal with existing account
			s.addCertLog(cert.ID, "info", "Attempting certificate renewal...", "acme")
			result, renewErr = acmeService.RenewCertificateHTTP(cert.CertificatePEM, cert.PrivateKeyPEM, &user)
		}

		// If renewal failed or no valid user, obtain new certificate.
		// Reuse the stored ACME account when we have one — registering a fresh
		// account on every failed attempt burns Let's Encrypt rate limits.
		if !hasValidUser || renewErr != nil {
			var existingUser *acme.ACMEUser
			if hasValidUser {
				existingUser = &user
			}
			if renewErr != nil {
				s.addCertLog(cert.ID, "warn", fmt.Sprintf("Renewal failed: %v, obtaining new certificate", renewErr), "acme")
			} else {
				s.addCertLog(cert.ID, "info", "No valid ACME account, obtaining new certificate", "acme")
			}
			result, newUser, renewErr = acmeService.ObtainCertificateHTTP(acmeEmail, []string(cert.DomainNames), existingUser)
		}

		if renewErr != nil {
			s.updateRenewalError(ctx, cert.ID, fmt.Sprintf("failed to renew/obtain certificate via HTTP-01: %v", renewErr))
			return
		}
	}

	s.addCertLog(cert.ID, "success", "Certificate obtained successfully", "acme")

	// Validate renewed certificate before saving
	s.addCertLog(cert.ID, "info", "Validating renewed certificate...", "validate")
	if err := acme.ValidateRenewedCertificate(result.CertificatePEM, result.PrivateKeyPEM, []string(cert.DomainNames)); err != nil {
		s.updateRenewalError(ctx, cert.ID, fmt.Sprintf("renewed certificate validation failed: %v", err))
		return
	}
	s.addCertLog(cert.ID, "success", "Certificate validation passed", "validate")

	// Backup existing certificate files before overwriting
	s.addCertLog(cert.ID, "info", "Backing up existing certificate files...", "backup")
	restore, cleanup, err := acmeService.BackupCertificateFiles(cert.ID)
	if err != nil {
		s.addCertLog(cert.ID, "warn", fmt.Sprintf("Failed to backup certificate files: %v (continuing anyway)", err), "backup")
		// Set no-op functions so the rest of the code works
		restore = func() error { return nil }
		cleanup = func() {}
	} else {
		defer cleanup()
	}

	// Save new certificate files
	s.addCertLog(cert.ID, "info", "Saving certificate files...", "save")
	certPath, keyPath, err := acmeService.SaveCertificateFiles(cert.ID, result.CertificatePEM, result.PrivateKeyPEM, result.IssuerCertificatePEM)
	if err != nil {
		s.addCertLog(cert.ID, "warn", "Save failed, attempting rollback...", "save")
		if restoreErr := restore(); restoreErr != nil {
			s.addCertLog(cert.ID, "error", fmt.Sprintf("Rollback also failed: %v", restoreErr), "save")
		} else {
			s.addCertLog(cert.ID, "info", "Rollback successful, previous certificate restored", "save")
		}
		s.updateRenewalError(ctx, cert.ID, fmt.Sprintf("failed to save renewed certificate files: %v", err))
		return
	}

	// Update certificate record
	s.addCertLog(cert.ID, "info", "Updating certificate record...", "finalize")
	now := time.Now()
	cert.Status = model.CertStatusIssued
	cert.CertificatePEM = result.CertificatePEM
	cert.PrivateKeyPEM = result.PrivateKeyPEM
	cert.IssuerCertificatePEM = result.IssuerCertificatePEM
	cert.ExpiresAt = &result.ExpiresAt
	cert.IssuedAt = &now
	cert.CertificatePath = &certPath
	cert.PrivateKeyPath = &keyPath
	cert.ErrorMessage = nil

	// Save new ACME account if we created one
	if newUser != nil {
		acmeAccount, err := newUser.ToJSON()
		if err == nil {
			cert.AcmeAccount = acmeAccount
		}
	}

	if err := s.repo.Update(ctx, cert); err != nil {
		s.updateRenewalError(ctx, cert.ID, fmt.Sprintf("failed to update renewed certificate: %v", err))
		return
	}

	s.addCertLog(cert.ID, "success", fmt.Sprintf("Certificate renewed successfully! Expires: %s", result.ExpiresAt.Format("2006-01-02")), "complete")

	// Save history
	s.saveHistory(cert, "renewed", "success", fmt.Sprintf("Certificate renewed for %v", []string(cert.DomainNames)))

	// Notify that certificate is ready - regenerate nginx configs for proxy hosts using this cert
	s.notifyCertificateReady(cert.ID)
}

// GetExpiringSoon returns certificates expiring within days
func (s *CertificateService) GetExpiringSoon(ctx context.Context, days int) ([]model.Certificate, error) {
	return s.repo.GetExpiringSoon(ctx, days)
}

// updateCertError updates certificate with error status and saves history.
// Used for initial issuance failures where no valid certificate existed before.
func (s *CertificateService) updateCertError(ctx context.Context, certID, errMsg string) {
	// Add error log
	s.addCertLog(certID, "error", errMsg, "error")

	cert, err := s.repo.GetByID(ctx, certID)
	if err != nil || cert == nil {
		return
	}

	cert.Status = model.CertStatusError
	cert.ErrorMessage = &errMsg
	s.repo.Update(ctx, cert)

	// Save history
	s.saveHistory(cert, "error", "error", errMsg)
}

// updateRenewalError restores a previously-issued certificate back to "issued" status
// after a renewal failure. The existing certificate files on disk are still valid,
// so the status must NOT be changed to "error" (which could lead to accidental deletion).
func (s *CertificateService) updateRenewalError(ctx context.Context, certID, errMsg string) {
	s.addCertLog(certID, "error", errMsg, "error")

	cert, err := s.repo.GetByID(ctx, certID)
	if err != nil || cert == nil {
		return
	}

	// Restore to issued — the old cert is still valid on disk
	cert.Status = model.CertStatusIssued
	cert.ErrorMessage = &errMsg
	s.repo.Update(ctx, cert)

	// Save history as renewal error
	s.saveHistory(cert, "renewed", "error", errMsg)
}

// Certificate logging methods for real-time progress tracking

const certLogKeyPrefix = "cert:logs:"
const certLogTTL = 30 * time.Minute // Keep logs for 30 minutes

// addCertLog adds a log entry for certificate issuance
func (s *CertificateService) addCertLog(certID, level, message, step string) {
	if s.redisCache == nil || !s.redisCache.IsReady() {
		log.Printf("[Certificate:%s] %s: %s", certID[:8], level, message)
		return
	}

	logEntry := model.CertificateLog{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Step:      step,
	}

	ctx := context.Background()
	key := certLogKeyPrefix + certID

	// Get existing logs
	var logs []model.CertificateLog
	_ = s.redisCache.Get(ctx, key, &logs) // Ignore error, logs will be empty slice if not found

	// Append new log
	logs = append(logs, logEntry)

	// Save back to Redis
	s.redisCache.Set(ctx, key, logs, certLogTTL)

	log.Printf("[Certificate:%s] %s: %s", certID[:8], level, message)
}

// GetCertLogs retrieves all logs for a certificate
func (s *CertificateService) GetCertLogs(ctx context.Context, certID string) (*model.CertificateLogResponse, error) {
	cert, err := s.repo.GetByID(ctx, certID)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, model.ErrNotFound
	}

	var logs []model.CertificateLog

	if s.redisCache != nil && s.redisCache.IsReady() {
		key := certLogKeyPrefix + certID
		_ = s.redisCache.Get(ctx, key, &logs) // Ignore error, logs will be empty slice if not found
	}

	isComplete := cert.Status == model.CertStatusIssued || cert.Status == model.CertStatusError

	return &model.CertificateLogResponse{
		CertificateID: certID,
		Status:        cert.Status,
		Logs:          logs,
		IsComplete:    isComplete,
	}, nil
}

// clearCertLogs removes logs for a certificate (called when issuance is complete)
func (s *CertificateService) clearCertLogs(certID string) {
	if s.redisCache == nil || !s.redisCache.IsReady() {
		return
	}

	ctx := context.Background()
	key := certLogKeyPrefix + certID
	s.redisCache.Delete(ctx, key)
}

// ListHistory returns paginated certificate history
func (s *CertificateService) ListHistory(ctx context.Context, page, perPage int, certificateID string) (*model.CertificateHistoryListResponse, error) {
	histories, total, err := s.repo.ListHistory(ctx, page, perPage, certificateID)
	if err != nil {
		return nil, err
	}

	totalPages := (total + perPage - 1) / perPage
	return &model.CertificateHistoryListResponse{
		Data:       histories,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// saveHistory saves a certificate history entry
func (s *CertificateService) saveHistory(cert *model.Certificate, action, status, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancel()

	// Get current logs for this certificate
	logs, err := s.GetCertLogs(ctx, cert.ID)
	var logsJSON string
	if err == nil && logs != nil && len(logs.Logs) > 0 {
		logsBytes, _ := json.Marshal(logs.Logs)
		logsJSON = string(logsBytes)
	}

	history := &model.CertificateHistory{
		CertificateID: cert.ID,
		Action:        action,
		Status:        status,
		Message:       message,
		DomainNames:   cert.DomainNames,
		Provider:      cert.Provider,
		ExpiresAt:     cert.ExpiresAt,
		Logs:          logsJSON,
	}

	_, err = s.repo.CreateHistory(ctx, history)
	if err != nil {
		log.Printf("[CertificateService] Failed to save history for certificate %s: %v", cert.ID, err)
	}
}

// diagnoseDNS01Error provides user-friendly error messages for DNS-01 challenge failures
func diagnoseDNS01Error(err error) string {
	msg := err.Error()

	if strings.Contains(msg, "time limit exceeded") || strings.Contains(msg, "propagation") {
		return fmt.Sprintf("DNS propagation timeout: DNS record was not detected within the time limit. "+
			"This usually means the API token lacks Zone:Read permission, or DNS propagation is slow. "+
			"Please verify your API token has both Zone:DNS:Edit and Zone:Zone:Read permissions. Original error: %v", err)
	}

	if strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "Unauthorized") {
		return fmt.Sprintf("Authentication failed: The API credentials were rejected by the DNS provider. "+
			"Please check that your API token or API key is valid and has not expired. Original error: %v", err)
	}

	if strings.Contains(msg, "could not find zone") || strings.Contains(msg, "zone not found") {
		return fmt.Sprintf("Zone not found: The DNS provider could not find the DNS zone for your domain. "+
			"Please ensure the domain is added to your DNS provider account and the API token has access to it. Original error: %v", err)
	}

	if strings.Contains(msg, "rate limit") || strings.Contains(msg, "rate_limit") {
		return fmt.Sprintf("Rate limit exceeded: Too many requests to the DNS provider API. "+
			"Please wait a few minutes and try again. Original error: %v", err)
	}

	return fmt.Sprintf("Failed to obtain certificate via DNS-01: %v", err)
}
