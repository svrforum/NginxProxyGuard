package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/acme"
	"nginx-proxy-guard/pkg/cache"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// CertificateReadyCallback is called when a certificate is successfully issued
// It receives the certificate ID and should regenerate nginx configs for affected proxy hosts
type CertificateReadyCallback func(ctx context.Context, certificateID string) error

type CertificateService struct {
	repo                *repository.CertificateRepository
	dnsRepo             *repository.DNSProviderRepository
	systemSettingsRepo  *repository.SystemSettingsRepository
	certsPath           string
	defaultACMEEmail    string
	onCertReady         CertificateReadyCallback
	redisCache          *cache.RedisClient
}

const (
	// Lock TTL for certificate renewal (10 minutes to handle slow ACME operations)
	certRenewalLockTTL = 10 * time.Minute
	// Default timeout for database operations
	dbOperationTimeout = 30 * time.Second
)

func NewCertificateService(
	repo *repository.CertificateRepository,
	dnsRepo *repository.DNSProviderRepository,
	systemSettingsRepo *repository.SystemSettingsRepository,
	certsPath string,
	defaultACMEEmail string,
	redisCache *cache.RedisClient,
) *CertificateService {
	return &CertificateService{
		repo:               repo,
		dnsRepo:            dnsRepo,
		systemSettingsRepo: systemSettingsRepo,
		certsPath:          certsPath,
		defaultACMEEmail:   defaultACMEEmail,
		redisCache:         redisCache,
	}
}

// getACMEService creates an ACME service with current settings from database
// This ensures staging/production setting changes take effect immediately
func (s *CertificateService) getACMEService(ctx context.Context) (*acme.Service, string) {
	// Get current settings from database
	settings, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[CertificateService] Failed to get system settings, using defaults: %v", err)
		// Fallback to production (safer default)
		return acme.NewService(false, s.certsPath), s.defaultACMEEmail
	}

	// Use email from settings if available, otherwise use default
	email := s.defaultACMEEmail
	if settings.ACMEEmail != "" {
		email = settings.ACMEEmail
	}

	// Create ACME service with current staging setting
	return acme.NewService(settings.ACMEStaging, s.certsPath), email
}

// SetCertificateReadyCallback sets the callback to be called when a certificate is ready
func (s *CertificateService) SetCertificateReadyCallback(cb CertificateReadyCallback) {
	s.onCertReady = cb
}

// notifyCertificateReady calls the callback if set
func (s *CertificateService) notifyCertificateReady(certID string) {
	if s.onCertReady != nil {
		ctx := context.Background()
		if err := s.onCertReady(ctx, certID); err != nil {
			log.Printf("Failed to regenerate configs for certificate %s: %v", certID, err)
		}
	}
}

// Create initiates certificate creation based on provider type
func (s *CertificateService) Create(ctx context.Context, req *model.CreateCertificateRequest) (*model.Certificate, error) {
	// Set defaults
	if req.Provider == "" {
		req.Provider = model.CertProviderLetsEncrypt
	}

	cert := &model.Certificate{
		DomainNames: pq.StringArray(req.DomainNames),
		Provider:    req.Provider,
		AutoRenew:   req.AutoRenew,
		Status:      model.CertStatusPending,
	}

	if req.DNSProviderID != nil {
		cert.DNSProviderID = req.DNSProviderID
	}

	// Create certificate record in DB first
	cert, err := s.repo.Create(ctx, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate record: %w", err)
	}

	// Process based on provider type
	switch req.Provider {
	case model.CertProviderLetsEncrypt:
		go s.obtainLetsEncryptCert(cert.ID, req.DomainNames, req.DNSProviderID)

	case model.CertProviderSelfSigned:
		validityDays := req.ValidityDays
		if validityDays <= 0 {
			validityDays = 365
		}
		go s.generateSelfSignedCert(cert.ID, req.DomainNames, validityDays)
	}

	return cert, nil
}

// obtainLetsEncryptCert runs in background to obtain Let's Encrypt certificate
// If dnsProviderID is nil, uses HTTP-01 challenge; otherwise uses DNS-01 challenge
func (s *CertificateService) obtainLetsEncryptCert(certID string, domains []string, dnsProviderID *string) {
	ctx := context.Background()

	// Initialize logging
	s.addCertLog(certID, "info", fmt.Sprintf("Starting certificate issuance for domains: %v", domains), "init")

	// Get the certificate record
	cert, err := s.repo.GetByID(ctx, certID)
	if err != nil || cert == nil {
		s.updateCertError(ctx, certID, "failed to get certificate record")
		return
	}

	// Get ACME service with current settings from database
	// This ensures staging/production changes take effect immediately
	acmeService, acmeEmail := s.getACMEService(ctx)

	var result *acme.CertificateResult
	var user *acme.ACMEUser

	if dnsProviderID != nil {
		// Use DNS-01 challenge
		s.addCertLog(certID, "info", "Using DNS-01 challenge method", "challenge")

		dnsProvider, err := s.dnsRepo.GetByID(ctx, *dnsProviderID)
		if err != nil || dnsProvider == nil {
			s.updateCertError(ctx, certID, "DNS provider not found")
			return
		}

		s.addCertLog(certID, "info", fmt.Sprintf("DNS provider: %s (%s)", dnsProvider.Name, dnsProvider.ProviderType), "challenge")
		s.addCertLog(certID, "info", "Requesting certificate from Let's Encrypt...", "acme")

		result, user, err = acmeService.ObtainCertificate(acmeEmail, domains, dnsProvider, nil)
		if err != nil {
			s.updateCertError(ctx, certID, diagnoseDNS01Error(err))
			return
		}
	} else {
		// Use HTTP-01 challenge (no DNS provider needed)
		s.addCertLog(certID, "info", "Using HTTP-01 challenge method", "challenge")
		s.addCertLog(certID, "info", "Requesting certificate from Let's Encrypt...", "acme")
		s.addCertLog(certID, "warn", "Make sure the domain points to this server and port 80 is accessible", "validation")

		result, user, err = acmeService.ObtainCertificateHTTP(acmeEmail, domains, nil)
		if err != nil {
			s.updateCertError(ctx, certID, fmt.Sprintf("failed to obtain certificate via HTTP-01: %v", err))
			return
		}
	}

	s.addCertLog(certID, "success", "Certificate obtained successfully from Let's Encrypt", "acme")

	// Validate certificate before saving
	s.addCertLog(certID, "info", "Validating certificate...", "validate")
	if err := acme.ValidateRenewedCertificate(result.CertificatePEM, result.PrivateKeyPEM, domains); err != nil {
		s.updateCertError(ctx, certID, fmt.Sprintf("certificate validation failed: %v", err))
		return
	}
	s.addCertLog(certID, "success", "Certificate validation passed", "validate")

	// Save certificate files
	s.addCertLog(certID, "info", "Saving certificate files...", "save")
	certPath, keyPath, err := acmeService.SaveCertificateFiles(certID, result.CertificatePEM, result.PrivateKeyPEM, result.IssuerCertificatePEM)
	if err != nil {
		s.updateCertError(ctx, certID, fmt.Sprintf("failed to save certificate files: %v", err))
		return
	}

	// Serialize ACME user for later renewal
	acmeAccount, _ := user.ToJSON()

	// Update certificate record
	s.addCertLog(certID, "info", "Updating certificate record...", "finalize")
	now := time.Now()
	cert.Status = model.CertStatusIssued
	cert.CertificatePEM = result.CertificatePEM
	cert.PrivateKeyPEM = result.PrivateKeyPEM
	cert.IssuerCertificatePEM = result.IssuerCertificatePEM
	cert.ExpiresAt = &result.ExpiresAt
	cert.IssuedAt = &now
	cert.CertificatePath = &certPath
	cert.PrivateKeyPath = &keyPath
	cert.AcmeAccount = acmeAccount
	cert.ErrorMessage = nil

	if err := s.repo.Update(ctx, cert); err != nil {
		s.updateCertError(ctx, certID, fmt.Sprintf("failed to update certificate: %v", err))
		return
	}

	s.addCertLog(certID, "success", fmt.Sprintf("Certificate issued successfully! Expires: %s", result.ExpiresAt.Format("2006-01-02")), "complete")

	// Save history
	s.saveHistory(cert, "issued", "success", fmt.Sprintf("Certificate issued for %v", []string(cert.DomainNames)))

	// Notify that certificate is ready - regenerate nginx configs for proxy hosts using this cert
	s.notifyCertificateReady(certID)
}

// generateSelfSignedCert generates a self-signed certificate
func (s *CertificateService) generateSelfSignedCert(certID string, domains []string, validityDays int) {
	ctx := context.Background()

	// Initialize logging
	s.addCertLog(certID, "info", fmt.Sprintf("Starting self-signed certificate generation for domains: %v", domains), "init")

	cert, err := s.repo.GetByID(ctx, certID)
	if err != nil || cert == nil {
		s.updateCertError(ctx, certID, "failed to get certificate record")
		return
	}

	// Get ACME service (for file operations, staging setting doesn't matter for self-signed)
	acmeService, _ := s.getACMEService(ctx)

	// Generate self-signed certificate
	s.addCertLog(certID, "info", fmt.Sprintf("Generating self-signed certificate (validity: %d days)", validityDays), "generate")
	result, err := acmeService.GenerateSelfSigned(domains, validityDays, "nginx-guard", "US")
	if err != nil {
		s.updateCertError(ctx, certID, fmt.Sprintf("failed to generate self-signed certificate: %v", err))
		return
	}
	s.addCertLog(certID, "success", "Self-signed certificate generated successfully", "generate")

	// Save certificate files
	s.addCertLog(certID, "info", "Saving certificate files...", "save")
	certPath, keyPath, err := acmeService.SaveCertificateFiles(certID, result.CertificatePEM, result.PrivateKeyPEM, result.IssuerCertificatePEM)
	if err != nil {
		s.updateCertError(ctx, certID, fmt.Sprintf("failed to save certificate files: %v", err))
		return
	}

	// Update certificate record
	s.addCertLog(certID, "info", "Updating certificate record...", "finalize")
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

	if err := s.repo.Update(ctx, cert); err != nil {
		s.updateCertError(ctx, certID, fmt.Sprintf("failed to update certificate: %v", err))
		return
	}

	s.addCertLog(certID, "success", fmt.Sprintf("Self-signed certificate created successfully! Expires: %s", result.ExpiresAt.Format("2006-01-02")), "complete")

	// Save history
	s.saveHistory(cert, "issued", "success", fmt.Sprintf("Self-signed certificate created for %v", []string(cert.DomainNames)))

	// Notify that certificate is ready - regenerate nginx configs for proxy hosts using this cert
	s.notifyCertificateReady(certID)
}

// UploadCustom uploads a custom certificate
func (s *CertificateService) UploadCustom(ctx context.Context, req *model.UploadCertificateRequest) (*model.Certificate, error) {
	// Validate certificate
	domains, expiresAt, err := acme.ValidateCertificate(req.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	// Use provided domains or extracted domains
	if len(req.DomainNames) == 0 {
		req.DomainNames = domains
	}

	cert := &model.Certificate{
		DomainNames:          pq.StringArray(req.DomainNames),
		Provider:             model.CertProviderCustom,
		Status:               model.CertStatusIssued,
		AutoRenew:            false, // Custom certs don't auto-renew
		CertificatePEM:       req.CertificatePEM,
		PrivateKeyPEM:        req.PrivateKeyPEM,
		IssuerCertificatePEM: req.IssuerPEM,
		ExpiresAt:            &expiresAt,
	}

	now := time.Now()
	cert.IssuedAt = &now

	// Create record
	cert, err = s.repo.Create(ctx, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate record: %w", err)
	}

	// Save files (use any ACME service instance, staging setting doesn't matter for file operations)
	acmeService, _ := s.getACMEService(ctx)
	certPath, keyPath, err := acmeService.SaveCertificateFiles(cert.ID, req.CertificatePEM, req.PrivateKeyPEM, req.IssuerPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to save certificate files: %w", err)
	}

	cert.CertificatePath = &certPath
	cert.PrivateKeyPath = &keyPath

	if err := s.repo.Update(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to update certificate paths: %w", err)
	}

	return cert, nil
}

// UpdateCustom replaces an existing custom certificate's PEM data in-place
func (s *CertificateService) UpdateCustom(ctx context.Context, certID string, req *model.UploadCertificateRequest) (*model.Certificate, error) {
	// Get existing certificate
	cert, err := s.repo.GetByID(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	if cert == nil {
		return nil, model.ErrNotFound
	}

	// Only custom certificates can be updated this way
	if cert.Provider != model.CertProviderCustom {
		return nil, model.ErrCustomCertOnly
	}

	// Validate new certificate
	domains, expiresAt, err := acme.ValidateCertificate(req.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	// Use provided domains or extracted domains
	if len(req.DomainNames) == 0 {
		req.DomainNames = domains
	}

	// Save files (overwrite existing paths) - with backup
	acmeService, _ := s.getACMEService(ctx)
	restore, cleanup, backupErr := acmeService.BackupCertificateFiles(certID)
	if backupErr != nil {
		log.Printf("[CertificateService] Warning: backup failed for %s: %v", certID, backupErr)
		restore = func() error { return nil }
		cleanup = func() {}
	} else {
		defer cleanup()
	}

	certPath, keyPath, err := acmeService.SaveCertificateFiles(certID, req.CertificatePEM, req.PrivateKeyPEM, req.IssuerPEM)
	if err != nil {
		if restoreErr := restore(); restoreErr != nil {
			log.Printf("[CertificateService] Warning: restore failed for %s: %v", certID, restoreErr)
		}
		return nil, fmt.Errorf("failed to save certificate files: %w", err)
	}

	// Update certificate record
	now := time.Now()
	cert.DomainNames = req.DomainNames
	cert.CertificatePEM = req.CertificatePEM
	cert.PrivateKeyPEM = req.PrivateKeyPEM
	cert.IssuerCertificatePEM = req.IssuerPEM
	cert.ExpiresAt = &expiresAt
	cert.IssuedAt = &now
	cert.CertificatePath = &certPath
	cert.PrivateKeyPath = &keyPath
	cert.Status = model.CertStatusIssued
	cert.ErrorMessage = nil

	if err := s.repo.Update(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}

	// Notify that certificate is ready - regenerate nginx configs
	s.notifyCertificateReady(certID)

	return cert, nil
}

// GetByID retrieves a certificate by ID
func (s *CertificateService) GetByID(ctx context.Context, id string) (*model.Certificate, error) {
	return s.repo.GetByID(ctx, id)
}

// List retrieves certificates with pagination, search, sort, and filters
func (s *CertificateService) List(ctx context.Context, page, perPage int, search, sortBy, sortOrder, status, provider string) (*model.CertificateListResponse, error) {
	certs, total, err := s.repo.List(ctx, page, perPage, search, sortBy, sortOrder, status, provider)
	if err != nil {
		return nil, err
	}

	totalPages := (total + perPage - 1) / perPage

	details := make([]model.CertificateWithDetails, len(certs))
	for i := range certs {
		details[i] = certs[i].ToWithDetails()
	}

	return &model.CertificateListResponse{
		Data:       details,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// DeleteErrorCertificates deletes all certificates with error status
func (s *CertificateService) DeleteErrorCertificates(ctx context.Context) (int64, error) {
	// Get error certificates for file cleanup
	errorCerts, err := s.repo.ListByStatus(ctx, "error")
	if err != nil {
		return 0, fmt.Errorf("failed to list error certificates: %w", err)
	}

	// Delete certificate files (best-effort)
	acmeService, _ := s.getACMEService(ctx)
	for _, cert := range errorCerts {
		_ = acmeService.DeleteCertificateFiles(cert.ID)
	}

	// Delete from DB
	count, err := s.repo.DeleteByErrorStatus(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete error certificates: %w", err)
	}

	return count, nil
}

// Delete removes a certificate
func (s *CertificateService) Delete(ctx context.Context, id string) error {
	// Delete certificate files (use any ACME service instance, staging setting doesn't matter)
	acmeService, _ := s.getACMEService(ctx)
	if err := acmeService.DeleteCertificateFiles(id); err != nil {
		// Log but continue - files might not exist
	}

	return s.repo.Delete(ctx, id)
}

func (s *CertificateService) ClearError(ctx context.Context, id string) error {
	return s.repo.ClearError(ctx, id)
}

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

		// If renewal failed or no valid user, obtain new certificate
		if !hasValidUser || renewErr != nil {
			if renewErr != nil {
				s.addCertLog(cert.ID, "warn", fmt.Sprintf("Renewal failed: %v, obtaining new certificate", renewErr), "acme")
			} else {
				s.addCertLog(cert.ID, "info", "No valid ACME account, obtaining new certificate", "acme")
			}
			result, newUser, renewErr = acmeService.ObtainCertificate(acmeEmail, []string(cert.DomainNames), dnsProvider, nil)
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

		// If renewal failed or no valid user, obtain new certificate
		if !hasValidUser || renewErr != nil {
			if renewErr != nil {
				s.addCertLog(cert.ID, "warn", fmt.Sprintf("Renewal failed: %v, obtaining new certificate", renewErr), "acme")
			} else {
				s.addCertLog(cert.ID, "info", "No valid ACME account, obtaining new certificate", "acme")
			}
			result, newUser, renewErr = acmeService.ObtainCertificateHTTP(acmeEmail, []string(cert.DomainNames), nil)
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
