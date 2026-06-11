package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/acme"
	"nginx-proxy-guard/pkg/cache"

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
	inUseChecker        CertificateInUseChecker
}

// CertificateInUseChecker reports how many proxy hosts and redirect hosts
// currently reference a certificate. Wired in bootstrap to avoid circular deps.
type CertificateInUseChecker func(ctx context.Context, certificateID string) (proxyHosts, redirectHosts int, err error)

// SetCertificateInUseChecker sets the dependency checker used to guard Delete.
func (s *CertificateService) SetCertificateInUseChecker(cb CertificateInUseChecker) {
	s.inUseChecker = cb
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
	// In-use guard: deleting a referenced certificate removes its files from
	// disk while the generated nginx configs still point at them — the next
	// nginx -t then fails system-wide. The FKs are ON DELETE SET NULL, so the
	// DB would silently detach while the on-disk configs go stale.
	if s.inUseChecker != nil {
		proxyCount, redirectCount, err := s.inUseChecker(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to check certificate usage: %w", err)
		}
		if proxyCount+redirectCount > 0 {
			return fmt.Errorf("%w: referenced by %d proxy host(s) and %d redirect host(s); unassign it from those hosts first",
				model.ErrCertificateInUse, proxyCount, redirectCount)
		}
	}

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

