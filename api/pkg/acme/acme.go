package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/providers/dns/dynu"
	"github.com/go-acme/lego/v4/registration"

	"nginx-proxy-guard/internal/model"
)

// validateCertID validates that the certificate ID is safe for use in file paths
// This prevents path traversal attacks
func validateCertID(certID string) error {
	if certID == "" {
		return fmt.Errorf("certificate ID cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(certID, "..") || strings.Contains(certID, "/") || strings.Contains(certID, "\\") {
		return fmt.Errorf("certificate ID contains invalid characters")
	}

	// Check for null bytes
	if strings.Contains(certID, "\x00") {
		return fmt.Errorf("certificate ID contains null bytes")
	}

	// Only allow UUID format or alphanumeric with hyphens
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	uuidPattern := regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	alphanumPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	if !uuidPattern.MatchString(certID) && !alphanumPattern.MatchString(certID) {
		return fmt.Errorf("certificate ID must be a UUID or alphanumeric string")
	}

	// Limit length to prevent abuse
	if len(certID) > 100 {
		return fmt.Errorf("certificate ID is too long")
	}

	return nil
}

// ACME directory URLs
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ACMEUser implements the registration.User interface
type ACMEUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          crypto.PrivateKey      `json:"-"`
	KeyPEM       string                 `json:"key_pem"`
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// ToJSON serializes the user to JSON (for storing in DB)
func (u *ACMEUser) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}

// FromJSON deserializes the user from JSON
func (u *ACMEUser) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, u); err != nil {
		return err
	}

	// Parse the key PEM
	if u.KeyPEM != "" {
		block, _ := pem.Decode([]byte(u.KeyPEM))
		if block == nil {
			return fmt.Errorf("failed to decode key PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}
		u.Key = key
	}

	return nil
}

// Service handles ACME certificate operations
type Service struct {
	caURL      string
	certsDir   string
	webrootDir string
}

// NewService creates a new ACME service
func NewService(useStaging bool, certsDir string) *Service {
	caURL := LetsEncryptProduction
	if useStaging {
		caURL = LetsEncryptStaging
	}

	// Default webroot directory for HTTP-01 challenge
	// Use path within nginx_data volume so both API and nginx containers can access it
	webrootDir := "/etc/nginx/acme-challenge"

	return &Service{
		caURL:      caURL,
		certsDir:   certsDir,
		webrootDir: webrootDir,
	}
}

// SetWebrootDir sets the webroot directory for HTTP-01 challenges
func (s *Service) SetWebrootDir(dir string) {
	s.webrootDir = dir
}

// CertificateResult contains the issued certificate data
type CertificateResult struct {
	CertificatePEM       string
	PrivateKeyPEM        string
	IssuerCertificatePEM string
	ExpiresAt            time.Time
}

// ObtainCertificateHTTP requests a new certificate using HTTP-01 challenge (no DNS API needed)
func (s *Service) ObtainCertificateHTTP(email string, domains []string, existingUser *ACMEUser) (*CertificateResult, *ACMEUser, error) {
	var user *ACMEUser
	var err error

	// Use existing user or create new one
	if existingUser != nil && existingUser.Key != nil {
		user = existingUser
	} else {
		user, err = s.createUser(email)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ACME user: %w", err)
		}
	}

	// Configure lego client
	config := lego.NewConfig(user)
	config.CADirURL = s.caURL
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Ensure webroot directory exists
	challengePath := filepath.Join(s.webrootDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengePath, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create webroot directory: %w", err)
	}

	// Set up HTTP-01 provider using webroot
	err = client.Challenge.SetHTTP01Provider(&webrootProvider{path: s.webrootDir})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set HTTP provider: %w", err)
	}

	// Register user if not already registered
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to register ACME account: %w", err)
		}
		user.Registration = reg
	}

	// Obtain certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Parse certificate to get expiry
	expiresAt, err := getCertificateExpiry(certificates.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	result := &CertificateResult{
		CertificatePEM:       string(certificates.Certificate),
		PrivateKeyPEM:        string(certificates.PrivateKey),
		IssuerCertificatePEM: string(certificates.IssuerCertificate),
		ExpiresAt:            expiresAt,
	}

	return result, user, nil
}

// webrootProvider implements the HTTP-01 challenge using webroot
type webrootProvider struct {
	path string
}

func (w *webrootProvider) Present(domain, token, keyAuth string) error {
	challengePath := filepath.Join(w.path, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengePath, 0755); err != nil {
		return err
	}

	filePath := filepath.Join(challengePath, token)
	return os.WriteFile(filePath, []byte(keyAuth), 0644)
}

func (w *webrootProvider) CleanUp(domain, token, keyAuth string) error {
	filePath := filepath.Join(w.path, ".well-known", "acme-challenge", token)
	return os.Remove(filePath)
}

// ObtainCertificate requests a new certificate from Let's Encrypt using DNS-01
func (s *Service) ObtainCertificate(email string, domains []string, provider *model.DNSProvider, existingUser *ACMEUser) (*CertificateResult, *ACMEUser, error) {
	var user *ACMEUser
	var err error

	// Use existing user or create new one
	if existingUser != nil && existingUser.Key != nil {
		user = existingUser
	} else {
		user, err = s.createUser(email)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ACME user: %w", err)
		}
	}

	// Configure lego client
	config := lego.NewConfig(user)
	config.CADirURL = s.caURL
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Set up DNS provider
	dnsProvider, err := s.createDNSProvider(provider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	// Register user if not already registered
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to register ACME account: %w", err)
		}
		user.Registration = reg
	}

	// Obtain certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Parse certificate to get expiry
	expiresAt, err := getCertificateExpiry(certificates.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	result := &CertificateResult{
		CertificatePEM:       string(certificates.Certificate),
		PrivateKeyPEM:        string(certificates.PrivateKey),
		IssuerCertificatePEM: string(certificates.IssuerCertificate),
		ExpiresAt:            expiresAt,
	}

	return result, user, nil
}

// RenewCertificate renews an existing certificate using DNS-01 challenge
func (s *Service) RenewCertificate(certPEM, keyPEM string, provider *model.DNSProvider, user *ACMEUser) (*CertificateResult, error) {
	config := lego.NewConfig(user)
	config.CADirURL = s.caURL
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Set up DNS provider
	dnsProvider, err := s.createDNSProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	// Renew certificate
	certResource := certificate.Resource{
		Certificate: []byte(certPEM),
		PrivateKey:  []byte(keyPEM),
	}

	certificates, err := client.Certificate.Renew(certResource, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	expiresAt, err := getCertificateExpiry(certificates.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	result := &CertificateResult{
		CertificatePEM:       string(certificates.Certificate),
		PrivateKeyPEM:        string(certificates.PrivateKey),
		IssuerCertificatePEM: string(certificates.IssuerCertificate),
		ExpiresAt:            expiresAt,
	}

	return result, nil
}

// RenewCertificateHTTP renews an existing certificate using HTTP-01 challenge
func (s *Service) RenewCertificateHTTP(certPEM, keyPEM string, user *ACMEUser) (*CertificateResult, error) {
	config := lego.NewConfig(user)
	config.CADirURL = s.caURL
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Ensure webroot directory exists
	challengePath := filepath.Join(s.webrootDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create webroot directory: %w", err)
	}

	// Set up HTTP-01 provider using webroot
	err = client.Challenge.SetHTTP01Provider(&webrootProvider{path: s.webrootDir})
	if err != nil {
		return nil, fmt.Errorf("failed to set HTTP provider: %w", err)
	}

	// Renew certificate
	certResource := certificate.Resource{
		Certificate: []byte(certPEM),
		PrivateKey:  []byte(keyPEM),
	}

	certificates, err := client.Certificate.Renew(certResource, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	expiresAt, err := getCertificateExpiry(certificates.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	result := &CertificateResult{
		CertificatePEM:       string(certificates.Certificate),
		PrivateKeyPEM:        string(certificates.PrivateKey),
		IssuerCertificatePEM: string(certificates.IssuerCertificate),
		ExpiresAt:            expiresAt,
	}

	return result, nil
}

// GenerateSelfSigned generates a self-signed certificate
func (s *Service) GenerateSelfSigned(domains []string, validityDays int, org, country string) (*CertificateResult, error) {
	if validityDays <= 0 {
		validityDays = 365
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Certificate template
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			Country:      []string{country},
			CommonName:   domains[0],
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	result := &CertificateResult{
		CertificatePEM:       string(certPEM),
		PrivateKeyPEM:        string(keyPEM),
		IssuerCertificatePEM: string(certPEM), // Self-signed, so issuer is self
		ExpiresAt:            notAfter,
	}

	return result, nil
}

// SaveCertificateFiles saves certificate and key to files
func (s *Service) SaveCertificateFiles(certID string, certPEM, keyPEM, issuerPEM string) (certPath, keyPath string, err error) {
	// Validate certID to prevent path traversal
	if err := validateCertID(certID); err != nil {
		return "", "", fmt.Errorf("invalid certificate ID: %w", err)
	}

	// Use filepath.Join for safe path construction
	certDir := filepath.Join(s.certsDir, certID)

	// Verify the resulting path is within certsDir
	cleanCertDir := filepath.Clean(certDir)
	cleanCertsDir := filepath.Clean(s.certsDir)
	if !strings.HasPrefix(cleanCertDir, cleanCertsDir+string(filepath.Separator)) {
		return "", "", fmt.Errorf("invalid certificate directory path")
	}

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	certPath = fmt.Sprintf("%s/fullchain.pem", certDir)
	keyPath = fmt.Sprintf("%s/privkey.pem", certDir)

	// Write fullchain (cert + issuer)
	fullchain := certPEM
	if issuerPEM != "" && issuerPEM != certPEM {
		fullchain = certPEM + "\n" + issuerPEM
	}

	if err := os.WriteFile(certPath, []byte(fullchain), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write certificate file: %w", err)
	}

	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write key file: %w", err)
	}

	return certPath, keyPath, nil
}

// DeleteCertificateFiles removes certificate files
func (s *Service) DeleteCertificateFiles(certID string) error {
	// Validate certID to prevent path traversal
	if err := validateCertID(certID); err != nil {
		return fmt.Errorf("invalid certificate ID: %w", err)
	}

	// Use filepath.Join for safe path construction
	certDir := filepath.Join(s.certsDir, certID)

	// Verify the resulting path is within certsDir
	cleanCertDir := filepath.Clean(certDir)
	cleanCertsDir := filepath.Clean(s.certsDir)
	if !strings.HasPrefix(cleanCertDir, cleanCertsDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid certificate directory path")
	}

	return os.RemoveAll(certDir)
}

// createUser creates a new ACME user with generated key
func (s *Service) createUser(email string) (*ACMEUser, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return &ACMEUser{
		Email:  email,
		Key:    privateKey,
		KeyPEM: string(keyPEM),
	}, nil
}

// createDNSProvider creates a DNS provider based on type and credentials
func (s *Service) createDNSProvider(provider *model.DNSProvider) (challenge.Provider, error) {
	if provider == nil {
		return nil, fmt.Errorf("DNS provider is required")
	}

	switch provider.ProviderType {
	case model.DNSProviderCloudflare:
		var creds model.CloudflareCredentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid cloudflare credentials: %w", err)
		}

		// Set environment variables for cloudflare provider
		if creds.APIToken != "" {
			os.Setenv("CLOUDFLARE_DNS_API_TOKEN", creds.APIToken)
		} else {
			os.Setenv("CLOUDFLARE_EMAIL", creds.Email)
			os.Setenv("CLOUDFLARE_API_KEY", creds.APIKey)
		}

		if creds.ZoneID != "" {
			os.Setenv("CLOUDFLARE_ZONE_API_TOKEN", creds.APIToken)
		}

		return cloudflare.NewDNSProvider()

	case model.DNSProviderDuckDNS:
		var creds model.DuckDNSCredentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid duckdns credentials: %w", err)
		}

		// Set environment variable for DuckDNS provider
		os.Setenv("DUCKDNS_TOKEN", creds.Token)

		return duckdns.NewDNSProvider()

	case model.DNSProviderDynu:
		var creds model.DynuCredentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid dynu credentials: %w", err)
		}

		// Set environment variable for Dynu provider
		os.Setenv("DYNU_API_KEY", creds.APIKey)

		return dynu.NewDNSProvider()

	default:
		return nil, fmt.Errorf("unsupported DNS provider type: %s", provider.ProviderType)
	}
}

// getCertificateExpiry parses a certificate and returns its expiry time
func getCertificateExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// ValidateCertificate validates a certificate PEM and returns domain names
func ValidateCertificate(certPEM string) ([]string, time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	domains := cert.DNSNames
	if cert.Subject.CommonName != "" && len(domains) == 0 {
		domains = []string{cert.Subject.CommonName}
	}

	return domains, cert.NotAfter, nil
}
