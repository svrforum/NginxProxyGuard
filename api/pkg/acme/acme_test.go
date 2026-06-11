package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/registration"
)

// generateTestCert creates a self-signed test certificate for given domains
func generateTestCert(domains []string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}

	return string(pem.EncodeToMemory(certBlock)), string(pem.EncodeToMemory(keyBlock))
}

// generateTestCA creates a CA cert and signs a leaf cert
func generateTestCAAndLeaf(domains []string) (leafPEM, keyPEM, caPEM string) {
	// Generate CA key and cert
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caBlock := &pem.Block{Type: "CERTIFICATE", Bytes: caDER}

	// Generate leaf key and cert signed by CA
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafBlock := &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}

	return string(pem.EncodeToMemory(leafBlock)), string(pem.EncodeToMemory(keyBlock)), string(pem.EncodeToMemory(caBlock))
}

func countPEMBlocks(data string) int {
	count := 0
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		count++
	}
	return count
}

// --- AccountMatchesDirectory tests ---
//
// Guards the staging↔production self-heal: a stored account registered against
// the previous CA directory must NOT be reused against the current one (lego
// would skip registration and every order would fail).

func userWithRegistrationURI(uri string) *ACMEUser {
	u := &ACMEUser{}
	if uri != "" {
		u.Registration = &registration.Resource{URI: uri}
	}
	return u
}

func TestAccountMatchesDirectory_SameDirectory(t *testing.T) {
	prod := NewService(false, t.TempDir())
	user := userWithRegistrationURI("https://acme-v02.api.letsencrypt.org/acme/acct/123456")
	if !prod.AccountMatchesDirectory(user) {
		t.Error("expected production account to match production directory")
	}

	staging := NewService(true, t.TempDir())
	stagingUser := userWithRegistrationURI("https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456")
	if !staging.AccountMatchesDirectory(stagingUser) {
		t.Error("expected staging account to match staging directory")
	}
}

func TestAccountMatchesDirectory_StagingToProductionSwitch(t *testing.T) {
	// Account was registered against staging; service now points at production.
	prod := NewService(false, t.TempDir())
	stagingAccount := userWithRegistrationURI("https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456")
	if prod.AccountMatchesDirectory(stagingAccount) {
		t.Error("staging account must NOT match production directory (self-heal required)")
	}

	// And the reverse: production account against a staging service.
	staging := NewService(true, t.TempDir())
	prodAccount := userWithRegistrationURI("https://acme-v02.api.letsencrypt.org/acme/acct/123456")
	if staging.AccountMatchesDirectory(prodAccount) {
		t.Error("production account must NOT match staging directory (self-heal required)")
	}
}

func TestAccountMatchesDirectory_NoRegistration(t *testing.T) {
	prod := NewService(false, t.TempDir())
	if prod.AccountMatchesDirectory(nil) {
		t.Error("nil user must not match")
	}
	if prod.AccountMatchesDirectory(&ACMEUser{}) {
		t.Error("user with no registration must not match")
	}
	if prod.AccountMatchesDirectory(userWithRegistrationURI("")) {
		t.Error("user with empty registration URI must not match")
	}
}

// --- BuildFullchain tests ---

func TestBuildFullchain_NoDuplication(t *testing.T) {
	leafPEM, _, caPEM := generateTestCAAndLeaf([]string{"example.com"})

	// Simulate lego Bundle: true behavior (cert already contains leaf+intermediate)
	bundled := leafPEM + caPEM

	// issuerPEM is the same intermediate cert
	fullchain := BuildFullchain(bundled, caPEM)

	blocks := countPEMBlocks(fullchain)
	if blocks != 2 {
		t.Errorf("expected 2 PEM blocks (leaf + intermediate), got %d", blocks)
	}
}

func TestBuildFullchain_CertOnly(t *testing.T) {
	certPEM, _ := generateTestCert([]string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	fullchain := BuildFullchain(certPEM, "")
	blocks := countPEMBlocks(fullchain)
	if blocks != 1 {
		t.Errorf("expected 1 PEM block, got %d", blocks)
	}
}

func TestBuildFullchain_CertAndDifferentIssuer(t *testing.T) {
	leafPEM, _, caPEM := generateTestCAAndLeaf([]string{"example.com"})

	fullchain := BuildFullchain(leafPEM, caPEM)
	blocks := countPEMBlocks(fullchain)
	if blocks != 2 {
		t.Errorf("expected 2 PEM blocks (leaf + issuer), got %d", blocks)
	}
}

func TestBuildFullchain_EmptyInput(t *testing.T) {
	fullchain := BuildFullchain("", "")
	if fullchain != "" {
		t.Errorf("expected empty string for empty input, got %q", fullchain)
	}
}

func TestBuildFullchain_ProperNewlines(t *testing.T) {
	leafPEM, _, caPEM := generateTestCAAndLeaf([]string{"example.com"})

	fullchain := BuildFullchain(leafPEM, caPEM)

	// Should not have double newlines between blocks
	if strings.Contains(fullchain, "\n\n\n") {
		t.Error("fullchain contains triple newlines")
	}

	// Each block should end with proper END marker
	if !strings.Contains(fullchain, "-----END CERTIFICATE-----") {
		t.Error("fullchain missing END CERTIFICATE marker")
	}
}

func TestBuildFullchain_TripleDuplication(t *testing.T) {
	leafPEM, _, caPEM := generateTestCAAndLeaf([]string{"example.com"})

	// Worst case: bundled cert has leaf+intermediate, and issuer also has intermediate
	bundled := leafPEM + caPEM + caPEM // triple duplication
	fullchain := BuildFullchain(bundled, caPEM)

	blocks := countPEMBlocks(fullchain)
	if blocks != 2 {
		t.Errorf("expected 2 PEM blocks after dedup, got %d", blocks)
	}
}

// --- ValidateRenewedCertificate tests ---

func TestValidateRenewedCertificate_Valid(t *testing.T) {
	domains := []string{"example.com", "www.example.com"}
	certPEM, keyPEM := generateTestCert(domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	err := ValidateRenewedCertificate(certPEM, keyPEM, domains)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateRenewedCertificate_MismatchedKey(t *testing.T) {
	domains := []string{"example.com"}
	certPEM, _ := generateTestCert(domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM := generateTestCert(domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	err := ValidateRenewedCertificate(certPEM, otherKeyPEM, domains)
	if err == nil {
		t.Error("expected error for mismatched key, got nil")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("expected 'do not match' error, got: %v", err)
	}
}

func TestValidateRenewedCertificate_Expired(t *testing.T) {
	domains := []string{"example.com"}
	certPEM, keyPEM := generateTestCert(domains, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	err := ValidateRenewedCertificate(certPEM, keyPEM, domains)
	if err == nil {
		t.Error("expected error for expired cert, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' error, got: %v", err)
	}
}

func TestValidateRenewedCertificate_MissingDomain(t *testing.T) {
	certPEM, keyPEM := generateTestCert([]string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	err := ValidateRenewedCertificate(certPEM, keyPEM, []string{"example.com", "other.com"})
	if err == nil {
		t.Error("expected error for missing domain, got nil")
	}
	if !strings.Contains(err.Error(), "does not cover domain") {
		t.Errorf("expected 'does not cover domain' error, got: %v", err)
	}
}

func TestValidateRenewedCertificate_WildcardMatch(t *testing.T) {
	certPEM, keyPEM := generateTestCert([]string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	err := ValidateRenewedCertificate(certPEM, keyPEM, []string{"sub.example.com"})
	if err != nil {
		t.Errorf("expected wildcard to match sub.example.com, got error: %v", err)
	}
}

func TestValidateRenewedCertificate_WildcardNoMatchDeepSub(t *testing.T) {
	certPEM, keyPEM := generateTestCert([]string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	// *.example.com should NOT match deep.sub.example.com
	err := ValidateRenewedCertificate(certPEM, keyPEM, []string{"deep.sub.example.com"})
	if err == nil {
		t.Error("expected error for deep subdomain with wildcard, got nil")
	}
}

func TestValidateRenewedCertificate_EmptyDomains(t *testing.T) {
	domains := []string{"example.com"}
	certPEM, keyPEM := generateTestCert(domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	// Empty expected domains should pass (just validates cert-key pair)
	err := ValidateRenewedCertificate(certPEM, keyPEM, nil)
	if err != nil {
		t.Errorf("expected no error with empty expected domains, got: %v", err)
	}
}

func TestValidateRenewedCertificate_ECKey(t *testing.T) {
	domains := []string{"example.com"}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	err := ValidateRenewedCertificate(certPEM, keyPEM, domains)
	if err != nil {
		t.Errorf("expected no error for EC cert, got: %v", err)
	}
}
