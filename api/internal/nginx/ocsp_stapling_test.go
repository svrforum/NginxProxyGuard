package nginx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// writeTestCert writes a fullchain whose leaf names the given OCSP responders.
func writeTestCert(t *testing.T, path string, ocsp ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(359),
		Subject:      pkix.Name{CommonName: "ocsp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		OCSPServer:   ocsp,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCertLacksOCSPResponder(t *testing.T) {
	dir := t.TempDir()
	without, with := filepath.Join(dir, "le.pem"), filepath.Join(dir, "ocsp.pem")
	writeTestCert(t, without)
	writeTestCert(t, with, "http://ocsp.example.com")
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		without:                       true,
		with:                          false,
		filepath.Join(dir, "missing"): false, // unreadable: nginx decides, as before
		garbage:                       false,
	} {
		if got := certLacksOCSPResponder(path); got != want {
			t.Errorf("%s: got %v, want %v", filepath.Base(path), got, want)
		}
	}
}

// With ssl_stapling on in the http block, nginx warns about every certificate
// without an OCSP responder on each reload (#359). A server block whose
// certificate has none switches stapling off; one whose certificate has one
// keeps stapling; a host's own ssl_stapling in Advanced Config is left alone,
// since a second one in the same block fails nginx -t.
func TestStaplingOffOnlyForCertsWithoutOCSPResponder(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000359"
	for _, tt := range []struct {
		name     string
		ocsp     []string
		advanced string
		wantOff  bool
	}{
		{"no responder", nil, "", true},
		{"responder", []string{"http://ocsp.example.com"}, "", false},
		{"no responder, own ssl_stapling", nil, "ssl_stapling on;", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := newRequestPathTestManager(t)
			h := goldenSSLHost(id, "ocsp.example.com")
			h.AdvancedConfig = tt.advanced
			writeTestCert(t, filepath.Join(m.certsPath, *h.CertificateID, "fullchain.pem"), tt.ocsp...)
			if err := m.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: h, GlobalSettings: baseGlobalSettings()}); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(h)))
			if err != nil {
				t.Fatal(err)
			}
			out := string(b)
			if !strings.Contains(out, "ssl_certificate /etc/nginx/certs/") {
				t.Fatal("SSL server block missing")
			}
			if got := strings.Contains(out, "ssl_stapling off;"); got != tt.wantOff {
				t.Errorf("ssl_stapling off rendered = %v, want %v", got, tt.wantOff)
			}
			if n := strings.Count(out, "ssl_stapling "); n > 1 {
				t.Errorf("%d ssl_stapling directives in one server block", n)
			}
		})
	}

	t.Run("redirect host", func(t *testing.T) {
		m, _ := newRequestPathTestManager(t)
		certID := "00000000-0000-0000-0000-0000000003b9"
		host := &model.RedirectHost{ID: id, DomainNames: []string{"old.example.com"}, ForwardScheme: "https",
			ForwardDomainName: "new.example.com", RedirectCode: 301, SSLEnabled: true, CertificateID: &certID, Enabled: true}
		writeTestCert(t, filepath.Join(m.certsPath, certID, "fullchain.pem"))
		if err := m.GenerateRedirectConfig(context.Background(), host); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(m.configPath, GetRedirectConfigFilename(host)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "ssl_stapling off;") {
			t.Error("redirect host with a certificate without OCSP responder keeps stapling")
		}
	})
}
