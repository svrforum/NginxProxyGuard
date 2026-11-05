package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"

	"nginx-proxy-guard/internal/model"
)

// issuingACME is a fake ACME server (RFC 8555) that issues: its one
// authorization is already valid, so lego skips the challenge, and finalize
// signs the CSR with a throwaway CA. It records the public key of every CSR,
// which is the key the certificate was issued for. It validates nothing.
type issuingACME struct {
	srv     *httptest.Server
	mu      sync.Mutex
	nonce   int
	chain   []byte
	csrKeys []crypto.PublicKey
}

func newIssuingACME(t *testing.T, domain string) *issuingACME {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake acme ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	f := &issuingACME{}
	reply := func(w http.ResponseWriter, status int, body any) {
		f.mu.Lock()
		f.nonce++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", f.nonce))
		f.mu.Unlock()
		if body == nil {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	order := func(status string) map[string]any {
		o := map[string]any{
			"status":         status,
			"identifiers":    []map[string]string{{"type": "dns", "value": domain}},
			"authorizations": []string{f.srv.URL + "/authz/1"},
			"finalize":       f.srv.URL + "/finalize/1",
		}
		if status == "valid" {
			o["certificate"] = f.srv.URL + "/cert/1"
		}
		return o
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, map[string]string{
			"newNonce":   f.srv.URL + "/nonce",
			"newAccount": f.srv.URL + "/account",
			"newOrder":   f.srv.URL + "/order",
			"revokeCert": f.srv.URL + "/revoke",
			"keyChange":  f.srv.URL + "/key-change",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, nil)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", f.srv.URL+"/account/1")
		reply(w, http.StatusCreated, map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", f.srv.URL+"/order/1")
		reply(w, http.StatusCreated, order("pending"))
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, order("valid"))
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"type": "dns", "value": domain},
			"challenges": []map[string]string{{
				"type": "http-01", "status": "valid",
				"url": f.srv.URL + "/challenge/1", "token": "http01-token",
			}},
		})
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		csr, err := csrFromJWS(r.Body)
		if err != nil {
			t.Errorf("finalize: %v", err)
			reply(w, http.StatusBadRequest, nil)
			return
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: domain},
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			t.Errorf("sign the CSR: %v", err)
			reply(w, http.StatusInternalServerError, nil)
			return
		}
		f.mu.Lock()
		f.csrKeys = append(f.csrKeys, csr.PublicKey)
		f.chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
		f.mu.Unlock()
		w.Header().Set("Location", f.srv.URL+"/order/1")
		reply(w, http.StatusOK, order("valid"))
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		chain := f.chain
		f.nonce++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", f.nonce))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(chain)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)

	// lego builds its own HTTP client; this is how it trusts the test server.
	caFile := filepath.Join(t.TempDir(), "issuing-acme-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	return f
}

// keys returns the kinds of the CSR keys seen so far.
func (f *issuingACME) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	kinds := make([]string, len(f.csrKeys))
	for i, k := range f.csrKeys {
		kinds[i] = keyKind(k)
	}
	return kinds
}

// csrFromJWS reads the CSR out of a finalize request's flattened JWS.
func csrFromJWS(body io.Reader) (*x509.CertificateRequest, error) {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(body).Decode(&jws); err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, err
	}
	var fin struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &fin); err != nil {
		return nil, err
	}
	der, err := base64.RawURLEncoding.DecodeString(fin.CSR)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// keyKind names a key the way the key types do: rsa2048, ec256, ec384.
func keyKind(key any) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return fmt.Sprintf("ec%d", k.Curve.Params().BitSize)
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ec%d", k.Curve.Params().BitSize)
	}
	return fmt.Sprintf("%T", key)
}

func TestLegoKeyType(t *testing.T) {
	for keyType, want := range map[string]certcrypto.KeyType{
		model.CertKeyTypeRSA2048: certcrypto.RSA2048,
		model.CertKeyTypeEC256:   certcrypto.EC256,
		model.CertKeyTypeEC384:   certcrypto.EC384,
		"":                       certcrypto.RSA2048, // rows from before #364
	} {
		if got := legoKeyType(keyType); got != want {
			t.Errorf("legoKeyType(%q) = %s, want %s", keyType, got, want)
		}
	}
}

// The certificate is issued for a key of the type it was created with (#364).
func TestIssuanceUsesTheCertificatesKeyType(t *testing.T) {
	for keyType, want := range map[string]string{
		model.CertKeyTypeRSA2048: "rsa2048",
		model.CertKeyTypeEC256:   "ec256",
		model.CertKeyTypeEC384:   "ec384",
		"":                       "rsa2048",
	} {
		t.Run(want+"/"+keyType, func(t *testing.T) {
			ca := newIssuingACME(t, "key.example.com")
			svc := &Service{caURL: ca.srv.URL + "/directory", certsDir: t.TempDir(), webrootDir: t.TempDir()}

			result, _, err := svc.ObtainCertificateHTTP("admin@example.com", []string{"key.example.com"}, nil, keyType)
			if err != nil {
				t.Fatalf("obtain: %v", err)
			}
			key, err := certcrypto.ParsePEMPrivateKey([]byte(result.PrivateKeyPEM))
			if err != nil {
				t.Fatalf("parse the issued key: %v", err)
			}
			if got := keyKind(key); got != want {
				t.Errorf("issued key = %s, want %s", got, want)
			}
			if got := ca.keys(); len(got) != 1 || got[0] != want {
				t.Errorf("CSR keys = %v, want [%s]", got, want)
			}
		})
	}
}

// A renewal keeps the certificate's key, so an ECDSA certificate stays one.
func TestRenewalKeepsTheCertificatesKey(t *testing.T) {
	ca := newIssuingACME(t, "key.example.com")
	svc := &Service{caURL: ca.srv.URL + "/directory", certsDir: t.TempDir(), webrootDir: t.TempDir()}

	first, user, err := svc.ObtainCertificateHTTP("admin@example.com", []string{"key.example.com"}, nil, model.CertKeyTypeEC256)
	if err != nil {
		t.Fatalf("obtain: %v", err)
	}
	renewed, err := svc.RenewCertificateHTTP(first.CertificatePEM, first.PrivateKeyPEM, user, model.CertKeyTypeEC256)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	firstKey, err := certcrypto.ParsePEMPrivateKey([]byte(first.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	renewedKey, err := certcrypto.ParsePEMPrivateKey([]byte(renewed.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !firstKey.(*ecdsa.PrivateKey).Equal(renewedKey) {
		t.Errorf("renewal changed the key: %s became %s", keyKind(firstKey), keyKind(renewedKey))
	}
	if got := ca.keys(); len(got) != 2 || got[1] != "ec256" {
		t.Errorf("CSR keys = %v, want the renewal's to be ec256", got)
	}
}
