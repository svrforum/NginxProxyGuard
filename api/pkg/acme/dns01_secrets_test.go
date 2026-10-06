package acme

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	legolog "github.com/go-acme/lego/v4/log"

	"nginx-proxy-guard/internal/model"
)

// duckTestToken is a fake DuckDNS token. Nothing a failed DNS-01 attempt
// reports may carry it.
const duckTestToken = "7d0c5a8e-3b1f-4c2a-9e6d-1f2a3b4c5d6e"

const duckTestDomain = "home.duckdns.org"

// newFakeACME is just enough of an ACME server (RFC 8555) for lego to reach the
// DNS-01 challenge: a directory, nonces, an account, and one order whose one
// authorization offers dns-01. It validates nothing; the DNS provider fails
// before there is anything to validate. It is a loopback TLS server, because
// lego refuses a directory that is not HTTPS.
func newFakeACME(t *testing.T, domain string) *httptest.Server {
	t.Helper()
	var (
		srv   *httptest.Server
		mu    sync.Mutex
		nonce int
	)
	reply := func(w http.ResponseWriter, status int, body any) {
		mu.Lock()
		nonce++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce))
		mu.Unlock()
		if body == nil {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
			"revokeCert": srv.URL + "/revoke",
			"keyChange":  srv.URL + "/key-change",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, nil)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/account/1")
		reply(w, http.StatusCreated, map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		reply(w, http.StatusCreated, map[string]any{
			"status":         "pending",
			"identifiers":    []map[string]string{{"type": "dns", "value": domain}},
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize/1",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": domain},
			"challenges": []map[string]string{{
				"type": "dns-01", "status": "pending",
				"url": srv.URL + "/challenge/1", "token": "dns01-challenge-token",
			}},
		})
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	// lego builds its own HTTP client; this is how it is told to trust the
	// test server's certificate.
	caFile := filepath.Join(t.TempDir(), "fake-acme-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	return srv
}

type duckRoundTrip func(*http.Request) (*http.Response, error)

func (f duckRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// lockedBuffer collects lego's log output, which may be written from more
// than one goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A DNS-01 issuance and a renewal through the real lego and its DuckDNS client,
// failing at the DuckDNS update. DuckDNS takes the token in the query string,
// and lego quotes the update URL when DuckDNS answers anything but OK and,
// through net/http, when it cannot be reached. The error ObtainCertificate or
// RenewCertificate returns is what the certificate service stores in
// certificates.error_message and the history and sends in the
// cert.renewal_failed notification, and lego prints the failed clean-up through
// its own logger into the container log. Neither may carry the token; both must
// still say what went wrong.
//
// No request leaves the machine: the ACME server is a loopback test server,
// DuckDNS is answered by a stand-in for http.DefaultTransport (lego's DuckDNS
// client has no transport of its own), and CNAME following, which would query
// public DNS for the challenge record, is switched off.
func TestDNS01FailureKeepsTheDuckDNSTokenOutOfErrorsAndLogs(t *testing.T) {
	cases := []struct {
		name   string
		answer func(*http.Request) (*http.Response, error)
		want   string // what the error must still say
	}{
		{
			name: "token rejected",
			answer: func(r *http.Request) (*http.Response, error) {
				return duckAnswer(r, http.StatusOK, "KO"), nil
			},
			want: "returned the following result (KO)",
		},
		{
			name: "unreachable",
			answer: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp 192.0.2.10:443: connect: connection refused")
			},
			want: "connection refused",
		},
		{
			name: "answer echoes the request",
			answer: func(r *http.Request) (*http.Response, error) {
				return duckAnswer(r, http.StatusOK, "blocked: "+r.URL.String()), nil
			},
			want: "blocked: https://www.duckdns.org/update",
		},
	}

	certPEM, keyPEM := generateTestCert([]string{duckTestDomain}, time.Now().Add(-time.Hour), time.Now().Add(240*time.Hour))
	entryPoints := []struct {
		name    string
		attempt func(*Service, *model.DNSProvider) error
	}{
		{"issuance", func(svc *Service, provider *model.DNSProvider) error {
			_, _, err := svc.ObtainCertificate("admin@example.com", []string{duckTestDomain}, provider, nil)
			return err
		}},
		{"renewal", func(svc *Service, provider *model.DNSProvider) error {
			user, err := svc.createUser("admin@example.com")
			if err != nil {
				return err
			}
			_, err = svc.RenewCertificate(certPEM, keyPEM, provider, user)
			return err
		}},
	}

	for _, tc := range cases {
		for _, entry := range entryPoints {
			t.Run(entry.name+": "+tc.name, func(t *testing.T) {
				acmeServer := newFakeACME(t, duckTestDomain)
				t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")

				var duckCalls int
				prevTransport := http.DefaultTransport
				http.DefaultTransport = duckRoundTrip(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host != "www.duckdns.org" {
						t.Errorf("unexpected request to %s", r.URL.Host)
						return nil, errors.New("unexpected request")
					}
					duckCalls++
					return tc.answer(r)
				})
				t.Cleanup(func() { http.DefaultTransport = prevTransport })

				var legoLog lockedBuffer
				prevLogger := legolog.Logger
				legolog.Logger = log.New(&legoLog, "", 0)
				t.Cleanup(func() { legolog.Logger = prevLogger })

				creds, _ := json.Marshal(model.DuckDNSCredentials{Token: duckTestToken})
				provider := &model.DNSProvider{ProviderType: model.DNSProviderDuckDNS, Credentials: creds}
				svc := &Service{caURL: acmeServer.URL + "/directory", certsDir: t.TempDir(), webrootDir: t.TempDir()}

				err := entry.attempt(svc, provider)
				if err == nil {
					t.Fatal("expected the DNS-01 attempt to fail")
				}
				// Present, then the clean-up after the failure.
				if duckCalls < 2 {
					t.Fatalf("DuckDNS was asked %d time(s), want the update and the clean-up", duckCalls)
				}
				msg, logged := err.Error(), legoLog.String()
				if !strings.Contains(msg, tc.want) {
					t.Errorf("the error lost the diagnosis %q: %s", tc.want, msg)
				}
				if !strings.Contains(logged, "cleaning up failed") {
					t.Errorf("lego did not log the failed clean-up, so the log path was not exercised:\n%s", logged)
				}
				for where, text := range map[string]string{"error": msg, "lego log": logged} {
					for _, form := range []string{duckTestToken, url.QueryEscape(duckTestToken)} {
						if strings.Contains(text, form) {
							t.Errorf("the DuckDNS token reaches the %s: %s", where, text)
						}
					}
				}
			})
		}
	}
}

func duckAnswer(r *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}
}
