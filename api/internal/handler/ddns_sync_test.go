package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// syncTestToken is a fake DuckDNS token. It must not show up anywhere a sync's
// outcome is reported.
const syncTestToken = "duck-secret-7f3a"

// syncRecordRepo is the part of the DDNS record repository SyncOne uses. It
// keeps what would be written to ddns_records.
type syncRecordRepo struct {
	rec       model.DDNSRecord
	status    string
	lastError string
}

var errNotUsed = errors.New("not used by SyncOne")

func (r *syncRecordRepo) Create(context.Context, *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, errNotUsed
}

func (r *syncRecordRepo) GetByID(context.Context, string) (*model.DDNSRecord, error) {
	rec := r.rec
	return &rec, nil
}

func (r *syncRecordRepo) List(context.Context, int, int) ([]model.DDNSRecord, int, error) {
	return nil, 0, errNotUsed
}

func (r *syncRecordRepo) Update(context.Context, string, *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, errNotUsed
}

func (r *syncRecordRepo) Delete(context.Context, string) error { return errNotUsed }

func (r *syncRecordRepo) ListEnabled(context.Context) ([]model.DDNSRecord, error) {
	return nil, errNotUsed
}

func (r *syncRecordRepo) ListByProxyHost(context.Context, string) ([]model.DDNSRecord, error) {
	return nil, errNotUsed
}

func (r *syncRecordRepo) UpdateStatus(_ context.Context, _, _, status, errMsg string, _ time.Time) error {
	r.status, r.lastError = status, errMsg
	return nil
}

type syncProviderRepo struct{ provider model.DNSProvider }

func (p syncProviderRepo) GetByID(context.Context, string) (*model.DNSProvider, error) {
	provider := p.provider
	return &provider, nil
}

type syncIPDetector struct{}

func (syncIPDetector) DetectPublicIPv4(context.Context) (string, error) { return "203.0.113.7", nil }

// roundTripFunc stands in for the network. The DuckDNS updater builds its own
// http.Client without a Transport, so it goes through http.DefaultTransport;
// swapping that is how the real service and updater are reached from here
// without a request leaving the machine.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func textResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}
}

// POST /ddns-records/:id/sync through the real service and DuckDNS updater.
// A provider that answered and refused is the operator's to fix: 400 with its
// reason (#312). A provider outage or a provider that cannot be reached is not,
// and stays 500 (ca46235). In every case the token, which DuckDNS takes in the
// query string, stays out of the response, the stored last_error and the log.
func TestDDNSSyncOneStatusFollowsTheProviderAnswer(t *testing.T) {
	cases := []struct {
		name       string
		answer     func(*http.Request) (*http.Response, error)
		wantStatus int
		wantText   string // in the response and in the stored last_error
	}{
		{
			name: "token rejected",
			answer: func(r *http.Request) (*http.Response, error) {
				return textResponse(r, http.StatusOK, "KO"), nil
			},
			wantStatus: http.StatusBadRequest,
			wantText:   "duckdns update failed: KO",
		},
		{
			name: "provider outage",
			answer: func(r *http.Request) (*http.Response, error) {
				// An error page that reflects the request URL, token and all.
				return textResponse(r, http.StatusServiceUnavailable, "<html>"+r.URL.String()+"</html>"), nil
			},
			wantStatus: http.StatusInternalServerError,
			wantText:   "HTTP 503",
		},
		{
			name: "unreachable",
			answer: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp 192.0.2.10:443: connect: connection refused")
			},
			wantStatus: http.StatusInternalServerError,
			wantText:   "connection refused",
		},
		{
			name: "unexpected answer",
			answer: func(r *http.Request) (*http.Response, error) {
				// A 200 block page from an intercepting proxy, quoting the
				// request URL. The body is kept; the token in it is not.
				return textResponse(r, http.StatusOK, "<html>blocked: "+r.URL.String()+"</html>"), nil
			},
			wantStatus: http.StatusInternalServerError,
			wantText:   "blocked: https://www.duckdns.org/update?domains=myhome",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked string
			prevTransport := http.DefaultTransport
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				asked = r.URL.Host
				return tc.answer(r)
			})
			t.Cleanup(func() { http.DefaultTransport = prevTransport })

			var logs bytes.Buffer
			prevLog := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(prevLog) })

			creds, _ := json.Marshal(model.DuckDNSCredentials{Token: syncTestToken})
			records := &syncRecordRepo{rec: model.DDNSRecord{ID: "rec-1", Hostname: "myhome.duckdns.org", DNSProviderID: "prov-1", Enabled: true}}
			providers := syncProviderRepo{provider: model.DNSProvider{ID: "prov-1", ProviderType: model.DNSProviderDuckDNS, Credentials: creds}}
			h := NewDDNSHandler(service.NewDDNSService(records, providers, syncIPDetector{}), nil)

			rec := httptest.NewRecorder()
			c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/api/v1/ddns-records/rec-1/sync", nil), rec)
			c.SetParamNames("id")
			c.SetParamValues("rec-1")
			if err := h.SyncOne(c); err != nil {
				t.Fatalf("SyncOne returned an error instead of writing a response: %v", err)
			}

			if asked != "www.duckdns.org" {
				t.Fatalf("the updater asked %q, want www.duckdns.org", asked)
			}
			body := rec.Body.String()
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, body)
			}
			if !strings.Contains(body, tc.wantText) {
				t.Errorf("response %s does not carry %q", body, tc.wantText)
			}

			// What UpdateStatus stores: the repository passes it through
			// persistedErrorText, which is this scrub.
			stored := database.ScrubDriverText(records.lastError)
			if records.status != model.DDNSStatusError || !strings.Contains(stored, tc.wantText) {
				t.Errorf("stored status %q, last_error %q; want %q carrying %q", records.status, stored, model.DDNSStatusError, tc.wantText)
			}

			for where, text := range map[string]string{"response": body, "last_error": stored, "log": logs.String()} {
				if strings.Contains(text, syncTestToken) {
					t.Errorf("the DuckDNS token leaks into the %s: %s", where, text)
				}
			}
		})
	}
}
