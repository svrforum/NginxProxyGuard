package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"net/http"
	"net/http/httptest"
	"nginx-proxy-guard/internal/database"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

func TestInfomaniakUpdate(t *testing.T) {
	const ip = "203.0.113.7"
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
		success    bool
	}{
		{"updated", "successfully_changed " + ip, 200, nil, true},
		{"unchanged", "no_change " + ip + "\n", 200, nil, true},
		{"legacy updated", "good " + ip, 200, nil, true},
		{"legacy unchanged", "nochg " + ip, 200, nil, true},
		{"wrong IP", "good 203.0.113.8", 200, nil, false},
		{"no IP", "good", 200, nil, false},
		{"invalid IP", "good invalid", 200, nil, false},
		{"wrong prefix", "goodbye " + ip, 200, nil, false},
		{"extra fields", "good " + ip + " ignored", 200, nil, false},
		{"bad credentials", "badauth", 400, model.ErrInvalidCredentials, false},
		{"bad credentials with 200", "badauth", 200, model.ErrInvalidCredentials, false},
		{"missing hostname", "nohost", 400, model.ErrInvalidInput, false},
		{"missing hostname with 200", "nohost", 200, model.ErrInvalidInput, false},
		{"unauthorized", "", 401, model.ErrInvalidCredentials, false},
		{"forbidden", "", 403, model.ErrInvalidCredentials, false},
		{"rate limited", "badauth", 429, nil, false},
		{"unavailable", "badauth", 503, nil, false},
		{"timeout", "", 408, nil, false},
		{"html", "<html>dyn-user dyn-password</html>", 200, nil, false},
		{"oversized", strings.Repeat("x", 1025), 200, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, password, ok := r.BasicAuth()
				if !ok || user != "dyn-user" || password != "dyn-password" {
					t.Error("incorrect Basic Auth")
				}
				if r.Method != http.MethodGet || r.URL.Path != "/nic/update" || r.URL.Query().Get("hostname") != "home.example.com" || r.URL.Query().Get("myip") != ip {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				if strings.Contains(r.URL.String(), "dyn-") {
					t.Error("credentials leaked into URL")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			u := &infomaniakUpdater{client: srv.Client(), endpoint: srv.URL + "/nic/update"}
			err := u.Update(context.Background(), model.DDNSRecord{Hostname: "home.example.com"}, json.RawMessage(`{"username":"dyn-user","password":"dyn-password"}`), ip)
			if (err == nil) != tc.success {
				t.Fatalf("err = %v, success = %v", err, tc.success)
			}
			for _, sentinel := range []error{model.ErrInvalidCredentials, model.ErrInvalidInput} {
				if errors.Is(err, sentinel) != (tc.want == sentinel) {
					t.Errorf("err = %v, want sentinel %v", err, tc.want)
				}
			}
			if err != nil && strings.Contains(err.Error(), "dyn-") {
				t.Fatal("credentials leaked in error")
			}
		})
	}
}

func TestInfomaniakCredentialValidation(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `invalid`, `{"username":"x"}`, `{"password":"x"}`, `{"username":" ","password":"x"}`, `{"username":"x","password":" "}`, `{"username":"x:y","password":"z"}`} {
		creds := json.RawMessage(raw)
		p := model.DNSProvider{ProviderType: model.DNSProviderInfomaniak, Credentials: creds}
		if !errors.Is(p.ValidateCredentials(), model.ErrInvalidCredentials) {
			t.Errorf("model accepted %s", raw)
		}
		if err := (&repository.DNSProviderRepository{}).TestConnection(context.Background(), model.DNSProviderInfomaniak, creds); !errors.Is(err, model.ErrInvalidCredentials) {
			t.Errorf("repository accepted %s: %v", raw, err)
		}
		// An invalid configuration must be rejected before any network request.
		if err := (&infomaniakUpdater{}).Update(context.Background(), model.DDNSRecord{}, creds, "203.0.113.7"); !errors.Is(err, model.ErrInvalidCredentials) {
			t.Errorf("updater accepted %s: %v", raw, err)
		}
	}
	creds := json.RawMessage(`{"username":"user","password":"password"}`)
	if err := (&repository.DNSProviderRepository{}).TestConnection(context.Background(), model.DNSProviderInfomaniak, creds); err != nil {
		t.Fatal(err)
	}
	p := model.DNSProvider{ProviderType: model.DNSProviderInfomaniak, Credentials: creds}
	if err := p.ValidateCredentials(); err != nil {
		t.Fatal(err)
	}
	masked := p.MaskCredentials()
	if !masked.HasCredentials || masked.Credentials != nil {
		t.Fatal("credentials were not masked")
	}
	for _, ip := range []string{"", "invalid", "2001:db8::1"} {
		if err := (&infomaniakUpdater{}).Update(context.Background(), model.DDNSRecord{}, creds, ip); !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("accepted IP %q: %v", ip, err)
		}
	}
}

func TestInfomaniakRedirectAndCancellation(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	u := newInfomaniakUpdater()
	u.endpoint = srv.URL
	creds := json.RawMessage(`{"username":"user","password":"password"}`)
	if err := u.Update(context.Background(), model.DDNSRecord{}, creds, "203.0.113.7"); err == nil {
		t.Fatal("redirect was accepted")
	}
	if calls != 0 {
		t.Fatal("redirect was followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := u.Update(ctx, model.DDNSRecord{}, creds, "203.0.113.7"); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	svc := NewDDNSService(nil, nil, nil)
	if _, ok := svc.updaters[model.DNSProviderInfomaniak].(*infomaniakUpdater); !ok {
		t.Fatal("Infomaniak updater is not registered")
	}
	if _, ok := svc.updaters[model.DNSProviderInfomaniak].(ddnsDeleter); ok {
		t.Fatal("Infomaniak must not delete remote records")
	}
}

func TestInfomaniakProxyHostOptIn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT id, name, provider_type").WithArgs("p1").WillReturnRows(
		sqlmock.NewRows([]string{"id", "name", "provider_type", "credentials", "is_default", "created_at", "updated_at"}).
			AddRow("p1", "Infomaniak", model.DNSProviderInfomaniak, []byte(`{"username":"user","password":"password"}`), false, time.Now(), time.Now()))
	svc := &ProxyHostService{dnsProviderRepo: repository.NewDNSProviderRepository(&database.DB{DB: db})}
	id := "p1"
	if err := svc.validateDDNSOptIn(context.Background(), true, &id); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
