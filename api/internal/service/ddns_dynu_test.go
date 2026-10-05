package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestMatchDynuDomain(t *testing.T) {
	domains := []dynuDomain{{ID: 1, Name: "home.example.org"}, {ID: 2, Name: "example.net"}}
	// exact match wins
	if d, ok := matchDynuDomain(domains, "home.example.org"); !ok || d.ID != 1 {
		t.Fatalf("exact: got %+v ok=%v", d, ok)
	}
	// subdomain -> longest suffix domain
	if d, ok := matchDynuDomain(domains, "vpn.example.net"); !ok || d.ID != 2 {
		t.Fatalf("suffix: got %+v ok=%v", d, ok)
	}
	// no match
	if _, ok := matchDynuDomain(domains, "nope.other.com"); ok {
		t.Fatalf("expected no match")
	}
}

func TestDynuUpdate_PostsIPv4ToMatchedDomain(t *testing.T) {
	var gotKey, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("API-Key")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dns":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"domains": []map[string]interface{}{{"id": 42, "name": "home.example.org"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/dns/42":
			gotPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"statusCode":200}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u := &dynuUpdater{client: srv.Client(), apiBase: srv.URL}
	creds, _ := json.Marshal(model.DynuCredentials{APIKey: "k123"})
	err := u.Update(context.Background(), model.DDNSRecord{Hostname: "home.example.org"}, creds, "203.0.113.7")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if gotKey != "k123" {
		t.Errorf("API-Key header = %q, want k123", gotKey)
	}
	if gotPath != "/dns/42" {
		t.Errorf("update path = %q, want /dns/42", gotPath)
	}
	if !strings.Contains(gotBody, `"ipv4Address":"203.0.113.7"`) {
		t.Errorf("body missing ipv4Address: %s", gotBody)
	}
}

func TestDynuUpdate_NoMatchingDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"domains": []map[string]interface{}{{"id": 1, "name": "other.example.com"}},
		})
	}))
	defer srv.Close()

	u := &dynuUpdater{client: srv.Client(), apiBase: srv.URL}
	creds, _ := json.Marshal(model.DynuCredentials{APIKey: "k"})
	err := u.Update(context.Background(), model.DDNSRecord{Hostname: "home.example.org"}, creds, "203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "no domain") {
		t.Fatalf("expected no-domain error, got %v", err)
	}
	// A hostname the account does not have is the operator's to fix: 400. (#312)
	if !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("no-domain error should carry ErrInvalidInput, got %v", err)
	}
}

// Dynu answers a wrong API key with 401 {"statusCode":401,"type":
// "Authentication Exception","message":"Failed."}. A refusal is the operator's
// to fix (400); a rate limit or a Dynu fault is not (500). Both requests —
// listing the domains and posting the IP — are classified the same way. (#312)
func TestDynuUpdate_ClassifiesRejections(t *testing.T) {
	cases := []struct {
		name       string
		listStatus int
		postStatus int
		want       string
	}{
		{"list 401", http.StatusUnauthorized, 0, "credentials"},
		{"list 403", http.StatusForbidden, 0, "credentials"},
		{"list 400", http.StatusBadRequest, 0, "input"},
		{"list 429", http.StatusTooManyRequests, 0, ""},
		{"list 500", http.StatusInternalServerError, 0, ""},
		{"update 401", http.StatusOK, http.StatusUnauthorized, "credentials"},
		{"update 400", http.StatusOK, http.StatusBadRequest, "input"},
		{"update 503", http.StatusOK, http.StatusServiceUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := tc.postStatus
				if r.Method == http.MethodGet {
					status = tc.listStatus
				}
				w.WriteHeader(status)
				if status == http.StatusOK {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"domains": []map[string]interface{}{{"id": 42, "name": "home.example.org"}},
					})
					return
				}
				fmt.Fprintf(w, `{"statusCode":%d,"message":"Failed."}`, status)
			}))
			defer srv.Close()

			u := &dynuUpdater{client: srv.Client(), apiBase: srv.URL}
			creds, _ := json.Marshal(model.DynuCredentials{APIKey: "k123"})
			err := u.Update(context.Background(), model.DDNSRecord{Hostname: "home.example.org"}, creds, "203.0.113.7")
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := ddnsErrKind(err); got != tc.want {
				t.Errorf("kind = %q, want %q (%v)", got, tc.want, err)
			}
		})
	}
}

// A key of only spaces gets past the save-time check, which only rejects an
// empty one. Either way the stored provider is the operator's to fix: 400, not
// 500, and Dynu is never asked. (#312)
func TestDynuUpdate_BlankAPIKeyIsInvalidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Dynu was asked %s %s with a blank key", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	u := &dynuUpdater{client: srv.Client(), apiBase: srv.URL}
	for _, key := range []string{"", "   "} {
		creds, _ := json.Marshal(model.DynuCredentials{APIKey: key})
		err := u.Update(context.Background(), model.DDNSRecord{Hostname: "home.example.org"}, creds, "203.0.113.7")
		if !errors.Is(err, model.ErrInvalidCredentials) {
			t.Errorf("key %q: want ErrInvalidCredentials, got %v", key, err)
		}
	}
}

func TestDynuUpdate_MissingAPIKey(t *testing.T) {
	u := newDynuUpdater()
	creds, _ := json.Marshal(model.DynuCredentials{APIKey: ""})
	err := u.Update(context.Background(), model.DDNSRecord{Hostname: "x.example.org"}, creds, "203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("expected missing api_key error, got %v", err)
	}
}
