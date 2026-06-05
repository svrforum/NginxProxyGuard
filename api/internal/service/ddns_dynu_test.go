package service

import (
	"context"
	"encoding/json"
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
}

func TestDynuUpdate_MissingAPIKey(t *testing.T) {
	u := newDynuUpdater()
	creds, _ := json.Marshal(model.DynuCredentials{APIKey: ""})
	err := u.Update(context.Background(), model.DDNSRecord{Hostname: "x.example.org"}, creds, "203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("expected missing api_key error, got %v", err)
	}
}
