package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestBuildDuckDNSURL(t *testing.T) {
	got := buildDuckDNSURL("https://www.duckdns.org", "myhome.duckdns.org", "tok-123", "203.0.113.7")
	want := "https://www.duckdns.org/update?domains=myhome&ip=203.0.113.7&token=tok-123"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDuckDNSUpdaterOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer srv.Close()
	u := &duckDNSUpdater{client: srv.Client(), base: srv.URL}
	creds, _ := json.Marshal(model.DuckDNSCredentials{Token: "tok-123"})
	rec := model.DDNSRecord{Hostname: "myhome.duckdns.org"}
	if err := u.Update(context.Background(), rec, creds, "203.0.113.7"); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestDuckDNSUpdaterKO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("KO"))
	}))
	defer srv.Close()
	u := &duckDNSUpdater{client: srv.Client(), base: srv.URL}
	creds, _ := json.Marshal(model.DuckDNSCredentials{Token: "tok-123"})
	if err := u.Update(context.Background(), model.DDNSRecord{Hostname: "x.duckdns.org"}, creds, "1.2.3.4"); err == nil {
		t.Fatal("expected error on KO response")
	}
}
