package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestCloudflareARecordBody(t *testing.T) {
	b := cloudflareARecordBody("home.example.com", "203.0.113.7", true, 1)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "A" || m["name"] != "home.example.com" || m["content"] != "203.0.113.7" {
		t.Fatalf("bad body: %s", b)
	}
	if m["proxied"] != true {
		t.Fatalf("proxied not set: %s", b)
	}
}

func TestCloudflareUpdaterUpsert(t *testing.T) {
	var putHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records"):
			// existing A record found
			w.Write([]byte(`{"success":true,"result":[{"id":"rec123","type":"A","name":"home.example.com","content":"1.1.1.1"}]}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/dns_records/rec123"):
			putHit = true
			w.Write([]byte(`{"success":true,"result":{"id":"rec123"}}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()

	u := &cloudflareUpdater{client: srv.Client(), apiBase: srv.URL}
	creds, _ := json.Marshal(model.CloudflareCredentials{APIToken: "t", ZoneID: "0123456789abcdef0123456789abcdef"})
	rec := model.DDNSRecord{Hostname: "home.example.com", RecordType: "A", Proxied: true, TTL: 1}
	if err := u.Update(context.Background(), rec, creds, "203.0.113.7"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !putHit {
		t.Fatal("expected PUT to update existing record")
	}
}
