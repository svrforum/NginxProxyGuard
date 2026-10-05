package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// A proxy (orange-cloud) toggle with an unchanged IP must still PUT — the bug in
// #215 was comparing only the record content (IP) and skipping the update. The
// existing record here already has the target IP but proxied=false; flipping the
// managed record to proxied=true must reach Cloudflare.
func TestCloudflareUpdaterProxiedChangeForcesPut(t *testing.T) {
	var putHit bool
	var putBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records"):
			// existing record already points at the target IP, but is NOT proxied
			w.Write([]byte(`{"success":true,"result":[{"id":"rec123","type":"A","name":"home.example.com","content":"203.0.113.7","proxied":false,"ttl":1}]}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/dns_records/rec123"):
			putHit = true
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &putBody)
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
		t.Fatal("expected PUT when only proxied changed (unchanged IP)")
	}
	if putBody["proxied"] != true {
		t.Fatalf("expected PUT body proxied=true, got: %v", putBody)
	}
}

// A record that already matches every managed field (IP, proxied, TTL) must NOT
// PUT — otherwise every sync would rewrite unchanged records.
func TestCloudflareUpdaterNoChangeSkipsPut(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records"):
			w.Write([]byte(`{"success":true,"result":[{"id":"rec123","type":"A","name":"home.example.com","content":"203.0.113.7","proxied":true,"ttl":1}]}`))
		case r.Method == "PUT" || r.Method == "POST":
			wrote = true
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
	if wrote {
		t.Fatal("expected no write when record already matches (IP+proxied+TTL)")
	}
}

// A refusal from the API is the operator's to fix (400): a wrong token or key
// comes back 401/403 — live, a fake token got 401 code 10000 "Authentication
// error" on a zone path and 403 code 9109 "Invalid access token" on /zones —
// and a zone or record the account does not have comes back as another 4xx.
// A malformed token got 400 code 6003, so it lands on the 4xx rule: still 400.
// A timeout, a rate limit, a Cloudflare fault, a page that is not the API's
// JSON, or JSON without the API's errors list (what a gateway in front may
// send) stays a plain error (500). (#312)
func TestCloudflareUpdaterClassifiesRejections(t *testing.T) {
	apiErr := func(code int, msg string) string {
		return `{"success":false,"errors":[{"code":` + strconv.Itoa(code) + `,"message":"` + msg + `"}],"result":null}`
	}
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"wrong token", http.StatusForbidden, apiErr(9109, "Invalid access token"), "credentials"},
		{"authentication error", http.StatusUnauthorized, apiErr(10000, "Authentication error"), "credentials"},
		{"malformed token", http.StatusBadRequest, apiErr(6003, "Invalid request headers"), "input"},
		{"not found", http.StatusNotFound, apiErr(0, "zone not found"), "input"},
		{"request timeout", http.StatusRequestTimeout, apiErr(0, "request timeout"), ""},
		{"rate limited", http.StatusTooManyRequests, apiErr(0, "rate limited"), ""},
		{"server error", http.StatusInternalServerError, apiErr(0, "internal error"), ""},
		{"edge page", http.StatusForbidden, "<html>Attention Required!</html>", ""},
		{"empty object", http.StatusForbidden, `{}`, ""},
		{"null", http.StatusForbidden, `null`, ""},
		{"gateway message", http.StatusForbidden, `{"message":"Forbidden"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			u := &cloudflareUpdater{client: srv.Client(), apiBase: srv.URL}
			creds, _ := json.Marshal(model.CloudflareCredentials{APIToken: "t", ZoneID: "0123456789abcdef0123456789abcdef"})
			rec := model.DDNSRecord{Hostname: "home.example.com", RecordType: "A", Proxied: true, TTL: 1}
			err := u.Update(context.Background(), rec, creds, "203.0.113.7")
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := ddnsErrKind(err); got != tc.want {
				t.Errorf("kind = %q, want %q (%v)", got, tc.want, err)
			}
		})
	}
}

// Without a Zone ID the zone is guessed from the last two labels. A guess
// Cloudflare does not know, or a hostname too short to guess from, is fixed by
// setting the Zone ID — the operator's to do, so 400, not 500. (#312)
func TestCloudflareUpdaterZoneProblemsAreInvalidInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer srv.Close()

	u := &cloudflareUpdater{client: srv.Client(), apiBase: srv.URL}
	creds, _ := json.Marshal(model.CloudflareCredentials{APIToken: "t"})
	for _, host := range []string{"home.example.co.uk", "localhost"} {
		err := u.Update(context.Background(), model.DDNSRecord{Hostname: host}, creds, "203.0.113.7")
		if err == nil {
			t.Errorf("%s: expected an error", host)
			continue
		}
		if got := ddnsErrKind(err); got != "input" {
			t.Errorf("%s: kind = %q, want input (%v)", host, got, err)
		}
		if !strings.Contains(err.Error(), "set Zone ID") {
			t.Errorf("%s: %q lost the remedy", host, err)
		}
	}
}
