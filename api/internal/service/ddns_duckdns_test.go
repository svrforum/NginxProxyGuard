package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// KO is DuckDNS refusing the token (or a subdomain that is not on its
// account): the operator's to fix, so it carries ErrInvalidCredentials and the
// sync handler answers 400, not 500. (#312)
func TestDuckDNSUpdaterKO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("KO"))
	}))
	defer srv.Close()
	u := &duckDNSUpdater{client: srv.Client(), base: srv.URL}
	creds, _ := json.Marshal(model.DuckDNSCredentials{Token: "tok-123"})
	err := u.Update(context.Background(), model.DDNSRecord{Hostname: "x.duckdns.org"}, creds, "203.0.113.7")
	if err == nil {
		t.Fatal("expected error on KO response")
	}
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Errorf("KO should carry ErrInvalidCredentials, got %v", err)
	}
	if !strings.Contains(err.Error(), "duckdns update failed: KO") {
		t.Errorf("provider reason missing from %q", err)
	}
}

// An answer DuckDNS never gives says nothing about the credentials, so it must
// not be reported as their fault. Its body is kept for the operator, but a 200
// page can reflect the request URL as well as an error page can (a block page
// from an intercepting proxy), so the token in it must not survive.
func TestDuckDNSUpdaterUnexpectedAnswerStaysPlain(t *testing.T) {
	const token = "duck-secret-7f3a"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>blocked: %s</html>", r.URL.RequestURI())
	}))
	defer srv.Close()
	u := &duckDNSUpdater{client: srv.Client(), base: srv.URL}
	creds, _ := json.Marshal(model.DuckDNSCredentials{Token: token})
	err := u.Update(context.Background(), model.DDNSRecord{Hostname: "x.duckdns.org"}, creds, "203.0.113.7")
	if err == nil {
		t.Fatal("expected error on an unexpected answer")
	}
	if kind := ddnsErrKind(err); kind != "" {
		t.Errorf("unexpected answer classified as %q, want a plain error: %v", kind, err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error echoes the token: %q", err)
	}
	if !strings.Contains(err.Error(), "<html>blocked: /update?") {
		t.Errorf("the answer is missing from %q", err)
	}
}

// DuckDNS answers OK/KO with a 200, so another status came from whatever sits
// in front of it — a WAF's 403 included — and says nothing about the token or
// the subdomain: it stays a plain error (500) whatever the status. The page
// reflects the request URL, as some error pages do, so echoing it would hand
// back the token.
func TestDuckDNSUpdaterClassifiesHTTPStatus(t *testing.T) {
	const token = "duck-secret-7f3a"
	creds, _ := json.Marshal(model.DuckDNSCredentials{Token: token})
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, ""},
		{http.StatusForbidden, ""},
		{http.StatusBadRequest, ""},
		{http.StatusNotFound, ""},
		{http.StatusTooManyRequests, ""},
		{http.StatusServiceUnavailable, ""},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			fmt.Fprintf(w, "<html>error for %s</html>", r.URL.RequestURI())
		}))
		u := &duckDNSUpdater{client: srv.Client(), base: srv.URL}
		err := u.Update(context.Background(), model.DDNSRecord{Hostname: "myhome.duckdns.org"}, creds, "203.0.113.7")
		srv.Close()
		if err == nil {
			t.Errorf("HTTP %d: expected an error", tc.status)
			continue
		}
		if got := ddnsErrKind(err); got != tc.want {
			t.Errorf("HTTP %d: kind = %q, want %q (%v)", tc.status, got, tc.want, err)
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("HTTP %d: error echoes the token: %q", tc.status, err)
		}
		if want := fmt.Sprintf("HTTP %d", tc.status); !strings.Contains(err.Error(), want) {
			t.Errorf("HTTP %d: %q does not name the status", tc.status, err)
		}
	}
}

// DuckDNS takes the token in the query string, and net/http's *url.Error
// quotes the full request URL. The error becomes the API response,
// ddns_records.last_error, a notification and a log line, so a failure to
// reach DuckDNS must name the endpoint and the cause but never the token, and
// it stays a plain error (500): an outage is not the operator's mistake.
func TestDuckDNSUpdaterTransportErrorOmitsToken(t *testing.T) {
	const token = "duck-secret-7f3a"
	creds, _ := json.Marshal(model.DuckDNSCredentials{Token: token})
	rec := model.DDNSRecord{Hostname: "myhome.duckdns.org"}

	check := func(t *testing.T, err error, base string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected a transport error")
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("error leaks the token: %q", err)
		}
		if !strings.Contains(err.Error(), base) {
			t.Errorf("error does not name the endpoint %s: %q", base, err)
		}
		if kind := ddnsErrKind(err); kind != "" {
			t.Errorf("unreachable provider classified as %q, want a plain error: %v", kind, err)
		}
	}

	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		base := srv.URL
		srv.Close() // nothing listens there any more
		u := &duckDNSUpdater{client: &http.Client{Timeout: 5 * time.Second}, base: base}
		check(t, u.Update(context.Background(), rec, creds, "203.0.113.7"), base)
	})

	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer srv.Close()
		u := &duckDNSUpdater{client: &http.Client{Timeout: 50 * time.Millisecond}, base: srv.URL}
		check(t, u.Update(context.Background(), rec, creds, "203.0.113.7"), srv.URL)
	})

	// net/http quotes more than the request URL: a Location it cannot parse
	// and a status line it cannot read both come back in its error text, so a
	// peer that reflects the request puts the token there as well.
	t.Run("unparsable redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://[::1%zz]"+r.URL.RequestURI())
			w.WriteHeader(http.StatusFound)
		}))
		defer srv.Close()
		u := &duckDNSUpdater{client: srv.Client(), base: srv.URL}
		check(t, u.Update(context.Background(), rec, creds, "203.0.113.7"), srv.URL)
	})

	t.Run("malformed status line", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// The request target goes where the status code belongs.
			line, _ := bufio.NewReader(conn).ReadString('\n')
			if f := strings.Fields(line); len(f) > 1 {
				fmt.Fprintf(conn, "HTTP/1.1 %s OK\r\nContent-Length: 0\r\n\r\n", f[1])
			}
		}()
		base := "http://" + ln.Addr().String()
		u := &duckDNSUpdater{client: &http.Client{Timeout: 5 * time.Second}, base: base}
		check(t, u.Update(context.Background(), rec, creds, "203.0.113.7"), base)
	})
}
