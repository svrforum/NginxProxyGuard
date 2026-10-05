package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// Create and every update path (Update, UpdateWithoutReload, UpdateDBOnly all
// go through normalizeUpdateProxyHostRequest) store a bracketed IPv6 forward
// host as the bare literal, and leave anything else for the validator. (#314)
func TestNormalizeProxyHostRequestsForwardHost(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  string
		valid bool
	}{
		{"[2001:db8::1]", "2001:db8::1", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"backend.example.com", "backend.example.com", true},
		{"[192.0.2.1]", "[192.0.2.1]", false},
		{"[not-an-ip]", "[not-an-ip]", false},
	} {
		create := &model.CreateProxyHostRequest{DomainNames: []string{"app.example.com"}, ForwardHost: tc.in}
		if err := normalizeCreateProxyHostRequest(create); err != nil {
			t.Fatalf("create %q: %v", tc.in, err)
		}
		if create.ForwardHost != tc.want {
			t.Errorf("create %q: stored %q, want %q", tc.in, create.ForwardHost, tc.want)
		}

		existing := &model.ProxyHost{ID: "h1", ProxyType: model.ProxyTypeHTTP, ForwardScheme: "http", ForwardHost: "192.0.2.10", ForwardPort: 80}
		update := &model.UpdateProxyHostRequest{ForwardHost: tc.in}
		candidate, err := normalizeUpdateProxyHostRequest(existing, update)
		if err != nil {
			t.Fatalf("update %q: %v", tc.in, err)
		}
		if update.ForwardHost != tc.want || candidate.ForwardHost != tc.want {
			t.Errorf("update %q: stored %q, validated %q, want %q", tc.in, update.ForwardHost, candidate.ForwardHost, tc.want)
		}
		if got := model.ValidateHostnameOrIP(candidate.ForwardHost); got != tc.valid {
			t.Errorf("update %q: valid = %v, want %v", tc.in, got, tc.valid)
		}
	}

	// An update that does not carry forward_host keeps the stored one.
	existing := &model.ProxyHost{ID: "h2", ProxyType: model.ProxyTypeHTTP, ForwardScheme: "http", ForwardHost: "2001:db8::2", ForwardPort: 80}
	update := &model.UpdateProxyHostRequest{}
	candidate, err := normalizeUpdateProxyHostRequest(existing, update)
	if err != nil {
		t.Fatal(err)
	}
	if update.ForwardHost != "" || candidate.ForwardHost != "2001:db8::2" {
		t.Errorf("omitted forward_host: request %q, candidate %q", update.ForwardHost, candidate.ForwardHost)
	}
}

// A container-backed ForwardAuth verify URL ends up in proxy_pass, where
// "http://2001:db8::1:9091" is not a usable address. (#314)
func TestBuildProviderURLBracketsIPv6(t *testing.T) {
	https := "https"
	port := 9091
	for _, tc := range []struct {
		scheme *string
		ip     string
		want   string
	}{
		{nil, "192.0.2.10", "http://192.0.2.10:9091"},
		{&https, "2001:db8::1", "https://[2001:db8::1]:9091"},
	} {
		got := buildProviderURL(tc.scheme, tc.ip, &port)
		if got != tc.want {
			t.Errorf("buildProviderURL(%q) = %q, want %q", tc.ip, got, tc.want)
		}
		if err := model.ValidateProviderURL(got); err != nil {
			t.Errorf("buildProviderURL(%q) = %q, rejected by ValidateProviderURL: %v", tc.ip, got, err)
		}
	}
	if got := buildProviderURL(nil, "", &port); got != "" {
		t.Errorf("no IP must yield no URL, got %q", got)
	}
}

// The direct upstream probe reaches an IPv6 forward host and reports it as
// "[::1]:port", not the ambiguous "::1:port" — also when an older version or a
// restored backup stored it in brackets, which must not become "[[::1]]". (#314)
func TestProxyHostTester_TestUpstream_IPv6ForwardHost(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_ = srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	defer srv.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	for _, forwardHost := range []string{"::1", "[::1]"} {
		result, err := NewProxyHostTester().TestUpstream(context.Background(), &model.ProxyHost{
			ProxyType:     model.ProxyTypeHTTP,
			ForwardScheme: "http",
			ForwardHost:   forwardHost,
			ForwardPort:   port,
		})
		if err != nil {
			t.Fatalf("%s: TestUpstream returned error: %v", forwardHost, err)
		}
		if want := "[::1]:" + strconv.Itoa(port); result.Domain != want {
			t.Errorf("%s: Domain = %q, want %q", forwardHost, result.Domain, want)
		}
		if !result.Success {
			t.Errorf("%s: expected the IPv6 upstream to answer, got error %q", forwardHost, result.Error)
		}
	}
}
