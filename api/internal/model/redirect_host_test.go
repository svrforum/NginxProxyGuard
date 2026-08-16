package model

import "testing"

func TestValidateRedirectHost(t *testing.T) {
	valid := &RedirectHost{
		DomainNames:       []string{"example.com", "*.example.net"},
		ForwardScheme:     "https",
		ForwardDomainName: "target.example.com",
		ForwardPath:       "/new-path?source=legacy",
		RedirectCode:      308,
	}
	if err := ValidateRedirectHost(valid); err != nil {
		t.Fatalf("valid redirect host rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RedirectHost)
	}{
		{"domain directive injection", func(h *RedirectHost) { h.DomainNames = []string{"example.com; listen 9000"} }},
		{"domain newline injection", func(h *RedirectHost) { h.DomainNames = []string{"example.com\nserver {}"} }},
		{"invalid scheme", func(h *RedirectHost) { h.ForwardScheme = "https; return 200" }},
		{"target directive injection", func(h *RedirectHost) { h.ForwardDomainName = "target.example.com; proxy_pass http://internal" }},
		{"target contains URL", func(h *RedirectHost) { h.ForwardDomainName = "https://target.example.com" }},
		{"target wildcard", func(h *RedirectHost) { h.ForwardDomainName = "*.example.com" }},
		{"target invalid port", func(h *RedirectHost) { h.ForwardDomainName = "example.com:65536" }},
		{"target nonnumeric port", func(h *RedirectHost) { h.ForwardDomainName = "example.com:+443" }},
		{"target bare IPv6", func(h *RedirectHost) { h.ForwardDomainName = "2001:db8::1" }},
		{"path directive injection", func(h *RedirectHost) { h.ForwardPath = "/ok; } location /internal {" }},
		{"path newline injection", func(h *RedirectHost) { h.ForwardPath = "/ok\nreturn 200" }},
		{"path control character", func(h *RedirectHost) { h.ForwardPath = "/ok\x00bad" }},
		{"path nginx variable injection", func(h *RedirectHost) { h.ForwardPath = "/?token=$http_authorization" }},
		{"path without leading slash", func(h *RedirectHost) { h.ForwardPath = "relative" }},
		{"invalid redirect code", func(h *RedirectHost) { h.RedirectCode = 200 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := *valid
			host.DomainNames = append([]string(nil), valid.DomainNames...)
			tt.mutate(&host)
			if err := ValidateRedirectHost(&host); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateRedirectHostAcceptsCompatibleTargetsAndPaths(t *testing.T) {
	tests := []struct {
		name   string
		target string
		path   string
	}{
		{name: "hostname with port", target: "nas.example.com:5001", path: "/"},
		{name: "IPv4 with port", target: "192.0.2.10:8443", path: "/"},
		{name: "absolute FQDN", target: "example.com.", path: "/"},
		{name: "bracketed IPv6", target: "[2001:db8::1]", path: "/"},
		{name: "bracketed IPv6 with port", target: "[2001:db8::1]:8443", path: "/"},
		{name: "URL fragment", target: "target.example.com", path: "/docs#install"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := &RedirectHost{
				DomainNames:       []string{"redirect.example.com"},
				ForwardScheme:     "https",
				ForwardDomainName: tt.target,
				ForwardPath:       tt.path,
				RedirectCode:      301,
			}
			if err := ValidateRedirectHost(host); err != nil {
				t.Fatalf("compatible redirect rejected: %v", err)
			}
		})
	}
}

func TestRedirectHostRequestValidationUsesDefaults(t *testing.T) {
	create := &CreateRedirectHostRequest{
		DomainNames:       []string{"example.com"},
		ForwardDomainName: "target.example.com",
	}
	if err := create.Validate(); err != nil {
		t.Fatalf("default create request rejected: %v", err)
	}

	badScheme := "http; return 200"
	update := &UpdateRedirectHostRequest{ForwardScheme: &badScheme}
	if err := update.Validate(); err == nil {
		t.Fatal("expected unsafe partial update to be rejected")
	}
}
