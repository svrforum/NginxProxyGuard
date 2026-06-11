package model

import "testing"

func TestNormalizeProxyType(t *testing.T) {
	// Backup import compatibility: pre-v2.18.0 backups have no proxy_type
	// column, so the JSON unmarshals to an empty string. NormalizeProxyType
	// MUST coerce empty → "http" or the NOT NULL constraint blows up on
	// import. Lock this contract.
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: ProxyTypeHTTP},
		{in: " ", want: ProxyTypeHTTP},
		{in: "http", want: ProxyTypeHTTP},
		{in: "HTTP", want: ProxyTypeHTTP},
		{in: "stream", want: ProxyTypeStream},
		{in: "STREAM", want: ProxyTypeStream},
		{in: "Stream", want: ProxyTypeStream},
		{in: "garbage", want: ProxyTypeHTTP},
	}
	for _, tc := range cases {
		if got := NormalizeProxyType(tc.in); got != tc.want {
			t.Errorf("NormalizeProxyType(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeStreamProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: StreamProtocolTCP},
		{in: "tcp", want: StreamProtocolTCP},
		{in: "TCP", want: StreamProtocolTCP},
		{in: "udp", want: StreamProtocolUDP},
		{in: "UDP", want: StreamProtocolUDP},
		{in: "garbage", want: StreamProtocolTCP},
	}
	for _, tc := range cases {
		if got := NormalizeStreamProtocol(tc.in); got != tc.want {
			t.Errorf("NormalizeStreamProtocol(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateAdvancedConfig(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{"empty", "", false},
		{"plain directives", "client_max_body_size 100m;\nproxy_buffering off;", false},
		// #129: proxy_pass inside a custom location block is legitimate.
		{"proxy_pass in location", "location / {\n    proxy_pass http://127.0.0.1:8080;\n}", false},
		{"proxy_pass in nested location with directives", "location /api {\n    proxy_set_header Host $host;\n    proxy_pass http://backend:3000;\n}", false},
		{"fastcgi_pass in location", "location ~ \\.php$ {\n    fastcgi_pass unix:/run/php.sock;\n}", false},
		{"proxy_pass in if block", "location / {\n    if ($arg_x) {\n        proxy_pass http://a;\n    }\n}", false},
		// Still rejected: server-level (depth 0) upstream directives.
		{"proxy_pass at server level", "proxy_pass http://evil:80;", true},
		{"proxy_pass after closed block", "location /a { return 200; }\nproxy_pass http://evil;", true},
		// Filesystem directives are blocked at ANY depth — alias/root/autoindex
		// expose the nginx container's local files (local file disclosure), a
		// privilege forward_host does not grant. Static-serving is unsupported.
		{"alias at server level", "alias /etc/passwd;", true},
		{"root at server level", "root /etc;", true},
		{"alias in location (file disclosure)", "location /x {\n    alias /etc/;\n    autoindex on;\n}", true},
		{"root in location (file disclosure)", "location /x {\n    root /etc;\n}", true},
		{"autoindex in location", "location /x {\n    autoindex on;\n}", true},
		// Always blocked regardless of context.
		{"lua in location", "location / {\n    content_by_lua_block { os.execute('id') }\n}", true},
		{"include anywhere", "location / {\n    include /etc/passwd;\n}", true},
		{"modsecurity off in location", "location / {\n    modsecurity off;\n}", true},
		{"load_module", "load_module /tmp/evil.so;", true},
		{"error_page 403 override in location", "location / {\n    error_page 403 /pwn.html;\n}", true},
		{"satisfy in location", "location / {\n    satisfy any;\n}", true},
		// Injection guards.
		{"command substitution", "location / {\n    proxy_pass http://`whoami`;\n}", true},
		{"dollar-paren injection", "location / {\n    proxy_pass http://$(id);\n}", true},
		{"null byte", "location / {\n    proxy_pass http://a;\x00\n}", true},
		// Comments must not be parsed as directives.
		{"commented proxy_pass at server level", "# proxy_pass http://x;\nclient_max_body_size 1m;", false},
		// Server-block breakout: an unbalanced '}' must be rejected so the
		// config cannot close the managed server{} and open its own unprotected
		// top-level server{} (SSRF / no-WAF vhost / server_name hijack).
		{"server breakout via premature close", "location /a { proxy_pass http://127.0.0.1; }\n}\nserver {\n    listen 443 ssl;\n    location / { proxy_pass http://attacker.example.net; }", true},
		{"bare premature close then directive", "}\nclient_max_body_size 1m;", true},
		{"close-then-proxy_pass same line", "location /a { return 200; }\n} proxy_pass http://evil;", true},
		{"unbalanced extra open", "location / {\n    proxy_pass http://x;", true},
		// Balanced config with braces inside a quoted value must still pass
		// (quoted braces are not structural).
		{"quoted brace in value is not structural", "location / {\n    add_header X-Test \"{ok}\";\n    proxy_pass http://x;\n}", false},
		{"two balanced location blocks", "location /a { proxy_pass http://a; }\nlocation /b { proxy_pass http://b; }", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAdvancedConfig(tc.config)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateAdvancedConfig(%q) err=%v, wantErr=%v", tc.config, err, tc.wantErr)
			}
		})
	}
}
