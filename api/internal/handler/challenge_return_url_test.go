package handler

import "testing"

// The return URL comes from the challenge page's query string, so anyone can
// hand a visitor a challenge link that names it. Every case that a browser
// would follow to another host must collapse to "/".
func TestSanitizeReturnURL(t *testing.T) {
	const host = "app.example.com"
	cases := []struct {
		in   string
		want string
	}{
		// What NPG itself generates, and plain relative paths.
		{"https://app.example.com/page?x=1", "https://app.example.com/page?x=1"},
		{"http://APP.example.com:8080/", "http://APP.example.com:8080/"},
		{"/dashboard?tab=2", "/dashboard?tab=2"},
		{"/", "/"},
		{"", "/"},
		{"/@evil.example", "/@evil.example"},
		{"/%5Cevil.example", "/%5Cevil.example"},
		// The page decodes the original query, so "\" can appear after "?".
		{"/search?q=C:\\Users", "/search?q=C:\\Users"},
		{"https://app.example.com/a?b=\\c#\\d", "https://app.example.com/a?b=\\c#\\d"},

		// Userinfo: the browser goes to whatever follows the "@" (#398).
		{"https://app.example.com:81@evil.example/", "/"},
		{"https://app.example.com@evil.example/", "/"},
		{"https://user@app.example.com/", "/"},

		// Browsers read "\" as "/" and drop tabs and newlines.
		{"/\\evil.example", "/"},
		{"https://app.example.com\\@evil.example/", "/"},
		{"/\t/evil.example", "/"},
		{"/\n/evil.example", "/"},

		// Scheme-relative and slash-run forms that can resolve to another host.
		{"//evil.example", "/"},
		{"///evil.example", "/"},
		{"https:evil.example", "/"},
		{"https:/evil.example", "/"},
		{"https:///evil.example", "/"},

		// Other hosts and schemes.
		{"https://evil.example/", "/"},
		{"https://app.example.com.evil.example/", "/"},
		{"javascript:alert(1)", "/"},
		{" //evil.example", "/"},
	}
	for _, tc := range cases {
		if got := sanitizeReturnURL(tc.in, host); got != tc.want {
			t.Errorf("sanitizeReturnURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := sanitizeReturnURL("https://app.example.com/", ""); got != "/" {
		t.Errorf("empty request host accepted an absolute URL: %q", got)
	}
}
