package model

import "testing"

// A bracketed IPv6 literal is URL syntax for the bare address and is accepted
// as such. Nothing else is unwrapped, so brackets never become a way past the
// forward_host validator. (#314)
func TestNormalizeForwardHost(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  string
		valid bool
	}{
		{"2001:db8::1", "2001:db8::1", true},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"[::1]", "::1", true},
		{"[::ffff:192.0.2.1]", "::ffff:192.0.2.1", true},
		{"example.com", "example.com", true},
		{"192.0.2.10", "192.0.2.10", true},
		{"[not-an-ip]", "[not-an-ip]", false},
		{"[192.0.2.1]", "[192.0.2.1]", false},
		{"[backend.example.com]", "[backend.example.com]", false},
		{"", "", false},
		{"[]", "[]", false},
		{"[2001:db8::1", "[2001:db8::1", false},
		{"2001:db8::1]", "2001:db8::1]", false},
		{"[[2001:db8::1]]", "[[2001:db8::1]]", false},
		{"[2001:db8::1]:8080", "[2001:db8::1]:8080", false},
		{"[2001:db8::1%eth0]", "[2001:db8::1%eth0]", false},
	} {
		got := NormalizeForwardHost(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeForwardHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if valid := ValidateHostnameOrIP(got); valid != tc.valid {
			t.Errorf("ValidateHostnameOrIP(NormalizeForwardHost(%q)) = %v, want %v", tc.in, valid, tc.valid)
		}
	}
}
