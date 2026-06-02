package service

import "testing"

func TestParseTraceIP(t *testing.T) {
	body := "fl=123\nh=1.1.1.1\nip=203.0.113.7\nts=1.2\n"
	if got := parseTraceIP(body); got != "203.0.113.7" {
		t.Fatalf("parseTraceIP = %q, want 203.0.113.7", got)
	}
	if got := parseTraceIP("no ip here\n"); got != "" {
		t.Fatalf("parseTraceIP(no ip) = %q, want empty", got)
	}
}
