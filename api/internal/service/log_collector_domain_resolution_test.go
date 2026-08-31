package service

import "testing"

// Attribution decides whether fail2ban and WAF auto-ban ever see a failure, so
// a resolver miss silently disables both for that traffic.
//
// model.ValidateDomainName accepts a leading "*." and nginx serves the wildcard,
// but the resolver was an exact map lookup — so on a wildcard host EVERY request
// was unattributed and fail2ban was dead. Verified on a throwaway host before
// the fix: three different subdomains of a configured wildcard host all landed
// with proxy_host_id NULL.
func TestMatchWildcardHost(t *testing.T) {
	wildcards := []wildcardHost{
		{suffix: ".example.com", hostID: "broad"},
		{suffix: ".api.example.com", hostID: "specific"},
	}

	cases := []struct {
		domain string
		want   string
		why    string
	}{
		{"sub.example.com", "broad", "one label under the wildcard"},
		// nginx's *.example.com matches at any depth, not just one label.
		{"a.b.example.com", "broad", "several labels under the wildcard"},
		{"v1.api.example.com", "specific", "longest suffix wins over the broader wildcard"},
		// nginx does NOT let *.example.com match example.com itself.
		{"example.com", "", "the bare domain is not covered by its own wildcard"},
		{"notexample.com", "", "suffix match must respect the label boundary"},
		{"example.com.evil.test", "", "the wildcard must not match as a prefix"},
		{"", "", "empty host"},
	}

	for _, tc := range cases {
		if got := matchWildcardHost(tc.domain, wildcards); got != tc.want {
			t.Errorf("matchWildcardHost(%q) = %q, want %q — %s", tc.domain, got, tc.want, tc.why)
		}
	}

	if got := matchWildcardHost("anything.test", nil); got != "" {
		t.Errorf("no wildcards configured should resolve to nothing, got %q", got)
	}
}
