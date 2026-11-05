package database

import "testing"

// The strings below are what lib/pq actually renders, copied from a live
// Postgres 17 reply rather than invented: Error() is "pq: <message>", the
// SQLSTATE is appended in parentheses once the code is known, and " at
// position <line>:<col>" follows when the driver kept the statement.
func TestScrubDriverText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "malformed identifier keeps our wrapper and names the cause",
			in:   `failed to validate certificate_id: failed to get certificate: pq: invalid input syntax for type uuid: "not-a-uuid" (22P02)`,
			want: "failed to validate certificate_id: failed to get certificate: Invalid identifier format",
		},
		{
			name: "an over-long value keeps our wrapper and names the cause",
			in:   `failed to update provider: pq: value too long for type character varying(64) (22001)`,
			want: "failed to update provider: A value is longer than its field allows",
		},
		{
			name: "any other SQLSTATE falls back to the generic wording",
			in:   `failed to render config: pq: relation "proxy_hosts" does not exist (42P01)`,
			want: "failed to render config: A database error occurred",
		},
		{
			name: "position leak is cut away with the rest of the driver text",
			in:   `backup upload: pq: syntax error at or near "SELCT" (42601) at position 1:8`,
			want: "backup upload: A database error occurred",
		},
		{
			name: "driver text with no SQLSTATE rendered is still cut",
			in:   "sync host: pq: connection reset by peer",
			want: "sync host: A database error occurred",
		},
		{
			name: "a bare driver error becomes the reason alone",
			in:   `pq: invalid input syntax for type inet: "999.1.1.1" (22P02)`,
			want: "Invalid identifier format",
		},
		{
			name: "trailing punctuation on our half is not doubled",
			in:   "failed to update config status - pq: deadlock detected (40P01)",
			want: "failed to update config status: A database error occurred",
		},
		// The cases below are the overwhelming majority in this codebase and
		// must survive byte for byte: an nginx -t failure is the single most
		// useful string a host row can carry, and ACME rejections are what
		// makes a failed certificate diagnosable at all.
		{
			name: "nginx test output is untouched",
			in:   "nginx: [emerg] duplicate location \"/\" in /etc/nginx/conf.d/host_1.conf:42",
			want: "nginx: [emerg] duplicate location \"/\" in /etc/nginx/conf.d/host_1.conf:42",
		},
		{
			name: "ACME rejection is untouched",
			in:   "acme: error presenting token: cloudflare: failed to find zone for example.com",
			want: "acme: error presenting token: cloudflare: failed to find zone for example.com",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScrubDriverText(tt.in); got != tt.want {
				t.Errorf("ScrubDriverText(%q)\n got: %q\nwant: %q", tt.in, got, tt.want)
			}
		})
	}
}

// A scrub that leaves the SQLSTATE behind has done nothing useful, so assert
// the absence directly rather than trusting the table above to have listed
// every leaking fragment.
func TestScrubDriverTextLeavesNoDriverFragments(t *testing.T) {
	in := `failed to get host: pq: invalid input syntax for type uuid: "zz" (22P02) at position 1:63`
	got := ScrubDriverText(in)

	for _, leak := range []string{"pq:", "22P02", "uuid", "position", "syntax"} {
		if contains(got, leak) {
			t.Errorf("scrubbed text still contains %q: %q", leak, got)
		}
	}
	if !contains(got, "failed to get host") {
		t.Errorf("scrub dropped our own wrapper, leaving nothing locatable: %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
