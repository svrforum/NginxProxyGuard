package nginx

// Characterization tests for parseAdvancedConfigDirectives.
//
// These tests freeze CURRENT parser behavior — not what nginx spec says.
// The parser is intentionally simple: a single regex
//
//   (?m)^\s*([a-z_]+)\s+
//
// that finds lines (or start-of-line after optional indentation) whose first
// token is a lowercase identifier followed by whitespace. It returns the SET
// of first-token names. Known characterization points captured below:
//
//   - Nested tokens count too: "location", "if", "return", "rewrite" all show
//     up as "directives" even though they are nginx blocks/statements.
//   - Multiple directives on a single line (semicolon-separated) only yield
//     the FIRST one; the parser does not split on ';'.
//   - Only leading-line tokens are matched; inline tokens after ';' on the
//     same line are ignored. (This is a known quirk — do not "fix" here.)
//   - Uppercase input yields NOTHING because the regex is [a-z_]+ only.
//   - Commented-out lines ("# name …") are ignored (because '#' is not in
//     [a-z_]+ and it's non-whitespace, so the match is anchored to the `#`
//     and fails).
//   - Malformed tokens that lack a trailing space (e.g. "foo;") are NOT
//     captured because the regex requires a whitespace character after the
//     identifier.

import (
	"sort"
	"testing"
)

func TestParseAdvancedConfigDirectives_Characterization(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		// 1. Empty input.
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		// 2. Single directive.
		{
			name:  "single_directive",
			input: "proxy_read_timeout 60s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 3. Two directives on separate lines.
		{
			name:  "two_directives",
			input: "proxy_read_timeout 60s;\nproxy_send_timeout 30s;",
			want:  []string{"proxy_read_timeout", "proxy_send_timeout"},
		},
		// 4. Leading whitespace (spaces).
		{
			name:  "leading_whitespace_spaces",
			input: "    proxy_read_timeout 60s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 5. Leading whitespace (tab).
		{
			name:  "leading_whitespace_tab",
			input: "\tproxy_read_timeout 60s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 6. Single-line comment (pure comment line is ignored).
		{
			name:  "single_line_comment",
			input: "# this is a comment\nproxy_read_timeout 60s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 7. Inline comment after directive (directive still captured).
		{
			name:  "inline_comment",
			input: "proxy_read_timeout 60s; # inline comment",
			want:  []string{"proxy_read_timeout"},
		},
		// 8. Blank lines before / after.
		{
			name:  "blank_lines",
			input: "\n\nproxy_read_timeout 60s;\n\n",
			want:  []string{"proxy_read_timeout"},
		},
		// 9. Multi-line (multiple) comments.
		{
			name:  "multi_line_comments",
			input: "# c1\n# c2\n# c3\nproxy_read_timeout 60s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 10. Directives inside a location block — BOTH "location" and the
		//     inner directive are captured.
		{
			name:  "inside_location_block",
			input: "location / {\n    proxy_read_timeout 60s;\n}",
			want:  []string{"location", "proxy_read_timeout"},
		},
		// 11. if block — "if" and "return" are both captured.
		{
			name:  "if_block",
			input: "if ($request_uri ~ \"/blocked\") {\n    return 403;\n}",
			want:  []string{"if", "return"},
		},
		// 12. Multiple directives on a single line — only the FIRST is
		//     captured (the parser is line-oriented, not semicolon-aware).
		{
			name:  "multiple_same_line",
			input: "proxy_read_timeout 60s; proxy_send_timeout 30s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 13. Duplicate directive across lines — set behavior, single entry.
		{
			name:  "duplicate_directive",
			input: "proxy_read_timeout 60s;\nproxy_read_timeout 90s;",
			want:  []string{"proxy_read_timeout"},
		},
		// 14. Directive with missing semicolon — still captured (the parser
		//     looks at start-of-line, not statement boundary).
		{
			name:  "missing_semicolon",
			input: "proxy_read_timeout 60s\nproxy_send_timeout 30s;",
			want:  []string{"proxy_read_timeout", "proxy_send_timeout"},
		},
		// 15. Case sensitivity — uppercase input yields NOTHING, because the
		//     regex class is [a-z_] only. This is a known characterization
		//     point: nginx itself is case-sensitive and lowercase-by-convention.
		{
			name:  "uppercase_not_matched",
			input: "Proxy_Read_Timeout 60s;\nCLIENT_MAX_BODY_SIZE 100m;",
			want:  nil,
		},
		// 16. Complex value with a quoted string containing ';'.
		{
			name:  "complex_value_quoted",
			input: `add_header X-Custom "complex; value";`,
			want:  []string{"add_header"},
		},
		// 17. rewrite directive.
		{
			name:  "rewrite_directive",
			input: "rewrite ^/old/(.*)$ /new/$1 permanent;",
			want:  []string{"rewrite"},
		},
		// 18. Nested location block — "location" + inner directive.
		{
			name:  "nested_location_block",
			input: "location / {\n    location /api {\n        proxy_read_timeout 60s;\n    }\n}",
			want:  []string{"location", "proxy_read_timeout"},
		},
		// 19. Commented-out directive + real directive.
		{
			name:  "commented_out_and_real",
			input: "# proxy_read_timeout 60s;\nproxy_send_timeout 30s;",
			want:  []string{"proxy_send_timeout"},
		},
		// 20. Malformed line (no trailing whitespace after token) mixed with
		//     a valid directive. The malformed "xxxx;" token is NOT captured
		//     because the regex requires \s+ after the name.
		{
			name:  "malformed_line_and_real",
			input: "xxxx;\nproxy_read_timeout 60s;",
			want:  []string{"proxy_read_timeout"},
		},
	}

	if len(cases) != 20 {
		t.Fatalf("test suite expects exactly 20 cases, got %d", len(cases))
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := parseAdvancedConfigDirectives(tc.input)
			gotKeys := sortedKeys(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !stringSliceEqual(gotKeys, want) {
				t.Errorf("directive set mismatch\n input: %q\n got:   %v\n want:  %v", tc.input, gotKeys, want)
			}
		})
	}
}

// sortedKeys returns a sorted slice of map keys. The returned slice is nil for
// an empty map so it compares equal to nil with stringSliceEqual.
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
