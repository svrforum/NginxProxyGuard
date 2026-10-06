package nginx

// Path-scoped WAF exclusions (#231, #286) decide on the normalized path.
//
// The exclusion used to test REQUEST_URI, so a rule switched off for /api was
// also switched off for /api/../admin and /api/%2e%2e/admin, which nginx and
// the backend both serve as /admin. It now tests REQUEST_FILENAME after
// t:normalizePath, and a chained rule keeps the rule in force for a path a
// backend may resolve differently.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestURIScopePattern(t *testing.T) {
	cases := []struct {
		scope, want string
		match       []string // normalized REQUEST_FILENAME values that must match
		noMatch     []string
	}{
		{
			scope: "/api", want: `\A/api(?:/|\z)`,
			match:   []string{"/api", "/api/", "/api/x"},
			noMatch: []string{"/api-admin", "/apikeys", "/admin", "/x/api", "/admin\n/api/x", "/api\nx"},
		},
		{scope: "/api/", want: `\A/api(?:/|\z)`, match: []string{"/api/x"}},
		{
			// Stored as the log viewer prefills it (raw); REQUEST_FILENAME arrives
			// decoded once, so the stored value is decoded the same way.
			scope: "/files/my%20docs", want: `\A/files/my\x20docs(?:/|\z)`,
			match:   []string{"/files/my docs", "/files/my docs/a.pdf"},
			noMatch: []string{"/files/my%20docs/a.pdf"},
		},
		{scope: "/c++", want: `\A/c\+\+(?:/|\z)`, match: []string{"/c++/x"}, noMatch: []string{"/c  /x", "/cc/x"}},
		{scope: "/wp-admin/admin-ajax.php", want: `\A/wp-admin/admin-ajax\.php(?:/|\z)`, noMatch: []string{"/wp-admin/admin-ajaxXphp"}},
		{scope: "/a(b", want: `\A/a\(b(?:/|\z)`, match: []string{"/a(b/x"}},
		// Decoding can produce bytes that would end the directive, start a
		// macro or a new line; all of them render as \xHH.
		{scope: "/a%22b%5c%0a%25%7Bx", want: `\A/a\x22b\x5c\x0a\x25\{x(?:/|\z)`},
		{scope: "/caf%C3%A9", want: `\A/caf\xc3\xa9(?:/|\z)`},
		{scope: "/100%", want: `\A/100\x25(?:/|\z)`, match: []string{"/100%"}}, // not valid percent-encoding: used as typed
		{scope: "/", want: `\A/(?:/|\z)`, match: []string{"/"}, noMatch: []string{"/x"}},
		// ValidateScope accepts "//", and t:normalizePath merges slashes in the
		// request, so the stored value is merged too; as written it would
		// match nothing.
		{
			scope: "/api//v1", want: `\A/api/v1(?:/|\z)`,
			match:   []string{"/api/v1", "/api/v1/items"},
			noMatch: []string{"/api/v2", "/api", "/api/v10"},
		},
		{scope: "/a%2F%2Fb", want: `\A/a/b(?:/|\z)`, match: []string{"/a/b/x"}}, // decoded slashes merge too
		// ValidateScope also accepts a query. On REQUEST_URI the value matched
		// that exact path followed by that query, so the path before the "?"
		// still has to match exactly, and TestURIScopeQueryPattern covers the
		// query. Cut at the "?", "/file?path=x" exempted /file and everything
		// under it for every query string.
		{
			scope: "/file?path=x", want: `\A/file\z`,
			match:   []string{"/file"},
			noMatch: []string{"/file/", "/file/a.txt", "/files", "/x/file"},
		},
		{scope: "/wp/?p=1", want: `\A/wp/\z`, match: []string{"/wp/"}, noMatch: []string{"/wp", "/wp/x"}},
		{scope: "/x%3Fy?z", want: `\A/x\?y\z`, match: []string{"/x?y"}, noMatch: []string{"/x?y/z"}}, // an encoded "?" is part of the path
		{scope: "/?x", want: `\A/\z`, match: []string{"/"}, noMatch: []string{"/x"}},
		{scope: "//?x", want: `\A/\z`, match: []string{"/"}},
	}
	for _, tc := range cases {
		got := uriScopePattern(tc.scope)
		if got != tc.want {
			t.Errorf("uriScopePattern(%q) = %q, want %q", tc.scope, got, tc.want)
			continue
		}
		if strings.ContainsAny(got, "\"\n%") {
			t.Errorf("uriScopePattern(%q) = %q carries a raw quote, newline or percent", tc.scope, got)
		}
		re := regexp.MustCompile(got)
		for _, p := range tc.match {
			if !re.MatchString(p) {
				t.Errorf("scope %q must cover %q (pattern %s)", tc.scope, p, got)
			}
		}
		for _, p := range tc.noMatch {
			if re.MatchString(p) {
				t.Errorf("scope %q must not cover %q (pattern %s)", tc.scope, p, got)
			}
		}
	}
}

// A scope with a query keeps the restriction it had on REQUEST_URI, which
// libmodsecurity decodes: the query string begins with the stored part (both
// decoded), followed by "/", "?" or nothing. The pattern is tested on
// QUERY_STRING after t:urlDecode, so these are decoded query strings.
func TestURIScopeQueryPattern(t *testing.T) {
	cases := []struct {
		scope, want    string
		match, noMatch []string
	}{
		{scope: "/api", want: ""},
		{scope: "/file/", want: ""},
		{
			scope: "/?rest_route=/wp/v2/posts", want: `\Arest_route\x3d/wp/v2/posts(?:[/?]|\z)`,
			match:   []string{"rest_route=/wp/v2/posts", "rest_route=/wp/v2/posts/1", "rest_route=/wp/v2/posts?x=1"},
			noMatch: []string{"rest_route=/wp/v2/users&search=1", "s=1", "p=1", "rest_route=/wp/v2/postsx", "x=1&rest_route=/wp/v2/posts", ""},
		},
		// Stored as the log shows it, it is decoded like the request, so it
		// covers the same query.
		{scope: "/?rest_route=%2Fwp%2Fv2%2Fposts", want: `\Arest_route\x3d/wp/v2/posts(?:[/?]|\z)`, match: []string{"rest_route=/wp/v2/posts/1"}},
		{
			scope: "/index.php?route=tool/upload", want: `\Aroute\x3dtool/upload(?:[/?]|\z)`,
			match:   []string{"route=tool/upload"},
			noMatch: []string{"route=account/edit&q=1", "q=1", "route=tool/uploads"},
		},
		{scope: "/s?q=a+b", want: `\Aq\x3da\x20b(?:[/?]|\z)`, match: []string{"q=a b"}}, // "+" is a space, as t:urlDecode reads it
		{scope: "/x%3Fy?z", want: `\Az(?:[/?]|\z)`},
		{scope: "/a?b?c", want: `\Ab\?c(?:[/?]|\z)`, match: []string{"b?c"}, noMatch: []string{"bxc"}},
		{scope: "/q?100%", want: `\A100\x25(?:[/?]|\z)`, match: []string{"100%"}}, // not valid percent-encoding: used as typed
		{scope: "/q?%0a%22%25%7B", want: `\A\x0a\x22\x25\{(?:[/?]|\z)`},
		// An empty query part covers an empty query. QUERY_STRING is empty
		// without a "?" too, but a client could always add the "?" to reach
		// the scope, so that is not a wider exemption than before.
		{scope: "/file?", want: `\A(?:[/?]|\z)`, match: []string{"", "/x"}, noMatch: []string{"id=1"}},
	}
	for _, tc := range cases {
		got := uriScopeQueryPattern(tc.scope)
		if got != tc.want {
			t.Errorf("uriScopeQueryPattern(%q) = %q, want %q", tc.scope, got, tc.want)
			continue
		}
		if strings.ContainsAny(got, "\"\n%") {
			t.Errorf("uriScopeQueryPattern(%q) = %q carries a raw quote, newline or percent", tc.scope, got)
		}
		if got == "" {
			continue
		}
		re := regexp.MustCompile(got)
		for _, q := range tc.match {
			if !re.MatchString(q) {
				t.Errorf("scope %q must cover the query %q (pattern %s)", tc.scope, q, got)
			}
		}
		for _, q := range tc.noMatch {
			if re.MatchString(q) {
				t.Errorf("scope %q must not cover the query %q (pattern %s)", tc.scope, q, got)
			}
		}
	}
}

func TestHostWAFScopedExclusionWithQueryChainsTheQuery(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	host := &model.ProxyHost{ID: "00000000-0000-0000-0000-0000000000f7", WAFEnabled: true, WAFMode: "blocking"}
	exclusions := []model.WAFRuleExclusion{
		{RuleID: 949110, ScopeType: "uri", ScopeValue: "/index.php?route=tool/upload"},
		{RuleID: 949110, ScopeType: "uri", ScopeValue: "/api"},
	}
	if err := m.GenerateHostWAFConfig(context.Background(), host, exclusions, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.modsecPath, "host_"+host.ID+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	guard := `(?i)(?:` + unsafeRequestPathPattern + `)`
	for _, want := range []string{
		`SecRule REQUEST_FILENAME "@rx \A/index\.php\z" "id:1000000,phase:1,pass,nolog,t:none,t:normalizePath,chain"` + "\n" +
			`    SecRule QUERY_STRING "@rx \Aroute\x3dtool/upload(?:[/?]|\z)" "t:none,t:urlDecode,chain"` + "\n" +
			`    SecRule REQUEST_FILENAME "!@rx ` + guard + `" "t:none,ctl:ruleRemoveById=949110"` + "\n",
		// A scope without a query renders as before, with no query test.
		`SecRule REQUEST_FILENAME "@rx \A/api(?:/|\z)" "id:1000001,phase:1,pass,nolog,t:none,t:normalizePath,chain"` + "\n" +
			`    SecRule REQUEST_FILENAME "!@rx ` + guard + `" "t:none,ctl:ruleRemoveById=949110"` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("per-host WAF file is missing:\n%s\ngot:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "SecRule QUERY_STRING"); n != 1 {
		t.Errorf("expected one query test (for the scope with a query), got %d:\n%s", n, out)
	}
}

func TestHostWAFScopedExclusionMatchesNormalizedPath(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	host := &model.ProxyHost{ID: "00000000-0000-0000-0000-0000000000f6", WAFEnabled: true, WAFMode: "blocking"}
	exclusions := []model.WAFRuleExclusion{
		{RuleID: 942100, ScopeType: "uri", ScopeValue: "/api"},
		{RuleID: 942100, ScopeType: "param", ScopeValue: "q"},
		{RuleID: 941100, ScopeType: "host"},
	}
	if err := m.GenerateHostWAFConfig(context.Background(), host, exclusions, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.modsecPath, "host_"+host.ID+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)

	guard := `(?i)(?:` + unsafeRequestPathPattern + `)`
	want := `SecRule REQUEST_FILENAME "@rx \A/api(?:/|\z)" "id:1000000,phase:1,pass,nolog,t:none,t:normalizePath,chain"` + "\n" +
		`    SecRule REQUEST_FILENAME "!@rx ` + guard + `" "t:none,ctl:ruleRemoveById=942100"` + "\n"
	if !strings.Contains(out, want) {
		t.Fatalf("scoped exclusion is not the normalized-path chain; want:\n%s\ngot:\n%s", want, out)
	}
	// REQUEST_URI carries the query string and is not normalized; a second
	// decode (t:urlDecodeUni) turns "+" into a space. Neither may come back.
	for _, banned := range []string{"REQUEST_URI", "urlDecodeUni"} {
		if strings.Contains(out, banned) {
			t.Errorf("per-host WAF file mentions %s:\n%s", banned, out)
		}
	}
	// The ctl sits on the chained rule, not the chain starter. The reference
	// manual runs a starter's non-disruptive actions as soon as the starter
	// matches; libmodsecurity 3.0.15 happens to defer them to the full match,
	// but on the last rule the ctl depends on the whole chain either way.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, ",chain\"") && strings.Contains(line, "ctl:") {
			t.Errorf("chain starter carries the ctl action: %s", line)
		}
	}
	// Unchanged scopes keep their rendering.
	if !strings.Contains(out, `SecRuleUpdateTargetById 942100 "!ARGS:q"`) || !strings.Contains(out, "SecRuleRemoveById 941100") {
		t.Errorf("param/host scopes changed:\n%s", out)
	}

	// The guard refuses what t:normalizePath cannot make safe. REQUEST_FILENAME
	// is decoded once by libmodsecurity, so these are once-decoded values.
	re := regexp.MustCompile(guard)
	for _, p := range []string{"/api/..;/admin", `/api/..\admin`, "/api/%2e%2e/admin", "/api/../admin", "/api/./x", "/api/x/..", "/api/x\n"} {
		if !re.MatchString(p) {
			t.Errorf("guard must refuse the exclusion for %q", p)
		}
	}
	for _, p := range []string{"/api", "/api/x", "/c++/x", "/api/a..b", "/api/.hidden"} {
		if re.MatchString(p) {
			t.Errorf("guard refuses an ordinary path %q", p)
		}
	}
}
