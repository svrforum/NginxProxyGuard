package model

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseAllowedAgents(t *testing.T) {
	type sc = ScopedAllowedAgent
	cases := []struct {
		name   string
		raw    string
		site   []string
		scoped []ScopedAllowedAgent
		reason string // substring of the first invalid line's reason; "" = none
	}{
		{name: "empty", raw: ""},
		{name: "comments and blank lines", raw: "# okhttp @ api\n\n   \n#x"},
		{name: "plain line", raw: "GoodBot", site: []string{"GoodBot"}},
		{name: "real user agent", raw: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			site: []string{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}},
		{name: "@ inside the agent", raw: "bot@example.com\nfoo@bar @baz", site: []string{"bot@example.com", "foo@bar @baz"}},

		{name: "one path", raw: "okhttp @ /api", scoped: []sc{{"okhttp", []string{"/api"}}}},
		{name: "several paths", raw: "python-requests @ /webhook /hooks/",
			scoped: []sc{{"python-requests", []string{"/webhook", "/hooks/"}}}},
		{name: "tabs around @", raw: "okhttp\t@\t/api", scoped: []sc{{"okhttp", []string{"/api"}}}},
		{name: "agent with ; and spaces", raw: "Mozilla/5.0 (compatible; X)  @  /api",
			scoped: []sc{{"Mozilla/5.0 (compatible; X)", []string{"/api"}}}},
		{name: "@ inside a path", raw: "okhttp @ /@alice", scoped: []sc{{"okhttp", []string{"/@alice"}}}},
		{name: "wildcard agent", raw: "* @ /api", scoped: []sc{{"*", []string{"/api"}}}},
		{name: "root means the whole host", raw: "okhttp @ /", site: []string{"okhttp"}},
		{name: "root among paths", raw: "okhttp @ /api /", site: []string{"okhttp"}},
		{name: "mixed", raw: "GoodBot\n# note\nokhttp @ /api\nokhttp @ api",
			site: []string{"GoodBot"}, scoped: []sc{{"okhttp", []string{"/api"}}}, reason: `path "api" must start with "/"`},

		{name: "no leading slash", raw: "okhttp @ api", reason: `path "api" must start with "/"`},
		{name: "@ glued to path", raw: "okhttp @/api", reason: `with a space on each side`},
		{name: "@ glued to agent", raw: "okhttp@ /api", reason: `with a space on each side`},
		{name: "no agent", raw: "@ /api", reason: `no user agent`},
		{name: "no path", raw: "okhttp @", reason: `no path after`},
		{name: "second @", raw: "okhttp @ /api @ /v2", reason: `path "@" must start with "/"`},
		{name: "percent", raw: "okhttp @ /a%20b", reason: `percent-encoded`},
		{name: "double slash", raw: "okhttp @ //x", reason: `contains "//"`},
		{name: "inner double slash", raw: "okhttp @ /api//v1", reason: `contains "//"`},
		{name: "query", raw: "okhttp @ /api?x=1", reason: `query string`},
		{name: "fragment", raw: "okhttp @ /a#b", reason: `query string`},
		{name: "dot dot segment", raw: "okhttp @ /api/../admin", reason: `"." or ".." segment`},
		{name: "dot segment", raw: "okhttp @ /.", reason: `"." or ".." segment`},
		{name: "dots only segment", raw: "okhttp @ /a/.../b", reason: `"." or ".." segment`},
		{name: "dotted name is fine", raw: "okhttp @ /.well-known/x /v1.2",
			scoped: []sc{{"okhttp", []string{"/.well-known/x", "/v1.2"}}}},
		{name: "semicolon", raw: "okhttp @ /a;b", reason: `contains ";"`},
		{name: "quote", raw: `okhttp @ /a"b`, reason: `contains "\""`},
		{name: "brace", raw: "okhttp @ /a{b}", reason: `contains "{"`},
		{name: "non-ASCII", raw: "okhttp @ /위키", reason: `only printable ASCII`},
		{name: "too long", raw: "okhttp @ /" + strings.Repeat("a", 300), reason: `longer than 255`},
		{name: "too many paths", raw: "okhttp @ /a /b /c /d /e /f /g /h /i /j /k", reason: `at most 10 paths`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			site, scoped, invalid := ParseAllowedAgents(tc.raw)
			if !reflect.DeepEqual(site, tc.site) {
				t.Errorf("site = %q, want %q", site, tc.site)
			}
			if !reflect.DeepEqual(scoped, tc.scoped) {
				t.Errorf("scoped = %+v, want %+v", scoped, tc.scoped)
			}
			switch {
			case tc.reason == "" && len(invalid) > 0:
				t.Errorf("unexpected invalid lines: %+v", invalid)
			case tc.reason != "" && len(invalid) == 0:
				t.Errorf("want an invalid line (%s), got none", tc.reason)
			case tc.reason != "" && !strings.Contains(invalid[0].Reason, tc.reason):
				t.Errorf("reason = %q, want it to mention %q", invalid[0].Reason, tc.reason)
			}
			// A path that is accepted must also pass the WAF uri-scope rule,
			// which is what makes it safe to put in a config file.
			for _, s := range scoped {
				for _, p := range s.Paths {
					e := WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: p}
					if err := e.ValidateScope(); err != nil {
						t.Errorf("accepted path %q fails ValidateScope: %v", p, err)
					}
				}
			}
		})
	}
}

func TestParseAllowedAgentsCapsScopedLines(t *testing.T) {
	var lines []string
	for i := 0; i <= MaxScopedAllowedAgents; i++ {
		lines = append(lines, fmt.Sprintf("bot%d @ /p%d", i, i))
	}
	_, scoped, invalid := ParseAllowedAgents(strings.Join(lines, "\n"))
	if len(scoped) != MaxScopedAllowedAgents {
		t.Fatalf("scoped = %d lines, want %d", len(scoped), MaxScopedAllowedAgents)
	}
	if len(invalid) != 1 || invalid[0].Line != MaxScopedAllowedAgents+1 || !strings.Contains(invalid[0].Reason, "at most 20 lines") {
		t.Fatalf("want line %d refused by the cap, got %+v", MaxScopedAllowedAgents+1, invalid)
	}
}

// The write path refuses only a value the caller changed (#263). The UI sends
// the stored list back on every save and skips its own check for an unchanged
// value, so refusing an unusable stored line would make every later bot-filter
// save fail, mode changes included.
func TestValidateAllowedAgentsChange(t *testing.T) {
	const bad = "GoodBot\nokhttp @ api"
	if err := ValidateAllowedAgentsChange(bad, bad); err != nil {
		t.Errorf("an unchanged stored value must be accepted as it is, got %v", err)
	}
	if err := ValidateAllowedAgentsChange(bad, "GoodBot"); err == nil {
		t.Error("a changed value with an unusable line must be refused")
	}
	if err := ValidateAllowedAgentsChange("GoodBot\nokhttp @ /api", bad); err != nil {
		t.Errorf("a changed, usable value must be accepted, got %v", err)
	}
	if err := ValidateAllowedAgentsChange("", bad); err != nil {
		t.Errorf("clearing the list must be accepted, got %v", err)
	}
}

func TestValidateAllowedAgents(t *testing.T) {
	if err := ValidateAllowedAgents("GoodBot\n# x\nokhttp @ /api /v2/\nokhttp @ /"); err != nil {
		t.Fatalf("valid value refused: %v", err)
	}
	err := ValidateAllowedAgents("GoodBot\n\n# comment\nokhttp @ api\nokhttp @ //x")
	if err == nil {
		t.Fatal("want an error for the unusable line")
	}
	// The line number counts every line of the field, so the operator can
	// find it; the first bad line is the one reported.
	want := `invalid custom_allowed_agents line 4 ("okhttp @ api"): path "api" must start with "/"`
	if err.Error() != want {
		t.Fatalf("error = %q\nwant    %q", err.Error(), want)
	}
}
