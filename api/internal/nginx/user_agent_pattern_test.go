package nginx

// toRegexPattern output goes into `if ($http_user_agent ~* (...))` unquoted,
// so nginx's config tokenizer reads it before PCRE does. These tests pin what
// a golden file cannot: that every line survives that tokenizer and matches
// its own text, that lists which always rendered correctly render byte for
// byte the same, and that a list with nothing but comments renders nothing.

import (
	"regexp"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// legacyToRegexPattern is toRegexPattern as it was before ";", "\" and
// whitespace were escaped for nginx, kept to prove every other line renders
// exactly as it did.
func legacyToRegexPattern(s string) string {
	var patterns []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 500 {
			line = line[:500]
		}
		for _, r := range []struct{ from, to string }{
			{`\`, `\\`}, {".", `\.`}, {"+", `\+`}, {"?", `\?`}, {"(", `\(`}, {")", `\)`},
			{"[", `\[`}, {"]", `\]`}, {"{", `\{`}, {"}", `\}`}, {"^", `\^`}, {"$", `\$`},
			{"|", `\|`}, {"*", ".*"}, {" ", `\s`},
		} {
			line = strings.ReplaceAll(line, r.from, r.to)
		}
		patterns = append(patterns, line)
	}
	if len(patterns) > 100 {
		patterns = patterns[:100]
	}
	return strings.Join(patterns, "|")
}

// readNginxToken reads s the way nginx's tokenizer reads an unquoted token
// (ngx_conf_read_token): it ends at a space, tab, CR, LF, ";" or "{" that is
// not escaped by "\", and \\ \" \' \t \r \n are then unescaped. It returns the
// token and whatever follows it.
func readNginxToken(s string) (token, rest string) {
	end := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if strings.IndexByte(" \t\r\n;{", s[i]) >= 0 {
			end = i
			break
		}
	}
	var b strings.Builder
	for i := 0; i < end; i++ {
		if s[i] == '\\' && i+1 < end {
			switch s[i+1] {
			case '"', '\'', '\\':
				i++
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), s[end:]
}

func TestToRegexPatternKeepsValidListsUnchanged(t *testing.T) {
	lists := map[string]string{
		"bad bots":       strings.Join(model.KnownBadBots, "\n"),
		"AI bots":        strings.Join(model.AIBots, "\n"),
		"suspicious":     strings.Join(model.SuspiciousClients, "\n"),
		"search engines": strings.Join(model.SearchEngineBots, "\n"),
		"metacharacters": "a.b\nx+y\n(x)\n[abc]\n{n}\n^start\nend$\na|b\nq?\na*b\nSeekport Crawler\n  # comment\n\nbot@example.com\n한글봇",
	}
	for name, list := range lists {
		if got, want := toRegexPattern(list), legacyToRegexPattern(list); got != want {
			t.Errorf("%s: rendering changed\n got %s\nwant %s", name, got, want)
		}
	}
}

func TestToRegexPatternEscapesForNginx(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (compatible; Googlebot/2.1)": `Mozilla/5\.0\s\(compatible\;\sGooglebot/2\.1\)`,
		`foo\bar`:      `foo\x5cbar`,
		`trailing\`:    `trailing\x5c`,
		"tab\tinside":  `tab\sinside`,
		"a\x01b\x7fc":  `a\x01b\x7fc`,
		"cr\rinside":   `cr\x0dinside`,
		`\Q(?i)`:       `\x5cQ\(\?i\)`,
		`say \"hi\"`:   `say\s\x5c"hi\x5c"`,
		"# only":       "",
		" \t \n#x\n\n": "",
	}
	for in, want := range cases {
		if got := toRegexPattern(in); got != want {
			t.Errorf("toRegexPattern(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestToRegexPatternMatchesTheLiteralLine(t *testing.T) {
	lines := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"semi;colon", ";", `foo\bar`, `trailing\`, `\`, `\x41`, `\t`, `\n`, `\d+`, `\\`,
		"tab\tinside", "{brace}", "${var}", "$http_host", `"quoted"`, "'single'", "a#b",
		"%{REMOTE_ADDR}", "a\x01b", "del\x7f", `\Q(?i)`, `a\"b`, `x\;`, "}", "{", "a  b",
	}
	for _, line := range lines {
		p := toRegexPattern(line)
		// The template writes `~* (<p>))` and `if` strips one ")" off the
		// last argument: one token, read back exactly as written.
		arg := "(" + p + "))"
		tok, rest := readNginxToken(arg)
		if rest != "" || tok != arg {
			t.Errorf("%q: nginx would read %q (left %q), not %q", line, tok, rest, arg)
			continue
		}
		re, err := regexp.Compile("(?i)(" + p + ")")
		if err != nil {
			t.Errorf("%q: pattern %s does not compile: %v", line, p, err)
			continue
		}
		if !re.MatchString("prefix " + line + " suffix") {
			t.Errorf("%q: pattern %s does not match the line itself", line, p)
		}
	}
	// Escaped, not interpreted: none of these may match the near miss.
	for line, nearMiss := range map[string]string{
		`foo\bar`: "foo bar", `\x41`: "A", `\t`: "x\ty", `\d+`: "123", `\\`: `a\b`,
		"a.b": "axb", "[abc]": "a", "a|b": "a", `a\"b`: `a"b`,
	} {
		re := regexp.MustCompile("(?i)(" + toRegexPattern(line) + ")")
		if re.MatchString(nearMiss) {
			t.Errorf("%q also matches %q", line, nearMiss)
		}
	}
}

func TestToRegexPatternCaps(t *testing.T) {
	if got := toRegexPattern(strings.Repeat("a", 600)); got != strings.Repeat("a", 500) {
		t.Errorf("a line is cut at 500 bytes, got %d", len(got))
	}
	var lines []string
	for i := 0; i < 150; i++ {
		lines = append(lines, "# comment", "bot"+strings.Repeat("x", i))
	}
	if got := strings.Count(toRegexPattern(strings.Join(lines, "\n")), "|") + 1; got != 100 {
		t.Errorf("at most 100 lines are used, got %d", got)
	}
}

// A list holding only comments or blank lines rendered `~* ()`, which matches
// every user agent: a 403 for every visitor from a block list, and a bypass
// for every client from the allow list or the search-engine list.
func TestUserAgentListsWithoutPatternsRenderNothing(t *testing.T) {
	const empty = "# nothing here\n\n   \n#"
	certID := "00000000-0000-0000-0000-00000000cert"
	for _, ssl := range []bool{false, true} {
		host := baseHost("00000000-0000-0000-0000-0000000000b7", "192.0.2.20", true)
		if ssl {
			host.SSLEnabled, host.CertificateID = true, &certID
		}
		data := ProxyHostConfigData{
			Host: host,
			BotFilter: &model.BotFilter{Enabled: true, BlockBadBots: true, BlockAIBots: true, AllowSearchEngines: true,
				BlockSuspiciousClients: true, CustomBlockedAgents: empty, CustomAllowedAgents: empty},
			BadBotsList: empty, AIBotsList: empty, SuspiciousClientsList: empty, SearchEnginesList: empty,
			GeoRestriction: &model.GeoRestriction{Enabled: true, Mode: "whitelist", Countries: []string{"KR"}, AllowSearchBots: true},
		}
		out := renderForTest(t, data)
		if strings.Contains(out, "()") {
			t.Errorf("ssl=%v: an empty alternation was rendered:\n%s", ssl, out)
		}
		for _, absent := range []string{"set $is_search_bot 1;", "set $block_bad_bot 0;", "set $block_ai_bot 0;",
			"set $block_suspicious 0;", "set $block_custom 0;", "# Custom allowed agents bypass"} {
			if strings.Contains(out, absent) {
				t.Errorf("ssl=%v: %q rendered for a list with no pattern", ssl, absent)
			}
		}

		// The same lists with one real line each render every check again.
		data.BotFilter.CustomBlockedAgents, data.BotFilter.CustomAllowedAgents = empty+"\nEvilBot", empty+"\nGoodBot"
		data.BadBotsList, data.AIBotsList, data.SuspiciousClientsList, data.SearchEnginesList = "AhrefsBot", "GPTBot", "curl", "Googlebot"
		out = renderForTest(t, data)
		for _, present := range []string{
			"if ($http_user_agent ~* (Googlebot)) {\n        set $is_search_bot 1;",
			"if ($http_user_agent ~* (GoodBot)) {\n        set $priority_allow 1;",
			"if ($http_user_agent ~* (AhrefsBot)) {\n        set $block_bad_bot 1;",
			"if ($http_user_agent ~* (GPTBot)) {\n        set $block_ai_bot 1;",
			"if ($http_user_agent ~* (curl)) {\n        set $block_suspicious 1;",
			"if ($http_user_agent ~* (EvilBot)) {\n        set $block_custom 1;",
		} {
			if !strings.Contains(out, present) {
				t.Errorf("ssl=%v: missing %q", ssl, present)
			}
		}
	}
}
