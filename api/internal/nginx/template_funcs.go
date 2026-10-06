package nginx

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// GetTemplateFuncMap returns the common template function map used across all config generators
func GetTemplateFuncMap(apiHost string) template.FuncMap {
	return template.FuncMap{
		"join":      strings.Join,
		"hostPort":  formatHostPort,
		"hasPrefix": strings.HasPrefix,
		"now": func() string {
			return "auto-generated"
		},
		"escapeNginxPattern": func(s string) string {
			// Normalize: first remove any existing escapes to handle already-escaped patterns
			s = strings.ReplaceAll(s, `\"`, `"`)
			// Then escape all double quotes for nginx double-quoted strings
			return strings.ReplaceAll(s, `"`, `\"`)
		},
		"certPath": func(h *model.ProxyHost) string {
			// Use certificate ID if available, otherwise fall back to proxy host ID
			if h.CertificateID != nil && *h.CertificateID != "" {
				return *h.CertificateID
			}
			return h.ID
		},
		"wafConfig": func(h *model.ProxyHost) string {
			// Return per-host WAF config file
			return fmt.Sprintf("host_%s.conf", h.ID)
		},
		"ipWhitelist": func(s string) []string {
			// Entries nginx can actually put in a geo block. Anything else is
			// dropped here rather than at nginx: this column predates its own
			// validation, so old rows can hold junk, and one bad token inside a
			// geo block is an [emerg] that blocks the reload for every host.
			valid, _ := model.ParseIPWhitelist(s)
			return valid
		},
		"sanitizeID": func(id string) string {
			// Replace hyphens with underscores for nginx zone names
			return strings.ReplaceAll(id, "-", "_")
		},
		"toRegexPattern": func(s string) string {
			// Convert newline-separated patterns to pipe-separated regex pattern
			lines := strings.Split(s, "\n")
			var patterns []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if len(line) > 500 {
					line = line[:500]
				}
				// Escape special regex characters
				line = strings.ReplaceAll(line, "\\", "\\\\")
				line = strings.ReplaceAll(line, ".", "\\.")
				line = strings.ReplaceAll(line, "+", "\\+")
				line = strings.ReplaceAll(line, "?", "\\?")
				line = strings.ReplaceAll(line, "(", "\\(")
				line = strings.ReplaceAll(line, ")", "\\)")
				line = strings.ReplaceAll(line, "[", "\\[")
				line = strings.ReplaceAll(line, "]", "\\]")
				line = strings.ReplaceAll(line, "{", "\\{")
				line = strings.ReplaceAll(line, "}", "\\}")
				line = strings.ReplaceAll(line, "^", "\\^")
				line = strings.ReplaceAll(line, "$", "\\$")
				line = strings.ReplaceAll(line, "|", "\\|")
				line = strings.ReplaceAll(line, "*", ".*")
				line = strings.ReplaceAll(line, " ", "\\s")
				patterns = append(patterns, line)
			}
			if len(patterns) > 100 {
				patterns = patterns[:100]
			}
			return strings.Join(patterns, "|")
		},
		"apiHost": func() string {
			return apiHost
		},
		"len": func(s []string) int {
			return len(s)
		},
		"uriLocationDirective": func(matchType model.URIMatchType, pattern string) string {
			switch matchType {
			case model.URIMatchExact:
				return fmt.Sprintf("location = %s", pattern)
			case model.URIMatchPrefix:
				return fmt.Sprintf("location ^~ %s", pattern)
			case model.URIMatchRegex:
				return fmt.Sprintf("location ~* %s", pattern)
			default:
				return fmt.Sprintf("location ^~ %s", pattern)
			}
		},
		"hasURIBlockExceptionIPs": func(ub *model.URIBlock) bool {
			return ub != nil && (len(ub.ExceptionIPs) > 0 || ub.AllowPrivateIPs)
		},
		"escapeRegex": func(s string) string {
			s = strings.TrimSpace(s)
			if s == "" {
				return s
			}
			if strings.Contains(s, "/") {
				parts := strings.Split(s, "/")
				if len(parts) == 2 {
					ip := strings.ReplaceAll(parts[0], ".", "\\.")
					return ip + "/" + parts[1]
				}
			}
			return strings.ReplaceAll(s, ".", "\\.")
		},
		"isCIDR":             isCIDR,
		"cidrToNginxPattern": cidrToNginxPattern,
		"splitExceptions": func(s string) []string {
			if s == "" {
				return nil
			}
			lines := strings.Split(s, "\n")
			var patterns []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				patterns = append(patterns, line)
			}
			return patterns
		},
		"hasExceptions": func(s string) bool {
			if s == "" {
				return false
			}
			lines := strings.Split(s, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					return true
				}
			}
			return false
		},
		"mergeExceptions": func(global, host string) string {
			var patterns []string
			seen := make(map[string]bool)

			if global != "" {
				for _, line := range strings.Split(global, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
						patterns = append(patterns, line)
						seen[line] = true
					}
				}
			}

			if host != "" {
				for _, line := range strings.Split(host, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
						patterns = append(patterns, line)
						seen[line] = true
					}
				}
			}

			return strings.Join(patterns, "\n")
		},
		"hasMergedExceptions": func(global, host string) bool {
			if global != "" {
				for _, line := range strings.Split(global, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return true
					}
				}
			}
			if host != "" {
				for _, line := range strings.Split(host, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return true
					}
				}
			}
			return false
		},
		"filterRulesByPatternType": func(rules []model.ExploitBlockRuleForRender, patternType string) []model.ExploitBlockRuleForRender {
			var filtered []model.ExploitBlockRuleForRender
			for _, rule := range rules {
				if rule.PatternType == patternType {
					filtered = append(filtered, rule)
				}
			}
			return filtered
		},
		"hasExploitRules": func(rules []model.ExploitBlockRuleForRender) bool {
			return len(rules) > 0
		},
		"hasRulesOfType": func(rules []model.ExploitBlockRuleForRender, patternType string) bool {
			for _, rule := range rules {
				if rule.PatternType == patternType {
					return true
				}
			}
			return false
		},
		"hasDirective": func(directives map[string]bool, name string) bool {
			return directives[name]
		},
		"exemptionPattern": exemptionPattern,
	}
}

// exemptionPattern renders an operator-written exemption regex (exploit-rule
// URI exclusions and Block Exploits exceptions) for a test on
// $npg_request_target: the normalized request path, then the query string as
// sent. Before, the same patterns tested $request_uri, where the path is still
// percent-encoded; the exploit log shows it that way and the exclusion form
// suggests it. So each literal %HH is widened to (?:%HH|\xHH): the escape
// still matches the query string as sent, and the byte matches the decoded
// path. "^/files/my%20docs/" keeps matching /files/my%20docs/a, and so does a
// path copied from the log in Korean. To PCRE, "\%HH" and a %HH inside
// \Q...\E are that same literal, so they are widened as well; copied as
// written, they no longer matched the path they matched before.
//
// Block Exploits exceptions are not validated and may use any PCRE syntax, so
// whatever is not such a literal is copied as written: any other escape, a
// (?#...) comment, a backtracking verb such as (*MARK:name), a callout string
// and the inside of a character class. The result compiles wherever the input
// did.
//
// The pattern sits between the double quotes of that test, and nginx's
// tokenizer unescapes a quoted string before PCRE compiles it: "\\" becomes one
// backslash, \" and \' a quote, \t, \r and \n a control byte, and any other
// backslash pair stays as written. The stored text has always been written
// there as it is, so the widening works on what PCRE compiles: the text is
// unescaped first and escaped for the string again afterwards, and a pattern
// with no %HH to widen reaches PCRE exactly as before. Widened as stored,
// "^/a\\%2F" (PCRE: ^/a\%2F) rendered as "^/a\\(?:%2F|\x2F)", which reached
// PCRE as an escaped "(" and an unmatched ")", and nginx -t failed for the
// whole config.
//
// Widening grows each %HH from 3 bytes to 12, and nginx refuses a config token
// longer than 4094 bytes ("too long parameter"). Block Exploits exceptions have
// no length limit, so a pattern whose widened form would exceed
// maxExemptionPattern gets each %HH as \xHH instead, 4 bytes: it matches the
// decoded path, as the pattern matched the encoded one on $request_uri, but no
// escape in the query string. A pattern too long even for that is rendered as
// written, which matches the query string but not the path, and is logged.
//
// The template refuses every exemption on its own when $npg_request_path is
// "" (an unsafe path), so a pattern that matches "" needs nothing here.
func exemptionPattern(p string) string {
	pcre := unquoteNginxString(p)
	if widened := quoteNginxString(rewritePercentEscapes(pcre, widenEscape)); len(widened) <= maxExemptionPattern {
		return widened
	}
	if decoded := quoteNginxString(rewritePercentEscapes(pcre, byteEscape)); len(decoded) <= maxExemptionPattern {
		return decoded
	}
	log.Printf("[WARN] Exploit exemption pattern %.60q... (%d bytes) is too long to match a percent-encoded path; it is used as written", p, len(p))
	return quoteNginxString(pcre)
}

// maxExemptionPattern bounds a rendered exemption pattern: nginx reads a config
// token into a 4096-byte buffer and refuses one longer than 4094 bytes.
const maxExemptionPattern = 4000

// widenEscape and byteEscape are the two ways exemptionPattern writes a %HH.
func widenEscape(hh string) string { return `(?:%` + hh + `|\x` + hh + `)` }
func byteEscape(hh string) string  { return `\x` + hh }

// rewritePercentEscapes copies the PCRE pattern p with each literal %HH in it
// passed through rewrite: written bare, as \%HH, or inside a \Q...\E quote,
// which is split around it. Other escapes, (?#...) comments, backtracking
// verbs, callout strings and character classes are copied as written (see
// exemptionPattern).
func rewritePercentEscapes(p string, rewrite func(hh string) string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case strings.HasPrefix(p[i:], `\Q`):
			// Literal up to \E, or to the end of the pattern without one.
			quoted, next := p[i+2:], len(p)
			if n := strings.Index(quoted, `\E`); n >= 0 {
				quoted, next = quoted[:n], i+2+n+2
			}
			if !hasPercentEscape(quoted) {
				b.WriteString(p[i:next])
			} else {
				run := 0
				for j := 0; j < len(quoted); j++ {
					if isPercentEscape(quoted, j) {
						if j > run {
							b.WriteString(`\Q` + quoted[run:j] + `\E`)
						}
						b.WriteString(rewrite(quoted[j+1 : j+3]))
						j += 2
						run = j + 1
					}
				}
				if run < len(quoted) {
					b.WriteString(`\Q` + quoted[run:] + `\E`)
				}
			}
			i = next - 1
		case strings.HasPrefix(p[i:], "(?#"), strings.HasPrefix(p[i:], "(*"):
			// A comment, or a verb such as (*MARK:name): text up to the first ")".
			n := strings.IndexByte(p[i:], ')')
			if n < 0 {
				n = len(p) - i - 1
			}
			b.WriteString(p[i : i+n+1])
			i += n
		case strings.HasPrefix(p[i:], "(?C") && i+3 < len(p) && strings.IndexByte("`'\"^%#${", p[i+3]) >= 0:
			// A callout string runs to its closing delimiter ("}" for "{"),
			// and a doubled delimiter stands for itself.
			d := p[i+3]
			if d == '{' {
				d = '}'
			}
			j := i + 4
			for j < len(p) && (p[j] != d || j+1 < len(p) && p[j+1] == d) {
				if p[j] == d {
					j++
				}
				j++
			}
			b.WriteString(p[i:min(j+1, len(p))])
			i = j
		case c == '\\' && isPercentEscape(p, i+1):
			// \% is a literal "%" to PCRE, so \%HH is the same %HH.
			b.WriteString(rewrite(p[i+2 : i+4]))
			i += 3
		case c == '\\':
			// \cX takes the next character as its argument, whatever it is.
			n := 2
			if strings.HasPrefix(p[i:], `\c`) {
				n = 3
			}
			n = min(n, len(p)-i)
			b.WriteString(p[i : i+n])
			i += n - 1
		case c == '[':
			n := charClassLen(p[i:])
			b.WriteString(p[i : i+n])
			i += n - 1
		case isPercentEscape(p, i):
			b.WriteString(rewrite(p[i+1 : i+3]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// isPercentEscape reports whether s holds a %HH at i.
func isPercentEscape(s string, i int) bool {
	return i+2 < len(s) && s[i] == '%' && isHexDigit(s[i+1]) && isHexDigit(s[i+2])
}

// hasPercentEscape reports whether s holds a %HH anywhere.
func hasPercentEscape(s string) bool {
	for i := range len(s) {
		if isPercentEscape(s, i) {
			return true
		}
	}
	return false
}

// charClassLen returns the length of the PCRE character class at the start of
// p (p[0] == '['), or len(p) when it is not closed. A "]" right after "[" or
// "[^" is a member, a backslash escapes the next character, and a POSIX class
// such as [:alpha:] is skipped whole.
func charClassLen(p string) int {
	i := 1
	if i < len(p) && p[i] == '^' {
		i++
	}
	if i < len(p) && p[i] == ']' {
		i++
	}
	for i < len(p) {
		switch {
		case p[i] == '\\':
			i += 2
		case strings.HasPrefix(p[i:], "[:"):
			if n := strings.Index(p[i+2:], ":]"); n >= 0 {
				i += n + 4
			} else {
				i++
			}
		case p[i] == ']':
			return i + 1
		default:
			i++
		}
	}
	return len(p)
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// unquoteNginxString returns what nginx's config tokenizer makes of s written
// between double quotes: \", \' and \\ stand for the character after the
// backslash, \t, \r and \n for the control byte, and any other backslash pair
// stays as written.
func unquoteNginxString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\'', '\\':
				c = s[i+1]
				i++
			case 't':
				c = '\t'
				i++
			case 'r':
				c = '\r'
				i++
			case 'n':
				c = '\n'
				i++
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// quoteNginxString escapes s for a double-quoted nginx string, so that the
// tokenizer gives s back byte for byte. A backslash is doubled only where the
// tokenizer would read it as part of an escape (before a quote, a backslash,
// t, r, n or a control byte it escapes, and at the end, where it would escape
// the closing quote), so "^/a\.php" renders as it is written.
func quoteNginxString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '\\':
			if i+1 == len(s) || strings.IndexByte("\"'\\trn\t\r\n", s[i+1]) >= 0 {
				b.WriteString(`\\`)
			} else {
				b.WriteByte(c)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// GetRedirectTemplateFuncMap returns template functions for redirect host config
func GetRedirectTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
		"now": func() string {
			return "auto-generated"
		},
		"certPath": func(h *model.RedirectHost) string {
			if h.CertificateID != nil && *h.CertificateID != "" {
				return *h.CertificateID
			}
			return h.ID
		},
		"redirectReturn": func(h *model.RedirectHost) string {
			scheme := h.ForwardScheme
			if scheme == "auto" || scheme == "" {
				scheme = "$scheme"
			}
			target := fmt.Sprintf("%s://%s", scheme, h.ForwardDomainName)
			if h.ForwardPath != "" {
				target += h.ForwardPath
			}
			if h.PreservePath {
				target += "$request_uri"
			}
			return fmt.Sprintf("return %d %s;", h.RedirectCode, target)
		},
	}
}

// GetSimpleTemplateFuncMap returns a minimal template function map for simple templates
func GetSimpleTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"now": func() string {
			return "auto-generated"
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			case string:
				return len(val)
			case map[string]interface{}:
				return len(val)
			case []model.WAFRuleExclusion:
				return len(val)
			case []model.ExploitBlockRuleForRender:
				return len(val)
			default:
				return 0
			}
		},
		"joinComma": func(s []string) string {
			return strings.Join(s, ",")
		},
		// scopedRuleID numbers the helper rules a URI-scoped exclusion needs.
		//
		// ModSecurity requires every rule in a set to carry a unique id, and a
		// scoped exclusion is implemented as its own SecRule. The range starts
		// at 1,000,000 — the conventional local-rule space, clear of the
		// 900,000-999,999 block OWASP CRS uses, so a CRS upgrade cannot collide
		// with an operator's exclusions. Per-host files are separate rule sets,
		// so the index only has to be unique within one host. (#231)
		"scopedRuleID": func(i int) int {
			return 1000000 + i
		},
		"uriScopePattern":      uriScopePattern,
		"uriScopeQueryPattern": uriScopeQueryPattern,
		// unsafePathGuard is the regex a uri-scoped exclusion's chained rule
		// refuses: the nginx map's unsafe paths. In REQUEST_FILENAME that also
		// takes in a plain dot segment, which nginx resolves in $uri but
		// libmodsecurity leaves in place.
		"unsafePathGuard": func() string {
			return `(?i)(?:` + unsafeRequestPathPattern + `)`
		},
	}
}

// uriScopePattern turns a stored uri scope into the anchored pattern its
// exclusion rule matches against REQUEST_FILENAME after t:normalizePath.
//
// "@beginsWith /api" was a raw byte prefix, so an exemption scoped to /api also
// switched the rule off for /api-admin, /apikeys and /apiv2 — paths the
// operator never named, with no signal anywhere in the UI. (#286) Matched on
// REQUEST_URI it also covered /api/../admin, which nginx and the backend both
// serve as /admin.
//
// Details that are load-bearing, each checked against libmodsecurity 3.0.15:
//   - REQUEST_FILENAME arrives percent-decoded once, exactly as nginx decodes
//     $uri, so the stored value is decoded once too. The log viewer prefills
//     the raw logged path, and a raw "/files/my%20docs" never matched the
//     decoded request for that path. A value that is not valid percent-encoding
//     is used as typed.
//   - No t:urlDecodeUni: it would be a second decode, and it turns "+" into a
//     space, so a scope like /c++ would stop matching /c++/x.
//   - \A and \z, not ^ and $: libmodsecurity compiles @rx multiline, so
//     "^/api" also matched "/admin%0a/api".
//   - A trailing slash is trimmed. An operator who typed "/api/" means the same
//     subtree, and "\A/api/(?:/|\z)" would match nothing they use. The query
//     string is not part of REQUEST_FILENAME, so "/" is the only boundary.
//   - Runs of "/" are collapsed after decoding, as t:normalizePath collapses
//     them in the request. ValidateScope accepts "/api//v1", which would
//     otherwise match no request and silently stop exempting anything.
//   - A value with a "?" (ValidateScope accepts one; an older UI prefilled the
//     logged path with its query) names one resource and a query. On
//     REQUEST_URI it matched that exact path followed by that query, and it
//     still does: the path before the "?" must match exactly (no subtree, no
//     trimmed slash), and uriScopeQueryPattern adds a chained test on the
//     query. Cut at the "?" alone, it exempted the whole path under every
//     query; matched as written, it matched nothing.
//   - Every byte outside [A-Za-z0-9/_~-] is escaped: regex metacharacters with a
//     backslash, the rest as \xHH. ValidateScope permits . + * ( ) [ ] ^, and an
//     unbalanced "(" compiles to a rule that never fires while `nginx -t` still
//     reports success, because libmodsecurity swallows the PCRE compile error.
//     Decoding can also produce a quote, a backslash, "%{" or a newline, each of
//     which would otherwise end the directive or start a macro.
func uriScopePattern(v string) string {
	path, _, hasQuery := strings.Cut(v, "?")
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if hasQuery {
		return `\A` + scopeRegexLiteral(path) + `\z`
	}
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		// An all-slashes value stays literal rather than widening to every path.
		trimmed = path
	}
	return `\A` + scopeRegexLiteral(trimmed) + `(?:/|\z)`
}

// uriScopeQueryPattern returns the pattern a uri scope's query part must match
// in QUERY_STRING after t:urlDecode, or "" when the stored value has no "?".
//
// QUERY_STRING is the raw query, so it is decoded (t:urlDecode: %HH, and "+"
// as a space) and so is the stored part, the same way. On REQUEST_URI, which
// libmodsecurity decodes, a scope of "/?rest_route=/wp/v2/posts" also covered
// the editor's ?rest_route=%2Fwp%2Fv2%2Fposts%2F1. The boundary is the one the
// scope had there: the query begins with the stored part, followed by "/", "?"
// or nothing. Whoever knows the scope can still append "/&q=..." to it; that
// was so before, and ctl:ruleRemoveById cannot be narrower than the request.
func uriScopeQueryPattern(v string) string {
	_, query, ok := strings.Cut(v, "?")
	if !ok {
		return ""
	}
	if decoded, err := url.QueryUnescape(query); err == nil {
		query = decoded
	}
	return `\A` + scopeRegexLiteral(query) + `(?:[/?]|\z)`
}

// scopeRegexLiteral writes s as a regex matching exactly s, with every byte
// outside [A-Za-z0-9/_~-] escaped (see uriScopePattern).
func scopeRegexLiteral(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '/', c == '_', c == '~', c == '-':
			b.WriteByte(c)
		case strings.IndexByte(`.+*?()|[]{}^$`, c) >= 0:
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String()
}
