package model

import (
	"fmt"
	"regexp"
	"strings"
)

// A custom_allowed_agents line may limit its exemption to path prefixes (#313):
//
//	GoodBot                              exempt on the whole host, as before
//	okhttp @ /api                        exempt only under /api
//	python-requests @ /webhook /hooks    exempt under either path
//
// An exemption for a common client library (okhttp, python-requests, Go's
// http client — exactly what "Block suspicious clients" catches) used to open
// the whole host to every program built on it, when only one API needed it.
//
// A path covers itself and everything below it: /api covers /api and /api/v1,
// not /api-admin. nginx matches it against the decoded, normalized path it
// routes on, so a path is written decoded and with no query string, "//" or
// dot segment: such a value could never match, and it is refused rather than
// kept as a line that silently does nothing. A trailing "/" is ignored, and "/"
// alone means the whole host.
//
// Any "@" standing alone between spaces starts the path list, so "okhttp @ api"
// is an error, not a user agent that contains " @ ". An "@" written against the
// path or the agent ("okhttp @/api", "okhttp@ /api") is an error too; a user
// agent that merely contains "@" ("bot@example.com") is not affected.

const (
	// MaxScopedAllowedAgents bounds the lines that carry paths. Each one
	// renders one server-level `if` that every request to the host runs, in
	// every server block of the host and, for the global default, of every
	// inheriting host. nginx keeps a location context per `if`, about 30 KB
	// with ModSecurity: 300 inheriting HTTP hosts at this cap measured 401 MB
	// against 220 MB without such lines.
	MaxScopedAllowedAgents = 20
	// MaxAllowedAgentPaths bounds the paths on one line. They share the line's
	// one regex, so they add to its length, not to the number of `if`s.
	MaxAllowedAgentPaths = 10
)

// ScopedAllowedAgent is a custom_allowed_agents line limited to paths.
type ScopedAllowedAgent struct {
	Agent string   // the user-agent text before " @ ", matched like any other line
	Paths []string // as written; each starts with "/" and is not "/" itself
}

// InvalidAllowedAgent is a line that names paths but cannot be used.
type InvalidAllowedAgent struct {
	Line   int    // 1-based line number in the field
	Text   string // the line, trimmed
	Reason string
}

var (
	// allowedAgentScopeSep is an "@" with a space or tab (or the end of the
	// line) on each side. Only spaces and tabs, so the UI's copy of the parser
	// reads a line exactly the same way.
	allowedAgentScopeSep = regexp.MustCompile(`(?:^|[ \t])@(?:[ \t]|$)`)
	// allowedAgentGluedSep is the same separator with a space missing.
	allowedAgentGluedSep = regexp.MustCompile(`(?:^|[ \t])@/|[^ \t]@[ \t]+/`)
)

// ParseAllowedAgents splits a custom_allowed_agents value into the lines that
// apply to the whole host, the lines limited to paths, and the lines that try
// to name paths but cannot be used. Blank lines and "#" comments are skipped.
//
// Both callers need all three. The write path answers 400 for the first
// invalid line; the render path renders the first two and drops the rest,
// because a value saved before this syntax existed, restored from a backup or
// cloned never went through the write path, and an unusable line must cost
// only its own exemption, never the config.
func ParseAllowedAgents(raw string) (site []string, scoped []ScopedAllowedAgent, invalid []InvalidAllowedAgent) {
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		reject := func(reason string) {
			invalid = append(invalid, InvalidAllowedAgent{Line: i + 1, Text: line, Reason: reason})
		}
		sep := allowedAgentScopeSep.FindStringIndex(line)
		if sep == nil {
			if allowedAgentGluedSep.MatchString(line) {
				reject(`write " @ " with a space on each side of "@"`)
				continue
			}
			site = append(site, line)
			continue
		}
		agent := strings.TrimSpace(line[:sep[0]])
		paths := strings.FieldsFunc(line[sep[1]:], func(r rune) bool { return r == ' ' || r == '\t' })
		switch {
		case agent == "":
			reject(`no user agent before "@"`)
			continue
		case len(paths) == 0:
			reject(`no path after "@"`)
			continue
		case len(paths) > MaxAllowedAgentPaths:
			reject(fmt.Sprintf("at most %d paths per line", MaxAllowedAgentPaths))
			continue
		}
		reason, wholeHost := "", false
		for _, p := range paths {
			if reason = allowedAgentPathError(p); reason != "" {
				break
			}
			wholeHost = wholeHost || p == "/"
		}
		switch {
		case reason != "":
			reject(reason)
		case wholeHost:
			site = append(site, agent)
		case len(scoped) == MaxScopedAllowedAgents:
			reject(fmt.Sprintf("at most %d lines can be limited to paths", MaxScopedAllowedAgents))
		default:
			scoped = append(scoped, ScopedAllowedAgent{Agent: agent, Paths: paths})
		}
	}
	return site, scoped, invalid
}

// ValidateAllowedAgents names the first line that cannot be used, so the API
// can say which one it rejected and why.
func ValidateAllowedAgents(raw string) error {
	if _, _, invalid := ParseAllowedAgents(raw); len(invalid) > 0 {
		bad := invalid[0]
		return fmt.Errorf("invalid custom_allowed_agents line %d (%q): %s", bad.Line, bad.Text, bad.Reason)
	}
	return nil
}

// ValidateAllowedAgentsChange is the write-path rule for a sent value: it is
// validated only when it differs from the stored one (the #263 rule). The UI
// sends the stored list back on every save, and a row written before this
// syntax existed, restored from a backup or cloned may hold a line the check
// refuses; refusing it unchanged would fail every later save of the bot filter.
// The renderer drops such a line either way.
func ValidateAllowedAgentsChange(sent, stored string) error {
	if sent == stored {
		return nil
	}
	return ValidateAllowedAgents(sent)
}

// allowedAgentPathError says why p cannot be a path, or returns "". The checks
// before ValidateScope only give a precise reason for something that can never
// match; ValidateScope, the WAF uri-scope rule, is the gate on what may reach a
// config file at all.
func allowedAgentPathError(p string) string {
	switch {
	case !strings.HasPrefix(p, "/"):
		return fmt.Sprintf(`path %q must start with "/"`, p)
	case strings.Contains(p, "%"):
		return fmt.Sprintf(`path %q contains "%%": percent-encoded paths are not supported`, p)
	case strings.Contains(p, "//"):
		return fmt.Sprintf(`path %q contains "//"`, p)
	case strings.ContainsAny(p, "?#"):
		return fmt.Sprintf(`path %q contains "?" or "#": only the path is matched, not a query string`, p)
	case hasDotOnlySegment(p):
		return fmt.Sprintf(`path %q contains a "." or ".." segment`, p)
	}
	if i := strings.IndexAny(p, "\"'\\`;{}$|&<>"); i >= 0 {
		return fmt.Sprintf(`path %q contains %q, which is not allowed`, p, p[i:i+1])
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return fmt.Sprintf("path %q: only printable ASCII is allowed", p)
		}
	}
	if len(p) > maxScopeValue {
		return fmt.Sprintf("path %q is longer than %d characters", p, maxScopeValue)
	}
	scope := WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: p}
	if err := scope.ValidateScope(); err != nil {
		return fmt.Sprintf("path %q: %s", p, strings.TrimPrefix(err.Error(), "invalid scope_value: "))
	}
	return ""
}

// hasDotOnlySegment reports a segment made of dots alone. nginx resolves "."
// and ".." before it matches a path, and maps a request path that still holds
// such a segment to "" (conf.d/npg_request_path.conf), so a path containing one
// would never match anything.
func hasDotOnlySegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg != "" && strings.Trim(seg, ".") == "" {
			return true
		}
	}
	return false
}
