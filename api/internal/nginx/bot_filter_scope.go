package nginx

import (
	"strings"

	"nginx-proxy-guard/internal/model"
)

// scopedAllowedAgent is a custom_allowed_agents line limited to paths (#313),
// ready for _security.conf.tmpl.
type scopedAllowedAgent struct {
	Paths    []string // as written, for the comment above the checks
	Patterns []string // each tested against $bot_scoped_subject: "$npg_request_path\n$http_user_agent"
}

// siteAllowedAgents renders the custom_allowed_agents lines that apply to the
// whole host. Lines limited to paths are rendered by scopedAllowedAgents
// instead, and lines that cannot be used are dropped (model.ParseAllowedAgents
// says why). With no such line it returns "", and the template renders
// nothing.
func siteAllowedAgents(raw string) string {
	site, _, _ := model.ParseAllowedAgents(raw)
	return toRegexPattern(strings.Join(site, "\n"))
}

// scopedAllowedAgents renders the custom_allowed_agents lines limited to
// paths. The template sets $priority_allow for such a line only when the user
// agent matches AND the request path is under one of its paths.
//
// The path is decided on $npg_request_path (conf.d/npg_request_path.conf), the
// decoded and normalized path nginx routes on, and never on $request_uri:
// "/api/../admin" and "/api/%2e%2e/admin" begin with "/api/" but reach /admin.
// Not on $uri either, although that is the same path at first: the server-level
// checks run again on an error_page redirect (/error_502.html) and inside an
// auth_request subrequest (geo challenge, ForwardAuth) with $uri changed, which
// turned an exempt request into a 403 whenever the upstream was down, a
// challenge was on or ForwardAuth guarded the path. The map value is computed
// once per request and holds. It is "" for a path a backend may still read
// differently ("/api/..;/admin") and for a request sent with a dot segment
// ("/api/x/..;/../admin"), and no pattern matches "".
//
// A line renders one `if` (more only when it is too long for one, below).
// nginx builds a location context for every `if`, about 30 KB with
// ModSecurity, in every server block of the host and, for the global default,
// of every inheriting host; separate `if`s for the agent, each path and the
// result would cost 2 + paths per line, 240 at the caps. So the subject is the
// path, a newline, then the user agent, and one regex tests both: the path
// part case-sensitively, the agent part case-insensitively like every other
// list. A non-empty $npg_request_path holds no control byte and a header value
// no newline, so the first newline is the boundary.
//
// nginx refuses a config token longer than 4094 bytes ("too long parameter"),
// which fails nginx -t for the whole config. A line's agent renders to at most
// 2000 bytes and one path to at most 1017, so one path with its agent always
// fits in maxScopedPattern; the paths are packed into as few patterns as fit,
// and a line with long paths and a long agent renders one `if` per group.
//
// A path matches itself and everything below it, the same boundary as a WAF
// uri scope (uriScopePattern): /api covers /api and /api/v1, not /api-admin;
// a trailing "/" is ignored.
func scopedAllowedAgents(raw string) []scopedAllowedAgent {
	_, scoped, _ := model.ParseAllowedAgents(raw)
	out := make([]scopedAllowedAgent, 0, len(scoped))
	for _, s := range scoped {
		ua := toRegexPattern(s.Agent)
		if ua == "" {
			continue
		}
		r := scopedAllowedAgent{Paths: s.Paths}
		emit := func(group []string) {
			// One path with its agent always fits; a pattern that would not
			// is left out rather than fail nginx -t for every host.
			if pattern := scopedPattern(group, ua); len(pattern) <= maxScopedPattern {
				r.Patterns = append(r.Patterns, pattern)
			}
		}
		var group []string
		for _, p := range s.Paths {
			// uriScopePattern's escaping of the path, without its anchors.
			prefix := strings.TrimSuffix(strings.TrimPrefix(uriScopePattern(p), `\A`), `(?:/|\z)`)
			if len(group) > 0 && len(scopedPattern(group, ua))+len("|")+len(prefix) > maxScopedPattern {
				emit(group)
				group = nil
			}
			group = append(group, prefix)
		}
		emit(group)
		if len(r.Patterns) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// maxScopedPattern bounds one rendered pattern: nginx reads a config token
// into a 4096-byte buffer and refuses one longer than 4094 bytes, and `(` and
// `))` around the pattern take three.
const maxScopedPattern = 4000

// scopedPattern matches "<path>\n<user agent>" when the path is one of the
// prefixes or below it and the user agent contains ua.
func scopedPattern(prefixes []string, ua string) string {
	return `\A(?:` + strings.Join(prefixes, "|") + `)(?:/[^\n]*)?\n.*(?i:` + ua + `)`
}
