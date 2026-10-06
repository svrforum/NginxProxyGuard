package nginx

import (
	"bytes"
	"os"
	"path/filepath"
)

// requestPathMapFile is the http-level file that defines $npg_request_path and
// $npg_request_target. It lives directly in conf.d/ so the `include
// conf.d/*.conf` of both the API-generated nginx.conf and the image's
// first-boot nginx.conf loads it, and it is the ONLY place the variables are
// defined: nginx accepts a second map for the same variable without complaint
// and silently keeps the last one parsed.
const requestPathMapFile = "npg_request_path.conf"

// How a backend may still spell a dot, a path separator, a ";" path parameter
// and a space in a path nginx has already decoded once: literally; percent-
// encoded again, so a leftover %2e means the client encoded it twice (nginx's
// one decode of %252e leaves %2e) and %252e that it encoded three times; as an
// IIS/.NET %u escape; or as overlong UTF-8, which legacy IIS and Tomcat
// decoders folded to "." and "/".
//
// The re-encoding depth is capped — %(?:25){0,2} is up to triple-encoding — so
// every alternative is a fixed string. That is on purpose: the quantifiers
// here sit inside the repetition in unsafeRequestPathPattern, and an unbounded
// one there backtracks quadratically on a crafted path, enough to blow
// libmodsecurity's SecPcreMatchLimit and fail the guard open. A backend that
// decodes four or more times is not something this pattern promises to catch.
const (
	pathDotPattern   = `(?:\.|%(?:25){0,2}(?:2e|u002e)|\xc0\xae|\xe0\x80\xae|\xf0\x80\x80\xae)`
	pathSepPattern   = `(?:/|\x5c|%(?:25){0,2}(?:2f|5c|u002f|u005c)|\xc0\xaf|\xc1\x9c|\xe0\x80\xaf|\xe0\x81\x9c|\xf0\x80\x80\xaf|\xf0\x80\x81\x9c)`
	pathParamPattern = `(?:;|%(?:25){0,2}3b)`
	pathSpacePattern = `(?:\x20|%(?:25){0,2}20)`
)

// unsafeRequestPathPattern matches a once-decoded request path in which a
// backend may find a dot segment that nginx did not resolve, because to nginx
// it is not one. Such a path can resolve above the prefix nginx routed it
// under, so it gets no path-scoped exemption.
//
// A segment counts when it starts with a dot in any of the spellings above,
// holds nothing but dots and spaces, and ends at a separator, a ";" or the end
// of the path. That covers
//
//   - "." and ".." — a plain dot segment ModSecurity's REQUEST_FILENAME keeps;
//   - "..;" — Tomcat and Jetty strip the ";" path parameter, nginx does not;
//   - "..\" — a backslash is a separator to Windows/IIS backends;
//   - "%2e%2e/", "..%2f", "..%5c" — still encoded after nginx's one decode;
//   - "%u002e%u002e/", "..\xc0\xaf" — %u escapes and overlong UTF-8;
//   - ".. /", "..../" — Windows drops trailing spaces and dots in a segment.
//
// The dot-and-space run after the first dot is capped at 16, long enough for
// any real "../" or "..../" and short enough to keep the match linear; a
// segment padded past that is not a traversal nginx or a backend would honour.
// ASCII control bytes are refused outright: a parser that drops tab and newline
// (the WHATWG URL parser) turns "/api/%0a../admin" into "/api/../admin".
//
// Nothing else is refused. A double-encoded slash inside a name
// (job/feature%252Ffoo), a literal "%" or a lone backslash keeps its
// exemption, because without a dot segment a backend cannot leave the prefix.
//
// The nginx map below and the ModSecurity guard in waf_config.go both use it,
// so the two engines refuse the same paths. nginx applies it to $uri, where a
// plainly spelled "/../" is already resolved away; ModSecurity applies it to a
// non-normalized REQUEST_FILENAME, where it is not, and refuses it there.
// Neither engine compiles it in UTF mode, so \xc0 and the like match single
// bytes. Every quantifier is bounded, so the match is linear in the path
// length on PCRE as well as on Go's RE2.
const unsafeRequestPathPattern = `[\x00-\x1f\x7f]|(?:\A|` + pathSepPattern + `)` + pathDotPattern +
	`(?:` + pathDotPattern + `|` + pathSpacePattern + `){0,16}(?:` + pathSepPattern + `|` + pathParamPattern + `|\z)`

// requestPathMapContent defines $npg_request_path, the request path every
// path-scoped exemption is decided on, and $npg_request_target, that path
// followed by the query string as sent.
//
// $request_uri is the raw request target. "/api/../admin" and
// "/api/%2e%2e/admin" both begin with "/api/", but nginx routes them to the
// location for /admin and proxy_pass forwards the raw target, which the
// backend resolves to /admin too — so a prefix test on $request_uri granted an
// exemption for a path the request never reached. $uri is the decoded and
// normalized path nginx routes on.
//
// It has to be a map rather than $uri read in place. A map value is computed
// the first time it is read — in the server rewrite phase of the original
// request, by the checks in host_common.conf — and then cached for the rest of
// the request. error_page internal redirects and auth_request subrequests run
// the server-level checks again with a different $uri (/error_502.html,
// /_challenge/validate); reading $uri there loses the exemption mid-request,
// while the cached map value keeps the path the client asked for.
//
// Operator-written exemption patterns (exploit-rule URI exclusions and Block
// Exploits exceptions) used to test $request_uri, query string included, and
// some depend on it ("rest_route=", `^/i/\?c=feed`). They test
// $npg_request_target, which keeps the query from $request_uri: $args would be
// empty again after an error_page redirect. The templates refuse every such
// exemption when $npg_request_path is "", whatever the pattern matches.
var requestPathMapContent = []byte(`# Normalized request path for path-scoped security decisions - auto-generated by Nginx Proxy Guard
# DO NOT EDIT - every path-scoped security exemption reads $npg_request_path
# (or $npg_request_target: the same path plus the query string as sent),
# not $request_uri (the raw request target, where /api/../admin starts with /api/).
#
# A path in which a backend may still find a dot segment nginx did not resolve
# ("..;", a backslash, "%2e%2e" or "..%2f" left over from a second encoding,
# control bytes) maps to "", and no exemption is granted for it.
map $uri $npg_request_path {
    default $uri;
    "~*(?:` + unsafeRequestPathPattern + `)" "";
}

map $request_uri $npg_request_target {
    default $npg_request_path;
    "~^[^?]*(?<npg_request_query>\?.*)" $npg_request_path$npg_request_query;
}
`)

// ensureRequestPathMap writes conf.d/npg_request_path.conf when missing or
// stale. The content is static, so this is a read+compare no-op on the hot
// path. It must run before anything that reads $npg_request_path is written:
// nginx -t rejects an unknown variable, and the nginx entrypoint's boot-time
// recovery only disables per-host files, so a missing definition referenced
// from includes/host_common.conf would keep nginx from starting at all.
func (m *Manager) ensureRequestPathMap() error {
	path := filepath.Join(m.configPath, requestPathMapFile)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, requestPathMapContent) {
		return nil
	}
	return m.writeFileAtomic(path, requestPathMapContent, 0644)
}
