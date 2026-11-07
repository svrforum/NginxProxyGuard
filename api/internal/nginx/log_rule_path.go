package nginx

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The two patterns of nginx's request path guard ($npg_request_path,
// requestPathMapContent), compiled as the map compiles them (~*).
var (
	rawDotSegmentRe     = regexp.MustCompile(`(?i)` + rawDotSegmentPattern)
	unsafeRequestPathRe = regexp.MustCompile(`(?i)(?:` + unsafeRequestPathPattern + `)`)
)

// LogRulePath returns the path of a raw request target as nginx sets $uri
// (up to "?" or "#", percent escapes decoded once), for comparing with the
// path prefixes of a host's log rules (#347), and false when a prefix rule
// must not apply to it. That is where nginx's request path guard gives no
// path-scoped exemption either: a dot segment in the raw target
// (rawDotSegmentPattern), or one a backend may still find in the decoded path
// (unsafeRequestPathPattern). Otherwise a request could hide from the logs by
// spelling another path into a skipped one.
//
// It is also false for a decoded path that is not valid UTF-8, holds "//" or
// a backslash. Go matches the guard's \xc0 and the like as characters, not as
// bytes, so the overlong spellings it lists are caught as invalid UTF-8 here.
func LogRulePath(target string) (string, bool) {
	if !strings.HasPrefix(target, "/") || rawDotSegmentRe.MatchString(target) {
		return "", false
	}
	path := target
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || !utf8.ValidString(decoded) || strings.Contains(decoded, "//") ||
		strings.Contains(decoded, `\`) || unsafeRequestPathRe.MatchString(decoded) {
		return "", false
	}
	return decoded, true
}
