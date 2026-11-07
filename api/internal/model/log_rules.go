package model

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// HostLogRules are the access log lines of a proxy host that the log
// collector does not store (#347): every line (SkipAll), or the lines with
// one of the status codes or methods, or under one of the path prefixes.
// Lines NPG blocked are stored anyway, and fail2ban counts every line before
// the rules are applied (service.LogCollector).
type HostLogRules struct {
	ProxyHostID string `json:"proxy_host_id"`
	SkipAll     bool   `json:"skip_all"`
	// SkipStatuses are status codes ("207") or classes ("3xx").
	SkipStatuses []string `json:"skip_statuses"`
	// SkipMethods are request methods in upper case ("PROPFIND").
	SkipMethods []string `json:"skip_methods"`
	// SkipPaths are path prefixes ("/remote.php/dav/"), compared with the
	// request's path as nginx decodes it.
	SkipPaths []string   `json:"skip_paths"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// IsEmpty reports whether the rules skip nothing.
func (r HostLogRules) IsEmpty() bool {
	return !r.SkipAll && len(r.SkipStatuses) == 0 && len(r.SkipMethods) == 0 && len(r.SkipPaths) == 0
}

// HostLogRulesEntry is a proxy host with its log rules, for the list of
// every host (GET /log-rules). A host without rules has empty lists.
type HostLogRulesEntry struct {
	HostLogRules
	DomainNames []string `json:"domain_names"`
	Enabled     bool     `json:"enabled"`
}

// UpdateHostLogRulesRequest replaces a host's log rules. Empty rules remove
// them, so the host stores every line again.
type UpdateHostLogRulesRequest struct {
	SkipAll      bool     `json:"skip_all"`
	SkipStatuses []string `json:"skip_statuses"`
	SkipMethods  []string `json:"skip_methods"`
	SkipPaths    []string `json:"skip_paths"`
}

const (
	// MaxHostLogRuleEntries is how many entries each list of a host's log
	// rules takes.
	MaxHostLogRuleEntries = 50
	// MaxHostLogRulePath is the longest path prefix a rule takes.
	MaxHostLogRulePath = 256
)

var (
	logRuleStatusPattern = regexp.MustCompile(`^[1-5]([0-9]{2}|xx)$`)
	logRuleMethodPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)
)

// NormalizeHostLogRules checks a request's rules and returns them as they
// are stored: each entry trimmed, a status class in lower case ("3xx"), a
// method in upper case, and each entry once. An entry that is not a status
// code or class, a method, or a path prefix (NormalizeLogRulePath) is
// refused, and so is a list longer than MaxHostLogRuleEntries.
func NormalizeHostLogRules(req UpdateHostLogRulesRequest) (HostLogRules, error) {
	rules := HostLogRules{SkipAll: req.SkipAll}
	var err error
	if rules.SkipStatuses, err = normalizeLogRuleList("skip_statuses", req.SkipStatuses, NormalizeLogRuleStatus); err != nil {
		return HostLogRules{}, err
	}
	if rules.SkipMethods, err = normalizeLogRuleList("skip_methods", req.SkipMethods, NormalizeLogRuleMethod); err != nil {
		return HostLogRules{}, err
	}
	if rules.SkipPaths, err = normalizeLogRuleList("skip_paths", req.SkipPaths, NormalizeLogRulePath); err != nil {
		return HostLogRules{}, err
	}
	return rules, nil
}

// normalizeLogRuleList trims each entry, writes it as normalize gives it,
// drops repeats and refuses an entry normalize refuses. Never nil.
func normalizeLogRuleList(field string, entries []string, normalize func(string) (string, bool)) ([]string, error) {
	out := make([]string, 0, len(entries))
	for i, entry := range entries {
		value, ok := normalize(strings.TrimSpace(entry))
		if !ok {
			return nil, fmt.Errorf("%w: %s[%d] %.80q is not valid", ErrInvalidInput, field, i, entry)
		}
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	if len(out) > MaxHostLogRuleEntries {
		return nil, fmt.Errorf("%w: %s takes at most %d entries", ErrInvalidInput, field, MaxHostLogRuleEntries)
	}
	return out, nil
}

// NormalizeLogRuleStatus checks a status entry of the log rules, a code
// ("207") or a class ("3xx"), and returns it in lower case.
func NormalizeLogRuleStatus(s string) (string, bool) {
	s = strings.ToLower(s)
	return s, logRuleStatusPattern.MatchString(s)
}

// NormalizeLogRuleMethod checks a method entry of the log rules and returns
// it in upper case, as the request line carries it.
func NormalizeLogRuleMethod(s string) (string, bool) {
	s = strings.ToUpper(s)
	return s, logRuleMethodPattern.MatchString(s)
}

// NormalizeLogRulePath checks a path prefix of the log rules and returns it
// as it is stored, the way the request path it is compared with is written
// (nginx.LogRulePath): percent escapes decoded, starting with "/", with no
// query, no "." or ".." segment, no "//" and no backslash, at most
// MaxHostLogRulePath bytes.
func NormalizeLogRulePath(p string) (string, bool) {
	if p == "" || len(p) > MaxHostLogRulePath || strings.ContainsAny(p, "?#") {
		return "", false
	}
	decoded, err := url.PathUnescape(p)
	if err != nil {
		return "", false
	}
	for _, r := range decoded {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	if !isCanonicalPath(decoded) {
		return "", false
	}
	return decoded, true
}

// isCanonicalPath reports whether p starts with "/" and has no "//", no
// backslash and no segment that is "." or ".." or starts with ".;" or "..;".
func isCanonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, `\`) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		name, _, _ := strings.Cut(seg, ";")
		if name == "." || name == ".." {
			return false
		}
	}
	return true
}
