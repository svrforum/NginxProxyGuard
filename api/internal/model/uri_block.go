package model

import (
	"fmt"
	"strings"
	"time"
)

// URIMatchType represents the type of URI pattern matching
type URIMatchType string

const (
	URIMatchExact  URIMatchType = "exact"  // Exact match (nginx: location =)
	URIMatchPrefix URIMatchType = "prefix" // Prefix match (nginx: location ^~)
	URIMatchRegex  URIMatchType = "regex"  // Regex match (nginx: location ~*)
)

// URIBlockRule represents a single URI blocking rule
type URIBlockRule struct {
	ID          string       `json:"id"`
	Pattern     string       `json:"pattern"`
	MatchType   URIMatchType `json:"match_type"`
	Description string       `json:"description,omitempty"`
	Enabled     bool         `json:"enabled"`

	// ExceptionIPs are addresses only this rule lets through (#343), on top
	// of the block's exception list, which every rule lets through. They are
	// saved as NormalizeURIBlockRuleExceptionIPs writes them.
	ExceptionIPs []string `json:"exception_ips,omitempty"`
}

// MaxURIBlockRuleExceptionIPs is how many exception addresses one rule takes.
const MaxURIBlockRuleExceptionIPs = 100

// NormalizeURIBlockRuleExceptionIPs writes the rule's own exception addresses
// as NormalizeIPOrCIDR gives them, each once, in the order given. An entry
// that is not an IP address or a CIDR range is refused, and so is a list
// longer than MaxURIBlockRuleExceptionIPs.
func NormalizeURIBlockRuleExceptionIPs(rule *URIBlockRule) error {
	if len(rule.ExceptionIPs) == 0 {
		rule.ExceptionIPs = nil
		return nil
	}
	ips := make([]string, 0, len(rule.ExceptionIPs))
	seen := make(map[string]bool, len(rule.ExceptionIPs))
	for _, entry := range rule.ExceptionIPs {
		ip, ok := NormalizeIPOrCIDR(strings.TrimSpace(entry))
		if !ok {
			return fmt.Errorf("%w: exception IP %.60q of the rule %.200q is not an IP address or CIDR range", ErrInvalidInput, entry, rule.Pattern)
		}
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	if len(ips) > MaxURIBlockRuleExceptionIPs {
		return fmt.Errorf("%w: the rule %.200q has %d exception IPs, more than the %d a rule takes", ErrInvalidInput, rule.Pattern, len(ips), MaxURIBlockRuleExceptionIPs)
	}
	rule.ExceptionIPs = ips
	return nil
}

// URIBlock represents URI blocking settings for a proxy host
type URIBlock struct {
	ID              string         `json:"id"`
	ProxyHostID     string         `json:"proxy_host_id"`
	Enabled         bool           `json:"enabled"`
	Rules           []URIBlockRule `json:"rules"`
	ExceptionIPs    []string       `json:"exception_ips"`
	AllowPrivateIPs bool           `json:"allow_private_ips"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`

	// ExceptionHostnames are domain names (#320) whose addresses are
	// excepted like ExceptionIPs. Never null.
	ExceptionHostnames []string `json:"exception_hostnames"`
	// ExceptionDNS is what a host config renders of the names: each with the
	// scope of the list it came from, the host's or the global one
	// (mergeURIBlocks). Set for the render only, never stored or sent.
	ExceptionDNS []DNSRef `json:"-"`
}

// CreateURIBlockRequest is the request to create/update URI block settings
type CreateURIBlockRequest struct {
	Enabled         *bool          `json:"enabled,omitempty"`
	Rules           []URIBlockRule `json:"rules,omitempty"`
	ExceptionIPs    []string       `json:"exception_ips,omitempty"`
	AllowPrivateIPs *bool          `json:"allow_private_ips,omitempty"`

	// ExceptionHostnames replaces the stored names. Unlike the other
	// fields, which a save always writes, nil (the field left out) keeps
	// them, so a client that does not know the field cannot clear them;
	// [] clears them.
	ExceptionHostnames *[]string `json:"exception_hostnames,omitempty"`
}

// AddURIBlockRuleRequest is the request to add a single rule (from log viewer)
type AddURIBlockRuleRequest struct {
	Pattern     string       `json:"pattern" validate:"required"`
	MatchType   URIMatchType `json:"match_type" validate:"required,oneof=exact prefix regex"`
	Description string       `json:"description,omitempty"`
	Enabled     *bool        `json:"enabled,omitempty"`
}

// GlobalURIBlock represents global URI blocking settings (applied to all hosts)
type GlobalURIBlock struct {
	ID              string         `json:"id"`
	Enabled         bool           `json:"enabled"`
	Rules           []URIBlockRule `json:"rules"`
	ExceptionIPs    []string       `json:"exception_ips"`
	AllowPrivateIPs bool           `json:"allow_private_ips"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`

	// ExceptionHostnames are domain names (#320) whose addresses are
	// excepted like ExceptionIPs. Never null.
	ExceptionHostnames []string `json:"exception_hostnames"`
}

// CreateGlobalURIBlockRequest is the request to create/update global URI block settings
type CreateGlobalURIBlockRequest struct {
	Enabled         *bool          `json:"enabled,omitempty"`
	Rules           []URIBlockRule `json:"rules,omitempty"`
	ExceptionIPs    []string       `json:"exception_ips,omitempty"`
	AllowPrivateIPs *bool          `json:"allow_private_ips,omitempty"`

	// ExceptionHostnames: nil keeps the stored names, [] clears them (see
	// CreateURIBlockRequest).
	ExceptionHostnames *[]string `json:"exception_hostnames,omitempty"`
}

// Common URI patterns for quick blocking
var CommonURIPatterns = []struct {
	Pattern     string
	MatchType   URIMatchType
	Description string
}{
	{"/wp-admin", URIMatchPrefix, "WordPress Admin"},
	{"/wp-login.php", URIMatchExact, "WordPress Login"},
	{"/xmlrpc.php", URIMatchExact, "WordPress XML-RPC"},
	{"/wp-config.php", URIMatchExact, "WordPress Config"},
	{"/.env", URIMatchExact, "Environment File"},
	{"/.git", URIMatchPrefix, "Git Directory"},
	{"/phpmyadmin", URIMatchPrefix, "phpMyAdmin"},
	{"/adminer", URIMatchPrefix, "Adminer"},
	{`\.php$`, URIMatchRegex, "PHP Files"},
	{`\.(sql|bak|backup|old|orig|swp)$`, URIMatchRegex, "Backup Files"},
	{"/cgi-bin", URIMatchPrefix, "CGI-BIN Directory"},
	{"/administrator", URIMatchPrefix, "Joomla Admin"},
}

// A URI block rule becomes a location block in the config of every host it
// applies to, with its description in a "#" comment above it and its pattern
// written, as it is, as the location's argument:
//
//	location <modifier> <pattern> {
//
// nginx reads a config one argument at a time (ngx_conf_read_token), and these
// rules decide where an argument ends:
//
//   - Space, tab, CR and LF separate arguments, ";" ends the directive and "{"
//     opens its block. A backslash makes the character after it part of the
//     argument, and so is a "{" right after a "$" ("${").
//   - Where an argument starts, "#" starts a comment that runs to the end of
//     the line, "}" closes the enclosing block, and a double or a single
//     quote starts a quoted argument. Inside an unquoted argument, "#", "}"
//     and quotes are ordinary characters.
//   - A quoted argument ends at the next matching quote that no backslash
//     precedes. Between the quotes, separators, ";", "{", "}" and "#" are
//     ordinary characters, and so is a line break. Only a separator, ";" or
//     "{" may follow the closing quote.
//   - nginx reads an argument through a 4096-byte buffer, and nginx -t fails
//     ("too long parameter") on an unquoted argument longer than 4094 bytes
//     or a quoted one longer than 4095 bytes with its quotes.
//
// A pattern is written into the config only when nginx reads it as exactly one
// argument on the location's line, after which the "{" the template writes
// opens the location's block. The API refuses any other pattern as well (and
// checks what a pattern matches, see ValidateURIBlockRule), but nothing else
// is checked before writing, so a pattern nginx read as one argument before
// these checks existed is still written as it was. For example,
//
//	kept:      /wp-admin   \.(sql|bak)$   "^/[a-z]{32}\.php$"   '^/\d{4}/'
//	           /a}b   \.php#x   /it's   /a"b   /a\ b   \.php\;   /x${y}
//	left out:  ^/a{2,3}$ (the "{" opens the block early), /a;b (";" ends the
//	           directive), /a b (a second argument), #x and }x (a comment, the
//	           end of the block), "abc (a quote left open), "a"b and "a" "b"
//	           (more after the closing quote), an argument holding CR or LF,
//	           even between quotes or after a backslash (it would run onto
//	           another line), and an empty pattern (nginx would read the
//	           modifier as the argument).
//
// Whitespace around the argument is not part of it and is trimmed. A trailing
// backslash takes in the space the template writes after the pattern; the
// block still opens where it should, so such a pattern is kept as nginx
// accepted it before. The API refuses it on other grounds: a regex cannot end
// in a backslash, and an exact or prefix pattern holds none.

const (
	// maxUnquotedLocationArg and maxQuotedLocationArg (with its two quotes)
	// are the longest arguments nginx reads in this position.
	maxUnquotedLocationArg = 4094
	maxQuotedLocationArg   = 4095
	// uriBlockMaxPathPattern bounds an exact or prefix pattern.
	uriBlockMaxPathPattern = 2048
	// uriBlockMaxDescription bounds a rule description, written into a "#"
	// comment: nginx refuses a comment line of 4 KB or more, and the config
	// generator writes at most 1 KB of one.
	uriBlockMaxDescription = 1000
)

// nginxSpace holds the characters nginx's config reader separates arguments
// with.
const nginxSpace = " \t\r\n"

// RenderableURIBlockPattern returns the argument nginx reads from pattern
// written as a location's argument (pattern without the whitespace around
// it), and whether pattern is exactly that one argument, on one line (see
// above).
func RenderableURIBlockPattern(pattern string) (string, bool) {
	p := strings.TrimLeft(pattern, nginxSpace)
	if p == "" {
		return "", false
	}
	end, ok := locationArgumentEnd(p)
	arg := p[:end]
	switch {
	case !ok || strings.Trim(p[end:], nginxSpace) != "":
		// It starts or ends the directive or a block, starts a comment,
		// leaves a quote open, or something follows it on the line.
		return strings.TrimRight(p, nginxSpace), false
	case strings.ContainsAny(arg, "\r\n"):
		return arg, false
	case len(arg) > maxUnquotedLocationArg && arg[0] != '"' && arg[0] != '\'':
		return arg, false
	case len(arg) > maxQuotedLocationArg:
		return arg, false
	}
	return arg, true
}

// locationArgumentEnd returns the length of the argument p starts with (p does
// not start with a separator), and false when p starts with a character that
// ends the directive, opens or closes a block or starts a comment, or opens a
// quote it does not close. An unquoted argument ends at a separator, ";" or
// "{"; the caller checks what follows it.
func locationArgumentEnd(p string) (int, bool) {
	switch q := p[0]; q {
	case ';', '{', '}', '#':
		return 0, false
	case '"', '\'':
		for i := 1; i < len(p); i++ {
			switch p[i] {
			case '\\':
				i++
			case q:
				return i + 1, true
			}
		}
		return len(p), false
	}
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '$':
			if i+1 < len(p) && p[i+1] == '{' {
				i++
			}
		case ' ', '\t', '\r', '\n', ';', '{':
			return i, true
		}
	}
	return len(p), true
}

// URIBlockPatternValue returns what nginx makes of a pattern that
// RenderableURIBlockPattern accepts: the path or regex the location matches.
// Quotes around it are removed, \", \' and \\ stand for the character after
// the backslash, \t, \r and \n for a tab, CR and LF, and a backslash before
// anything else stays.
func URIBlockPatternValue(pattern string) string {
	arg, _ := RenderableURIBlockPattern(pattern)
	if n := len(arg); n >= 2 && (arg[0] == '"' || arg[0] == '\'') && arg[n-1] == arg[0] {
		arg = arg[1 : n-1]
	}
	if !strings.Contains(arg, `\`) {
		return arg
	}
	var b strings.Builder
	b.Grow(len(arg))
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		if c == '\\' && i+1 < len(arg) {
			switch next := arg[i+1]; next {
			case '"', '\'', '\\':
				c = next
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

// ValidateURIBlockRule checks a rule that a request adds or changes, after
// trimming its pattern (which is saved trimmed). MatchType must already carry
// the caller's default. The pattern must be one nginx argument (see above);
// what it matches (URIBlockPatternValue) must not be empty, an exact or prefix
// one must be a URL path, and a regex is compiled by the handler
// (ValidateRegexPattern).
func ValidateURIBlockRule(rule *URIBlockRule) error {
	switch rule.MatchType {
	case URIMatchExact, URIMatchPrefix, URIMatchRegex:
	default:
		return fmt.Errorf("%w: match_type must be exact, prefix or regex", ErrInvalidInput)
	}
	pattern, ok := RenderableURIBlockPattern(rule.Pattern)
	rule.Pattern = pattern
	maxLen := uriBlockMaxPathPattern
	if rule.MatchType == URIMatchRegex {
		maxLen = maxUnquotedLocationArg
	}
	switch {
	case pattern == "":
		return fmt.Errorf("%w: pattern is required", ErrInvalidInput)
	case len(pattern) > maxLen:
		return fmt.Errorf("%w: pattern exceeds maximum length of %d", ErrInvalidInput, maxLen)
	case !ok:
		return fmt.Errorf(`%w: pattern %.200q is not one nginx argument: put a pattern with spaces, ";" or "{" in double quotes, and do not start it with # or }, leave a quote open or break the line`, ErrInvalidInput, pattern)
	}
	value := URIBlockPatternValue(pattern)
	switch {
	case value == "":
		return fmt.Errorf("%w: pattern is required", ErrInvalidInput)
	case rule.MatchType != URIMatchRegex && (!strings.HasPrefix(value, "/") || strings.Contains(pattern, `\`)):
		return fmt.Errorf("%w: pattern %.200q must be a URL path starting with / (use match_type regex for a pattern)", ErrInvalidInput, pattern)
	}
	return ValidateSingleLine("description", rule.Description, uriBlockMaxDescription)
}
