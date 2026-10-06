// Package redact takes credentials out of text that is about to be returned,
// stored or logged.
//
// net/http renders a failed request as `Post "<full URL>": <cause>`
// (*url.Error), and a provider that answers with something unexpected often
// quotes the request back. So a credential carried in a request URL — a
// DuckDNS token in the query string, a Telegram bot token in the path, a
// Discord or generic webhook URL that is the credential as a whole — lands
// wherever the error text goes: an API response, an error column, a
// notification, the container log.
//
// Secrets matches by value: whatever wording carries the credential, the
// credential itself is what gets replaced, which covers wordings nobody
// listed. Shapes matches by shape, for text where the value is not at hand.
package redact

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Placeholder stands in for a removed credential.
const Placeholder = "[redacted]"

// minSecretLen is the shortest value treated as a credential. A shorter one
// protects nothing — it is guessed faster than it is leaked — and replacing it
// would cut ordinary words out of the message.
const minSecretLen = 6

// Secrets is a set of credential values to cut out of text. The zero value is
// empty and ready to use; a nil *Secrets redacts nothing.
type Secrets struct {
	replacements map[string]string // value as it may appear → what replaces it
}

func (s *Secrets) put(value, replacement string) {
	if len(value) < minSecretLen {
		return
	}
	if s.replacements == nil {
		s.replacements = map[string]string{}
	}
	s.replacements[value] = replacement
}

// Add registers credential values. Each is also matched as a query string and
// a URL path carry it, since the text being cleaned usually quotes a request.
// Empty and too-short values are ignored.
func (s *Secrets) Add(values ...string) {
	for _, v := range values {
		for _, form := range []string{v, strings.TrimSpace(v), url.QueryEscape(v), url.PathEscape(v)} {
			s.put(form, Placeholder)
		}
	}
}

// AddURL registers a URL that is itself a credential, such as a Discord or
// generic webhook URL. Wherever the whole URL appears it becomes URL(raw), which
// keeps the scheme and host an operator needs to tell which receiver failed;
// its path, query, fragment and user information are also matched on their
// own, and so is its host name when nothing follows the host. A value that does
// not parse as an absolute URL is registered whole.
func (s *Secrets) AddURL(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		s.Add(raw)
		return
	}
	safe := URL(raw)
	for _, whole := range []string{raw, u.String()} {
		s.put(whole, safe)
		// The form a Go %q leaves inside its quotes, which is how *url.Error
		// prints a URL that holds a quote or a backslash.
		s.put(unquoted(whole), unquoted(safe))
	}
	if len(u.EscapedPath()) > 1 {
		s.put(u.EscapedPath(), "/"+Placeholder)
		s.put(u.Path, "/"+Placeholder)
	}
	s.put(u.RawQuery, Placeholder)
	s.put(u.EscapedFragment(), Placeholder)
	// The host name is then the credential (see URL), and net/http also names
	// it on its own: `lookup <host>: no such host`.
	if name := u.Hostname(); hostOnly(u) && maskedName(name) != name {
		s.put(name, maskedName(name))
	}
	if u.User != nil {
		s.Add(u.User.Username())
		if password, ok := u.User.Password(); ok {
			s.Add(password)
		}
	}
}

func unquoted(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// Text returns text with every registered value replaced.
func (s *Secrets) Text(text string) string {
	if s == nil || len(s.replacements) == 0 || text == "" {
		return text
	}
	values := make([]string, 0, len(s.replacements))
	for v := range s.replacements {
		values = append(values, v)
	}
	// strings.Replacer takes the first pair, in argument order, that matches at
	// a position. Longest first, so a whole URL is replaced before the path
	// inside it.
	sort.Slice(values, func(i, j int) bool {
		if len(values[i]) != len(values[j]) {
			return len(values[i]) > len(values[j])
		}
		return values[i] < values[j]
	})
	pairs := make([]string, 0, 2*len(values))
	for _, v := range values {
		pairs = append(pairs, v, s.replacements[v])
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

// Error returns err with every registered value removed from its text. An error
// whose text carries none is returned unchanged. Otherwise only the cleaned text
// is kept: the result does not unwrap to err, whose text is what is hidden.
func (s *Secrets) Error(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if cleaned := s.Text(msg); cleaned != msg {
		return errors.New(cleaned)
	}
	return err
}

// RequestError is Error for the outcome of an HTTP request whose URL is itself
// a credential. The URL net/http quotes in a failed request (*url.Error) is
// registered as if passed to AddURL, so it keeps no more than URL keeps.
func (s *Secrets) RequestError(err error) error {
	var reqErr *url.Error
	if s != nil && errors.As(err, &reqErr) {
		s.AddURL(reqErr.URL)
	}
	return s.Error(err)
}

// URL returns raw reduced to its scheme and host, with "/[redacted]" in place of
// anything after the host: https://discord.com/api/webhooks/1/x becomes
// https://discord.com/[redacted]. When nothing follows the host, the host name
// is what names the receiver, and a service that hands out a host name per
// receiver puts the credential in its first label — Pipedream's
// https://<credential>.m.pipedream.net — so that label is replaced instead:
// https://[redacted].m.pipedream.net. A value that does not parse as an absolute
// URL becomes Placeholder.
func URL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Placeholder
	}
	if !hostOnly(u) {
		return u.Scheme + "://" + u.Host + "/" + Placeholder
	}
	host := u.Host
	if name := u.Hostname(); maskedName(name) != name {
		host = maskedName(name) + strings.TrimPrefix(host, name)
	}
	return u.Scheme + "://" + host + u.Path
}

// hostOnly reports whether nothing follows the host of u.
func hostOnly(u *url.URL) bool {
	return (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}

// maskedName is a host name with its first label replaced by Placeholder. An IP
// address and a name of a single label are not names a service hands out, and
// come back unchanged.
func maskedName(name string) string {
	if _, err := netip.ParseAddr(name); err == nil {
		return name
	}
	if _, rest, ok := strings.Cut(name, "."); ok {
		return Placeholder + "." + rest
	}
	return name
}

// ShapesPattern matches the credentials a URL carries in a recognisable shape:
// a token= query parameter (DuckDNS, Gotify), a Telegram bot path
// (/bot<id>:<secret>), a Discord webhook (/api/webhooks/<id>/<token>, with or
// without an API version) and a Slack webhook (/services/T…/B…/<secret>). The
// part that names the place is kept, in groups 1-4, and the credential is
// replaced.
//
// It is written to mean the same to Go's regexp and to PostgreSQL's, and the
// upgrade that scrubs rows older versions stored uses this exact string. No
// credential character class admits "[", so redacted text no longer matches,
// and none admits a quote or a backslash, so a replacement inside JSON text
// stays valid JSON.
const ShapesPattern = `(token=)[A-Za-z0-9._~%+-]+|(/bot)[0-9]+:[A-Za-z0-9_-]+|(/api/(?:v[0-9]+/)?webhooks/)[0-9]+/[A-Za-z0-9_-]+|(/services/)T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`

var shapes = regexp.MustCompile(ShapesPattern)

// Shapes replaces every credential ShapesPattern recognises. It is for text
// whose credential value is not at hand, such as an error message on its way
// into a column; a caller that holds the value should use Secrets as well.
func Shapes(text string) string {
	return shapes.ReplaceAllString(text, "${1}${2}${3}${4}"+Placeholder)
}
