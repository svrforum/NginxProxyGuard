package redact

import "regexp"

// ModSecurity writes the request value a rule matched into each message
// twice: the rule's data line, "Matched Data: <part> found within
// ARGS:password: <value>", and the engine's match line, "... against variable
// `ARGS:password' (Value: `<value>' )". WAF events store both, as rule_data
// and in the raw record, so a rule that fired on a login form kept the
// password for as long as WAF logs are kept.
//
// Rows stored before this are not rewritten: nearly all of them sit in
// compressed chunks, and rewriting one there decompresses its whole batch.
// What reads them back passes the value through ModSec instead.

// modSecSecretVariable matches a ModSecurity variable whose value is taken for
// a credential: any cookie, the whole request body or XML document, and an
// argument or request header whose name says password, token, key, session,
// cookie or authorization. The variable name stops at a colon, a quote, a
// backtick, white space or a backslash.
const modSecSecretVariable = `(?:REQUEST_COOKIES|REQUEST_BODY|XML)(?::[^:\x27\x60"\s\\]*)?|(?:ARGS|ARGS_GET|ARGS_POST|REQUEST_HEADERS):[^:\x27\x60"\s\\]*(?:pass|pwd|secret|token|sess|cookie|credential|signature|logged_in|authoriz|oauth|auth[_-]|[_-]auth|(?:api|access|private|signing|client)[_-]?key|wordpress_sec)[^:\x27\x60"\s\\]*`

var (
	modSecData  = regexp.MustCompile(`(?is)(Matched Data: ).*( found within (?:` + modSecSecretVariable + `): ).*`)
	modSecMatch = regexp.MustCompile(`(?is)(against variable \x60(?:` + modSecSecretVariable + `)\x27 \(Value: \x60).*(\x27 \))`)
)

// ModSec replaces the request value in a ModSecurity data or match line when
// the variable it was found in is a credential (modSecSecretVariable), keeping
// the rest of the line. It is for one line at a time, not for the JSON of a
// whole audit record.
func ModSec(text string) string {
	text = modSecData.ReplaceAllString(text, "${1}"+Placeholder+"${2}"+Placeholder)
	return modSecMatch.ReplaceAllString(text, "${1}"+Placeholder+"${2}")
}
