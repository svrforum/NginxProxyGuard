package redact

import (
	"strings"
	"unicode"
)

// ModSecurity writes the request value a rule matched into each message
// twice: the rule's data line, "Matched Data: <part> found within
// ARGS:password: <value>", and the engine's match line, "... against variable
// `ARGS:password' (Value: `<value>' )". WAF events store both, as rule_data
// and in the raw record, so a rule that fired on a login form kept the
// password for as long as WAF logs are kept.
//
// Rows stored before this are not rewritten: nearly all of them sit in
// compressed chunks, and rewriting one there decompresses its whole batch.
// What reads them back passes the value through ModSecMessage instead.

const (
	matchVarOpen  = "against variable `"
	matchValueSep = "' (Value: `"
	matchValueEnd = "' )"
	dataPrefix    = "Matched Data: "
	dataWithin    = " found within "
	dataHeader    = "Matched Data: Header "
)

// ModSecMessage hides the request value in one ModSecurity message — its data
// line and its match line — when either line names a credential variable
// (see secretVariable). The two are judged together because a chained rule
// often names the variable in one line only: the match line may say `TX:1'
// while the data line says ARGS:password, and a rule logging just
// %{MATCHED_VAR} leaves the name to the match line. The variable names stay,
// which is what excluding a false positive needs; anything else is returned
// unchanged.
func ModSecMessage(data, match string) (string, string) {
	valueAt := -1
	matchVar := ""
	if i := strings.Index(match, matchVarOpen); i >= 0 {
		rest := match[i+len(matchVarOpen):]
		if j := strings.Index(rest, matchValueSep); j >= 0 {
			matchVar = rest[:j]
			valueAt = i + len(matchVarOpen) + j + len(matchValueSep)
		}
	}
	dataVar, redactData := parseDataLine(data)
	if !secretVariable(matchVar) && !secretVariable(dataVar) {
		return data, match
	}
	if valueAt >= 0 {
		end := strings.LastIndex(match, matchValueEnd)
		if end < valueAt {
			end = len(match)
		}
		match = match[:valueAt] + Placeholder + match[end:]
	}
	return redactData(), match
}

// parseDataLine finds the variable a data line names and returns it with a
// function that blanks the line's values. CRS writes these forms:
//
//	Matched Data: <part> found within <var>: <value>
//	Matched Data: <value> found within <var>
//	Matched Data: Header <var>: <value>
//	<var>=<value>
//
// and a few that hold only a value (%{MATCHED_VAR}, %{TX.0}), which name no
// variable and are blanked whole.
func parseDataLine(data string) (string, func() string) {
	whole := func() string {
		if data == "" {
			return data
		}
		return Placeholder
	}
	if rest, ok := strings.CutPrefix(data, dataHeader); ok {
		if v, _, found := strings.Cut(rest, ": "); found {
			return v, func() string { return dataHeader + v + ": " + Placeholder }
		}
		return "", whole
	}
	if rest, ok := strings.CutPrefix(data, dataPrefix); ok {
		i := strings.Index(rest, dataWithin)
		if i < 0 {
			return "", whole
		}
		tail := rest[i+len(dataWithin):]
		v, _, hasValue := strings.Cut(tail, ": ")
		return v, func() string {
			if hasValue {
				return dataPrefix + Placeholder + dataWithin + v + ": " + Placeholder
			}
			return dataPrefix + Placeholder + dataWithin + v
		}
	}
	if v, _, found := strings.Cut(data, "="); found && collectionOf(v) != "" {
		return v, func() string { return v + "=" + Placeholder }
	}
	return "", whole
}

// collectionOf returns the upper-cased collection of a ModSecurity variable
// name such as ARGS:password or MATCHED_VARS:ARGS:password (what a chained
// rule reports), or "" when the name is not a request collection.
func collectionOf(variable string) string {
	for _, p := range []string{"MATCHED_VARS:", "MATCHED_VAR:"} {
		if len(variable) >= len(p) && strings.EqualFold(variable[:len(p)], p) {
			variable = variable[len(p):]
			break
		}
	}
	c, _, _ := strings.Cut(variable, ":")
	c = strings.ToUpper(c)
	switch c {
	case "ARGS", "ARGS_GET", "ARGS_POST", "REQUEST_HEADERS", "REQUEST_COOKIES", "REQUEST_BODY", "XML":
		return c
	}
	return ""
}

// secretVariable reports a variable whose value is taken for a credential:
// any cookie, the whole request body or XML document, and an argument or
// request header whose name says so (secretName).
func secretVariable(variable string) bool {
	switch collectionOf(variable) {
	case "REQUEST_COOKIES", "REQUEST_BODY", "XML":
		return true
	case "ARGS", "ARGS_GET", "ARGS_POST", "REQUEST_HEADERS":
		i := strings.LastIndex(variable, ":")
		return secretName(variable[i+1:])
	}
	return false
}

// Words a parameter or header name is split into (at punctuation and at
// camelCase) that mark it as a credential.
var secretWords = map[string]bool{
	"pw": true, "pwd": true, "pass": true, "passwd": true, "password": true, "passphrase": true, "passcode": true,
	"secret": true, "token": true, "auth": true, "authorization": true, "key": true, "apikey": true, "authkey": true,
	"jwt": true, "otp": true, "totp": true, "pin": true, "sig": true, "signature": true, "bearer": true,
	"session": true, "sess": true, "sessid": true, "sessionid": true, "cookie": true, "credential": true,
	"credentials": true, "oauth": true, "saml": true, "csrf": true, "xsrf": true,
}

// Ordinary words that contain a credential word.
var notSecretWords = map[string]bool{
	"compass": true, "bypass": true, "encompass": true, "surpass": true, "overpass": true, "underpass": true,
	"trespass": true, "passage": true, "passenger": true, "passive": true, "secretary": true,
}

func secretName(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range []string{"password", "passwd", "passcode", "passphrase", "pwd", "token", "secret", "session", "sessid", "sesskey",
		"cookie", "credential", "signature", "authoriz", "oauth", "apikey", "api_key", "api-key", "accesskey", "privatekey", "signingkey",
		"clientkey", "jwt", "saml", "logged_in"} {
		if strings.Contains(lower, s) && !notSecretWords[lower] {
			return true
		}
	}
	for _, w := range nameWords(name) {
		if notSecretWords[w] {
			continue
		}
		if secretWords[w] || strings.HasPrefix(w, "pass") || strings.HasSuffix(w, "pass") || strings.HasSuffix(w, "pw") ||
			(strings.HasPrefix(w, "auth") && !strings.HasPrefix(w, "author")) {
			return true
		}
	}
	return false
}

// nameWords splits a name such as json.secondaryToken, X-Auth-Token or pw2
// into lower-case words: at anything not a letter or digit, before an upper
// case letter that follows a lower case one, and between letters and digits.
func nameWords(name string) []string {
	var words []string
	var b strings.Builder
	prev := rune(0)
	flush := func() {
		if b.Len() > 0 {
			words = append(words, strings.ToLower(b.String()))
			b.Reset()
		}
	}
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev), unicode.IsDigit(r) != unicode.IsDigit(prev) && prev != 0:
			flush()
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
		prev = r
	}
	flush()
	return words
}
