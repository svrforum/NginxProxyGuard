package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestAddMatchesTheValueAsAURLCarriesIt(t *testing.T) {
	const secret = "tok en/1+2:3"
	var s Secrets
	s.Add(secret, "", "short")
	text := strings.Join([]string{"raw " + secret, "query " + url.QueryEscape(secret), "path " + url.PathEscape(secret), "short stays"}, "; ")
	want := "raw [redacted]; query [redacted]; path [redacted]; short stays"
	if got := s.Text(text); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// A webhook URL is the credential as a whole. Wherever it appears whole it keeps
// its scheme and host, which is how an operator tells receivers apart; its
// path, query and user information are matched on their own as well.
func TestAddURLKeepsOnlySchemeAndHost(t *testing.T) {
	const hook = "https://user:pass-word@hooks.example.com:8443/api/webhooks/123/abc-def?token=q1w2e3r4#frag-ment"
	var s Secrets
	s.AddURL(hook)
	cases := map[string]string{
		`Post "` + hook + `": EOF`: `Post "https://hooks.example.com:8443/[redacted]": EOF`,
		`malformed HTTP status code "/api/webhooks/123/abc-def?token=q1w2e3r4"`: `malformed HTTP status code "/[redacted]?[redacted]"`,
		"user pass-word":            "user [redacted]",
		"see frag-ment":             "see [redacted]",
		"hooks.example.com is down": "hooks.example.com is down",
	}
	for in, want := range cases {
		if got := s.Text(in); got != want {
			t.Errorf("Text(%q)\n got  %q\n want %q", in, got, want)
		}
	}

	var bad Secrets
	bad.AddURL("not a url at all")
	if got := bad.Text("parse: not a url at all"); got != "parse: [redacted]" {
		t.Errorf("an unparsable URL is not redacted whole: %q", got)
	}
}

// A URL with nothing after its host carries the credential in the host name, as
// Pipedream's https://<credential>.m.pipedream.net does, and net/http names that
// host a second time, on its own, when it cannot resolve it.
func TestAddURLMasksTheHostNameOfAURLWithNothingAfterIt(t *testing.T) {
	const hook = "https://eo1a2b3c4d5e6f7g.m.example.com"
	var s Secrets
	s.AddURL(hook)
	in := `Post "` + hook + `": dial tcp: lookup eo1a2b3c4d5e6f7g.m.example.com on 192.0.2.53:53: no such host`
	want := `Post "https://[redacted].m.example.com": dial tcp: lookup [redacted].m.example.com on 192.0.2.53:53: no such host`
	if got := s.Text(in); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	var addr Secrets
	addr.AddURL("http://192.0.2.7:8080")
	if in := `Post "http://192.0.2.7:8080": dial tcp 192.0.2.7:8080: connect: connection refused`; addr.Text(in) != in {
		t.Errorf("an address was masked: %q", addr.Text(in))
	}
}

func TestURLReducesToSchemeAndHost(t *testing.T) {
	cases := map[string]string{
		"https://discord.com/api/webhooks/1/x":  "https://discord.com/[redacted]",
		"https://api.telegram.org/bot1:x/getMe": "https://api.telegram.org/[redacted]",
		"http://[2001:db8::1]:8080/hook":        "http://[2001:db8::1]:8080/[redacted]",
		"https://gotify.example.com?token=abc":  "https://gotify.example.com/[redacted]",
		"https://hooks.example.com#frag":        "https://hooks.example.com/[redacted]",
		"no scheme or host":                     Placeholder,
		// Nothing after the host: the first label of the name is the credential.
		"https://eo1a2b3c4d5e6f7g.m.example.com":               "https://[redacted].m.example.com",
		"https://user:pw@eo1a2b3c4d5e6f7g.m.example.com:8443/": "https://[redacted].m.example.com:8443/",
		// An address or a one-label name is no name a service hands out.
		"http://192.0.2.7:8080": "http://192.0.2.7:8080",
		"http://[2001:db8::1]/": "http://[2001:db8::1]/",
		"http://receiver:8080/": "http://receiver:8080/",
	}
	for in, want := range cases {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErrorKeepsCleanErrorsAndDropsTheChainOfRedactedOnes(t *testing.T) {
	var s Secrets
	s.Add("secret-value")

	clean := errors.New("nothing to hide")
	if got := s.Error(clean); got != clean {
		t.Errorf("an error without the secret was replaced: %v", got)
	}
	if s.Error(nil) != nil {
		t.Error("nil became an error")
	}

	inner := errors.New("echoed secret-value")
	got := s.Error(fmt.Errorf("wrapped: %w", inner))
	if got.Error() != "wrapped: echoed [redacted]" {
		t.Errorf("got %q", got)
	}
	if errors.Is(got, inner) {
		t.Error("the redacted error still unwraps to the text it hides")
	}

	var none *Secrets
	if none.Error(inner) != inner || none.Text("x") != "x" {
		t.Error("a nil set must redact nothing")
	}
}

// net/http names the whole URL of a failed request; that URL is treated as a
// credential, so a token the caller did not register is still cut out of it.
func TestRequestErrorRedactsTheQuotedRequestURL(t *testing.T) {
	reqErr := &url.Error{Op: "Post", URL: "https://ntfy.example.com/my-secret-topic", Err: errors.New("dial tcp 192.0.2.7:443: connect: connection refused")}
	var s Secrets
	got := s.RequestError(fmt.Errorf("could not reach it: %w", reqErr))
	want := `could not reach it: Post "https://ntfy.example.com/[redacted]": dial tcp 192.0.2.7:443: connect: connection refused`
	if got.Error() != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// ShapesPattern is also what the upgrade runs in PostgreSQL, so the cases cover
// what it must do there: replace each shape, keep everything else, be a no-op
// on its own output, and keep JSON text valid.
func TestShapes(t *testing.T) {
	cases := map[string]string{
		`Get "https://www.duckdns.org/update?domains=home&ip=203.0.113.7&token=0d6a6c59-6c4a-4f8e-9b1e-7f3a2c1d9e88": EOF`: `Get "https://www.duckdns.org/update?domains=home&ip=203.0.113.7&token=[redacted]": EOF`,
		"used url [https://www.duckdns.org/update?clear=false&domains=x&token=abc%2Bdef&txt=y]":                            "used url [https://www.duckdns.org/update?clear=false&domains=x&token=[redacted]&txt=y]",
		`Post "https://api.telegram.org/bot123456789:AAH-x_y/sendMessage": EOF`:                                            `Post "https://api.telegram.org/bot[redacted]/sendMessage": EOF`,
		"https://discord.com/api/webhooks/1122334455/tok-EN_x":                                                             "https://discord.com/api/webhooks/[redacted]",
		"https://discord.com/api/v10/webhooks/1122334455/tok-EN_x?wait=true":                                               "https://discord.com/api/v10/webhooks/[redacted]?wait=true",
		"https://hooks.slack.com/services/T0123ABC/B0456DEF/abcDEF123456":                                                  "https://hooks.slack.com/services/[redacted]",
		"https://gotify.example.com/message?token=AbCdEf.123":                                                              "https://gotify.example.com/message?token=[redacted]",
		"auth error: access_token=abc123 expired":                                                                          "auth error: access_token=[redacted] expired",
	}
	for in, want := range cases {
		got := Shapes(in)
		if got != want {
			t.Errorf("Shapes(%q)\n got  %q\n want %q", in, got, want)
		}
		if again := Shapes(got); again != got {
			t.Errorf("not idempotent: %q became %q", got, again)
		}
	}

	untouched := []string{
		"acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: Incorrect TXT record",
		`Get "https://api.cloudflare.com/client/v4/zones?name=example.com&per_page=50": EOF`,
		"invalid token: required",
		"token=",
		"/bot/sendMessage",
		"/api/webhooks/",
		"/services/web/a/b",
		"duckdns update failed: KO",
	}
	for _, in := range untouched {
		if got := Shapes(in); got != in {
			t.Errorf("Shapes changed unrelated text %q into %q", in, got)
		}
	}

	// The upgrade rewrites jsonb columns through their text form, so a
	// replacement must never break an escape or a string boundary — including
	// a token that sits right before an escaped quote, as in a quoted URL.
	doc, _ := json.Marshal(map[string]any{"logs": []string{
		`Get "https://www.duckdns.org/update?domains=x&token=0d6a6c59-6c4a"`,
		"Post \"https://api.telegram.org/bot123:AAH/sendMessage\"\ttab\\backslash",
	}})
	var back map[string]any
	if err := json.Unmarshal([]byte(Shapes(string(doc))), &back); err != nil {
		t.Fatalf("redacted JSON no longer parses: %v\n%s", err, Shapes(string(doc)))
	}
	if strings.Contains(fmt.Sprint(back), "0d6a6c59") || strings.Contains(fmt.Sprint(back), "bot123") {
		t.Errorf("JSON text kept a credential: %v", back)
	}
}
