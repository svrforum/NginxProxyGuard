package redact

import (
	"strings"
	"testing"
)

func TestModSecMessage(t *testing.T) {
	type pair struct{ data, match string }
	cases := []struct {
		name     string
		in, want pair
	}{
		// The value goes when the variable names a credential...
		{"password arg",
			pair{"Matched Data: novc found within ARGS:password: hunter2-Secret!", "detected SQLi using libinjection against variable `ARGS:password' (Value: `hunter2-Secret!' )"},
			pair{"Matched Data: [redacted] found within ARGS:password: [redacted]", "detected SQLi using libinjection against variable `ARGS:password' (Value: `[redacted]' )"}},
		{"json token",
			pair{"Matched Data: 1c found within ARGS:json.secondaryToken: 1.--07C1r5b1", ""},
			pair{"Matched Data: [redacted] found within ARGS:json.secondaryToken: [redacted]", ""}},
		{"cookie",
			pair{"Matched Data: ' or found within REQUEST_COOKIES:PHPSESSID: ab' or 1=1", ""},
			pair{"Matched Data: [redacted] found within REQUEST_COOKIES:PHPSESSID: [redacted]", ""}},
		{"authorization header",
			pair{"Matched Data: Bearer found within REQUEST_HEADERS:Authorization: Bearer eyJh", ""},
			pair{"Matched Data: [redacted] found within REQUEST_HEADERS:Authorization: [redacted]", ""}},
		{"whole body",
			pair{"Matched Data: x found within REQUEST_BODY: user=a&password=b", ""},
			pair{"Matched Data: [redacted] found within REQUEST_BODY: [redacted]", ""}},
		// A chained rule reports MATCHED_VARS:<var> (942440, 933150, 941310, 944110).
		{"chained cookie",
			pair{"Matched Data: --Val found within MATCHED_VARS:REQUEST_COOKIES:_app_session: Exmpl--Val2-x=", "Matched \"Operator `Rx' with parameter `x' against variable `MATCHED_VARS:REQUEST_COOKIES:_app_session' (Value: `Exmpl--Val2-x=' )"},
			pair{"Matched Data: [redacted] found within MATCHED_VARS:REQUEST_COOKIES:_app_session: [redacted]", "Matched \"Operator `Rx' with parameter `x' against variable `MATCHED_VARS:REQUEST_COOKIES:_app_session' (Value: `[redacted]' )"}},
		// The match line names TX:1 (942130, 942521); the data line names the argument.
		{"match line on TX",
			pair{"Matched Data: 1=1 found within ARGS:pw: a' or 1=1", "Matched \"Operator `Rx' with parameter `x' against variable `TX:1' (Value: `1=1' )"},
			pair{"Matched Data: [redacted] found within ARGS:pw: [redacted]", "Matched \"Operator `Rx' with parameter `x' against variable `TX:1' (Value: `[redacted]' )"}},
		// A data line with only the value leaves the name to the match line.
		{"value-only data line",
			pair{"Exmpl';--Val1", "Matched \"Operator `Rx' with parameter `x' against variable `MATCHED_VARS:ARGS:password' (Value: `Exmpl';--Val1' )"},
			pair{"[redacted]", "Matched \"Operator `Rx' with parameter `x' against variable `MATCHED_VARS:ARGS:password' (Value: `[redacted]' )"}},
		{"name=value data line",
			pair{"ARGS:api_key=0123456789", ""},
			pair{"ARGS:api_key=[redacted]", ""}},
		{"value before the name",
			pair{"Matched Data: zxc' -- found within ARGS:passwd", ""},
			pair{"Matched Data: [redacted] found within ARGS:passwd", ""}},
		{"value with the closing quote inside",
			pair{"", "against variable `ARGS:Password' (Value: `ab' )' or 1=1' )"},
			pair{"", "against variable `ARGS:Password' (Value: `[redacted]' )"}},

		// ...and stays when it does not, which is what tuning a false positive needs.
		{"search keyword",
			pair{"Matched Data: docker- found within ARGS:search_keyword: docker-compose", "against variable `ARGS:search_keyword' (Value: `docker-compose' )"},
			pair{"Matched Data: docker- found within ARGS:search_keyword: docker-compose", "against variable `ARGS:search_keyword' (Value: `docker-compose' )"}},
		{"content", pair{"Matched Data: <a href found within ARGS:json.content: <a href=x>", ""}, pair{"Matched Data: <a href found within ARGS:json.content: <a href=x>", ""}},
		{"author", pair{"Matched Data: x found within ARGS:author: 3", ""}, pair{"Matched Data: x found within ARGS:author: 3", ""}},
		{"arg names", pair{"Matched Data: x found within ARGS_NAMES:password: password", ""}, pair{"Matched Data: x found within ARGS_NAMES:password: password", ""}},
		{"protocol", pair{"HTTP/1.0", "against variable `REQUEST_PROTOCOL' (Value: `HTTP/1.0' )"}, pair{"HTTP/1.0", "against variable `REQUEST_PROTOCOL' (Value: `HTTP/1.0' )"}},
		{"query arg", pair{"", "against variable `ARGS:q' (Value: `password=1' )"}, pair{"", "against variable `ARGS:q' (Value: `password=1' )"}},
		{"user agent", pair{"Matched Data: curl found within REQUEST_HEADERS:User-Agent: curl/8", ""}, pair{"Matched Data: curl found within REQUEST_HEADERS:User-Agent: curl/8", ""}},
		{"anomaly score", pair{"Total Score: 5", "against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )"}, pair{"Total Score: 5", "against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )"}},
	}
	for _, c := range cases {
		d, m := ModSecMessage(c.in.data, c.in.match)
		if d != c.want.data || m != c.want.match {
			t.Errorf("%s:\n got  %q\n      %q\n want %q\n      %q", c.name, d, m, c.want.data, c.want.match)
		}
		if d2, m2 := ModSecMessage(d, m); d2 != d || m2 != m {
			t.Errorf("%s: not idempotent: %q %q", c.name, d2, m2)
		}
	}
}

func TestSecretName(t *testing.T) {
	for _, n := range []string{"password", "Password", "newPassword", "user_pwd", "pw", "passwd", "newpass", "json.secondaryToken",
		"X-Auth-Token", "auth", "authSig", "authkey", "api_key", "apiKey", "key", "jwt", "otp", "pin", "SAMLResponse", "PHPSESSID",
		"client_secret", "Authorization", "Cookie", "wordpress_logged_in_abc", "_csrf", "access_token"} {
		if !secretName(n) {
			t.Errorf("secretName(%q) = false", n)
		}
	}
	for _, n := range []string{"search_keyword", "url", "content", "author", "authority", "compass", "bypass", "passage", "secretary",
		"s", "q", "User-Agent", "referer", "content-length", "json.parameters.viewFile", "keyword", "ping", "code"} {
		if secretName(n) {
			t.Errorf("secretName(%q) = true", n)
		}
	}
}

// The collector runs this for every message of every WAF event; a large
// value must cost a scan, not a backtracking regexp.
func TestModSecMessageLargeValue(t *testing.T) {
	v := strings.Repeat("a' or 1=1 -- ", 80000) // ~1 MB
	d, m := ModSecMessage("Matched Data: x found within ARGS:password: "+v, "against variable `ARGS:password' (Value: `"+v+"' )")
	if strings.Contains(d, "1=1") || strings.Contains(m, "1=1") {
		t.Fatal("value left in a large message")
	}
}
