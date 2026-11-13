package redact

import "testing"

func TestModSec(t *testing.T) {
	cases := map[string]string{
		// Data lines: the value goes when the variable names a credential.
		"Matched Data: novc found within ARGS:password: hunter2-Secret!":               "Matched Data: [redacted] found within ARGS:password: [redacted]",
		"Matched Data: 1c found within ARGS:json.secondaryToken: 1.--07C1r5b1":         "Matched Data: [redacted] found within ARGS:json.secondaryToken: [redacted]",
		"Matched Data: union found within ARGS_POST:user_pwd: x' union select":         "Matched Data: [redacted] found within ARGS_POST:user_pwd: [redacted]",
		"Matched Data: ' or found within REQUEST_COOKIES:PHPSESSID: ab' or 1=1":        "Matched Data: [redacted] found within REQUEST_COOKIES:PHPSESSID: [redacted]",
		"Matched Data: Bearer found within REQUEST_HEADERS:Authorization: Bearer eyJh": "Matched Data: [redacted] found within REQUEST_HEADERS:Authorization: [redacted]",
		"Matched Data: x found within REQUEST_BODY: user=a&password=b":                 "Matched Data: [redacted] found within REQUEST_BODY: [redacted]",
		"Matched Data: k found within ARGS:api_key: 0123456789":                        "Matched Data: [redacted] found within ARGS:api_key: [redacted]",
		"Matched Data: k found within ARGS:X-Auth-Token: 0123456789":                   "Matched Data: [redacted] found within ARGS:X-Auth-Token: [redacted]",
		// ...and stays when it does not, which is what tuning a false positive needs.
		"Matched Data: docker- found within ARGS:search_keyword: docker-compose": "Matched Data: docker- found within ARGS:search_keyword: docker-compose",
		"Matched Data: <a href found within ARGS:json.content: <a href=x>":       "Matched Data: <a href found within ARGS:json.content: <a href=x>",
		"Matched Data: x found within ARGS:author: 3":                            "Matched Data: x found within ARGS:author: 3",
		"Matched Data: x found within ARGS_NAMES:password: password":             "Matched Data: x found within ARGS_NAMES:password: password",
		"HTTP/1.0": "HTTP/1.0",
		// Match lines.
		"Matched \"Operator `Rx' with parameter `(?i)union' against variable `ARGS:passwd' (Value: `abc' union' )":       "Matched \"Operator `Rx' with parameter `(?i)union' against variable `ARGS:passwd' (Value: `[redacted]' )",
		"detected SQLi using libinjection against variable `ARGS:Password' (Value: `zxc!@#' )":                           "detected SQLi using libinjection against variable `ARGS:Password' (Value: `[redacted]' )",
		"Matched \"Operator `Within' with parameter `HTTP/1.1' against variable `REQUEST_PROTOCOL' (Value: `HTTP/1.0' )": "Matched \"Operator `Within' with parameter `HTTP/1.1' against variable `REQUEST_PROTOCOL' (Value: `HTTP/1.0' )",
		"Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `password=1' )":                    "Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `password=1' )",
	}
	for in, want := range cases {
		got := ModSec(in)
		if got != want {
			t.Errorf("ModSec(%q)\n got  %q\n want %q", in, got, want)
		}
		if again := ModSec(got); again != got {
			t.Errorf("ModSec is not idempotent on %q: %q", got, again)
		}
	}
}
