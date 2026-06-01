package repository

import (
	"encoding/json"
	"testing"
)

// nullEscape is the 6-char JSON null escape (backslash u 0000), built without a
// literal so the source file stays free of NUL bytes.
var nullEscape = string([]byte{'\\', 'u', '0', '0', '0', '0'})

func TestSanitizeJSONB(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain unchanged", `{"uri":"/login","s":200}`, `{"uri":"/login","s":200}`},
		{"null escape removed", `{"uri":"/x` + nullEscape + `y"}`, `{"uri":"/xy"}`},
		{"only null escape", `{"a":"` + nullEscape + `"}`, `{"a":""}`},
		// A literal backslash-u-0000 in the data is marshaled by Go as \\u0000;
		// it must be preserved, not mistaken for a genuine null escape.
		{"escaped backslash preserved", `{"a":"x\\u0000y"}`, `{"a":"x\\u0000y"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(sanitizeJSONB(json.RawMessage(tc.in)))
			if got != tc.want {
				t.Fatalf("sanitizeJSONB(%q)\n got = %q\nwant = %q", tc.in, got, tc.want)
			}
			// Whatever we emit must be valid JSON (so the jsonb cast won't fail
			// for structural reasons).
			if !json.Valid([]byte(got)) {
				t.Fatalf("output is not valid JSON: %q", got)
			}
		})
	}
}

func TestSanitizeJSONBRawNUL(t *testing.T) {
	in := json.RawMessage([]byte{'{', '"', 'a', '"', ':', '"', 0x00, 'b', '"', '}'})
	got := string(sanitizeJSONB(in))
	want := `{"a":"b"}`
	if got != want {
		t.Fatalf("raw NUL not stripped: got=%q want=%q", got, want)
	}
}

func TestSanitizeLogText(t *testing.T) {
	in := string([]byte{'a', 0x00, 'b'})
	if got := sanitizeLogText(in); got != "ab" {
		t.Fatalf("sanitizeLogText: got=%q want=%q", got, "ab")
	}
	if got := sanitizeLogText("clean"); got != "clean" {
		t.Fatalf("sanitizeLogText clean path: got=%q", got)
	}
}
