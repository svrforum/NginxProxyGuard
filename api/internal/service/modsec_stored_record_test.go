package service

// The raw_log stored for a modsec row (A3). Fixtures, all real ModSecurity
// 3.0.15 / CRS 4.26 output with documentation IPs and example.com hosts:
//
//	modsec_audit_v3.0.15.json              current audit parts (ABFHZ), the
//	                                       capture-modsec-audit.sh probe set
//	modsec_audit_v3.0.15_legacy_parts.json the previous capture (ABIJDEFHZ:
//	                                       response bodies, a 0-message 502)
//	modsec_audit_fake_credentials.json     requests carrying example Cookie,
//	                                       Authorization and X-Plex-Token
//	                                       values and a Set-Cookie response:
//	                                       two with the old parts (one with a
//	                                       6 KB argument), one with ABFHZ

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// auditFixture returns every entry of testdata/<name> as one compact JSON
// line, the way ModSecurity writes it to stdout.
func auditFixture(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		var c bytes.Buffer
		if err := json.Compact(&c, e); err != nil {
			t.Fatal(err)
		}
		out = append(out, c.String())
	}
	return out
}

var allAuditFixtures = []string{
	"modsec_audit_v3.0.15.json",
	"modsec_audit_v3.0.15_legacy_parts.json",
	"modsec_audit_fake_credentials.json",
}

// The example credentials in modsec_audit_fake_credentials.json.
var fakeCredentialValues = []string{"example-session-0000", "example-token-0000", "example-plex-token-0000"}

func decodeAudit(t *testing.T, raw string) ModSecAuditLog {
	t.Helper()
	var a ModSecAuditLog
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatalf("does not decode as ModSecAuditLog (GetEventRules would answer 500): %v", err)
	}
	return a
}

func TestStoredModSecRecord_KeepsNoCredentialsOrBodies(t *testing.T) {
	c := &LogCollector{}
	stored := 0
	for _, name := range allAuditFixtures {
		for i, line := range auditFixture(t, name) {
			orig := decodeAudit(t, line)
			req, err := c.parseModSecLog(line)
			if len(orig.Transaction.Messages) == 0 {
				if err == nil {
					t.Errorf("%s #%d: a record without rule messages must not be stored", name, i)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s #%d: %v", name, i, err)
			}
			stored++
			raw := req.RawLog
			if !strings.HasPrefix(raw, `{"npg":1,"transaction":`) {
				t.Errorf("%s #%d: missing the format marker: %.40s", name, i, raw)
			}
			for _, banned := range append([]string{`"body"`, `"Set-Cookie"`}, fakeCredentialValues...) {
				if strings.Contains(raw, banned) {
					t.Errorf("%s #%d: stored raw_log still contains %s", name, i, banned)
				}
			}
			got := decodeAudit(t, raw).Transaction
			for k := range got.Request.Headers {
				if !storedModSecRequestHeaders[strings.ToLower(k)] {
					t.Errorf("%s #%d: request header %q is not on the allowlist", name, i, k)
				}
			}
			if len(got.Response.Headers) != 0 {
				t.Errorf("%s #%d: response headers kept: %v", name, i, got.Response.Headers)
			}
			tx := orig.Transaction
			if got.Request.Headers["Host"] != tx.Request.Headers["Host"] || got.Request.Headers["User-Agent"] != tx.Request.Headers["User-Agent"] {
				t.Errorf("%s #%d: Host/User-Agent lost", name, i)
			}
			if got.UniqueID != tx.UniqueID || got.ClientIP != tx.ClientIP || got.Request.Method != tx.Request.Method ||
				got.Response.HTTPCode != tx.Response.HTTPCode || got.Producer.SeqRules != tx.Producer.SeqRules ||
				got.Request.HTTPVersion != tx.Request.HTTPVersion || got.TimeStamp != tx.TimeStamp {
				t.Errorf("%s #%d: request essentials changed", name, i)
			}
			if t.Failed() {
				t.Logf("stored: %.300s", raw)
				return
			}
		}
	}
	if stored < 9 {
		t.Fatalf("only %d records with rule messages across the fixtures", stored)
	}
}

// Everything the WAF event panel reads (message, rule id, severity, data,
// tags) survives; data and match are only cut past storedModSecFieldCap.
func TestStoredModSecRecord_KeepsEveryRuleMessage(t *testing.T) {
	c := &LogCollector{}
	for _, name := range allAuditFixtures {
		for i, line := range auditFixture(t, name) {
			req, err := c.parseModSecLog(line)
			if err != nil {
				continue // no rule messages: not stored
			}
			want := decodeAudit(t, line).Transaction.Messages
			for j := range want {
				want[j].Details.Data = capRunes(want[j].Details.Data, storedModSecFieldCap)
				want[j].Details.Match = capRunes(want[j].Details.Match, storedModSecFieldCap)
			}
			if got := decodeAudit(t, req.RawLog).Transaction.Messages; !reflect.DeepEqual(got, want) {
				t.Errorf("%s #%d: rule messages differ\nwant %+v\ngot  %+v", name, i, want, got)
			}
		}
	}
}

// ModSecurity does not cap a rule's data: a 6 KB argument comes back whole in
// every message. The stored copy, the URI in it and rule_data are cut.
func TestStoredModSecRecord_CapsLongFields(t *testing.T) {
	c := &LogCollector{}
	var longLine string
	for _, line := range auditFixture(t, "modsec_audit_fake_credentials.json") {
		if strings.Contains(line, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
			longLine = line
		}
	}
	if longLine == "" {
		t.Fatal("fixture lost its long-argument record")
	}
	orig := decodeAudit(t, longLine).Transaction
	if utf8.RuneCountInString(orig.Messages[0].Details.Data) <= storedModSecFieldCap ||
		utf8.RuneCountInString(orig.Request.URI) <= storedModSecURICap {
		t.Fatal("fixture record is not long enough to exercise the caps")
	}
	req, err := c.parseModSecLog(longLine)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeAudit(t, req.RawLog).Transaction
	for _, m := range got.Messages {
		if n := utf8.RuneCountInString(m.Details.Data); n > storedModSecFieldCap+1 {
			t.Errorf("data not capped: %d runes", n)
		}
		if n := utf8.RuneCountInString(m.Details.Match); n > storedModSecFieldCap+1 {
			t.Errorf("match not capped: %d runes", n)
		}
	}
	if !strings.HasSuffix(got.Messages[0].Details.Data, "…") {
		t.Error("a cut data field must say so")
	}
	if n := utf8.RuneCountInString(got.Request.URI); n != storedModSecURICap+1 || !strings.HasPrefix(orig.Request.URI, strings.TrimSuffix(got.Request.URI, "…")) {
		t.Errorf("stored URI: %d runes", n)
	}
	if req.RequestURI != orig.Request.URI {
		t.Error("the request_uri column must keep the full URI")
	}
	if n := utf8.RuneCountInString(req.RuleData); n != storedModSecFieldCap+1 {
		t.Errorf("rule_data: %d runes, want the cap plus the mark", n)
	}
	if len(req.RawLog) >= len(longLine)/2 {
		t.Errorf("stored %d bytes of a %d-byte record", len(req.RawLog), len(longLine))
	}
}

// TrimStoredModSecRawLog rewrites rows stored before the trimmed format into
// exactly what the collector stores now, and leaves everything else alone.
func TestTrimStoredModSecRawLog(t *testing.T) {
	c := &LogCollector{}
	for _, name := range []string{"modsec_audit_v3.0.15_legacy_parts.json", "modsec_audit_fake_credentials.json"} {
		for i, line := range auditFixture(t, name) {
			trimmed, changed := TrimStoredModSecRawLog(line)
			if !changed || !strings.HasPrefix(trimmed, storedModSecMarker) {
				t.Fatalf("%s #%d: legacy row not trimmed (changed=%v)", name, i, changed)
			}
			if req, err := c.parseModSecLog(line); err == nil && req.RawLog != trimmed {
				t.Errorf("%s #%d: the reclaim helper and the collector store different records", name, i)
			}
			again, changed := TrimStoredModSecRawLog(trimmed)
			if changed || again != trimmed {
				t.Fatalf("%s #%d: not idempotent", name, i)
			}
		}
	}
	for _, raw := range []string{"", "not json", `{"npg":1,"transaction":{}}`} {
		if got, changed := TrimStoredModSecRawLog(raw); changed || got != raw {
			t.Errorf("%q must be left alone", raw)
		}
	}
}

// Rows already in the database keep the full record; they must still parse
// as before (the WAF panel reads them), including the 0-message entry.
func TestParseModSecLog_LegacyPartsFixture(t *testing.T) {
	c := &LogCollector{}
	parsed, skipped := 0, 0
	for i, line := range auditFixture(t, "modsec_audit_v3.0.15_legacy_parts.json") {
		req, err := c.parseModSecLog(line)
		if len(decodeAudit(t, line).Transaction.Messages) == 0 {
			skipped++
			if err == nil {
				t.Errorf("#%d: 0-message entry must be skipped", i)
			}
			continue
		}
		if err != nil || req.RuleID == 0 || req.ClientIP == "" {
			t.Errorf("#%d: %v %+v", i, err, req)
		}
		parsed++
	}
	if parsed == 0 || skipped == 0 {
		t.Fatalf("parsed=%d skipped=%d: the legacy fixture must keep both kinds", parsed, skipped)
	}
}

func TestCapRunes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 3, "abc"},
		{"abcd", 3, "abc…"},
		{"한국어입니다", 3, "한국어…"},
		{"한국어", 3, "한국어"},
		{"ab\x00c", 4, "ab\x00c"},       // not truncated: NUL bytes are kept (JSON escapes them)
		{"\xff\xfeabc", 2, "\xff\xfe…"}, // invalid UTF-8 counts byte by byte
		{"", 0, ""},
	} {
		if got := capRunes(tc.in, tc.n); got != tc.want {
			t.Errorf("capRunes(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
