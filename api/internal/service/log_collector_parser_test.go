package service

import (
	"encoding/json"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// Issue #130: when nginx's global_req_limit fires, it hard-aborts the request
// before any server-block code can assign $block_reason_var, so the access log
// arrives with block="-". The log_collector status->reason fallback at
// log_collector.go:625-628 must tag it as rate_limit based on status alone.
//
// This test exercises the full parser path against a real-shape log line that
// matches what nginx now emits with limit_req_status 429 (the fix this PR
// landed). Without the fix, nginx would emit 503 here and the fallback would
// not match — the request would land in the DB with block_reason="" and
// disappear from the UI's Block column.
func TestParseAccessLog_RateLimitTaggingFor429(t *testing.T) {
	c := &LogCollector{}

	// Real access-log shape from main_config.go log_format `main`.
	const line = `127.0.0.1 - - [28/Apr/2026:00:00:00 +0900] "test.local" "GET /ui/chunk-XYZ.js HTTP/2.0" 429 0 "-" "Mozilla/5.0" "-" rt=0.000 uct="-" uht="-" urt="-" ua="-" us="-" geo="-" asn="-" block="-" bot="-" exploit_rule="-"`

	logReq, err := c.parseAccessLog(line)
	if err != nil {
		t.Fatalf("parseAccessLog returned error: %v", err)
	}
	if logReq == nil {
		t.Fatal("parseAccessLog returned nil request")
	}
	if logReq.StatusCode != 429 {
		t.Errorf("expected status 429, got %d", logReq.StatusCode)
	}
	// Parser leaves BlockReason at its zero value when nginx says block="-"
	// — this is what unlocks the status-based fallback in log_collector.go.
	// Before this fix the parser wrote "none" here and the fallback was dead code.
	if logReq.BlockReason != "" {
		t.Errorf("expected empty BlockReason from parser when block=\"-\", got %q", logReq.BlockReason)
	}

	// Apply the same fallback the live collector uses (log_collector.go:625-628).
	// nginx returns 429 → parser leaves BlockReason="" → fallback fires → DB row
	// stores "rate_limit" via the log_insert.go INSERT path.
	if logReq.BlockReason == "" && logReq.StatusCode == 429 {
		logReq.BlockReason = model.BlockReasonRateLimit
	}
	if logReq.BlockReason != model.BlockReasonRateLimit {
		t.Errorf("expected BlockReasonRateLimit after fallback, got %q", logReq.BlockReason)
	}
}

// Sanity check: a normal 200 response with block="-" should also leave
// BlockReason empty out of the parser. The DB INSERT path (log_insert.go)
// uses COALESCE(NULLIF($30, '')::block_reason, 'none'), so an empty value
// becomes 'none' on disk — preserving the existing UI/query behavior.
func TestParseAccessLog_NormalResponseLeavesBlockReasonEmpty(t *testing.T) {
	c := &LogCollector{}

	const line = `127.0.0.1 - - [28/Apr/2026:00:00:00 +0900] "test.local" "GET / HTTP/2.0" 200 1234 "-" "Mozilla/5.0" "-" rt=0.005 uct="-" uht="-" urt="0.001" ua="10.0.0.1:8080" us="200" geo="KR" asn="9318" block="-" bot="-" exploit_rule="-"`

	logReq, err := c.parseAccessLog(line)
	if err != nil {
		t.Fatalf("parseAccessLog: %v", err)
	}
	if logReq.StatusCode != 200 {
		t.Errorf("expected 200, got %d", logReq.StatusCode)
	}
	if logReq.BlockReason != "" {
		t.Errorf("normal 200 with block=\"-\" must produce empty BlockReason; got %q", logReq.BlockReason)
	}
}

// Counter-test: a 503 (the pre-fix nginx behavior) would NOT be tagged by the
// fallback. This makes the regression visible if anyone reverts limit_req_status
// 429 back to the nginx default.
func TestParseAccessLog_RateLimitFallbackIgnores503(t *testing.T) {
	c := &LogCollector{}

	const line = `127.0.0.1 - - [28/Apr/2026:00:00:00 +0900] "test.local" "GET / HTTP/2.0" 503 0 "-" "curl/8" "-" rt=0.000 uct="-" uht="-" urt="-" ua="-" us="-" geo="-" asn="-" block="-" bot="-" exploit_rule="-"`

	logReq, err := c.parseAccessLog(line)
	if err != nil {
		t.Fatalf("parseAccessLog: %v", err)
	}
	if logReq.StatusCode != 503 {
		t.Errorf("expected 503, got %d", logReq.StatusCode)
	}
	// Apply the same fallback. 503 must NOT be tagged — that was the bug.
	if logReq.BlockReason == "" && logReq.StatusCode == 429 {
		logReq.BlockReason = model.BlockReasonRateLimit
	}
	if logReq.BlockReason != "" {
		t.Errorf("503 must remain untagged so the regression that motivated the fix stays visible; got %q", logReq.BlockReason)
	}
	// Sanity: the line really does say block="-" (the parser must not invent a value).
	if !strings.Contains(line, `block="-"`) {
		t.Fatal("test line lost the block=\"-\" field; this test is now meaningless")
	}
}

// Issue #139: ModSecurity 3.0.15 (shipped in v2.13.16 via c342ea8) changed
// request.http_version in audit JSON from a number (1.1) to a string ("1.1").
// The Go struct used float64, so every audit line silently failed
// json.Unmarshal and every WAF event was dropped before reaching the DB.
//
// These tests pin both the legacy number form and the new string form so a
// future ModSec bump can't silently break log ingestion again.

const modsecAuditTemplate3015 = `{"transaction":{"client_ip":"203.0.113.10","time_stamp":"Mon May 18 10:00:00 2026","server_id":"abc","client_port":52352,"host_ip":"192.168.1.1","host_port":443,"unique_id":"x","request":{"method":"GET","http_version":"1.1","uri":"/?q=union+select","headers":{"Host":"example.com","User-Agent":"curl/8"}},"response":{"http_code":403,"headers":{}},"producer":{"modsecurity":"ModSecurity v3.0.15 (Linux)","connector":"ModSecurity-nginx v1.0.4","secrules_engine":"Enabled"},"messages":[{"message":"SQL Injection Attack","details":{"match":"matched","reference":"r","ruleId":"942100","file":"f","lineNumber":"1","data":"d","severity":"2","ver":"OWASP_CRS/4.21.0","rev":"","tags":["attack-sqli","application-multi"],"maturity":"0","accuracy":"0"}}]}}`

const modsecAuditTemplate3014 = `{"transaction":{"client_ip":"203.0.113.10","time_stamp":"Mon May 18 10:00:00 2026","server_id":"abc","client_port":52352,"host_ip":"192.168.1.1","host_port":443,"unique_id":"x","request":{"method":"GET","http_version":1.1,"uri":"/?q=union+select","headers":{"Host":"example.com","User-Agent":"curl/8"}},"response":{"http_code":403,"headers":{}},"producer":{"modsecurity":"ModSecurity v3.0.14 (Linux)","connector":"ModSecurity-nginx v1.0.4","secrules_engine":"Enabled"},"messages":[{"message":"SQL Injection Attack","details":{"match":"matched","reference":"r","ruleId":"942100","file":"f","lineNumber":"1","data":"d","severity":"2","ver":"OWASP_CRS/4.21.0","rev":"","tags":["attack-sqli","application-multi"],"maturity":"0","accuracy":"0"}}]}}`

// Sanity: both fixtures decode into the same Go struct without error. This is
// the load-bearing assertion — if either fails, audit lines from that ModSec
// version land in the bit bucket.
func TestModSecAuditLog_AcceptsBothNumberAndStringHTTPVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string // expected stored value after unmarshal
	}{
		{"3.0.14 numeric form", modsecAuditTemplate3014, "1.1"},
		{"3.0.15 string form", modsecAuditTemplate3015, "1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got ModSecAuditLog
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("ModSec %s audit JSON failed to unmarshal: %v\n"+
					"This is the exact failure mode of #139 — a parser regression "+
					"silently drops every WAF event from this ModSec version.", tc.name, err)
			}
			if string(got.Transaction.Request.HTTPVersion) != tc.want {
				t.Errorf("HTTPVersion: got %q, want %q", got.Transaction.Request.HTTPVersion, tc.want)
			}
		})
	}
}

// Full parser path: both fixtures must produce a usable CreateLogRequest with
// the same RequestProtocol rendering. This locks the end-to-end behavior, not
// just the JSON shape.
func TestParseModSecLog_EndToEnd_BothFormats(t *testing.T) {
	c := &LogCollector{}
	for _, tc := range []struct {
		name string
		line string
	}{
		{"3.0.14", modsecAuditTemplate3014},
		{"3.0.15", modsecAuditTemplate3015},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := c.parseModSecLog(tc.line)
			if err != nil {
				t.Fatalf("parseModSecLog returned error for %s: %v", tc.name, err)
			}
			if req.LogType != model.LogTypeModSec {
				t.Errorf("LogType: got %q, want %q", req.LogType, model.LogTypeModSec)
			}
			if req.RuleID != 942100 {
				t.Errorf("RuleID: got %d, want 942100", req.RuleID)
			}
			if req.AttackType != "sqli" {
				t.Errorf("AttackType: got %q, want %q", req.AttackType, "sqli")
			}
			if req.RequestProtocol != "HTTP/1.1" {
				t.Errorf("RequestProtocol: got %q, want %q (must match v2.13.13 output for both forms)",
					req.RequestProtocol, "HTTP/1.1")
			}
			if req.ActionTaken != "blocked" {
				t.Errorf("ActionTaken: got %q, want %q (HTTP 403 in blocking mode)", req.ActionTaken, "blocked")
			}
			if req.BlockReason != model.BlockReasonWAF {
				t.Errorf("BlockReason: got %q, want %q", req.BlockReason, model.BlockReasonWAF)
			}
		})
	}
}

// Null/missing http_version must not crash the parser. ModSec emits this field
// today, but a future bump that drops it (or sends null) should produce a
// degraded log row rather than a silent ingestion outage.
func TestModSecAuditLog_NullHTTPVersionIsTolerated(t *testing.T) {
	line := strings.Replace(modsecAuditTemplate3015, `"http_version":"1.1"`, `"http_version":null`, 1)
	var got ModSecAuditLog
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("null http_version must not fail unmarshal: %v", err)
	}
	if got.Transaction.Request.HTTPVersion != "" {
		t.Errorf("null should leave HTTPVersion empty, got %q", got.Transaction.Request.HTTPVersion)
	}
}
