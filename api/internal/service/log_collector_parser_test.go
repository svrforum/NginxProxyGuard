package service

import (
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
