package service

import "testing"

// A WebSocket upgrade is logged with HTTP 101 and a request_time equal to the
// whole connection lifetime (minutes/hours), not request latency. It must still
// count as a request, but must NOT feed the response-time average — otherwise a
// single long-lived socket skews avg_response_time by orders of magnitude.
// (GitHub Issue #148)
func TestAccumulateRow_WebSocketExcludedFromResponseTime(t *testing.T) {
	stats := AggregatedStats{
		HostStats: make(map[string]int64),
		PathStats: make(map[string]int64),
	}

	stats.accumulateRow(200, 100, 0.050, "a.com", "/x", "none")
	stats.accumulateRow(200, 100, 0.150, "a.com", "/y", "none")
	// A 19.6-minute WebSocket, exactly like the report in #148.
	stats.accumulateRow(101, 21606, 1178.977, "a.com", "/websockets", "none")

	if stats.TotalRequests != 3 {
		t.Fatalf("TotalRequests = %d, want 3 (WebSocket still counts as a request)", stats.TotalRequests)
	}
	if stats.TimedRequests != 2 {
		t.Fatalf("TimedRequests = %d, want 2 (WebSocket 101 excluded from latency)", stats.TimedRequests)
	}
	if stats.TotalTime > 1.0 {
		t.Fatalf("TotalTime = %.3fs — WebSocket connection lifetime leaked into latency total", stats.TotalTime)
	}

	avgMs := stats.TotalTime / float64(stats.TimedRequests) * 1000
	if avgMs < 99 || avgMs > 101 {
		t.Fatalf("avg response time = %.1fms, want ~100ms (got skewed by WebSocket?)", avgMs)
	}
}
