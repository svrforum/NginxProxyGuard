package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Only modsec rows carry a raw_log. For access and error rows it was a copy
// of the line nobody read back, about half of every stored row; the line
// itself stays in the raw log file and in docker logs.
func TestRawLogStoredOnlyForModSecRows(t *testing.T) {
	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	c.batchSize = 1 << 30 // memory buffer only

	const access = `192.0.2.10 - - [09/Oct/2026:12:00:00 +0900] "app.example.com" "GET /a?b=c HTTP/2.0" 200 1234 "-" "Mozilla/5.0" "-" rt=0.005 uct="-" uht="-" urt="0.001" ua="192.0.2.20:8080" us="200" geo="-" asn="-" block="-" bot="-" exploit_rule="-"`
	const oldAccess = `192.0.2.10 - - [09/Oct/2026:12:00:00 +0900] "GET /old HTTP/1.1" 404 0 "-" "curl/8" "-"`
	const errLine = `2026/10/09 12:00:00 [error] 63#63: *5 access forbidden by rule, client: 192.0.2.10, server: app.example.com, request: "GET /denied HTTP/1.1", host: "app.example.com"`

	for _, line := range []string{access, oldAccess} {
		req, err := c.parseAccessLog(line)
		if err != nil {
			t.Fatalf("parseAccessLog(%.40s): %v", line, err)
		}
		if req.RawLog != "" {
			t.Errorf("access row keeps raw_log: %.60s", req.RawLog)
		}
	}
	req, err := c.parseErrorLog(errLine)
	if err != nil {
		t.Fatal(err)
	}
	if req.RawLog != "" || req.ErrorMessage == "" || req.ClientIP != "192.0.2.10" {
		t.Errorf("error row: raw_log=%q message=%q client=%q", req.RawLog, req.ErrorMessage, req.ClientIP)
	}
	mreq, err := c.parseModSecLog(modsecAuditTemplate3015)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mreq.RawLog, storedModSecMarker) {
		t.Errorf("modsec row must keep its audit record, got %.60q", mreq.RawLog)
	}

	// The same through the collector's own handlers, as the rows are buffered
	// for insertion.
	c.handleAccessLine(context.Background(), access)
	c.handleModSecLine(context.Background(), modsecAuditTemplate3015, time.Now())
	c.bufferMu.Lock()
	defer c.bufferMu.Unlock()
	if len(c.buffer) != 2 {
		t.Fatalf("buffered %d rows, want 2", len(c.buffer))
	}
	for _, r := range c.buffer {
		switch r.LogType {
		case model.LogTypeAccess:
			if r.RawLog != "" || r.RequestURI != "/a?b=c" {
				t.Errorf("buffered access row: raw_log=%q uri=%q", r.RawLog, r.RequestURI)
			}
		case model.LogTypeModSec:
			if !strings.HasPrefix(r.RawLog, storedModSecMarker) {
				t.Errorf("buffered modsec row lost its audit record")
			}
		}
	}
}
