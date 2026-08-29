package service

import "testing"

// nginx logs whatever request line arrived. When it could not parse one — a
// scanner's raw TLS bytes, an SMB or RDP probe, a bare "GARBAGE /path" — the
// parser used to require three whitespace-separated tokens INSIDE the quoted
// request field. `"` is a non-space character, so the pattern happily spanned
// the quote boundary and captured the HOST as the method: request_method came
// out as `_"` (161 rows a week on one install) and the host went missing.
//
// The missing host is the part that matters beyond cosmetics: host attribution
// is what decides whether fail2ban ever sees a failure
// (see log_collector.go's ProxyHostID gate).
func TestParseAccessLog_MalformedRequestLine(t *testing.T) {
	c := &LogCollector{}

	const suffix = ` 400 150 "-" "-" "-" rt=0.000 uct="-" uht="-" urt="-" ua="-" us="-" geo="-" asn="-" block="-" bot="-" exploit_rule="-"`

	cases := []struct {
		name       string
		request    string
		wantMethod string
		wantURI    string
		wantProto  string
	}{
		{
			name:       "two tokens (malformed request line)",
			request:    `GARBAGE /p5-malformed`,
			wantMethod: "GARBAGE",
			wantURI:    "/p5-malformed",
			wantProto:  "",
		},
		{
			name:       "single token",
			request:    `\x16\x03\x01\x06`,
			wantMethod: `\x16\x03\x01\x06`,
			wantURI:    "",
			wantProto:  "",
		},
		{
			name:       "well formed still works",
			request:    `GET /ok HTTP/1.1`,
			wantMethod: "GET",
			wantURI:    "/ok",
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "http/2 preface",
			request:    `PRI * HTTP/2.0`,
			wantMethod: "PRI",
			wantURI:    "*",
			wantProto:  "HTTP/2.0",
		},
		{
			name:       "empty request line",
			request:    ``,
			wantMethod: "",
			wantURI:    "",
			wantProto:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := `203.0.113.10 - - [29/Aug/2026:00:00:00 +0900] "_" "` + tc.request + `"` + suffix

			logReq, err := c.parseAccessLog(line)
			if err != nil {
				t.Fatalf("parseAccessLog: %v", err)
			}
			if logReq == nil {
				t.Fatal("parseAccessLog returned nil")
			}

			// The regression: the host must never leak into the method.
			if logReq.RequestMethod == `_"` {
				t.Fatalf(`request_method is %q — the host leaked across the quote boundary again`, logReq.RequestMethod)
			}
			if logReq.Host != "_" {
				t.Errorf("host = %q, want %q", logReq.Host, "_")
			}
			if logReq.StatusCode != 400 {
				t.Errorf("status = %d, want 400", logReq.StatusCode)
			}
			if logReq.RequestMethod != tc.wantMethod {
				t.Errorf("method = %q, want %q", logReq.RequestMethod, tc.wantMethod)
			}
			if logReq.RequestURI != tc.wantURI {
				t.Errorf("uri = %q, want %q", logReq.RequestURI, tc.wantURI)
			}
			if logReq.RequestProtocol != tc.wantProto {
				t.Errorf("protocol = %q, want %q", logReq.RequestProtocol, tc.wantProto)
			}
		})
	}
}

// A real host must still be attributed on a malformed request — this is the
// path that feeds fail2ban.
func TestParseAccessLog_MalformedRequestKeepsHost(t *testing.T) {
	c := &LogCollector{}
	const line = `203.0.113.10 - - [29/Aug/2026:00:00:00 +0900] "app.example.com" "BADMETHOD /x" 400 150 "-" "-" "-" rt=0.000 uct="-" uht="-" urt="-" ua="-" us="-" geo="-" asn="-" block="-" bot="-" exploit_rule="-"`

	logReq, err := c.parseAccessLog(line)
	if err != nil {
		t.Fatalf("parseAccessLog: %v", err)
	}
	if logReq.Host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com — without it fail2ban never counts this request", logReq.Host)
	}
	if logReq.RequestMethod != "BADMETHOD" {
		t.Errorf("method = %q, want BADMETHOD", logReq.RequestMethod)
	}
}
