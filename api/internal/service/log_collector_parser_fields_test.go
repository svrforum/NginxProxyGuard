package service

import (
	"strconv"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// accessLine is an access log line in NPG's main format, with the
// client-sent fields given and nginx's own fields after them.
func accessLine(user, request string, status int, referer, ua, xff, upstream, block string) string {
	return `203.0.113.9 - ` + user + ` [15/Oct/2026:12:00:00 +0900] "app.example.com" "` + request + `" ` +
		strconv.Itoa(status) + ` 548 "` + referer + `" "` + ua + `" "` + xff +
		`" rt=0.002 uct="-" uht="-" urt="-" ua="` + upstream + `" us="-" geo="KR" asn="-" block="` + block + `" bot="-" exploit_rule="-"`
}

// The fields nginx writes after X-Forwarded-For are read from there only. A
// Referer, User-Agent or X-Forwarded-For the client ends in `block=`, `ua=` or
// `rt=` used to set them, which could erase the reason of a blocked request or
// make it look answered by the backend.
func TestParseAccessLogReadsNginxFieldsAfterTheClientFields(t *testing.T) {
	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	r, err := c.parseAccessLog(accessLine("-", "GET /admin HTTP/1.1", 403,
		"https://x.example.com/ block=", "Mozilla/5.0 rt=99.9 ua=", "ua=", "-", "uri_block"))
	if err != nil {
		t.Fatal(err)
	}
	if r.BlockReason != model.BlockReasonURIBlock || r.UpstreamAddr != "" || r.RequestTime != 0.002 || r.GeoCountryCode != "KR" {
		t.Errorf("block=%q upstream=%q rt=%v geo=%q, want uri_block, none, 0.002, KR", r.BlockReason, r.UpstreamAddr, r.RequestTime, r.GeoCountryCode)
	}
	if r.HTTPReferer != "https://x.example.com/ block=" || r.HTTPXForwardedFor != "ua=" {
		t.Errorf("referer=%q xff=%q, want them as sent", r.HTTPReferer, r.HTTPXForwardedFor)
	}
}

// $remote_user is written unquoted and holds what the client sent. A user name
// with a space made the line unparseable: it was neither stored nor counted.
func TestParseAccessLogUserWithSpaces(t *testing.T) {
	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	served := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	for _, user := range []string{"a b", "a  b c", `x\x22 y`} {
		r, err := c.parseAccessLog(accessLine(user, "GET / HTTP/1.1", 401, "-", "curl/8", "-", "192.0.2.10:80", "-"))
		if err != nil {
			t.Fatalf("user %q: %v", user, err)
		}
		if r.Host != "app.example.com" || r.StatusCode != 401 || r.RequestURI != "/" || !r.Timestamp.Equal(served) {
			t.Errorf("user %q: host=%q status=%d uri=%q time=%v", user, r.Host, r.StatusCode, r.RequestURI, r.Timestamp)
		}
	}
	// A name holding " [" can take the time field's place; the line still
	// parses, with the time it is read.
	r, err := c.parseAccessLog(accessLine("a [b", "GET / HTTP/1.1", 401, "-", "curl/8", "-", "192.0.2.10:80", "-"))
	if err != nil || r.Host != "app.example.com" || r.StatusCode != 401 {
		t.Errorf("user \"a [b\": %+v, %v", r, err)
	}
}
