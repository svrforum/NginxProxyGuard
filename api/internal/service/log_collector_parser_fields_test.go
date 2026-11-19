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

// sp= is $server_port, the port the request arrived on (#389). Lines from
// before it was logged have none, and a client field cannot supply one.
func TestParseAccessLogServerPort(t *testing.T) {
	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	line := accessLine("-", "GET /home HTTP/2.0", 200, "https://x.example.com/ sp=1", "curl/8 sp=2", "-", "192.0.2.10:8080", "-")
	cases := []struct {
		name string
		line string
		want int
	}{
		{"logged", line + " sp=11443", 11443},
		{"older line", line, 0},
		{"out of range", line + " sp=99999", 0},
	}
	for _, tc := range cases {
		r, err := c.parseAccessLog(tc.line)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if r.ServerPort != tc.want {
			t.Errorf("%s: server port %d, want %d", tc.name, r.ServerPort, tc.want)
		}
		if r.RequestProtocol != "HTTP/2.0" {
			t.Errorf("%s: protocol %q, want HTTP/2.0", tc.name, r.RequestProtocol)
		}
	}
}

// A stream_main line becomes a stream row (#392): transport in the method and
// protocol, $bytes_sent and $session_time in the access columns, and the port
// that picks the stream host. Lines from before the port was logged still
// parse, without it.
func TestParseStreamLog(t *testing.T) {
	line := `198.51.100.7 [19/Nov/2026:10:15:02 +0900] UDP 200 5120 640 12.345 "192.0.2.10:25565" "640" "5120" "0.001" sp=25565`
	got, port, err := parseStreamLog(line)
	if err != nil {
		t.Fatalf("parseStreamLog: %v", err)
	}
	if got.LogType != model.LogTypeStream || got.ClientIP != "198.51.100.7" || got.RequestMethod != "UDP" ||
		got.RequestProtocol != "UDP" || got.StatusCode != 200 || got.BodyBytesSent != 5120 ||
		got.RequestTime != 12.345 || got.UpstreamAddr != "192.0.2.10:25565" || got.ServerPort != 25565 || port != 25565 {
		t.Errorf("parsed %+v (port %d)", got, port)
	}
	if want := time.Date(2026, 11, 19, 1, 15, 2, 0, time.UTC); !got.Timestamp.Equal(want) {
		t.Errorf("timestamp %v, want %v", got.Timestamp, want)
	}

	old := `198.51.100.7 [19/Nov/2026:10:15:02 +0900] TCP 502 0 0 0.003 "192.0.2.10:22" "0" "0" "-"`
	if got, port, err := parseStreamLog(old); err != nil || port != 0 || got.ServerPort != 0 || got.StatusCode != 502 {
		t.Errorf("line without sp=: %+v port %d err %v", got, port, err)
	}
	noUpstream := `198.51.100.7 [19/Nov/2026:10:15:02 +0900] TCP 403 0 0 0.000 "-" "-" "-" "-" sp=2222`
	if got, _, err := parseStreamLog(noUpstream); err != nil || got.UpstreamAddr != "" {
		t.Errorf("refused connection: %+v err %v", got, err)
	}
	for _, bad := range []string{"", `198.51.100.7 - - [19/Nov/2026:10:15:02 +0900] "GET / HTTP/1.1" 200 1 "-" "-"`} {
		if _, _, err := parseStreamLog(bad); err == nil {
			t.Errorf("parsed a non-stream line: %q", bad)
		}
	}
}

// Stream hosts are found by protocol and port; HTTP hosts and hosts without a
// port are not listeners.
func TestStreamListeners(t *testing.T) {
	hosts := []model.ProxyHost{
		{ID: "a", ProxyType: model.ProxyTypeStream, DomainNames: []string{"game.example.com"}, StreamProtocol: "udp", StreamListenPort: 25565},
		{ID: "b", ProxyType: model.ProxyTypeStream, DomainNames: []string{"ssh.example.com"}, StreamListenPort: 2222},
		{ID: "c", DomainNames: []string{"web.example.com"}},
		{ID: "d", ProxyType: model.ProxyTypeStream, DomainNames: []string{"dup.example.com"}, StreamProtocol: "udp", StreamListenPort: 25565},
	}
	m := streamListeners(hosts)
	if l := m["udp:25565"]; l.hostID != "a" || l.name != "game.example.com" {
		t.Errorf("udp:25565 = %+v", l)
	}
	if l := m["tcp:2222"]; l.hostID != "b" {
		t.Errorf("tcp:2222 (protocol defaults to tcp) = %+v", l)
	}
	if len(m) != 2 {
		t.Errorf("listeners %v, want 2", m)
	}
}
