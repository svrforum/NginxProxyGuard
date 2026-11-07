package service

import (
	"context"
	"fmt"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// What a host's log rules (#347) leave out of the database, and what they
// never do: a line NPG blocked, or a path spelled to read differently.
func TestHostLogFilterSkips(t *testing.T) {
	f := compileHostLogFilter(model.HostLogRules{
		SkipStatuses: []string{"207", "3xx"},
		SkipMethods:  []string{"PROPFIND"},
		SkipPaths:    []string{"/remote.php/dav/"},
	})
	cases := []struct {
		name string
		edit func(r *model.CreateLogRequest)
		want bool
	}{
		{"a line no rule names", func(r *model.CreateLogRequest) {}, false},
		{"status 207", func(r *model.CreateLogRequest) { r.StatusCode = 207 }, true},
		{"a 3xx status", func(r *model.CreateLogRequest) { r.StatusCode = 304 }, true},
		{"another 2xx status", func(r *model.CreateLogRequest) { r.StatusCode = 204 }, false},
		{"the method", func(r *model.CreateLogRequest) { r.RequestMethod = "PROPFIND" }, true},
		{"under the path", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/files/a.txt?x=1" }, true},
		{"under the path, encoded", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/My%20File" }, true},
		{"beside the path", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/davx" }, false},
		{"a dot segment out of it", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/../../admin" }, false},
		{"..; out of it", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/..;/admin" }, false},
		{"an encoded dot segment", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/%2e%2e/admin" }, false},
		{"the backend's 403 under the path", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/x"; r.StatusCode = 403 }, true},
		{"NPG's 403 without a reason (WAF)", func(r *model.CreateLogRequest) {
			r.RequestURI = "/remote.php/dav/x"
			r.StatusCode = 403
			r.UpstreamAddr = ""
		}, false},
		{"a URI block", func(r *model.CreateLogRequest) {
			r.RequestMethod = "PROPFIND"
			r.StatusCode = 403
			r.UpstreamAddr = ""
			r.BlockReason = model.BlockReasonURIBlock
		}, false},
		{"a rate limit", func(r *model.CreateLogRequest) {
			r.RequestMethod = "PROPFIND"
			r.StatusCode = 429
			r.UpstreamAddr = ""
			r.BlockReason = model.BlockReasonRateLimit
		}, false},
		{"a 3xx NPG answered (HTTPS redirect)", func(r *model.CreateLogRequest) { r.StatusCode = 301; r.UpstreamAddr = "" }, true},
		{"the backend's 302", func(r *model.CreateLogRequest) { r.StatusCode = 302 }, true},
		{"NPG's 302 (ForwardAuth sign-in)", func(r *model.CreateLogRequest) { r.StatusCode = 302; r.UpstreamAddr = "" }, false},
		{"a path spelled with a trailing dot run", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/..../admin" }, false},
		{"a fragment hiding a dot segment", func(r *model.CreateLogRequest) { r.RequestURI = "/remote.php/dav/x#/../../admin" }, false},
	}
	for _, tc := range cases {
		r := model.CreateLogRequest{RequestMethod: "GET", RequestURI: "/index.html", StatusCode: 200, UpstreamAddr: "192.0.2.10:80"}
		tc.edit(&r)
		if got := f.skips(&r, true); got != tc.want {
			t.Errorf("%s: skips = %v, want %v", tc.name, got, tc.want)
		}
	}

	underPath := model.CreateLogRequest{RequestMethod: "GET", RequestURI: "/remote.php/dav/a", StatusCode: 200, UpstreamAddr: "192.0.2.10:80"}
	if f.skips(&underPath, false) {
		t.Error("a path rule applied while the access log strips the query string")
	}
	all := compileHostLogFilter(model.HostLogRules{SkipAll: true})
	if !all.skips(&model.CreateLogRequest{RequestMethod: "GET", RequestURI: "/", StatusCode: 200, UpstreamAddr: "192.0.2.10:80"}, false) {
		t.Error("skip_all keeps a plain line")
	}
	if all.skips(&model.CreateLogRequest{RequestMethod: "GET", RequestURI: "/", StatusCode: 403}, true) {
		t.Error("skip_all skips a line NPG blocked")
	}
	if compileHostLogFilter(model.HostLogRules{SkipStatuses: []string{}}) != nil {
		t.Error("rules that skip nothing compile to a filter")
	}
	var none *hostLogFilter
	if none.skips(&model.CreateLogRequest{StatusCode: 207}, true) {
		t.Error("a host without rules skips a line")
	}
}

// A skipped line still counts towards fail2ban; it is only not stored.
func TestHostLogRulesSkipStorageNotFail2ban(t *testing.T) {
	ctx := context.Background()
	c, f2b := f2bGateCollector(t, map[string]string{"dav.example.com": f2bGateHost, "other.example.com": "00000000-0000-4000-8000-0000000014a2"})
	c.hostLogRules.Store(&hostLogRuleSet{filters: map[string]*hostLogFilter{
		f2bGateHost: compileHostLogFilter(model.HostLogRules{SkipStatuses: []string{"4xx"}}),
	}})

	c.handleAccessLine(ctx, f2bGateLine("192.0.2.7", "dav.example.com", "/missing", 404, "192.0.2.20:80", "-"))
	c.handleAccessLine(ctx, f2bGateLine("192.0.2.7", "dav.example.com", "/blocked", 403, "-", "-"))
	c.handleAccessLine(ctx, f2bGateLine("192.0.2.7", "dav.example.com", "/index.html", 200, "192.0.2.20:80", "-"))
	c.handleAccessLine(ctx, f2bGateLine("192.0.2.7", "other.example.com", "/missing", 404, "192.0.2.20:80", "-"))

	if got := f2bGateCount(f2b, f2bGateHost, "192.0.2.7"); got != 2 {
		t.Errorf("fail2ban counted %d failures on the host, want 2 (the skipped 404 and NPG's 403)", got)
	}
	var stored []string
	for _, r := range c.buffer {
		stored = append(stored, fmt.Sprintf("%s %s %d", r.Host, r.RequestURI, r.StatusCode))
	}
	want := "[dav.example.com /blocked 403 dav.example.com /index.html 200 other.example.com /missing 404]"
	if fmt.Sprint(stored) != want {
		t.Errorf("stored %v, want %s", stored, want)
	}
}

type fakeLogRulesSource struct {
	rules []model.HostLogRules
	err   error
}

func (f *fakeLogRulesSource) ListActive(context.Context) ([]model.HostLogRules, error) {
	return f.rules, f.err
}

type fakeGlobalSettings struct {
	strip bool
	err   error
}

func (f *fakeGlobalSettings) Get(context.Context) (*model.GlobalSettings, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &model.GlobalSettings{AccessLogStripQuery: f.strip}, nil
}

// Path prefixes apply only once the global settings say the access log keeps
// the raw request target; a failed read keeps what the last load decided, and
// a failed read of the rules keeps the rules.
func TestLoadHostLogRules(t *testing.T) {
	ctx := context.Background()
	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	rules := &fakeLogRulesSource{rules: []model.HostLogRules{{ProxyHostID: f2bGateHost, SkipPaths: []string{"/dav/"}}}}
	settings := &fakeGlobalSettings{err: fmt.Errorf("db down")}
	c.SetLogRulesRepo(rules, settings)
	line := &model.CreateLogRequest{ProxyHostID: f2bGateHost, RequestMethod: "GET", RequestURI: "/dav/a", StatusCode: 207, UpstreamAddr: "192.0.2.10:80"}

	c.loadHostLogRules(ctx)
	if c.skipsStorage(line) {
		t.Error("a path rule applied before the global settings were read")
	}
	settings.err = nil
	c.loadHostLogRules(ctx)
	if !c.skipsStorage(line) {
		t.Error("the path rule does not apply once the settings were read")
	}
	settings.strip = true
	c.loadHostLogRules(ctx)
	if c.skipsStorage(line) {
		t.Error("a path rule applied while the access log strips the query string")
	}
	settings.strip, settings.err = false, fmt.Errorf("db down")
	c.loadHostLogRules(ctx)
	if c.skipsStorage(line) {
		t.Error("a failed settings read lost what the last load decided")
	}
	settings.err, rules.err = nil, fmt.Errorf("db down")
	c.loadHostLogRules(ctx)
	if c.skipsStorage(line) {
		t.Error("a failed rules read replaced the rules")
	}
}

// A line NPG blocked stays blocked whatever the client wrote into the fields
// it sends (log_collector_parser.go reads nginx's fields from its own part of
// the line), so no rule drops it.
func TestCraftedBlockedLineIsKept(t *testing.T) {
	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	r, err := c.parseAccessLog(accessLine("-", "GET /dav/x HTTP/1.1", 403, "https://x.example.com/ block=", "Mozilla/5.0", "ua=", "-", "uri_block"))
	if err != nil {
		t.Fatal(err)
	}
	all := compileHostLogFilter(model.HostLogRules{SkipAll: true})
	if all.skips(r, true) {
		t.Error("skip_all dropped a blocked line whose Referer and X-Forwarded-For were crafted")
	}
}
