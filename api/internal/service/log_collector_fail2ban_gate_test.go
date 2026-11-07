package service

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// Bootstrap hands the DNS entry service to SetFail2banExemption.
var _ Fail2banExemption = (*DNSEntryService)(nil)

const f2bGateHost = "00000000-0000-4000-8000-0000000014a1"

// f2bGateExemption records what the collector asks it, as "hostID clientIP"
// and the request time, and answers exempt.
type f2bGateExemption struct {
	exempt bool
	calls  []string
	ats    []time.Time
}

func (f *f2bGateExemption) ExemptAccessDenial(ctx context.Context, hostID, clientIP string, at time.Time) bool {
	f.calls = append(f.calls, hostID+" "+clientIP)
	f.ats = append(f.ats, at)
	return f.exempt
}

// f2bGateCollector returns a collector that hands failures to a fail2ban
// service which only counts: every host in hosts (domain → host ID) counts
// 401, 403 and 404 towards a threshold (1000) and an action ("log") that
// never touch the database, and so does the global jail for traffic no host
// owns.
func f2bGateCollector(t *testing.T, hosts map[string]string) (*LogCollector, *Fail2banService) {
	t.Helper()
	f2b := NewFail2banService(nil, nil, nil, nil, nil, nil, nil)
	for _, id := range hosts {
		f2b.configCache[id] = &model.Fail2banConfig{Enabled: true, MaxRetries: 1000, FindTime: 600, FailCodes: "401,403,404", Action: "log"}
	}
	f2b.globalConfig = &model.GlobalFail2banConfig{Enabled: true, MaxRetries: 1000, FindTime: 600, FailCodes: "401,403,404", Action: "log"}
	f2b.trustedProxyCIDRs = []string{"192.0.2.0/24"} // without a declared proxy range the global jail does nothing

	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	c.batchSize = 1 << 30 // memory buffer only
	c.SetFail2banService(f2b)
	c.SetProxyHostRepo(repository.NewProxyHostRepository(nil)) // attribution needs one; the cache below answers
	for domain, id := range hosts {
		c.domainCache[domain] = id
	}
	c.domainCacheTime = time.Now() // fresh, so an unknown host is not looked up in the database
	f2b.SetConfiguredHostResolver(c.IsConfiguredHost)
	return c, f2b
}

// f2bGateCount is how many failures fail2ban holds for ip under key: a host
// ID, or globalJailKey.
func f2bGateCount(f2b *Fail2banService, key, ip string) int {
	f2b.mu.RLock()
	defer f2b.mu.RUnlock()
	return len(f2b.ipEvents[key][ip])
}

// f2bGateLine is an access log line in nginx's "main" format. upstream "-"
// means nginx answered the request itself.
func f2bGateLine(ip, host, uri string, status int, upstream, block string) string {
	upstreamStatus := "-"
	if upstream != "-" {
		upstreamStatus = strconv.Itoa(status)
	}
	return fmt.Sprintf(`%s - - [15/Oct/2026:12:00:00 +0900] "%s" "GET %s HTTP/1.1" %d 548 "-" "Mozilla/5.0" "-" rt=0.000 uct="-" uht="-" urt="-" ua="%s" us="%s" geo="-" asn="-" block="%s" bot="-" exploit_rule="-"`,
		ip, host, uri, status, upstream, upstreamStatus, block)
}

func TestAccessPhaseDenial(t *testing.T) {
	denied := model.CreateLogRequest{StatusCode: 403, BlockReason: model.BlockReasonAccessDenied, RequestURI: "/admin"}
	cases := []struct {
		name string
		edit func(r *model.CreateLogRequest)
		want bool
	}{
		{"403 nginx answered with the access_denied label", func(r *model.CreateLogRequest) {}, true},
		{"the ACME location allows everyone", func(r *model.CreateLogRequest) { r.RequestURI = "/.well-known/acme-challenge/token" }, false},
		{"a path that only starts like the ACME location", func(r *model.CreateLogRequest) { r.RequestURI = "/.well-known/acme-challenge" }, true},
		{"the upstream answered 403", func(r *model.CreateLogRequest) { r.UpstreamAddr = "192.0.2.20:8080" }, false},
		{"401", func(r *model.CreateLogRequest) { r.StatusCode = 401 }, false},
		{"404", func(r *model.CreateLogRequest) { r.StatusCode = 404 }, false},
		{"a ban's 403", func(r *model.CreateLogRequest) { r.BlockReason = model.BlockReasonBannedIP }, false},
		{"no label", func(r *model.CreateLogRequest) { r.BlockReason = "" }, false},
	}
	for _, tc := range cases {
		r := denied
		tc.edit(&r)
		if got := accessPhaseDenial(&r); got != tc.want {
			t.Errorf("%s: accessPhaseDenial = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Only a 403 nginx answered itself with the access_denied label, outside the
// ACME location, on a line a proxy host owns, reaches the exemption.
// Everything else is counted as before without asking, and the global
// jail never asks.
func TestFail2banGateAsksOnlyAboutAccessPhaseDenials(t *testing.T) {
	ctx := context.Background()
	c, f2b := f2bGateCollector(t, map[string]string{"app.example.com": f2bGateHost})
	ex := &f2bGateExemption{exempt: true}
	c.SetFail2banExemption(ex)

	cases := []struct {
		name         string
		ip           string
		host, uri    string
		status       int
		upstream     string
		block        string
		asked        bool
		hostN, globN int
	}{
		{"access-phase 403", "198.51.100.10", "app.example.com", "/x", 403, "-", "access_denied", true, 0, 0},
		{"401", "198.51.100.11", "app.example.com", "/x", 401, "-", "-", false, 1, 0},
		{"401 with the access_denied label", "198.51.100.12", "app.example.com", "/x", 401, "-", "access_denied", false, 1, 0},
		{"404", "198.51.100.13", "app.example.com", "/x", 404, "-", "-", false, 1, 0},
		{"403 from the upstream", "198.51.100.14", "app.example.com", "/x", 403, "192.0.2.20:8080", "access_denied", false, 1, 0},
		{"403 of a ban", "198.51.100.15", "app.example.com", "/x", 403, "-", "banned_ip", false, 1, 0},
		{"403 of the geo block", "198.51.100.16", "app.example.com", "/x", 403, "-", "geo_block", false, 1, 0},
		{"403 without a label", "198.51.100.17", "app.example.com", "/x", 403, "-", "-", false, 1, 0},
		{"403 in the ACME location", "198.51.100.18", "app.example.com", "/.well-known/acme-challenge/token", 403, "-", "access_denied", false, 1, 0},
		{"403 no host owns", "198.51.100.19", "stray.example.com", "/x", 403, "-", "access_denied", false, 0, 1},
	}
	for _, tc := range cases {
		before := len(ex.calls)
		c.handleAccessLine(ctx, f2bGateLine(tc.ip, tc.host, tc.uri, tc.status, tc.upstream, tc.block))
		asked := len(ex.calls) > before
		if asked != tc.asked {
			t.Errorf("%s: exemption asked = %v, want %v", tc.name, asked, tc.asked)
		}
		if asked && ex.calls[before] != f2bGateHost+" "+tc.ip {
			t.Errorf("%s: asked about %q, want the attributed host and the client %q", tc.name, ex.calls[before], f2bGateHost+" "+tc.ip)
		}
		if got := f2bGateCount(f2b, f2bGateHost, tc.ip); got != tc.hostN {
			t.Errorf("%s: host count = %d, want %d", tc.name, got, tc.hostN)
		}
		if got := f2bGateCount(f2b, globalJailKey, tc.ip); got != tc.globN {
			t.Errorf("%s: global jail count = %d, want %d", tc.name, got, tc.globN)
		}
	}

	// The access log keeps every line, exempted or not.
	c.bufferMu.Lock()
	defer c.bufferMu.Unlock()
	if len(c.buffer) != len(cases) {
		t.Fatalf("buffered %d rows, want %d", len(c.buffer), len(cases))
	}
}

// The collector reads a line seconds after the request, and the exemption
// judges it by what nginx allowed then: it gets the line's time. A line
// whose time cannot be read is judged when it is read, as before.
func TestFail2banGateGetsTheRequestTime(t *testing.T) {
	ctx := context.Background()
	c, _ := f2bGateCollector(t, map[string]string{"app.example.com": f2bGateHost})
	ex := &f2bGateExemption{exempt: true}
	c.SetFail2banExemption(ex)
	line := f2bGateLine("198.51.100.21", "app.example.com", "/x", 403, "-", "access_denied")

	c.handleAccessLine(ctx, line)
	served := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC) // the line's 15/Oct/2026:12:00:00 +0900
	if len(ex.ats) != 1 || !ex.ats[0].Equal(served) {
		t.Fatalf("the exemption got %v, want the line's time %v", ex.ats, served)
	}

	before := time.Now()
	c.handleAccessLine(ctx, strings.Replace(line, "15/Oct/2026:12:00:00 +0900", "not a time", 1))
	after := time.Now()
	if len(ex.ats) != 2 || ex.ats[1].Before(before) || ex.ats[1].After(after) {
		t.Fatalf("the exemption got %v for a line without a readable time, want the time it was read (%v..%v)", ex.ats, before, after)
	}
}

// The exemption decides only whether the line counts: without one, or when
// it says no, the denial is counted as before.
func TestFail2banGateFollowsTheExemption(t *testing.T) {
	ctx := context.Background()
	line := f2bGateLine("198.51.100.20", "app.example.com", "/x", 403, "-", "access_denied")
	for _, tc := range []struct {
		name string
		ex   *f2bGateExemption
		want int
	}{
		{"no exemption wired", nil, 1},
		{"the exemption says count it", &f2bGateExemption{exempt: false}, 1},
		{"the exemption says leave it out", &f2bGateExemption{exempt: true}, 0},
	} {
		c, f2b := f2bGateCollector(t, map[string]string{"app.example.com": f2bGateHost})
		if tc.ex != nil {
			c.SetFail2banExemption(tc.ex)
		}
		c.handleAccessLine(ctx, line)
		if got := f2bGateCount(f2b, f2bGateHost, "198.51.100.20"); got != tc.want {
			t.Errorf("%s: host count = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// End to end with the DNS entry service's evaluator (dnsGateRig):
// on a domain-list host the list's own 403 for a client outside it is not
// counted; a client the list allows, an address nginx may still allow after a
// removal, a host whose login decides (satisfy any + ForwardAuth), a host with
// access rules in its Advanced Config, a host without a domain list and every
// 401 are.
func TestFail2banGateWithTheDNSEntryService(t *testing.T) {
	ctx := context.Background()
	r, _ := dnsGateRig(t)
	c, f2b := f2bGateCollector(t, map[string]string{
		"app1.example.com": dnsGateH1, "app2.example.com": dnsGateH2, "app5.example.com": dnsGateH5,
		"app.example.com": f2bGateHost,
	})
	c.SetFail2banExemption(r.svc)

	for _, tc := range []struct {
		name   string
		hostID string
		ip     string
		line   string
		want   int
	}{
		{"outside list A", dnsGateH1, "203.0.113.99", f2bGateLine("203.0.113.99", "app1.example.com", "/x", 403, "-", "access_denied"), 0},
		{"allowed by an IP row", dnsGateH1, "198.51.100.7", f2bGateLine("198.51.100.7", "app1.example.com", "/x", 403, "-", "access_denied"), 1},
		{"removed, nginx may still allow it", dnsGateH1, "203.0.113.9", f2bGateLine("203.0.113.9", "app1.example.com", "/x", 403, "-", "access_denied"), 1},
		{"satisfy any + ForwardAuth", dnsGateH2, "203.0.113.99", f2bGateLine("203.0.113.99", "app2.example.com", "/x", 403, "-", "access_denied"), 1},
		{"Advanced Config with allow/deny", dnsGateH5, "203.0.113.99", f2bGateLine("203.0.113.99", "app5.example.com", "/x", 403, "-", "access_denied"), 1},
		{"a host without a domain list", f2bGateHost, "203.0.113.99", f2bGateLine("203.0.113.99", "app.example.com", "/x", 403, "-", "access_denied"), 1},
		{"a 401 of a client outside list A", dnsGateH1, "203.0.113.99", f2bGateLine("203.0.113.99", "app1.example.com", "/login", 401, "-", "-"), 1},
	} {
		c.handleAccessLine(ctx, tc.line)
		if got := f2bGateCount(f2b, tc.hostID, tc.ip); got != tc.want {
			t.Errorf("%s: count = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// f2bGateSettingsRow is a system_settings row as SystemSettingsRepository.Get
// reads it, with the global trusted IPs and domains given (the domains as a
// text[] literal). It follows the repository's column list: a column added
// there is added here.
func f2bGateSettingsRow(trustedIPs, trustedNames string) []driver.Value {
	at := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	return []driver.Value{
		"00000000-0000-4000-8000-0000000014b1", // id
		false, nil, nil, false, "", nil, nil,   // geoip: enabled, license key, account id, auto update, interval, last updated, version
		false, nil, false, false, int64(30), nil, nil, // acme: enabled, email, staging, auto renew, renew days, DNS provider, DNS credentials
		nil, false, int64(30), false, false, // notification email, cert expiry, its days, security events, backup complete
		int64(30), int64(90), int64(10), false, nil, // log and stats retention, backups kept, auto backup, its schedule
		int64(5), int64(1095), int64(90), int64(30), int64(30), int64(1095), // DDNS interval; access, WAF, error, system and audit log retention
		false, int64(7), int64(100), int64(5), true, false, int64(365), // raw log: enabled, retention, max size, rotations, compress, archive, archive retention
		false, true, false, true, false, false, "", // bot filter defaults
		"", "", "", "", // bot lists
		false, int64(10), int64(300), int64(3600), // WAF auto-ban
		trustedIPs, false, trustedNames, // global trusted IPs, their WAF bypass, global trusted domains
		"", "none", "X-Forwarded-For", "", "allow", "system", "auto", // trusted proxies, preset, real IP header, exploit exceptions, direct IP access, font, error page language
		"",                                           // instance name
		true, []byte(`{}`), "{}", "{}", []byte(`{}`), // system logs: enabled, levels, exclude patterns, stdout excluded; DNS entry settings
		at, at, // created_at, updated_at
	}
}

// f2bGateSettingsRepo returns a SystemSettingsRepository over a mocked
// database that answers f2bGateSettingsRow twice: once to this helper, which
// reads it back so a fixture out of line with the repository fails here and
// not as a trusted IP gone missing, and once to the collector (it keeps the
// list for a minute).
func f2bGateSettingsRepo(t *testing.T, trustedIPs, trustedNames string) *repository.SystemSettingsRepository {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	row := f2bGateSettingsRow(trustedIPs, trustedNames)
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(`FROM system_settings`).WillReturnRows(sqlmock.NewRows(positionalColumns(len(row))).AddRow(row...))
	}
	repo := repository.NewSystemSettingsRepository(db)
	if got, err := repo.Get(context.Background()); err != nil || got.GlobalTrustedIPs != trustedIPs || len(got.GlobalTrustedHostnames) == 0 {
		t.Fatalf("the settings fixture no longer reads back; add the repository's new columns to it: %+v, %v", got, err)
	}
	return repo
}

// The global trusted domains let their addresses through the perimeter, never
// past fail2ban or the WAF auto-ban: the collector trusts the static IPs
// alone. A trusted domain's address is counted as any client is, a 403 it
// got past a list block that includes the trusted domains too, while the
// list's own 403 for a client outside it is still left out. A static trusted
// IP is counted by neither.
func TestLogCollectorTrustedIPsIgnoreTrustedDomains(t *testing.T) {
	ctx := context.Background()
	r, _ := dnsTrustedGateRig(t) // office.example.com publishes 192.0.2.20; trust1's list block includes it
	c, f2b := f2bGateCollector(t, map[string]string{"trust1.example.com": dnsTrustH1, "app.example.com": f2bGateHost})
	c.SetFail2banExemption(r.svc)
	c.SetSystemSettingsRepo(f2bGateSettingsRepo(t, "192.0.2.5", "{office.example.com}"))
	waf := NewWAFAutoBanService(nil, nil, nil, nil, nil, nil)
	waf.enabled, waf.threshold = true, 1000 // counts in memory, never bans
	c.SetWAFAutoBanService(waf)

	for _, tc := range []struct {
		name, hostID, ip, line string
		want                   int
	}{
		{"a trusted domain's 404", f2bGateHost, "192.0.2.20", f2bGateLine("192.0.2.20", "app.example.com", "/x", 404, "-", "-"), 1},
		{"a trusted domain's 403 past the list block", dnsTrustH1, "192.0.2.20", f2bGateLine("192.0.2.20", "trust1.example.com", "/x", 403, "-", "access_denied"), 1},
		{"the list's own 403 for a client outside it", dnsTrustH1, "192.0.2.99", f2bGateLine("192.0.2.99", "trust1.example.com", "/x", 403, "-", "access_denied"), 0},
		{"a static trusted IP's 404", f2bGateHost, "192.0.2.5", f2bGateLine("192.0.2.5", "app.example.com", "/x", 404, "-", "-"), 0},
	} {
		c.handleAccessLine(ctx, tc.line)
		if got := f2bGateCount(f2b, tc.hostID, tc.ip); got != tc.want {
			t.Errorf("%s: fail2ban count = %d, want %d", tc.name, got, tc.want)
		}
	}

	for _, tc := range []struct {
		ip   string
		want int
	}{{"192.0.2.20", 1}, {"192.0.2.5", 0}} {
		line := strings.Replace(modsecAuditTemplate3015, `"client_ip":"203.0.113.10"`, `"client_ip":"`+tc.ip+`"`, 1)
		c.handleModSecLine(ctx, line, time.Now())
		waf.mu.RLock()
		got := len(waf.ipEvents[tc.ip])
		waf.mu.RUnlock()
		if got != tc.want {
			t.Errorf("WAF auto-ban events of %s = %d, want %d", tc.ip, got, tc.want)
		}
	}
}
