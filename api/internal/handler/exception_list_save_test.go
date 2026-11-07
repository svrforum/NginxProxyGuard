package handler

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// The saves of the four exception lists (#320): URI block exceptions,
// priority allow, rate limit exceptions and the global trusted list. Each
// test drives the real handlers, services and repositories over a mocked
// database, with a fake DNS entry service and an nginx that only records.
// A statement the test did not expect fails the save, so a 200 also shows
// the save wrote nothing it should not have.

const (
	exHostID  = "00000000-0000-4000-8000-0000000005a1"
	exCloneID = "00000000-0000-4000-8000-0000000005a2"
)

var exTime = time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)

// saveLog records, in order and from any goroutine, what the fakes below
// were asked.
type saveLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *saveLog) add(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, fmt.Sprintf(format, args...))
}

func (l *saveLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.calls...)
}

// waitFor waits up to 5 s for call, which a worker the save started logs.
func (l *saveLog) waitFor(t *testing.T, call string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if slices.Contains(l.snapshot(), call) {
			return
		}
	}
	t.Fatalf("no %q; calls %v", call, l.snapshot())
}

// fakeExceptionDNS stands for the DNS entry service. limitErr is what the
// limits answer.
type fakeExceptionDNS struct {
	log      *saveLog
	limitErr error
}

func (f *fakeExceptionDNS) ValidateScopeNames(_ context.Context, scope string, names []string) error {
	f.log.add("limits %s %v", scope, names)
	return f.limitErr
}

func (f *fakeExceptionDNS) SyncScope(_ context.Context, scope string, names []string) error {
	f.log.add("sync %s %v", scope, names)
	return nil
}

func (f *fakeExceptionDNS) SettingsChanged(context.Context, model.DNSEntrySettings, model.DNSEntrySettings) {
}

// hostsNginx is the hosts' nginx. SyncAllConfigs logs "syncall", and the
// regeneration of a disabled host "regen <id>". The NginxManager methods it
// does not define are nil and panic if called.
type hostsNginx struct {
	service.NginxManager
	log *saveLog
}

func (n hostsNginx) RemoveOrphanedHostConfigs(context.Context, func(context.Context) ([]model.ProxyHost, error)) []string {
	n.log.add("syncall")
	return nil
}

func (n hostsNginx) TestConfig(context.Context) error { return nil }

func (n hostsNginx) ReloadNginx(context.Context) error { return nil }

func (n hostsNginx) RemoveConfigAndReload(_ context.Context, host *model.ProxyHost) error {
	n.log.add("regen %s", host.ID)
	return nil
}

// exceptionSave holds the handlers of the four lists over one mocked
// database.
type exceptionSave struct {
	mock     sqlmock.Sqlmock
	log      *saveLog
	dns      *fakeExceptionDNS
	geo      *GeoHandler
	security *SecurityHandler
	settings *SystemSettingsHandler
	hosts    *ProxyHostHandler
}

func newExceptionSave(t *testing.T) *exceptionSave {
	t.Helper()
	db, mock := newMockDB(t)
	dbw := &database.DB{DB: db}
	log := &saveLog{}
	dns := &fakeExceptionDNS{log: log}
	audit := service.NewAuditService(repository.NewAuditLogRepository(db))
	hostRepo := repository.NewProxyHostRepository(dbw)
	geoRepo := repository.NewGeoRepository(dbw)
	rlRepo := repository.NewRateLimitRepository(db)
	ubRepo := repository.NewURIBlockRepository(dbw)
	phs := service.NewProxyHostService(hostRepo, nil, nil, nil, geoRepo, rlRepo, nil, nil, nil, nil, nil, nil, ubRepo,
		nil, nil, nil, nil, nil, hostsNginx{log: log})
	phs.SetDNSEntries(dns)
	sec := service.NewSecurityService(rlRepo, nil, nil, nil, hostRepo, phs, nil, ubRepo, nil, nil)
	sec.SetGlobalRateLimitRepo(repository.NewGlobalRateLimitRepository(db))
	sec.SetDNSEntries(dns)
	geo := NewGeoHandler(geoRepo, repository.NewGlobalGeoRepository(dbw), hostRepo, phs, audit)
	geo.dns = dns
	return &exceptionSave{
		mock: mock, log: log, dns: dns, geo: geo,
		security: NewSecurityHandler(sec, audit),
		settings: &SystemSettingsHandler{repo: repository.NewSystemSettingsRepository(db), audit: audit, proxyHostService: phs, dnsEntries: dns},
		hosts:    NewProxyHostHandler(phs, audit, nil, nil),
	}
}

// expectCalls asserts what the fakes were asked, in order.
func (s *exceptionSave) expectCalls(t *testing.T, want ...string) {
	t.Helper()
	if got := s.log.snapshot(); !reflect.DeepEqual(got, append([]string{}, want...)) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// callAt runs an echo handler on a JSON body sent to target, a path with
// its query.
func callAt(t *testing.T, h echo.HandlerFunc, method, target, body string, params ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	var names, values []string
	for i := 0; i+1 < len(params); i += 2 {
		names = append(names, params[i])
		values = append(values, params[i+1])
	}
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	if err := h(c); err != nil {
		t.Fatalf("handler returned %v", err)
	}
	return rec
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d; body %s", rec.Code, want, rec.Body)
	}
}

// expectFieldError asserts a 400 {error, field, code} whose error starts
// with field and mentions each of says.
func expectFieldError(t *testing.T, rec *httptest.ResponseRecorder, field, code string, says ...string) {
	t.Helper()
	expectStatus(t, rec, http.StatusBadRequest)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %s: %v", rec.Body, err)
	}
	if body["field"] != field || body["code"] != code || !strings.HasPrefix(body["error"], field) {
		t.Errorf("body = %v, want field %q and code %q", body, field, code)
	}
	for _, s := range says {
		if !strings.Contains(body["error"], s) {
			t.Errorf("error %q does not say %q", body["error"], s)
		}
	}
}

// Rows as the repositories read them. pqText is a text[] value as
// PostgreSQL sends it.
func pqText(values ...string) string {
	if len(values) == 0 {
		return "{}"
	}
	v, _ := pq.StringArray(values).Value()
	return v.(string)
}

func rowOf(values ...driver.Value) *sqlmock.Rows {
	return sqlmock.NewRows(positionalColumnNames(len(values))).AddRow(values...)
}

func noRows() *sqlmock.Rows { return sqlmock.NewRows([]string{"id"}) }

func idRow(id string) *sqlmock.Rows { return sqlmock.NewRows([]string{"id"}).AddRow(id) }

// exHostRow is the proxy_hosts row of host id (proxyHostRow, column 42 is
// enabled). A disabled host is regenerated by removing its config, which
// hostsNginx logs.
func exHostRow(id string, enabled bool) *sqlmock.Rows {
	row := proxyHostRow(id)
	row[42] = enabled
	return rowOf(row...)
}

func geoRow(hostID string, allowed []string, names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005c1", hostID, "whitelist", pqText("KR"), pqText(allowed...), true,
		false, true, false, false, exTime, exTime, pqText(names...))
}

func globalGeoRow(allowed []string, names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005d1", true, "whitelist", pqText("KR"), pqText(allowed...),
		true, false, false, exTime, exTime, pqText(names...))
}

func uriBlockRow(hostID string, names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005c2", hostID, true,
		[]byte(`[{"id":"r1","pattern":"/admin","match_type":"prefix","enabled":true}]`), "{}", true, exTime, exTime, pqText(names...))
}

func globalURIBlockRow(names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005d2", true, []byte(`[]`), "{}", true, exTime, exTime, pqText(names...))
}

func rateLimitRow(hostID string, names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005c3", hostID, true, int64(10), int64(20), "10m", "ip", int64(429),
		nil, false, exTime, exTime, pqText(names...))
}

func globalRateLimitRow(names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005d3", true, int64(50), int64(100), "10m", "ip", int64(429),
		nil, exTime, exTime, pqText(names...))
}

// settingsRow is the system_settings row SystemSettingsRepository.Get scans
// (71 columns, in order), with the global trusted list.
// TestExceptionSaveSettingsFixtureReadsBack keeps it in line.
func settingsRow(trustedIPs string, trustedNames ...string) *sqlmock.Rows {
	return rowOf(
		"00000000-0000-4000-8000-0000000005e1", // id
		false, nil, nil, false, "", nil, nil,   // geoip
		false, nil, false, false, int64(30), nil, nil, // acme
		nil, false, int64(30), false, false, // notifications
		int64(30), int64(90), int64(10), false, nil, // log and stats retention, backups
		int64(5), int64(1095), int64(90), int64(30), int64(30), int64(1095), // DDNS interval, log retention
		false, int64(7), int64(100), int64(5), true, false, int64(365), // raw log
		false, true, false, true, false, false, "", // bot filter defaults
		"", "", "", "", // bot lists
		false, int64(10), int64(300), int64(3600), // WAF auto-ban
		trustedIPs, false, pqText(trustedNames...), // global trusted IPs, their WAF bypass, global trusted domains
		"", "none", "X-Forwarded-For", "", "allow", "system", "auto", // trusted proxies .. error page language
		"",                                           // instance name
		true, []byte(`{}`), "{}", "{}", []byte(`{}`), // system logs; DNS entry settings
		exTime, exTime, // created_at, updated_at
	)
}

// namesArg matches a text[] argument that holds exactly these names.
type namesArg []string

func (n namesArg) Match(v driver.Value) bool {
	var a pq.StringArray
	if err := a.Scan(v); err != nil {
		return false
	}
	return slices.Equal([]string(a), []string(n))
}

// detailsArg matches any audit details and keeps them.
type detailsArg struct{ got *map[string]interface{} }

func (d detailsArg) Match(v driver.Value) bool {
	b, ok := v.([]byte)
	return ok && json.Unmarshal(b, d.got) == nil
}

// expectAuditInto expects the audit entry for action and keeps its details
// in got.
func expectAuditInto(mock sqlmock.Sqlmock, action string, got *map[string]interface{}) {
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), action, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), detailsArg{got}, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// expectDNSAudit asserts a dns_entries_changed entry's details.
func expectDNSAudit(t *testing.T, got map[string]interface{}, scope string, added, removed []string) {
	t.Helper()
	want := map[string]interface{}{"scope": scope, "name": scope, "added": toAny(added), "removed": toAny(removed)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dns_entries_changed details = %v, want %v", got, want)
	}
}

func toAny(list []string) []interface{} {
	out := []interface{}{}
	for _, s := range list {
		out = append(out, s)
	}
	return out
}

func TestExceptionSaveSettingsFixtureReadsBack(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("192.0.2.0/24", "partner.example.com"))
	got, err := repository.NewSystemSettingsRepository(db).Get(context.Background())
	if err != nil || got.GlobalTrustedIPs != "192.0.2.0/24" || !slices.Equal(got.GlobalTrustedHostnames, []string{"partner.example.com"}) {
		t.Fatalf("settingsRow no longer reads back; add the repository's new columns to it: %+v, %v", got, err)
	}
}

// The host form saves the geo restriction with skip_reload=true and reloads
// once at the end (C5). The names still reach the DNS entry service, in
// their stored form, before the skip; without the skip the host is
// regenerated after them.
func TestGeoSetForProxyHostSyncsDomainsBeforeTheSkipReloadBranch(t *testing.T) {
	limits := "limits prio:" + exHostID + " [partner.example.com]"
	sync := "sync prio:" + exHostID + " [partner.example.com]"
	for _, tc := range []struct {
		target string
		want   []string
	}{
		{"/?skip_reload=true", []string{limits, sync}},
		{"/", []string{limits, sync, "regen " + exHostID}},
	} {
		t.Run(tc.target, func(t *testing.T) {
			s := newExceptionSave(t)
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
			s.mock.ExpectQuery(`INSERT INTO geo_restrictions`).
				WithArgs(exHostID, "whitelist", pqText("KR"), "{}", true, false, true, false, false, namesArg{"partner.example.com"}).
				WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c1"))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).
				WillReturnRows(geoRow(exHostID, nil, "partner.example.com"))
			if tc.target == "/" {
				s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
				s.mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			expectAudit(s.mock, "geo_restriction_updated")
			expectAudit(s.mock, "dns_entries_changed")

			rec := callAt(t, s.geo.SetForProxyHost, http.MethodPost, tc.target,
				`{"mode":"whitelist","countries":["KR"],"allowed_hostnames":["Partner.Example.com."]}`, "id", exHostID)
			expectStatus(t, rec, http.StatusOK)
			s.expectCalls(t, tc.want...)
		})
	}
}

// The same for the URI block. A regeneration here would read the host
// (the next statement is the handler's read for the audit, an enabled host)
// and then fail on the audit's insert, so the 200 also shows none ran.
func TestUpsertURIBlockSyncsDomainsEvenWhenTheReloadIsSkipped(t *testing.T) {
	s := newExceptionSave(t)
	s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows()) // the handler's
	s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows()) // the service's
	s.mock.ExpectQuery(`INSERT INTO uri_blocks`).
		WithArgs(exHostID, true, sqlmock.AnyArg(), "{}", true, namesArg{"partner.example.com"}).
		WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c2"))
	s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID, "partner.example.com"))
	s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, true))
	expectAudit(s.mock, "uri_block_enabled")
	expectAudit(s.mock, "dns_entries_changed")

	rec := callAt(t, s.security.UpsertURIBlock, http.MethodPut, "/?skip_reload=true",
		`{"enabled":true,"rules":[{"pattern":"/admin","match_type":"prefix","enabled":true}],"exception_hostnames":["PARTNER.example.com"]}`,
		"proxyHostId", exHostID)
	expectStatus(t, rec, http.StatusOK)
	s.expectCalls(t, "limits uri:"+exHostID+" [partner.example.com]", "sync uri:"+exHostID+" [partner.example.com]")
}

// A global list's names reach the DNS entry service before every host is
// regenerated: SyncAllConfigs for uri:global, prio:global and rl:global,
// the background worker for the global trusted list, which a save of the
// names alone starts too.
func TestGlobalSavesSyncDomainsBeforeSyncAll(t *testing.T) {
	const p = "partner.example.com"
	t.Run("uri:global", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(noRows()) // the handler's
		s.mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(noRows()) // the service's
		s.mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(noRows()) // the upsert's
		s.mock.ExpectExec(`INSERT INTO global_uri_blocks`).WithArgs(true, sqlmock.AnyArg(), "{}", true, namesArg{p}).
			WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(globalURIBlockRow(p))
		s.mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(noRows())
		expectAudit(s.mock, "global_uri_block_enabled")
		expectAudit(s.mock, "dns_entries_changed")

		rec := callJSON(t, s.security.UpdateGlobalURIBlock, http.MethodPut, `{"enabled":true,"rules":[],"exception_hostnames":["`+p+`"]}`)
		expectStatus(t, rec, http.StatusOK)
		s.expectCalls(t, "limits uri:global ["+p+"]", "sync uri:global ["+p+"]", "syncall")
	})
	t.Run("prio:global", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(noRows()) // the handler's
		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(noRows()) // the upsert's
		s.mock.ExpectExec(`INSERT INTO global_geo_restrictions`).
			WithArgs(true, "whitelist", pqText("KR"), "{}", true, false, false, namesArg{p}).
			WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow(nil, p))
		s.mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(noRows())
		expectAudit(s.mock, "global_geo_updated")
		expectAudit(s.mock, "dns_entries_changed")

		rec := callJSON(t, s.geo.UpdateGlobal, http.MethodPut, `{"enabled":true,"mode":"whitelist","countries":["KR"],"allowed_hostnames":["`+p+`"]}`)
		expectStatus(t, rec, http.StatusOK)
		s.expectCalls(t, "limits prio:global ["+p+"]", "sync prio:global ["+p+"]", "syncall")
	})
	t.Run("rl:global", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(noRows()) // the handler's
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(noRows()) // the service's
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(noRows()) // the upsert's
		s.mock.ExpectExec(`INSERT INTO global_rate_limits`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), namesArg{p}).
			WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow(p))
		s.mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(noRows())
		expectAudit(s.mock, "global_rate_limit_updated")
		expectAudit(s.mock, "dns_entries_changed")

		rec := callJSON(t, s.security.UpdateGlobalRateLimit, http.MethodPut, `{"enabled":true,"whitelist_hostnames":["`+p+`"]}`)
		expectStatus(t, rec, http.StatusOK)
		s.expectCalls(t, "limits rl:global ["+p+"]", "sync rl:global ["+p+"]", "syncall")
	})
	t.Run("trusted", func(t *testing.T) {
		s := newExceptionSave(t)
		// The worker reads the hosts while the handler writes its audit.
		s.mock.MatchExpectationsInOrder(false)
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("")) // the handler's
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("")) // the update's
		s.mock.ExpectExec(`UPDATE system_settings`).WithArgs(namesArg{p}, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("", p))
		s.mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(noRows())
		expectAudit(s.mock, "dns_entries_changed")
		expectAudit(s.mock, "settings_updated")

		rec := callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, `{"global_trusted_hostnames":["`+p+`"]}`)
		expectStatus(t, rec, http.StatusOK)
		s.log.waitFor(t, "syncall")
		s.expectCalls(t, "limits trusted ["+p+"]", "sync trusted ["+p+"]", "syncall")
	})
}

// A refused name answers 400 with the field by its position in the request
// and the name rule's code, before anything is written or handed on.
func TestExceptionListNameErrorsNameTheField(t *testing.T) {
	const names = `["partner.example.com","bad_name"]`
	for _, tc := range []struct {
		name, field string
		call        func(s *exceptionSave) *httptest.ResponseRecorder
	}{
		{"host URI block", "exception_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.security.UpsertURIBlock, http.MethodPut, `{"exception_hostnames":`+names+`}`, "proxyHostId", exHostID)
		}},
		{"global URI block", "exception_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.security.UpdateGlobalURIBlock, http.MethodPut, `{"exception_hostnames":`+names+`}`)
		}},
		{"host geo, POST", "allowed_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
			return callJSON(t, s.geo.SetForProxyHost, http.MethodPost, `{"mode":"whitelist","countries":["KR"],"allowed_hostnames":`+names+`}`, "id", exHostID)
		}},
		{"host geo, PUT", "allowed_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.geo.UpdateForProxyHost, http.MethodPut, `{"allowed_hostnames":`+names+`}`, "id", exHostID)
		}},
		{"global geo", "allowed_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.geo.UpdateGlobal, http.MethodPut, `{"allowed_hostnames":`+names+`}`)
		}},
		{"host rate limit", "whitelist_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.security.UpsertRateLimit, http.MethodPut, `{"whitelist_hostnames":`+names+`}`, "proxyHostId", exHostID)
		}},
		{"global rate limit", "whitelist_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.security.UpdateGlobalRateLimit, http.MethodPut, `{"whitelist_hostnames":`+names+`}`)
		}},
		{"global trusted list", "global_trusted_hostnames[1]", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
			return callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, `{"global_trusted_hostnames":`+names+`}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newExceptionSave(t)
			expectFieldError(t, tc.call(s), tc.field, "underscore")
			s.expectCalls(t)
		})
	}
}

// A domain name in an IP field is refused with the field that takes it.
func TestIPFieldDomainSaysWhereItGoes(t *testing.T) {
	for _, tc := range []struct {
		name, field, goesIn string
		call                func(s *exceptionSave) *httptest.ResponseRecorder
	}{
		{"host URI block", "exception_ips[1]", "exception_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.security.UpsertURIBlock, http.MethodPut, `{"exception_ips":["192.0.2.1","partner.example.com"]}`, "proxyHostId", exHostID)
		}},
		{"global URI block", "exception_ips[1]", "exception_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			return callJSON(t, s.security.UpdateGlobalURIBlock, http.MethodPut, `{"exception_ips":["192.0.2.1","partner.example.com"]}`)
		}},
		{"host geo", "allowed_ips[1]", "allowed_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
			return callJSON(t, s.geo.SetForProxyHost, http.MethodPost, `{"mode":"whitelist","countries":["KR"],"allowed_ips":["192.0.2.1","partner.example.com"]}`, "id", exHostID)
		}},
		{"global geo", "allowed_ips[1]", "allowed_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(noRows())
			return callJSON(t, s.geo.UpdateGlobal, http.MethodPut, `{"allowed_ips":["192.0.2.1","partner.example.com"]}`)
		}},
		{"host rate limit", "whitelist_ips", "whitelist_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM rate_limits`).WithArgs(exHostID).WillReturnRows(noRows())
			return callJSON(t, s.security.UpsertRateLimit, http.MethodPut, `{"whitelist_ips":"192.0.2.1, partner.example.com"}`, "proxyHostId", exHostID)
		}},
		{"global rate limit", "whitelist_ips", "whitelist_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(noRows())
			return callJSON(t, s.security.UpdateGlobalRateLimit, http.MethodPut, `{"whitelist_ips":"192.0.2.1\npartner.example.com"}`)
		}},
		{"global trusted list", "global_trusted_ips[1]", "global_trusted_hostnames", func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
			return callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, `{"global_trusted_ips":"192.0.2.1\npartner.example.com"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newExceptionSave(t)
			expectFieldError(t, tc.call(s), tc.field, model.CodeHostnameInIPField, "partner.example.com", "a domain name goes in "+tc.goesIn)
			s.expectCalls(t)
		})
	}
}

// A priority allow entry an older version stored (a domain name) passes when
// it is sent back as it was, so the rest of the form stays editable, and is
// saved as it was; a new one is refused.
func TestGeoLegacyNameEntriesPassUnchangedAndNewOnesAreRefused(t *testing.T) {
	stored := []string{"192.0.2.10", "legacy.example.com"}
	const kept = `"allowed_ips":["192.0.2.10","legacy.example.com"]`
	const added = `"allowed_ips":["192.0.2.10","legacy.example.com","new.example.com"]`
	t.Run("host", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, stored))
		s.mock.ExpectQuery(`INSERT INTO geo_restrictions`).
			WithArgs(exHostID, "whitelist", pqText("KR"), namesArg(stored), true, false, true, false, false).
			WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c1"))
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, stored))
		expectAudit(s.mock, "geo_restriction_updated")
		rec := callAt(t, s.geo.SetForProxyHost, http.MethodPost, "/?skip_reload=true", `{"mode":"whitelist","countries":["KR"],`+kept+`}`, "id", exHostID)
		expectStatus(t, rec, http.StatusOK)

		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, stored))
		rec = callAt(t, s.geo.SetForProxyHost, http.MethodPost, "/?skip_reload=true", `{"mode":"whitelist","countries":["KR"],`+added+`}`, "id", exHostID)
		expectFieldError(t, rec, "allowed_ips[2]", model.CodeHostnameInIPField, "allowed_hostnames")
		s.expectCalls(t)
	})
	t.Run("global", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow(stored)) // the handler's
		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow(stored)) // the upsert's
		s.mock.ExpectExec(`UPDATE global_geo_restrictions`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), namesArg(stored), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow(stored))
		s.mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(noRows())
		expectAudit(s.mock, "global_geo_updated")
		expectStatus(t, callJSON(t, s.geo.UpdateGlobal, http.MethodPut, `{`+kept+`}`), http.StatusOK)

		s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow(stored))
		expectFieldError(t, callJSON(t, s.geo.UpdateGlobal, http.MethodPut, `{`+added+`}`), "allowed_ips[2]", model.CodeHostnameInIPField, "allowed_hostnames")
		s.expectCalls(t, "syncall")
	})
}

// The same for the lines of the global trusted list, which was not checked
// before: a stored line sent back passes, a new domain name or a new line
// that is not an address is refused.
func TestTrustedIPLegacyLinesPassUnchangedAndNewOnesAreRefused(t *testing.T) {
	const stored = "# office\n192.0.2.0/24\nlegacy.example.com"
	put := func(s *exceptionSave, text string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"global_trusted_ips": text})
		return callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, string(body))
	}
	s := newExceptionSave(t)
	s.settings.proxyHostService = nil                                              // the background worker has nothing to apply
	s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(stored)) // the handler's
	s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(stored)) // the update's
	s.mock.ExpectExec(`UPDATE system_settings`).WithArgs(stored, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(stored))
	expectAudit(s.mock, "settings_updated")
	expectStatus(t, put(s, stored), http.StatusOK)

	s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(stored))
	expectFieldError(t, put(s, stored+"\nnew.example.com"), "global_trusted_ips[3]", model.CodeHostnameInIPField, "global_trusted_hostnames")
	s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(stored))
	expectFieldError(t, put(s, stored+"\n192.0.2.300"), "global_trusted_ips[3]", "", "not an IP address")
	s.expectCalls(t)
}

// More names than the limits allow is a 400 with code limit, the list's name
// field for the per-list limit, before anything is written or handed on.
func TestExceptionListOverTheDomainLimitIsRefusedBeforeSaving(t *testing.T) {
	const names = `["a.example.com","b.example.com"]`
	perList := &service.DNSLimitError{Field: "items", Limit: 1, Got: 2}
	for _, tc := range []struct {
		name, field, scope string
		limit              *service.DNSLimitError
		call               func(s *exceptionSave) *httptest.ResponseRecorder
	}{
		{"host URI block", "exception_hostnames", "uri:" + exHostID, perList, func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
			return callJSON(t, s.security.UpsertURIBlock, http.MethodPut, `{"exception_hostnames":`+names+`}`, "proxyHostId", exHostID)
		}},
		{"host geo", "allowed_hostnames", "prio:" + exHostID, perList, func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
			return callJSON(t, s.geo.SetForProxyHost, http.MethodPost, `{"mode":"whitelist","countries":["KR"],"allowed_hostnames":`+names+`}`, "id", exHostID)
		}},
		{"global rate limit", "whitelist_hostnames", "rl:global", perList, func(s *exceptionSave) *httptest.ResponseRecorder {
			s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(noRows())
			return callJSON(t, s.security.UpdateGlobalRateLimit, http.MethodPut, `{"whitelist_hostnames":`+names+`}`)
		}},
		{"global trusted list, install total", "dns_entry_settings.max_total", "trusted",
			&service.DNSLimitError{Field: "dns_entry_settings.max_total", Limit: 64, Got: 65}, func(s *exceptionSave) *httptest.ResponseRecorder {
				s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
				return callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, `{"global_trusted_hostnames":`+names+`}`)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newExceptionSave(t)
			s.dns.limitErr = tc.limit
			want := *tc.limit
			want.Field = tc.field
			expectFieldError(t, tc.call(s), tc.field, "limit", want.Error())
			s.expectCalls(t, "limits "+tc.scope+" [a.example.com b.example.com]")
		})
	}
}

// A save of a list that has no names, before and after, leaves the DNS entry
// service alone: no limits, no hand-over, no dns_entries_changed.
func TestSaveWithoutDomainsLeavesTheDNSServiceAlone(t *testing.T) {
	t.Run("host URI block", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
		s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
		s.mock.ExpectQuery(`INSERT INTO uri_blocks`).WithArgs(exHostID, true, sqlmock.AnyArg(), "{}", true, namesArg{}).
			WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c2"))
		s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID))
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, true))
		expectAudit(s.mock, "uri_block_enabled")
		rec := callAt(t, s.security.UpsertURIBlock, http.MethodPut, "/?skip_reload=true",
			`{"enabled":true,"rules":[{"pattern":"/admin","match_type":"prefix","enabled":true}],"exception_hostnames":[]}`, "proxyHostId", exHostID)
		expectStatus(t, rec, http.StatusOK)
		s.expectCalls(t)
	})
	t.Run("host geo", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
		s.mock.ExpectQuery(`INSERT INTO geo_restrictions`).
			WithArgs(exHostID, "whitelist", pqText("KR"), "{}", true, false, true, false, false, namesArg{}).
			WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c1"))
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, nil))
		expectAudit(s.mock, "geo_restriction_updated")
		rec := callAt(t, s.geo.SetForProxyHost, http.MethodPost, "/?skip_reload=true",
			`{"mode":"whitelist","countries":["KR"],"allowed_hostnames":[]}`, "id", exHostID)
		expectStatus(t, rec, http.StatusOK)
		s.expectCalls(t)
	})
	t.Run("global trusted list", func(t *testing.T) {
		s := newExceptionSave(t)
		s.settings.proxyHostService = nil
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
		s.mock.ExpectExec(`UPDATE system_settings`).WithArgs(namesArg{}, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
		expectAudit(s.mock, "settings_updated")
		expectStatus(t, callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, `{"global_trusted_hostnames":[]}`), http.StatusOK)
		s.expectCalls(t)
	})
}

// A save that changes a list's names records dns_entries_changed with the
// list's scope and the names added and removed, next to the save's own
// entry.
func TestDNSEntriesChangedIsAuditedPerScope(t *testing.T) {
	const a, b, c = "a.example.com", "b.example.com", "c.example.com"
	const swap = `["b.example.com","c.example.com"]`
	t.Run("host geo, PUT", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, nil, a, b)) // the handler's
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, nil, a, b)) // the update's
		s.mock.ExpectExec(`UPDATE geo_restrictions SET`).WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, nil, b, c))
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
		s.mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))
		expectAudit(s.mock, "geo_restriction_updated")
		var got map[string]interface{}
		expectAuditInto(s.mock, "dns_entries_changed", &got)

		expectStatus(t, callJSON(t, s.geo.UpdateForProxyHost, http.MethodPut, `{"allowed_hostnames":`+swap+`}`, "id", exHostID), http.StatusOK)
		expectDNSAudit(t, got, "prio:"+exHostID, []string{c}, []string{a})
		s.expectCalls(t, "limits prio:"+exHostID+" [b.example.com c.example.com]", "sync prio:"+exHostID+" [b.example.com c.example.com]", "regen "+exHostID)
	})
	t.Run("host URI block, DELETE", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))      // the audit's name
		s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID, a, b)) // the handler's
		s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false))      // the service's
		s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID, a, b)) // the service's
		s.mock.ExpectExec(`DELETE FROM uri_blocks`).WillReturnResult(sqlmock.NewResult(0, 1))
		expectAudit(s.mock, "uri_block_disabled")
		var got map[string]interface{}
		expectAuditInto(s.mock, "dns_entries_changed", &got)

		expectStatus(t, callJSON(t, s.security.DeleteURIBlock, http.MethodDelete, ``, "proxyHostId", exHostID), http.StatusNoContent)
		expectDNSAudit(t, got, "uri:"+exHostID, nil, []string{a, b})
		s.expectCalls(t, "sync uri:"+exHostID+" []")
	})
	t.Run("global rate limit", func(t *testing.T) {
		s := newExceptionSave(t)
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow(a, b)) // the handler's
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow(a, b)) // the service's
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow(a, b)) // the upsert's
		s.mock.ExpectExec(`UPDATE global_rate_limits`).WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow(b, c))
		s.mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(noRows())
		expectAudit(s.mock, "global_rate_limit_updated")
		var got map[string]interface{}
		expectAuditInto(s.mock, "dns_entries_changed", &got)

		expectStatus(t, callJSON(t, s.security.UpdateGlobalRateLimit, http.MethodPut, `{"whitelist_hostnames":`+swap+`}`), http.StatusOK)
		expectDNSAudit(t, got, "rl:global", []string{c}, []string{a})
	})
	t.Run("global trusted list", func(t *testing.T) {
		s := newExceptionSave(t)
		s.settings.proxyHostService = nil
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("", a, b))
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("", a, b))
		s.mock.ExpectExec(`UPDATE system_settings`).WillReturnResult(sqlmock.NewResult(0, 1))
		s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("", b, c))
		var got map[string]interface{}
		expectAuditInto(s.mock, "dns_entries_changed", &got)
		expectAudit(s.mock, "settings_updated")

		expectStatus(t, callJSON(t, s.settings.UpdateSystemSettings, http.MethodPut, `{"global_trusted_hostnames":`+swap+`}`), http.StatusOK)
		expectDNSAudit(t, got, "trusted", []string{c}, []string{a})
	})
}

// A clone copies the three lists' names, hands each to the DNS entry service
// under the new host's scope, and names them in the clone's audit entry.
func TestCloneCopiesDomainsAndSyncsTheNewScopes(t *testing.T) {
	const prio, rl, uri = "prio.example.com", "rl.example.com", "uri.example.com"
	s := newExceptionSave(t)
	clone := proxyHostRow(exCloneID)
	clone[2], clone[42] = "{copy.example.com}", false
	s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false)) // the handler's
	s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, false)) // the clone's
	for i := 0; i < 2; i++ {                                                                                            // Clone's and Create's duplicate-domain checks
		s.mock.ExpectQuery(`SELECT DISTINCT d`).WillReturnRows(sqlmock.NewRows([]string{"d"}))
	}
	s.mock.ExpectQuery(`INSERT INTO proxy_hosts`).WillReturnRows(rowOf(clone...))
	s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, nil, prio))
	s.mock.ExpectQuery(`INSERT INTO geo_restrictions`).
		WithArgs(exCloneID, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), namesArg{prio}).
		WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c4"))
	s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exCloneID).WillReturnRows(geoRow(exCloneID, nil, prio))
	s.mock.ExpectQuery(`FROM rate_limits`).WithArgs(exHostID).WillReturnRows(rateLimitRow(exHostID, rl))
	s.mock.ExpectQuery(`INSERT INTO rate_limits`).
		WithArgs(exCloneID, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), namesArg{rl}).
		WillReturnRows(rateLimitRow(exCloneID, rl))
	s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID, uri))
	s.mock.ExpectQuery(`INSERT INTO uri_blocks`).
		WithArgs(exCloneID, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), namesArg{uri}).
		WillReturnRows(idRow("00000000-0000-4000-8000-0000000005c5"))
	s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exCloneID).WillReturnRows(uriBlockRow(exCloneID, uri))
	for i := 0; i < 2; i++ { // the clone's names: for the DNS entry service, then for the audit
		s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exCloneID).WillReturnRows(geoRow(exCloneID, nil, prio))
		s.mock.ExpectQuery(`FROM rate_limits`).WithArgs(exCloneID).WillReturnRows(rateLimitRow(exCloneID, rl))
		s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exCloneID).WillReturnRows(uriBlockRow(exCloneID, uri))
		if i == 0 {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exCloneID).WillReturnRows(rowOf(clone...))
		}
	}
	var got map[string]interface{}
	expectAuditInto(s.mock, "proxy_host_cloned", &got)

	expectStatus(t, callJSON(t, s.hosts.Clone, http.MethodPost, `{"domain_names":["copy.example.com"]}`, "id", exHostID), http.StatusCreated)
	s.expectCalls(t,
		"sync prio:"+exCloneID+" ["+prio+"]",
		"sync rl:"+exCloneID+" ["+rl+"]",
		"sync uri:"+exCloneID+" ["+uri+"]")
	want := map[string]interface{}{
		"prio:" + exCloneID: []interface{}{prio},
		"rl:" + exCloneID:   []interface{}{rl},
		"uri:" + exCloneID:  []interface{}{uri},
	}
	if !reflect.DeepEqual(got["dns_names"], want) {
		t.Errorf("the clone's audit dns_names = %v, want %v", got["dns_names"], want)
	}
}

// The global trusted list through the real handler, repository and
// columns: an old version's line passes as it is, the names are stored
// normalized and handed over, a new domain line changes nothing, and
// clearing the names is handed over and audited. Skipped without
// NPG_TEST_DATABASE_URL, as in CI.
func TestTrustedListSaveAgainstTheDatabase(t *testing.T) {
	db := openSystemSettingsDB(t)
	log := &saveLog{}
	h := &SystemSettingsHandler{
		repo:       repository.NewSystemSettingsRepository(db),
		audit:      service.NewAuditService(repository.NewAuditLogRepository(db)),
		dnsEntries: &fakeExceptionDNS{log: log},
	}
	admin := permGrants{"settings:read": true, "settings:write": true}
	put := func(body map[string]interface{}) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		return callWithGrants(t, h.UpdateSystemSettings, admin, http.MethodPut, string(b))
	}
	stored := func() (ips string, names []string) {
		t.Helper()
		if err := db.QueryRow(`SELECT global_trusted_ips, global_trusted_hostnames FROM system_settings`).Scan(&ips, pq.Array(&names)); err != nil {
			t.Fatal(err)
		}
		return ips, names
	}
	expectStatus(t, callWithGrants(t, h.GetSystemSettings, admin, http.MethodGet, ""), http.StatusOK) // creates the row
	const legacy = "# office\n192.0.2.0/24\nlegacy.example.com"
	if _, err := db.Exec(`UPDATE system_settings SET global_trusted_ips = $1`, legacy); err != nil {
		t.Fatal(err)
	}

	expectStatus(t, put(map[string]interface{}{"global_trusted_ips": legacy, "global_trusted_hostnames": []string{"Partner.Example.com.", "partner.example.com"}}), http.StatusOK)
	if ips, names := stored(); ips != legacy || !slices.Equal(names, []string{"partner.example.com"}) {
		t.Fatalf("stored %q and %q, want the old lines and the one name", ips, names)
	}
	expectFieldError(t, put(map[string]interface{}{"global_trusted_ips": legacy + "\nnew.example.com"}), "global_trusted_ips[3]", model.CodeHostnameInIPField)
	if ips, _ := stored(); ips != legacy {
		t.Fatalf("a refused save stored %q", ips)
	}
	expectStatus(t, put(map[string]interface{}{"global_trusted_hostnames": []string{}}), http.StatusOK)
	if _, names := stored(); len(names) != 0 {
		t.Fatalf("names after clearing them: %q", names)
	}

	s := &exceptionSave{log: log}
	s.expectCalls(t, "limits trusted [partner.example.com]", "sync trusted [partner.example.com]", "sync trusted []")
	changes := auditDetailsOf(t, db, "dns_entries_changed")
	want := []map[string]interface{}{
		{"scope": "trusted", "name": "trusted", "added": []interface{}{"partner.example.com"}, "removed": []interface{}{}},
		{"scope": "trusted", "name": "trusted", "added": []interface{}{}, "removed": []interface{}{"partner.example.com"}},
	}
	if len(changes) != 2 || !(reflect.DeepEqual(changes, want) || reflect.DeepEqual(changes, []map[string]interface{}{want[1], want[0]})) {
		t.Errorf("dns_entries_changed entries = %v, want %v", changes, want)
	}
}
