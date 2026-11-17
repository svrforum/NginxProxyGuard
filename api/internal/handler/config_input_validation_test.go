package handler

// Values written into the generated nginx config are checked when they are
// saved: a value that cannot stay on its line, in its quoted argument or in
// its directive is answered with 400 before anything reaches the database.

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// newMockDB returns a sqlmock database. A statement the test did not expect
// fails, which a handler answers with 500, so a 400 also shows the request
// stopped before the database.
func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	return db, mock
}

// callJSON runs an echo handler on a JSON body with the given path parameters.
func callJSON(t *testing.T, h echo.HandlerFunc, method, body string, params ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
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

// expectRejected asserts a 400 whose message contains each of want.
func expectRejected(t *testing.T, rec *httptest.ResponseRecorder, want ...string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	for _, w := range want {
		if !strings.Contains(body["error"], w) {
			t.Errorf("error %q does not mention %q", body["error"], w)
		}
	}
}

// expectAccepted asserts the request got past validation: it reached the
// mocked database, which refused it.
func expectAccepted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("valid request rejected: %s", rec.Body)
	}
}

var errStop = errors.New("stop after validation")

func TestAccessListWrites_RejectLineBreaksAndBadRules(t *testing.T) {
	cases := []struct{ name, body, field string }{
		{"line break in name", `{"name":"first line\nsecond line"}`, "name"},
		{"line break in description", `{"name":"n","description":"a\r\nb"}`, "description"},
		{"line break in rule description", `{"name":"n","items":[{"directive":"allow","address":"192.0.2.1","description":"a\nb"}]}`, "items[0].description"},
		{"unknown directive", `{"name":"n","items":[{"directive":"permit","address":"192.0.2.1"}]}`, "items[0].directive"},
		{"host name", `{"name":"n","items":[{"directive":"allow","address":"example.com"}]}`, "items[0].address"},
		{"address with a separator", `{"name":"n","items":[{"directive":"allow","address":"192.0.2.1;"}]}`, "items[0].address"},
		{"two addresses", `{"name":"n","items":[{"directive":"allow","address":"192.0.2.1"},{"directive":"deny","address":"192.0.2.2 192.0.2.3"}]}`, "items[1].address"},
	}
	const id = "00000000-0000-0000-0000-000000000001"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t)
			h := NewAccessListHandler(repository.NewAccessListRepository(&database.DB{DB: db}), nil, nil)
			expectRejected(t, callJSON(t, h.Create, http.MethodPost, tc.body), tc.field)
			// An update reads the stored rules first (a rule sent back as it
			// was read keeps what it is), then refuses before writing.
			expectStoredAccessList(mock, id)
			expectRejected(t, callJSON(t, h.Update, http.MethodPut, tc.body, "id", id), tc.field)
		})
	}
}

// expectStoredAccessList expects an update's read of list id, which has no
// rules.
func expectStoredAccessList(mock sqlmock.Sqlmock, id string) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`FROM access_lists WHERE id`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "satisfy_any", "pass_auth", "created_at", "updated_at"}).
			AddRow(id, "n", "", true, false, now, now))
	mock.ExpectQuery(`FROM access_list_items`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`FROM access_list_auth_users`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash"}))
}

func TestAccessListCreate_SavesValidRulesTrimmed(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO access_lists`).
		WithArgs("Office #2", "", true, false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("00000000-0000-0000-0000-0000000000a1"))
	mock.ExpectExec(`INSERT INTO access_list_items`).
		WithArgs("00000000-0000-0000-0000-0000000000a1", "allow", "192.0.2.0/24", "office LAN", 0, nil).
		WillReturnError(errStop)
	mock.ExpectRollback()
	h := NewAccessListHandler(repository.NewAccessListRepository(&database.DB{DB: db}), nil, nil)
	rec := callJSON(t, h.Create, http.MethodPost,
		`{"name":"Office #2","items":[{"directive":"allow","address":" 192.0.2.0/24 ","description":"office LAN"},{"directive":"deny","address":"all"}]}`)
	expectAccepted(t, rec)
}

func newSecurityHandlerForTest(db *sql.DB) *SecurityHandler {
	dbw := &database.DB{DB: db}
	svc := service.NewSecurityService(
		repository.NewRateLimitRepository(db), nil, repository.NewSecurityHeadersRepository(db), nil,
		repository.NewProxyHostRepository(dbw), nil, nil, repository.NewURIBlockRepository(dbw), nil, nil,
	)
	return NewSecurityHandler(svc, nil)
}

func TestBanIP_RejectsReasonWithLineBreak(t *testing.T) {
	db, mock := newMockDB(t)
	h := newSecurityHandlerForTest(db)
	expectRejected(t, callJSON(t, h.BanIP, http.MethodPost, `{"ip_address":"203.0.113.10","reason":"first line\nsecond line"}`), "reason")
	expectRejected(t, callJSON(t, h.BanIP, http.MethodPost, `{"ip_address":"203.0.113.10","reason":"a\rb"}`), "reason")

	mock.ExpectQuery(`banned_ips`).WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.BanIP, http.MethodPost, `{"ip_address":"203.0.113.10","reason":"scanner #3; repeated 404s"}`))
}

func TestSecurityHeaderWrites_RejectValuesThatCannotStayInTheirHeader(t *testing.T) {
	cases := []struct{ name, body, field string }{
		{"unknown frame option", `{"x_frame_options":"ALLOWALL"}`, "x_frame_options"},
		{"unknown referrer policy", `{"referrer_policy":"everything"}`, "referrer_policy"},
		{"line break in csp", `{"content_security_policy":"default-src 'self'\nimg-src *"}`, "content_security_policy"},
		{"double quote in csp", `{"content_security_policy":"default-src \"self\""}`, "content_security_policy"},
		{"line break in permissions policy", `{"permissions_policy":"camera=()\r\nmicrophone=()"}`, "permissions_policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newMockDB(t)
			h := newSecurityHandlerForTest(db)
			expectRejected(t, callJSON(t, h.UpsertSecurityHeaders, http.MethodPut, tc.body, "proxyHostId", "00000000-0000-0000-0000-000000000001"), tc.field)
			expectRejected(t, callJSON(t, h.UpdateGlobalSecurityHeaders, http.MethodPut, tc.body), tc.field)
		})
	}

	db, mock := newMockDB(t)
	h := newSecurityHandlerForTest(db)
	mock.ExpectQuery(`INSERT INTO security_headers`).WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.UpsertSecurityHeaders, http.MethodPut,
		`{"enabled":true,"x_frame_options":"DENY","referrer_policy":"no-referrer","content_security_policy":"default-src 'self'; img-src 'self' data:","permissions_policy":"geolocation=(self \"https://maps.example.com\")"}`,
		"proxyHostId", "00000000-0000-0000-0000-000000000001"))
	// The global default has no repository here, so a valid request fails
	// after validation, with 500.
	expectAccepted(t, callJSON(t, h.UpdateGlobalSecurityHeaders, http.MethodPut,
		`{"enabled":true,"content_security_policy":"default-src 'self'","permissions_policy":"camera=()"}`))
}

func TestURIBlockWrites_RejectPatternsThatAreNotOneToken(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-000000000001"
	cases := []struct{ name, pattern, matchType, description, inError string }{
		{"space in path", "/a b", "prefix", "", "pattern"},
		{"separator in path", "/a;", "exact", "", "pattern"},
		{"brace in regex", `^/\d{2}$`, "regex", "", "pattern"},
		{"comment sign first in regex", `#\.php$`, "regex", "", "pattern"},
		{"quote left open", `"^/a`, "regex", "", "pattern"},
		{"block after the pattern", "/x { return 200; } location /y", "prefix", "", "pattern"},
		{"regex in quotes that does not compile", `"^/a\\"`, "regex", "", "regex"},
		{"path without slash", "wp-admin", "prefix", "", "pattern"},
		{"unknown match type", "/a", "glob", "", "match_type"},
		{"line break in description", "/a", "exact", "first line\nsecond line", "description"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t)
			h := newSecurityHandlerForTest(db)
			rule, _ := json.Marshal(map[string]string{"pattern": tc.pattern, "match_type": tc.matchType, "description": tc.description})
			expectRejected(t, callJSON(t, h.AddURIBlockRule, http.MethodPost, string(rule), "proxyHostId", hostID), tc.inError)
			expectRejected(t, callJSON(t, h.AddGlobalURIBlockRule, http.MethodPost, string(rule)), tc.inError)

			bulk, _ := json.Marshal(map[string]any{"pattern": tc.pattern, "match_type": tc.matchType, "description": tc.description, "host_ids": []string{hostID}})
			expectRejected(t, callJSON(t, h.BulkAddURIBlockRule, http.MethodPost, string(bulk)), tc.inError)

			// Saves of the whole list read the stored rules first; here there
			// are none, so every rule is new and checked.
			list := `{"enabled":true,"rules":[{"pattern":"/ok","match_type":"exact","enabled":true},` + string(rule[:len(rule)-1]) + `,"enabled":true}]}`
			mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WillReturnError(sql.ErrNoRows)
			expectRejected(t, callJSON(t, h.UpsertURIBlock, http.MethodPut, list, "proxyHostId", hostID), "rules[1]", tc.inError)
			mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnError(sql.ErrNoRows)
			expectRejected(t, callJSON(t, h.UpdateGlobalURIBlock, http.MethodPut, list), "rules[1]", tc.inError)
		})
	}
}

func TestURIBlockWrites_AcceptValidRules(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-000000000001"
	db, mock := newMockDB(t)
	h := newSecurityHandlerForTest(db)

	for _, rule := range []string{
		`{"pattern":"/wp-admin","match_type":"prefix"}`,
		`{"pattern":" /.env ","match_type":"exact","description":"Environment file"}`,
		`{"pattern":"\\.(sql|bak|old)$","match_type":"regex"}`,
		// A regex with a quantifier is written in quotes, as nginx needs it;
		// the regex inside them is the one compiled.
		`{"pattern":"\"^/[0-9a-f]{32}\\.php$\"","match_type":"regex"}`,
		`{"pattern":"/a#b","match_type":"prefix"}`,
	} {
		mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WillReturnError(errStop)
		expectAccepted(t, callJSON(t, h.AddURIBlockRule, http.MethodPost, rule, "proxyHostId", hostID))
	}

	// A save of the whole list sends back the rules it was given. A stored
	// rule that an older version accepted is not checked again, so the rest of
	// the list stays editable; a new rule is.
	stored, _ := json.Marshal([]map[string]any{{"id": "r1", "pattern": "wp-login", "match_type": "prefix", "enabled": true}})
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	storedRow := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"id", "proxy_host_id", "enabled", "rules", "exception_ips", "allow_private_ips", "created_at", "updated_at", "exception_hostnames"}).
			AddRow("00000000-0000-0000-0000-0000000000b1", hostID, true, stored, "{}", true, now, now, "{}")
	}
	list := `{"enabled":true,"rules":[{"id":"r1","pattern":"wp-login","match_type":"prefix","enabled":true},{"pattern":"/xmlrpc.php","match_type":"exact","enabled":true}]}`
	mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WillReturnRows(storedRow())
	mock.ExpectQuery(`INSERT INTO uri_blocks`).WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.UpsertURIBlock, http.MethodPut, list, "proxyHostId", hostID))

	changed := `{"enabled":true,"rules":[{"id":"r1","pattern":"wp-login-x","match_type":"prefix","enabled":true}]}`
	mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WillReturnRows(storedRow())
	expectRejected(t, callJSON(t, h.UpsertURIBlock, http.MethodPut, changed, "proxyHostId", hostID), "rules[0]", "pattern")
}

// proxyHostRow is the proxy_hosts row GetByID scans (55 columns, in order),
// for an enabled HTTP host.
func proxyHostRow(id string) []driver.Value {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	return []driver.Value{
		id, "http", "{geo.example.com}", "http", "192.0.2.20", nil, nil, int64(8080),
		"", int64(0), "tcp", false, false, false, int64(0), int64(0), // stream_*
		false, false, false, false, nil, // ssl_*, certificate_id
		false, false, false, "7d", // websocket, cache
		false, "", nil, "", // block_exploits, exceptions, custom_locations, advanced_config
		false, "detection", int64(1), int64(5), false, // waf
		int64(0), int64(0), int64(0), "", "", "", "", // proxy timeouts and buffering
		nil, true, false, "ok", "", // access_list_id, enabled, is_favorite, config_status, config_error
		false, nil, false, nil, "{}", nil, // ddns_*, auth_provider_id, auth_bypass_paths, meta
		now, now, "{}", // created_at, updated_at, tags
	}
}

func TestGeoWrites_RejectEntriesThatAreNotCodesOrAddresses(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-000000000001"
	cases := []struct{ name, body, field string }{
		{"three letters", `{"mode":"blacklist","countries":["KOR"]}`, "countries[0]"},
		{"letter and digit", `{"mode":"blacklist","countries":["KR","A1"]}`, "countries[1]"},
		{"two countries in one entry", `{"mode":"blacklist","countries":["CN|RU"]}`, "countries[0]"},
		{"host name", `{"mode":"blacklist","countries":["CN"],"allowed_ips":["example.com"]}`, "allowed_ips[0]"},
		{"address with a quote", `{"mode":"blacklist","countries":["CN"],"allowed_ips":["192.0.2.10","192.0.2.11\""]}`, "allowed_ips[1]"},
		{"wildcard address", `{"mode":"blacklist","countries":["CN"],"allowed_ips":["192.0.2.*"]}`, "allowed_ips[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t)
			dbw := &database.DB{DB: db}
			h := NewGeoHandler(repository.NewGeoRepository(dbw), repository.NewGlobalGeoRepository(dbw), repository.NewProxyHostRepository(dbw), nil, nil)
			expectRejected(t, callJSON(t, h.UpdateGlobal, http.MethodPut, tc.body), tc.field)
			expectRejected(t, callJSON(t, h.UpdateForProxyHost, http.MethodPut, tc.body, "id", hostID), tc.field)

			row := proxyHostRow(hostID)
			mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(hostID).
				WillReturnRows(sqlmock.NewRows(positionalColumnNames(len(row))).AddRow(row...))
			expectRejected(t, callJSON(t, h.SetForProxyHost, http.MethodPost, tc.body, "id", hostID), tc.field)
		})
	}
}

// Any two letters are a country (XK is not on the picker's list, but the GeoIP
// lookup gives it), saved in upper case; "--" is kept; entries are saved
// normalized (model.NormalizeIPOrCIDR).
func TestGeoWrites_SaveCountriesInUpperCase(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-000000000001"
	db, mock := newMockDB(t)
	dbw := &database.DB{DB: db}
	h := NewGeoHandler(repository.NewGeoRepository(dbw), repository.NewGlobalGeoRepository(dbw), repository.NewProxyHostRepository(dbw), nil, nil)
	body := `{"mode":"whitelist","countries":["KR","us"," xk ","--"],"allowed_ips":["192.0.2.10"," 198.51.100.0/24","2001:db8::/48","::ffff:192.0.2.0/120"]}`
	const countries, allowed = `{"KR","US","XK","--"}`, `{"192.0.2.10","198.51.100.0/24","2001:db8::/48","192.0.2.0/24"}`

	mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`INSERT INTO global_geo_restrictions`).
		WithArgs(false, "whitelist", countries, allowed, true, false, false).
		WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.UpdateGlobal, http.MethodPut, body))

	row := proxyHostRow(hostID)
	mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(hostID).
		WillReturnRows(sqlmock.NewRows(positionalColumnNames(len(row))).AddRow(row...))
	mock.ExpectQuery(`INSERT INTO geo_restrictions`).
		WithArgs(hostID, "whitelist", countries, allowed, true, false, true, false, false).
		WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.SetForProxyHost, http.MethodPost, body, "id", hostID))

	mock.ExpectQuery(`geo_restrictions`).WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.UpdateForProxyHost, http.MethodPut, body, "id", hostID))
}

func positionalColumnNames(n int) []string {
	cols := make([]string, n)
	for i := range cols {
		cols[i] = "c" + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	return cols
}

func TestCloudProviderWrites_RejectRangesThatAreNotNetworks(t *testing.T) {
	for _, bad := range []string{"192.0.2.0/24;", "192.0.2.0/24\n198.51.100.0/24", "example.com", "default"} {
		t.Run(bad, func(t *testing.T) {
			db, _ := newMockDB(t)
			h := NewCloudProviderHandler(repository.NewCloudProviderRepository(db), nil, nil, nil)
			body, _ := json.Marshal(map[string]any{"name": "Custom", "slug": "custom", "region": "other", "ip_ranges": []string{"192.0.2.0/24", bad}})
			expectRejected(t, callJSON(t, h.CreateProvider, http.MethodPost, string(body)), "ip_ranges[1]")
			update, _ := json.Marshal(map[string]any{"ip_ranges": []string{bad}})
			expectRejected(t, callJSON(t, h.UpdateProvider, http.MethodPut, string(update), "slug", "custom"), "ip_ranges[0]")
		})
	}

	db, mock := newMockDB(t)
	h := NewCloudProviderHandler(repository.NewCloudProviderRepository(db), nil, nil, nil)
	mock.ExpectQuery(`INSERT INTO cloud_providers`).
		WithArgs("Custom", "custom", "other", "", `{"192.0.2.0/24","2001:db8::/32"}`, "").
		WillReturnError(errStop)
	expectAccepted(t, callJSON(t, h.CreateProvider, http.MethodPost,
		`{"name":"Custom","slug":"custom","region":"other","ip_ranges":["192.0.2.0/24"," 2001:db8::/32 "]}`))
}

// callHTTP runs a net/http handler on a JSON body at the given path.
func callHTTP(h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// A rule exclusion's description, category and reason are written into
// comments of the ModSecurity file of the host (or of every WAF host), so each
// must be one line, on every path that creates an exclusion.
func TestWAFExclusionWrites_RejectTextThatIsNotOneLine(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-000000000001"
	hostPath := "/api/v1/waf/hosts/" + hostID + "/rules/942100/disable"
	globalPath := "/api/v1/waf/global/rules/942100/disable"
	cases := []struct{ field, body string }{
		{"reason", `{"reason":"first line\nsecond line"}`},
		{"rule_description", `{"rule_description":"SQL Injection\r\nsecond line","scope_type":"uri","scope_value":"/search"}`},
		{"rule_category", `{"rule_category":"SQLI\nsecond line","scope_type":"param","scope_value":"q"}`},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			db, _ := newMockDB(t)
			dbw := &database.DB{DB: db}
			h := NewWAFHandler(repository.NewWAFRepository(dbw), repository.NewProxyHostRepository(dbw), nil, nil, nil, nil)
			expectRejected(t, callHTTP(h.DisableRule, http.MethodPost, hostPath, tc.body), tc.field)
			expectRejected(t, callHTTP(h.DisableGlobalRule, http.MethodPost, globalPath, tc.body), tc.field)
			byHost := `{"host":"waf.example.com","rule_id":942100,` + tc.body[1:]
			expectRejected(t, callHTTP(h.DisableRuleByHost, http.MethodPost, "/api/v1/waf/rules/disable-by-host", byHost), tc.field)
		})
	}

	// One line each: the request gets past the check to the database.
	db, mock := newMockDB(t)
	dbw := &database.DB{DB: db}
	h := NewWAFHandler(repository.NewWAFRepository(dbw), repository.NewProxyHostRepository(dbw), nil, nil, nil, nil)
	body := `{"rule_category":"SQLI","rule_description":"SQL Injection Attack","reason":"false positive on /search","scope_type":"uri","scope_value":"/search"}`
	mock.ExpectQuery(`FROM waf_rule_exclusions`).WillReturnError(errStop)
	expectAccepted(t, callHTTP(h.DisableRule, http.MethodPost, hostPath, body))
	mock.ExpectQuery(`FROM global_waf_rule_exclusions`).WillReturnError(errStop)
	expectAccepted(t, callHTTP(h.DisableGlobalRule, http.MethodPost, globalPath, body))
	mock.ExpectQuery(`FROM proxy_hosts`).WillReturnError(errStop)
	expectAccepted(t, callHTTP(h.DisableRuleByHost, http.MethodPost, "/api/v1/waf/rules/disable-by-host", `{"host":"waf.example.com","rule_id":942100,`+body[1:]))
}
