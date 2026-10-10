package handler

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
)

// createLog runs LogHandler.Create on one JSON body against a sqlmock database
// that accepts only the statements expect sets up.
func createLog(t *testing.T, body string, expect func(sqlmock.Sqlmock)) *httptest.ResponseRecorder {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if expect != nil {
		expect(mock)
	}
	h := NewLogHandler(repository.NewLogRepository(&database.DB{DB: db}), nil, nil)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/logs", strings.NewReader(body)))
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
	return rec
}

// A value the logs table refuses used to reach Postgres, and its refusal came
// back as 500 "Failed to create log" (#325). Each one is now a 400 that names
// the field, and nothing is sent to the database.
func TestCreateLog_InvalidFieldAnswers400(t *testing.T) {
	const (
		logTypes      = "access, error, modsec"
		severities    = "debug, info, notice, warn, error, crit, alert, emerg"
		blockReasons  = "none, waf, bot_filter, rate_limit, geo_block, exploit_block, banned_ip, uri_block, cloud_provider_challenge, cloud_provider_block, access_denied, filter_subscription"
		longExploitID = "SQLI-0000000000000000000000000000000000000000000001" // 51 characters
	)
	cases := []struct {
		name, body, field, accepted string
	}{
		// The report's steps 1, 4 and 3.
		{"severity outside its enum", `{"log_type":"error","severity":"err"}`, "severity", severities},
		{"log_type outside its enum", `{"log_type":"bogus"}`, "log_type", logTypes},
		{"block_reason outside its enum", `{"log_type":"modsec","rule_id":1,"block_reason":"bogus_reason"}`, "block_reason", blockReasons},
		{"log_type missing", `{"severity":"error"}`, "log_type", logTypes},
		// The other values the INSERT casts or bounds.
		{"client_ip not an address", `{"log_type":"access","client_ip":"not-an-ip"}`, "client_ip", ""},
		{"client_ip a range", `{"log_type":"access","client_ip":"192.0.2.0/24"}`, "client_ip", ""},
		{"proxy_host_id not a uuid", `{"log_type":"access","proxy_host_id":"host-1"}`, "proxy_host_id", ""},
		{"proxy_host_id urn form", `{"log_type":"access","proxy_host_id":"urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8"}`, "proxy_host_id", ""},
		{"status_code past the integer column", `{"log_type":"access","status_code":3000000000}`, "status_code", ""},
		{"status_code not an HTTP status", `{"log_type":"access","status_code":-1}`, "status_code", ""},
		{"geo_country_code past varchar(2)", `{"log_type":"access","geo_country_code":"USA"}`, "geo_country_code", ""},
		{"exploit_rule past varchar(50)", `{"log_type":"modsec","exploit_rule":"` + longExploitID + `"}`, "exploit_rule", ""},
		{"NUL in a text field", `{"log_type":"access","http_user_agent":"a\u0000b"}`, "http_user_agent", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := createLog(t, tc.body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body.String())
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("body is not a JSON error: %v: %s", err, rec.Body.String())
			}
			if !strings.Contains(resp["error"], tc.field) {
				t.Errorf("error %q does not name %s", resp["error"], tc.field)
			}
			if tc.accepted != "" && !strings.Contains(resp["error"], tc.accepted) {
				t.Errorf("error %q does not list the accepted values %q", resp["error"], tc.accepted)
			}
			if strings.HasPrefix(resp["error"], "invalid input") {
				t.Errorf("error %q still carries the sentinel's prefix", resp["error"])
			}
		})
	}
}

// insertedRow is what RETURNING hands back for a stored entry; nil means NULL.
func insertedRow(logType string, set map[string]driver.Value) *sqlmock.Rows {
	cols := []string{
		"id", "log_type", "timestamp", "host", "client_ip",
		"geo_country", "geo_country_code", "geo_city", "geo_asn", "geo_org",
		"request_method", "request_uri", "request_protocol", "status_code",
		"body_bytes_sent", "request_time", "upstream_response_time",
		"upstream_addr", "upstream_status",
		"http_referer", "http_user_agent", "http_x_forwarded_for",
		"severity", "error_message",
		"rule_id", "rule_message", "rule_severity", "rule_data", "attack_type", "action_taken",
		"block_reason", "bot_category", "exploit_rule",
		"proxy_host_id", "raw_log", "created_at",
	}
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	vals := make([]driver.Value, len(cols))
	for i, c := range cols {
		switch c {
		case "id":
			vals[i] = "00000000-0000-4000-8000-000000000325"
		case "log_type":
			vals[i] = logType
		case "timestamp", "created_at":
			vals[i] = now
		case "block_reason":
			vals[i] = "none"
		}
		if v, ok := set[c]; ok {
			vals[i] = v
		}
	}
	return sqlmock.NewRows(cols).AddRow(vals...)
}

// A valid entry is stored and answered 201 — including block_reason,
// bot_category and exploit_rule, which the request and the swagger schema
// always accepted but the INSERT left out, so they were silently dropped.
func TestCreateLog_ValidEntryIsStored(t *testing.T) {
	// The report's control: a severity inside the enum.
	rec := createLog(t, `{"log_type":"error","severity":"error"}`, func(m sqlmock.Sqlmock) {
		args := make([]driver.Value, 34)
		for i := range args {
			args[i] = sqlmock.AnyArg()
		}
		args[0], args[21] = "error", "error"
		m.ExpectQuery(regexp.QuoteMeta("INSERT INTO logs_partitioned")).WithArgs(args...).
			WillReturnRows(insertedRow("error", map[string]driver.Value{"severity": "error"}))
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("control entry: status %d, want 201: %s", rec.Code, rec.Body.String())
	}

	const hostID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	body := `{"log_type":"modsec","client_ip":"2001:db8::7","status_code":403,"rule_id":942100,` +
		`"block_reason":"waf","bot_category":"bad_bot","exploit_rule":"SQLI-001","proxy_host_id":"` + hostID + `"}`
	rec = createLog(t, body, func(m sqlmock.Sqlmock) {
		args := make([]driver.Value, 34)
		for i := range args {
			args[i] = sqlmock.AnyArg()
		}
		args[0], args[3] = "modsec", "2001:db8::7"
		// $30-$33: block_reason, bot_category, exploit_rule, proxy_host_id.
		args[29], args[30], args[31], args[32] = "waf", "bad_bot", "SQLI-001", hostID
		m.ExpectQuery(regexp.QuoteMeta("INSERT INTO logs_partitioned")).WithArgs(args...).
			WillReturnRows(insertedRow("modsec", map[string]driver.Value{
				"client_ip": "2001:db8::7", "status_code": int64(403), "rule_id": int64(942100),
				"block_reason": "waf", "bot_category": "bad_bot", "exploit_rule": "SQLI-001", "proxy_host_id": hostID,
			}))
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("full entry: status %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{
		"log_type": "modsec", "client_ip": "2001:db8::7", "block_reason": "waf",
		"bot_category": "bad_bot", "exploit_rule": "SQLI-001", "proxy_host_id": hostID,
	} {
		if got[field] != want {
			t.Errorf("response %s = %v, want %v", field, got[field], want)
		}
	}
}
