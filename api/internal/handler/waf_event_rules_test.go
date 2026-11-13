package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// eventRules runs GetEventRules for one stored raw_log value.
func eventRules(t *testing.T, rawLog string) wafEventRulesResponse {
	t.Helper()
	const logID = "00000000-0000-4000-8000-0000000000e1"
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// No host and no proxy_host_id: the handler then needs no exclusion lookup.
	mock.ExpectQuery(`FROM logs_partitioned`).WithArgs(logID, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"raw_log", "host", "proxy_host_id"}).AddRow(rawLog, nil, nil))

	dbw := &database.DB{DB: db}
	h := NewWAFHandler(repository.NewWAFRepository(dbw), repository.NewProxyHostRepository(dbw), nil, nil, nil, repository.NewLogRepository(dbw))
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/api/v1/waf/events/"+logID+"/rules?at="+at.Format(time.RFC3339Nano), nil), rec)
	c.SetParamNames("logId")
	c.SetParamValues(logID)
	if err := h.GetEventRules(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GetEventRules: %d %s", rec.Code, rec.Body.String())
	}
	var resp wafEventRulesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	return resp
}

// A modsec row stored before the trimmed format holds ModSecurity's full
// record; a newer row holds the trimmed copy. The event panel must list the
// same rules for both (a rule's data is only cut past 1024 characters).
func TestGetEventRules_ReadsFullAndTrimmedRowsAlike(t *testing.T) {
	checked := 0
	for _, name := range []string{"modsec_audit_v3.0.15_legacy_parts.json", "modsec_audit_fake_credentials.json", "modsec_audit_v3.0.15.json"} {
		b, err := os.ReadFile(filepath.Join("..", "service", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(b, &entries); err != nil {
			t.Fatal(err)
		}
		for i, e := range entries {
			var line bytes.Buffer
			if err := json.Compact(&line, e); err != nil {
				t.Fatal(err)
			}
			var probe service.ModSecAuditLog
			if err := json.Unmarshal(line.Bytes(), &probe); err != nil {
				t.Fatal(err)
			}
			if len(probe.Transaction.Messages) == 0 {
				continue // never stored as a WAF event
			}
			trimmed, changed := service.TrimStoredModSecRawLog(line.String())
			if !changed {
				t.Fatalf("%s #%d: not trimmed", name, i)
			}

			full, short := eventRules(t, line.String()), eventRules(t, trimmed)
			if len(full.Rules) == 0 {
				t.Fatalf("%s #%d: no rules from the full record", name, i)
			}
			for j := range full.Rules {
				if d := full.Rules[j].Data; len([]rune(d)) > 1024 {
					full.Rules[j].Data = string([]rune(d)[:1024]) + "…"
				}
			}
			if !reflect.DeepEqual(full, short) {
				t.Errorf("%s #%d: rules differ\nfull    %+v\ntrimmed %+v", name, i, full, short)
			}
			if strings.Contains(trimmed, "example-session-0000") {
				t.Errorf("%s #%d: credential left in the trimmed row", name, i)
			}
			checked++
		}
	}
	if checked < 9 {
		t.Fatalf("only %d events compared", checked)
	}
}

// A row stored before WAF events were redacted still holds the request value a
// rule matched; the panel must not show it for a credential.
func TestGetEventRules_HidesStoredCredentials(t *testing.T) {
	raw := `{"transaction":{"messages":[` +
		`{"message":"SQL Injection Attack Detected via libinjection","details":{"ruleId":"942100","data":"Matched Data: s&1c found within ARGS:password: hunter2' or 1=1"}},` +
		`{"message":"Remote Command Execution","details":{"ruleId":"932260","data":"Matched Data: docker found within ARGS:search_keyword: docker-compose"}}]}}`
	resp := eventRules(t, raw)
	if len(resp.Rules) != 2 {
		t.Fatalf("rules = %+v", resp.Rules)
	}
	if got, want := resp.Rules[0].Data, "Matched Data: [redacted] found within ARGS:password: [redacted]"; got != want {
		t.Errorf("credential data = %q, want %q", got, want)
	}
	if got, want := resp.Rules[1].Data, "Matched Data: docker found within ARGS:search_keyword: docker-compose"; got != want {
		t.Errorf("other data = %q, want %q", got, want)
	}
}
