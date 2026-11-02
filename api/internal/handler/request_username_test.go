package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
)

// The exploit rule exclusion handlers are net/http handlers. They read the
// caller from the request context, where nothing put it, so disabled_by was
// always empty. WithUsername carries the auth middleware's username across.
func TestExclusionRecordsWhoDisabledTheRule(t *testing.T) {
	const ruleID = "00000000-0000-0000-0000-000000000347"
	db, mock := newMockDB(t)
	now := time.Now()
	mock.ExpectQuery(`FROM exploit_block_rules\s+WHERE id`).WithArgs(ruleID).WillReturnRows(
		sqlmock.NewRows([]string{"id", "category", "name", "pattern", "pattern_type", "description",
			"severity", "enabled", "is_system", "sort_order", "created_at", "updated_at"}).
			AddRow(ruleID, "sql_injection", "r", "x", "query_string", "", "critical", true, false, 0, now, now))
	mock.ExpectQuery(`INSERT INTO global_exploit_rule_exclusions`).WithArgs(ruleID, nil, "noisy", "alice").WillReturnRows(
		sqlmock.NewRows([]string{"id", "rule_id", "uri_pattern", "reason", "disabled_by", "created_at"}).
			AddRow("00000000-0000-0000-0000-0000000000e1", ruleID, nil, "noisy", "alice", now))
	h := NewExploitBlockRuleHandler(repository.NewExploitBlockRuleRepository(db),
		repository.NewProxyHostRepository(&database.DB{DB: db}), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/exploit-rules/"+ruleID+"/global-exclude",
		strings.NewReader(`{"reason":"noisy"}`))
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set("username", "alice") // what the session and API token middleware set
	if err := WithUsername(h.AddGlobalExclusion)(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
