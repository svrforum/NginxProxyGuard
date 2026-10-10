package repository

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// createLogsTable creates logs_partitioned in schema from the DDL a fresh
// install runs, with the three enums it uses and a default partition for the
// rows to land in.
func createLogsTable(t *testing.T, db *sql.DB, schema string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	ddl := string(b)
	var stmts []string
	for _, typ := range []string{"block_reason", "log_severity", "log_type"} {
		m := regexp.MustCompile(`(?s)CREATE TYPE public\.` + typ + ` AS ENUM \(.*?\);`).FindString(ddl)
		if m == "" {
			t.Fatalf("no CREATE TYPE for %s in 001_init.sql", typ)
		}
		stmts = append(stmts, strings.ReplaceAll(m, "public.", schema+"."))
	}
	m := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.logs_partitioned \(.*?\n\)\nPARTITION BY RANGE \(created_at\);`).FindString(ddl)
	if m == "" {
		t.Fatal("no CREATE TABLE for logs_partitioned in 001_init.sql")
	}
	stmts = append(stmts,
		strings.ReplaceAll(m, "public.", schema+"."),
		`CREATE TABLE `+schema+`.logs_partitioned_default PARTITION OF `+schema+`.logs_partitioned DEFAULT`)
	mustExec(t, db, stmts...)
}

// POST /logs inserts through LogRepository.Create. Its INSERT left out
// block_reason, bot_category and exploit_rule, so a manual entry lost them
// (#325). And every entry ValidateCreateLogRequest lets through must be one
// the table stores: anything else is the 500 of #325 again.
func TestLogCreate_StoresWhatTheValidatorAccepts(t *testing.T) {
	db, schema := openSchemaTestDB(t)
	createLogsTable(t, db, schema)
	repo := NewLogRepository(&database.DB{DB: db})
	ctx := context.Background()

	create := func(req model.CreateLogRequest) *model.Log {
		t.Helper()
		if err := model.ValidateCreateLogRequest(&req); err != nil {
			t.Fatalf("%+v refused by the validator: %v", req, err)
		}
		got, err := repo.Create(ctx, &req)
		if err != nil {
			t.Fatalf("%+v refused by the table: %v", req, err)
		}
		return got
	}
	stored := func(id string) (blockReason string, botCategory, exploitRule sql.NullString) {
		t.Helper()
		if err := db.QueryRow(`SELECT block_reason::text, bot_category, exploit_rule FROM logs_partitioned WHERE id = $1`, id).
			Scan(&blockReason, &botCategory, &exploitRule); err != nil {
			t.Fatal(err)
		}
		return
	}

	got := create(model.CreateLogRequest{
		LogType: model.LogTypeModSec, ClientIP: "192.0.2.10", RuleID: 942100,
		BlockReason: model.BlockReasonWAF, BotCategory: "bad_bot", ExploitRule: "SQLI-001",
	})
	if got.BlockReason == nil || *got.BlockReason != model.BlockReasonWAF ||
		got.BotCategory == nil || *got.BotCategory != "bad_bot" ||
		got.ExploitRule == nil || *got.ExploitRule != "SQLI-001" {
		t.Errorf("response: block_reason %v, bot_category %v, exploit_rule %v; want waf, bad_bot, SQLI-001",
			got.BlockReason, got.BotCategory, got.ExploitRule)
	}
	if br, bc, er := stored(got.ID); br != "waf" || bc.String != "bad_bot" || er.String != "SQLI-001" {
		t.Errorf("stored: block_reason %q, bot_category %v, exploit_rule %v; want waf, bad_bot, SQLI-001", br, bc, er)
	}

	// Without one, block_reason is "none", as the log collector stores it.
	got = create(model.CreateLogRequest{LogType: model.LogTypeAccess, StatusCode: 200})
	if br, bc, er := stored(got.ID); br != "none" || bc.Valid || er.Valid {
		t.Errorf("stored: block_reason %q, bot_category %v, exploit_rule %v; want none, NULL, NULL", br, bc, er)
	}

	// The edges of every check, and every value of every enum.
	reqs := []model.CreateLogRequest{
		{LogType: model.LogTypeAccess, StatusCode: 100},
		{LogType: model.LogTypeAccess, StatusCode: 599},
		{LogType: model.LogTypeAccess, ClientIP: "2001:db8::1"},
		{LogType: model.LogTypeAccess, ClientIP: "::ffff:192.0.2.1"},
		{LogType: model.LogTypeAccess, ProxyHostID: "6BA7B810-9DAD-11D1-80B4-00C04FD430C8"},
		{LogType: model.LogTypeAccess, GeoCountryCode: "한국"},
		{LogType: model.LogTypeModSec, ExploitRule: strings.Repeat("규", 50)},
	}
	for _, v := range model.LogTypes {
		reqs = append(reqs, model.CreateLogRequest{LogType: model.LogType(v)})
	}
	for _, v := range model.LogSeverities {
		reqs = append(reqs, model.CreateLogRequest{LogType: model.LogTypeError, Severity: model.LogSeverity(v)})
	}
	for _, v := range model.BlockReasons {
		reqs = append(reqs, model.CreateLogRequest{LogType: model.LogTypeAccess, BlockReason: model.BlockReason(v)})
	}
	for _, req := range reqs {
		create(req)
	}
}
