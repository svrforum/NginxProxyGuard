package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// createLogsTable creates logs_partitioned in schema from the DDL a fresh
// install runs, with the three enums it uses, a default partition for the
// rows to land in, and the btree index on host (idx_logs_part_host, on a
// TimescaleDB install idx_logs_ht_host): the one index whose entries grow
// with a value the request sets, and refuse one over 2704 bytes.
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
		`CREATE TABLE `+schema+`.logs_partitioned_default PARTITION OF `+schema+`.logs_partitioned DEFAULT`,
		`CREATE INDEX ON `+schema+`.logs_partitioned USING btree (host)`)
	mustExec(t, db, stmts...)
}

// wideText is n characters of four bytes each, drawn from a fixed seed so
// that compression cannot shrink it: the largest index entry n characters
// can make.
func wideText(n int) string {
	r := rand.New(rand.NewPCG(325, 325))
	var b strings.Builder
	for range n {
		b.WriteRune(rune(0x20000 + r.IntN(0xA6E0))) // CJK Extension B
	}
	return b.String()
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
		{LogType: model.LogTypeAccess, Host: wideText(500)},
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

	// What the host limit keeps out: past the index's 2704 bytes the table
	// refuses the row (54000), which answered 500.
	_, err := db.Exec(`INSERT INTO logs_partitioned (log_type, host) VALUES ('access', $1)`, wideText(700))
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "54000" {
		t.Errorf("a 700-character host: got %v, want the index's 54000 refusal", err)
	}
}

// A timestamp is sent in UTC: RFC 3339 and the JSON decoder take an offset up
// to ±23:59, Postgres only up to ±15:59, and +16:00 or more answered 500. And
// it comes back in the session's time zone (the TZ the operator sets), so each
// one the validator accepts must still be a JSON date in any zone, or the 201
// and every log page holding the row answer with an empty body.
func TestLogCreate_TimestampsReadBackInAnyTimeZone(t *testing.T) {
	db, schema := openSchemaTestDB(t)
	createLogsTable(t, db, schema)
	repo := NewLogRepository(&database.DB{DB: db})
	ctx := context.Background()

	want := map[string]time.Time{}
	for _, s := range []string{
		"2026-10-11T00:00:00+16:00", "2026-10-11T00:00:00+20:00", "2026-10-11T00:00:00-23:59",
		// The ends of the accepted range, as UTC and reached through an offset.
		"0001-01-01T00:00:00.000001Z", "0001-01-01T00:00:00-23:59",
		"9998-12-31T23:59:59.999999Z", "9999-01-01T23:58:59+23:59",
	} {
		var ts time.Time
		if err := json.Unmarshal([]byte(`"`+s+`"`), &ts); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		req := model.CreateLogRequest{LogType: model.LogTypeAccess, Timestamp: ts}
		if err := model.ValidateCreateLogRequest(&req); err != nil {
			t.Fatalf("%s refused by the validator: %v", s, err)
		}
		got, err := repo.Create(ctx, &req)
		if err != nil {
			t.Fatalf("%s refused by the table: %v", s, err)
		}
		if !got.Timestamp.Equal(ts) {
			t.Errorf("%s stored as %s", s, got.Timestamp.Format(time.RFC3339Nano))
		}
		want[got.ID] = ts
	}

	// The operator's zone, the widest offsets in use, the old local mean
	// times furthest from UTC (Manila -15:56:08, Metlakatla +15:13:42), and
	// ±15:59, past any real zone.
	for _, zone := range []string{
		"UTC", "Asia/Seoul", "Pacific/Kiritimati", "Etc/GMT+12",
		"Asia/Manila", "America/Metlakatla", "<+1559>-15:59", "<-1559>+15:59",
	} {
		mustExec(t, db, `SET TIME ZONE '`+zone+`'`)
		page, err := repo.List(ctx, nil, 1, 100)
		if err != nil {
			t.Fatalf("%s: %v", zone, err)
		}
		if _, err := json.Marshal(page.Logs); err != nil {
			t.Errorf("%s: the log page cannot be sent: %v", zone, err)
		}
		if len(page.Logs) != len(want) {
			t.Fatalf("%s: %d rows listed, want %d", zone, len(page.Logs), len(want))
		}
		for _, l := range page.Logs {
			if !l.Timestamp.Equal(want[l.ID]) {
				t.Errorf("%s: read back as %s, want %s", zone,
					l.Timestamp.Format(time.RFC3339Nano), want[l.ID].Format(time.RFC3339Nano))
			}
		}
	}

	// What the year of margin keeps out: a UTC year of 9999, inside what JSON
	// carries, reads back as 10000 at +09:00, and the page cannot be sent.
	if _, err := repo.Create(ctx, &model.CreateLogRequest{
		LogType: model.LogTypeAccess, Timestamp: time.Date(9999, 12, 31, 20, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `SET TIME ZONE 'Asia/Seoul'`)
	page, err := repo.List(ctx, nil, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(page.Logs); err == nil {
		t.Error("a log page holding 9999-12-31T20:00:00Z was sent at +09:00; the margin may no longer be needed")
	}
}
