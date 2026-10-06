package handler

// A global WAF exclusion is written into the modsec file of every host that
// runs the WAF, including one set to Inherit: it stores waf_enabled=false and
// resolves to the enabled global WAF. Gated on the stored flag, the global
// exclusion never reached such a host (#306).

import (
	"context"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

func TestRegenerateAllHostConfigsReachesInheritingHosts(t *testing.T) {
	const hostID = "00000000-0000-4000-8000-000000000307"
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mock.MatchExpectationsInOrder(false)

	root := t.TempDir()
	modsec := filepath.Join(root, "modsec")
	for _, d := range []string{filepath.Join(root, "conf.d"), filepath.Join(root, "certs"), modsec} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("NGINX_SKIP_TEST", "true")
	t.Setenv("MODSEC_PATH", modsec)

	dbw := &database.DB{DB: db}
	h := NewWAFHandler(repository.NewWAFRepository(dbw), repository.NewProxyHostRepository(dbw), nil,
		repository.NewGlobalWAFRepository(db), nginx.NewManager(filepath.Join(root, "conf.d"), filepath.Join(root, "certs")), nil)

	// The proxy_hosts row List scans (55 columns, in order): an enabled HTTP
	// host whose WAF setting is Inherit.
	row := []driver.Value{
		hostID, "http", "{inherit.example.com}", "http", "192.0.2.11", nil, nil, int64(8080),
		"", int64(0), "tcp", false, false, false, int64(0), int64(0), // stream_*
		false, false, false, false, nil, // ssl_*, certificate_id
		false, false, false, "7d", // websocket, cache
		false, "", nil, "", // block_exploits, exceptions, custom_locations, advanced_config
		false, "detection", int64(1), int64(5), true, // waf_enabled (stored), mode, paranoia, threshold, waf_use_global
		int64(0), int64(0), int64(0), "", "", "", "", // proxy timeouts and buffering
		nil, true, false, "ok", "", // access_list_id, enabled, is_favorite, config_status, config_error
		false, nil, false, nil, "{}", nil, // ddns_*, auth_provider_id, auth_bypass_paths, meta
		now, now, "{}", // created_at, updated_at, tags
	}
	cols := make([]string, len(row))
	for i := range cols {
		cols[i] = fmt.Sprintf("c%d", i)
	}
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM proxy_hosts`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WillReturnRows(sqlmock.NewRows(cols).AddRow(row...))
	mock.ExpectQuery(`FROM global_waf_rule_exclusions`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "rule_id", "rule_category", "rule_description", "reason", "disabled_by", "created_at", "updated_at"}).
			AddRow("00000000-0000-4000-8000-0000000000cc", int64(941100), nil, nil, "false positive", nil, now, now))
	mock.ExpectQuery(`FROM global_waf LIMIT 1`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "enabled", "mode", "paranoia_level", "anomaly_threshold", "created_at", "updated_at"}).
			AddRow("00000000-0000-4000-8000-0000000000aa", true, "blocking", int64(1), int64(5), now, now))
	mock.ExpectQuery(`FROM waf_rule_exclusions`).WithArgs(hostID).
		WillReturnRows(sqlmock.NewRows(cols[:10]))

	if err := h.regenerateAllHostConfigs(context.Background()); err != nil {
		t.Fatalf("regenerateAllHostConfigs: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(modsec, "host_"+hostID+".conf"))
	if err != nil {
		t.Fatalf("modsec file for the inheriting host was not written: %v", err)
	}
	out := string(b)
	// The stored row says detection; the global default says blocking (On).
	if !strings.Contains(out, "# Mode: On") {
		t.Errorf("modsec file was not written from the resolved (global) WAF settings:\n%s", out)
	}
	if !strings.Contains(out, "# Exclusions: 1") || !strings.Contains(out, "SecRuleRemoveById 941100") {
		t.Errorf("the global exclusion did not reach the inheriting host:\n%s", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("queries for the inheriting host were not made: %v", err)
	}
}
