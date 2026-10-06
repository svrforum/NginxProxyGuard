package service

// A host that inherits the global WAF (waf_use_global=true) stores
// waf_enabled=false, which is what the UI saves for "Inherit", and resolves to
// the enabled global WAF in getHostConfigData. Every regeneration path writes
// its modsec file from that resolved host, so the exclusions have to be fetched
// on the resolved flag too. Gated on the stored one, the file was rewritten
// with "# Exclusions: 0" by the UI's post-save regenerate and by every bulk
// fan-out (certificate renewal, access lists, auth providers, exploit rules);
// only the boot-time SyncAll kept them (#202).

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
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

const inheritingHostID = "00000000-0000-4000-8000-000000000306"

var inheritFixtureTime = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// inheritingHostRow is the proxy_hosts row GetByID scans (55 columns, in order)
// for an enabled HTTP host whose WAF setting is Inherit.
func inheritingHostRow() []driver.Value {
	return []driver.Value{
		inheritingHostID, "http", "{inherit.example.com}", "http", "192.0.2.10", nil, nil, int64(8080),
		"", int64(0), "tcp", false, false, false, int64(0), int64(0), // stream_*
		false, false, false, false, nil, // ssl_*, certificate_id
		false, false, false, "7d", // websocket, cache
		false, "", nil, "", // block_exploits, exceptions, custom_locations, advanced_config
		false, "detection", int64(1), int64(5), true, // waf_enabled (stored), mode, paranoia, threshold, waf_use_global
		int64(0), int64(0), int64(0), "", "", "", "", // proxy timeouts and buffering
		nil, true, false, "ok", "", // access_list_id, enabled, is_favorite, config_status, config_error
		false, nil, false, nil, "{}", nil, // ddns_*, auth_provider_id, auth_bypass_paths, meta
		inheritFixtureTime, inheritFixtureTime, "{}", // created_at, updated_at, tags
	}
}

// positionalColumns names n columns; Scan is positional, so only the count
// matters.
func positionalColumns(n int) []string {
	cols := make([]string, n)
	for i := range cols {
		cols[i] = fmt.Sprintf("c%d", i)
	}
	return cols
}

// newInheritWAFService wires the real nginx Manager (writing into a temp dir,
// nginx -t skipped) to repositories over a mocked database, which answers the
// global WAF and the exclusion queries.
func newInheritWAFService(t *testing.T) (*ProxyHostService, sqlmock.Sqlmock, string) {
	t.Helper()
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
	s := &ProxyHostService{
		repo:          repository.NewProxyHostRepository(dbw),
		wafRepo:       repository.NewWAFRepository(dbw),
		globalWAFRepo: repository.NewGlobalWAFRepository(db),
		nginx:         nginx.NewManager(filepath.Join(root, "conf.d"), filepath.Join(root, "certs")),
	}

	mock.ExpectQuery(`FROM global_waf LIMIT 1`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "enabled", "mode", "paranoia_level", "anomaly_threshold", "created_at", "updated_at"}).
			AddRow("00000000-0000-4000-8000-0000000000aa", true, "blocking", int64(1), int64(5), inheritFixtureTime, inheritFixtureTime))
	mock.ExpectQuery(`FROM waf_rule_exclusions`).WithArgs(inheritingHostID).
		WillReturnRows(sqlmock.NewRows(positionalColumns(10)).
			AddRow("00000000-0000-4000-8000-0000000000bb", inheritingHostID, int64(942100), nil, nil, "false positive", nil, "uri", "/api", inheritFixtureTime))
	mock.ExpectQuery(`FROM global_waf_rule_exclusions`).
		WillReturnRows(sqlmock.NewRows(positionalColumns(8)))
	return s, mock, modsec
}

// expectInheritingHostFetch answers GetByID with the inheriting host.
func expectInheritingHostFetch(mock sqlmock.Sqlmock) {
	row := inheritingHostRow()
	mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(inheritingHostID).
		WillReturnRows(sqlmock.NewRows(positionalColumns(len(row))).AddRow(row...))
}

func assertInheritingHostExclusions(t *testing.T, mock sqlmock.Sqlmock, modsec string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(modsec, "host_"+inheritingHostID+".conf"))
	if err != nil {
		t.Fatalf("modsec file for the inheriting host was not written: %v", err)
	}
	out := string(b)
	// The stored row says detection; the global default says blocking (On).
	if !strings.Contains(out, "# Mode: On") {
		t.Fatalf("modsec file was not written from the resolved (global) WAF settings:\n%s", out)
	}
	if !strings.Contains(out, "# Exclusions: 1") || !strings.Contains(out, "ctl:ruleRemoveById=942100") {
		t.Errorf("the inheriting host lost its WAF exclusion:\n%s", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("exclusions were not read for the inheriting host: %v", err)
	}
}

// RegenerateConfigForHost is what the UI calls after every save
// (POST /proxy-hosts/:id/regenerate).
func TestRegenerateConfigForHostKeepsInheritedWAFExclusions(t *testing.T) {
	s, mock, modsec := newInheritWAFService(t)
	expectInheritingHostFetch(mock)
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := s.RegenerateConfigForHost(context.Background(), inheritingHostID); err != nil {
		t.Fatalf("RegenerateConfigForHost: %v", err)
	}
	assertInheritingHostExclusions(t, mock, modsec)
}

// buildHostRender feeds every bulk fan-out (RegenerateConfigsAtomic).
func TestBulkRegenerationKeepsInheritedWAFExclusions(t *testing.T) {
	s, mock, modsec := newInheritWAFService(t)
	expectInheritingHostFetch(mock)
	if err := s.RegenerateConfigsForHostIDs(context.Background(), []string{inheritingHostID}); err != nil {
		t.Fatalf("RegenerateConfigsForHostIDs: %v", err)
	}
	assertInheritingHostExclusions(t, mock, modsec)
}

// Update regenerates the host after saving it (with a nil request, without
// saving), and writes the modsec file from the resolved host as well.
func TestUpdateKeepsInheritedWAFExclusions(t *testing.T) {
	s, mock, modsec := newInheritWAFService(t)
	expectInheritingHostFetch(mock)
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := s.Update(context.Background(), inheritingHostID, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertInheritingHostExclusions(t, mock, modsec)
}

// Create writes the first modsec file of a host saved as Inherit. The exclusion
// the mock returns stands in for any that getMergedWAFExclusions finds (a new
// host gets the global ones); what matters is that they are fetched at all.
func TestCreateKeepsInheritedWAFExclusions(t *testing.T) {
	s, mock, modsec := newInheritWAFService(t)
	mock.ExpectQuery(`SELECT DISTINCT d`).WillReturnRows(sqlmock.NewRows([]string{"d"}))
	row := inheritingHostRow()
	mock.ExpectQuery(`INSERT INTO proxy_hosts`).
		WillReturnRows(sqlmock.NewRows(positionalColumns(len(row))).AddRow(row...))
	req := &model.CreateProxyHostRequest{
		ProxyType: "http", DomainNames: []string{"inherit.example.com"}, ForwardScheme: "http",
		ForwardHost: "192.0.2.10", ForwardPort: 8080, Enabled: true, WAFUseGlobal: true,
	}
	if _, err := s.Create(context.Background(), req); err != nil {
		t.Fatalf("Create: %v", err)
	}
	assertInheritingHostExclusions(t, mock, modsec)
}
