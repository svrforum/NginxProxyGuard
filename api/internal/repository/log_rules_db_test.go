package repository

import (
	"context"
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
)

const (
	logRulesDavHost    = "00000000-0000-4000-8000-000000003471"
	logRulesPlainHost  = "00000000-0000-4000-8000-000000003472"
	logRulesStreamHost = "00000000-0000-4000-8000-000000003473"
)

// The hosts' log rules (#347) on a fresh install's schema: saved and read
// back, listed with every host but a stream host, removed by rules that skip
// nothing, and refused for a host that does not exist.
func TestLogRulesRepository(t *testing.T) {
	db := openBackupTestDB(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO proxy_hosts (id, domain_names, forward_host, forward_port, proxy_type) VALUES
		('`+logRulesDavHost+`', '{dav.example.com}', '192.0.2.10', 80, 'http'),
		('`+logRulesPlainHost+`', '{app.example.com}', '192.0.2.11', 80, 'http'),
		('`+logRulesStreamHost+`', '{stream.example.com}', '192.0.2.12', 22, 'stream')`)
	repo := NewLogRulesRepository(db)

	rules := model.HostLogRules{SkipStatuses: []string{"207"}, SkipMethods: []string{"PROPFIND"}, SkipPaths: []string{"/remote.php/dav/"}}
	saved, err := repo.Set(ctx, logRulesDavHost, rules)
	if err != nil || saved == nil {
		t.Fatalf("set = %+v, %v", saved, err)
	}
	if !reflect.DeepEqual(saved.SkipStatuses, rules.SkipStatuses) || !reflect.DeepEqual(saved.SkipMethods, rules.SkipMethods) ||
		!reflect.DeepEqual(saved.SkipPaths, rules.SkipPaths) || saved.UpdatedAt == nil || saved.DomainNames[0] != "dav.example.com" {
		t.Errorf("saved = %+v", saved)
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ProxyHostID != logRulesPlainHost || list[1].ProxyHostID != logRulesDavHost {
		t.Fatalf("list = %+v, want app.example.com then dav.example.com, no stream host", list)
	}
	if !list[0].IsEmpty() || list[0].UpdatedAt != nil || list[0].SkipPaths == nil {
		t.Errorf("a host without rules = %+v, want empty, non-nil lists and no updated_at", list[0])
	}

	active, err := repo.ListActive(ctx)
	if err != nil || len(active) != 1 || active[0].ProxyHostID != logRulesDavHost {
		t.Fatalf("active = %+v, %v; want the dav host's rules", active, err)
	}

	if cleared, err := repo.Set(ctx, logRulesDavHost, model.HostLogRules{}); err != nil || cleared == nil || !cleared.IsEmpty() {
		t.Errorf("cleared = %+v, %v", cleared, err)
	}
	if active, _ := repo.ListActive(ctx); len(active) != 0 {
		t.Errorf("rules that skip nothing left a row: %+v", active)
	}

	for _, id := range []string{"00000000-0000-4000-8000-00000000ffff", "not-a-uuid", logRulesStreamHost} {
		for _, r := range []model.HostLogRules{rules, {}} {
			if got, err := repo.Set(ctx, id, r); got != nil || err != nil {
				t.Errorf("set %+v on %s = %+v, %v; want no host and no error", r, id, got, err)
			}
		}
		if got, err := repo.Get(ctx, id); got != nil || err != nil {
			t.Errorf("get on %s = %+v, %v; want no host and no error", id, got, err)
		}
	}
	if active, _ := repo.ListActive(ctx); len(active) != 0 {
		t.Errorf("a save for no host or a stream host wrote a row: %+v", active)
	}

	if _, err := db.Exec(`DELETE FROM proxy_hosts WHERE id = $1`, logRulesDavHost); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Set(ctx, logRulesPlainHost, model.HostLogRules{SkipAll: true}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM proxy_host_log_rules WHERE proxy_host_id = $1`, logRulesDavHost).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("a deleted host's rules: %d rows, %v; want them deleted with the host", rows, err)
	}
}

// A backup carries the hosts' log rules (#347) and a restore writes them as
// the API saves them, leaving out an entry the API refuses.
func TestBackupHostLogRulesRoundTrip(t *testing.T) {
	db := openBackupTestDB(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO proxy_hosts (id, domain_names, forward_host, forward_port) VALUES
		('`+logRulesDavHost+`', '{dav.example.com}', '192.0.2.10', 80)`)
	if _, err := NewLogRulesRepository(db).Set(ctx, logRulesDavHost, model.HostLogRules{SkipAll: true, SkipMethods: []string{"PROPFIND"}}); err != nil {
		t.Fatal(err)
	}
	repo := NewBackupRepository(db)
	exported, err := repo.exportHostLogRules(ctx)
	if err != nil || len(exported) != 1 || !exported[0].SkipAll || exported[0].SkipMethods[0] != "PROPFIND" {
		t.Fatalf("export = %+v, %v", exported, err)
	}

	mustExec(t, db, `DELETE FROM proxy_host_log_rules`)
	edited := exported[0]
	edited.SkipStatuses = []string{"207", "not-a-status"}
	edited.SkipPaths = []string{"/dav/../admin", "/dav/"}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.importHostLogRules(ctx, tx, &edited); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := NewLogRulesRepository(db).Get(ctx, logRulesDavHost)
	if err != nil || got == nil {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if !got.SkipAll || !reflect.DeepEqual(got.SkipStatuses, []string{"207"}) || !reflect.DeepEqual(got.SkipPaths, []string{"/dav/"}) ||
		!reflect.DeepEqual(got.SkipMethods, []string{"PROPFIND"}) {
		t.Errorf("restored = %+v", got)
	}
}
