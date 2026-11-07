package repository

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The instance name goes into a backup and comes back from it (#369). A
// backup from before the name existed, or one holding a name the API would
// refuse, keeps the name the install has.
func TestBackupCarriesTheInstanceName(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	ddl := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.system_settings \(.*?\n\);`).FindString(string(b))
	if ddl == "" {
		t.Fatal("001_init.sql has no CREATE TABLE for system_settings")
	}
	mustExec(t, db, strings.Replace(ddl, "public.", "", 1),
		`INSERT INTO system_settings DEFAULT VALUES`,
		`UPDATE system_settings SET instance_name = 'home lab'`)

	repo := NewBackupRepository(db)
	ctx := context.Background()
	exported, err := repo.exportSystemSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exported.InstanceName == nil || *exported.InstanceName != "home lab" {
		t.Fatalf("the backup holds instance name %v, want home lab", exported.InstanceName)
	}

	restore := func(name *string) string {
		t.Helper()
		mustExec(t, db, `UPDATE system_settings SET instance_name = 'before restore'`)
		ss := *exported
		ss.InstanceName = name
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := repo.importSystemSettings(ctx, tx, &ss); err != nil {
			t.Fatalf("restore: %v", err)
		}
		var got string
		if err := tx.QueryRowContext(ctx, `SELECT instance_name FROM system_settings`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	homeLab, tooLong, empty := "home lab", strings.Repeat("x", 33), ""
	for _, c := range []struct {
		name *string
		want string
	}{
		{&homeLab, "home lab"},
		{&empty, ""},
		{nil, "before restore"},      // a backup from before the name existed
		{&tooLong, "before restore"}, // a hand-edited backup
	} {
		if got := restore(c.name); got != c.want {
			t.Errorf("restoring %v left %q, want %q", c.name, got, c.want)
		}
	}
}
