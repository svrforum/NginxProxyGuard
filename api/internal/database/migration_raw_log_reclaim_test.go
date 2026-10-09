package database

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The raw log reclaim tables are created in two places: the executable end of
// 001_init.sql (a fresh install runs that file once) and an upgrades entry
// (every existing install, on every boot). Two hand-kept copies of a CREATE
// TABLE drift silently — a column added to one only exists on half the
// installs, and CREATE TABLE IF NOT EXISTS never repairs it. This holds them
// equal, executable, free of foreign keys and out of the backups.
var reclaimTables = []string{"raw_log_reclaim_job", "raw_log_reclaim_chunks"}

// createTableStatement returns the CREATE TABLE IF NOT EXISTS statement for
// table in sql, whitespace-normalised, or "" when there is none. Line comments
// are stripped first, so a commented-out copy does not count.
func createTableStatement(sql, table string) string {
	src := stripLineComments(sql)
	head := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.` + table + `\s*\(`)
	loc := head.FindStringIndex(src)
	if loc == nil {
		return ""
	}
	end := strings.Index(src[loc[0]:], ");")
	if end < 0 {
		return ""
	}
	return strings.Join(strings.Fields(src[loc[0]:loc[0]+end+2]), " ")
}

func TestRawLogReclaimTablesAreCreatedIdenticallyOnBothPaths(t *testing.T) {
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))
	banner := regexp.MustCompile(`(?m)^--\s*UPGRADE SECTION`).FindStringIndex(initSQL)
	if banner == nil {
		t.Fatal("001_init.sql has no UPGRADE SECTION banner")
	}
	upgradeSection := initSQL[banner[1]:]

	var upgradesEntry string
	for _, s := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(s, "raw_log_reclaim_job") {
			if upgradesEntry != "" {
				t.Fatal("more than one upgrades entry creates raw_log_reclaim_job")
			}
			upgradesEntry = s
		}
	}
	if upgradesEntry == "" {
		t.Fatal("no upgrades entry creates the raw log reclaim tables: existing installs would never get them")
	}

	for _, table := range reclaimTables {
		fresh := createTableStatement(upgradeSection, table)
		existing := createTableStatement(upgradesEntry, table)
		if fresh == "" {
			t.Errorf("%s: no executable CREATE TABLE IF NOT EXISTS in the 001_init.sql UPGRADE SECTION: fresh installs would not get it", table)
			continue
		}
		if existing == "" {
			t.Errorf("%s: missing from the upgrades entry", table)
			continue
		}
		if fresh != existing {
			t.Errorf("%s differs between the two paths:\n001_init.sql: %s\nupgrades:     %s", table, fresh, existing)
		}
		// Foreign keys would make the order of the fresh-install file matter
		// (see the FK-ordering pitfall); this state needs none.
		if strings.Contains(strings.ToUpper(fresh), "REFERENCES") {
			t.Errorf("%s declares a foreign key", table)
		}
	}
}

// The tables hold the job's progress, not configuration: restoring a backup
// must neither bring back nor wipe a half-finished reclaim.
func TestRawLogReclaimTablesAreNotBackedUp(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "repository", "backup*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no backup sources found (%v)", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "raw_log_reclaim") {
			t.Errorf("%s refers to the raw log reclaim tables; they are operational state and stay out of backups", f)
		}
	}
}
