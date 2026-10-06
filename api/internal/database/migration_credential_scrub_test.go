package database

import (
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/redact"
)

// The upgrade that scrubs credentials older versions stored runs
// redact.ShapesPattern in PostgreSQL. The executable copy in `upgrades` must
// carry the exact string the Go side redacts with, or a row written before the
// fix and a row written after it would be cleaned differently, and the
// documentation in 001_init.sql must be that block, line for line.
func TestCredentialScrubUpgradeUsesTheRedactPattern(t *testing.T) {
	want := "shapes CONSTANT text := '" + redact.ShapesPattern + "';"

	var scrubs []string
	for _, sql := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(sql, "shapes CONSTANT text") {
			scrubs = append(scrubs, sql)
		}
	}
	if len(scrubs) != 1 {
		t.Fatalf("found %d credential scrub(s) in upgrades, want 1", len(scrubs))
	}
	if !strings.Contains(scrubs[0], want) {
		t.Errorf("the credential scrub in upgrades does not use redact.ShapesPattern; want it to contain\n%s", want)
	}

	documented := "--   " + strings.ReplaceAll(scrubs[0], "\n", "\n--   ") + ";"
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))
	if !strings.Contains(initSQL, documented) {
		t.Errorf("the 001_init.sql UPGRADE SECTION does not document the credential scrub as it runs; want it to contain\n%s", documented)
	}
}
