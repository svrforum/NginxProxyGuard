package database

import (
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/redact"
)

// The upgrade that scrubs credentials stored in WAF events runs
// redact.ModSecSecretVariable in PostgreSQL. The executable copy in `upgrades`
// must carry the exact string new events are redacted with, or a row written
// before the fix and one written after it would be cleaned differently, and
// the documentation in 001_init.sql must be that block, line for line.
func TestModSecSecretScrubUpgradeUsesTheRedactPattern(t *testing.T) {
	want := "secret_var CONSTANT text := '" + redact.ModSecSecretVariable + "';"

	var scrubs []string
	for _, sql := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(sql, "modsec_secret_scrub_v1") {
			scrubs = append(scrubs, sql)
		}
	}
	if len(scrubs) != 1 {
		t.Fatalf("found %d WAF event scrub(s) in upgrades, want 1", len(scrubs))
	}
	if !strings.Contains(scrubs[0], want) {
		t.Errorf("the WAF event scrub in upgrades does not use redact.ModSecSecretVariable; want it to contain\n%s", want)
	}

	documented := "--   " + strings.ReplaceAll(scrubs[0], "\n", "\n--   ") + ";"
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))
	if !strings.Contains(initSQL, documented) {
		t.Errorf("the 001_init.sql UPGRADE SECTION does not document the WAF event scrub as it runs; want it to contain\n%s", documented)
	}
}
