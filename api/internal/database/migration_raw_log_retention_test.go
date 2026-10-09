package database

import (
	"path/filepath"
	"strings"
	"testing"
)

// The one-time raw log retention handover (marker raw_log_retention_by_days_v1)
// must stay the install-age-bounded rule model.RawLogRetentionHandover
// implements in Go for backup imports, and the 001_init.sql UPGRADE SECTION
// must document the block exactly as it runs.
func TestRawLogRetentionHandoverUpgrade(t *testing.T) {
	var found []string
	for _, sql := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(sql, "raw_log_retention_by_days_v1") {
			found = append(found, sql)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d raw log retention handover(s) in upgrades, want 1", len(found))
	}
	sql := found[0]

	for _, want := range []string{
		// one-time: gated by the marker and recording it in the same block
		"IF EXISTS (SELECT 1 FROM schema_migrations WHERE version = 'raw_log_retention_by_days_v1') THEN",
		"INSERT INTO schema_migrations (version) VALUES ('raw_log_retention_by_days_v1') ON CONFLICT DO NOTHING;",
		// only where the count kept more days, and never past the maximum
		"WHERE raw_log_rotate_count > raw_log_retention_days",
		"AND raw_log_retention_days < 3650",
		// never lowered; bounded by count, install age + 1 and 3650
		"SET raw_log_retention_days = GREATEST(raw_log_retention_days,",
		"LEAST(raw_log_rotate_count,",
		"floor(extract(epoch FROM (now() - created_at)) / 86400)::int + 1,",
		"3650))",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the handover in upgrades no longer contains %q:\n%s", want, sql)
		}
	}

	documented := "--   " + strings.ReplaceAll(sql, "\n", "\n--   ") + ";"
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))
	if !strings.Contains(initSQL, documented) {
		t.Errorf("the 001_init.sql UPGRADE SECTION does not document the raw log retention handover as it runs; want it to contain\n%s", documented)
	}
}
