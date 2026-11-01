package database

import (
	"regexp"
	"strings"
	"testing"
)

// The initial schema and its executable upgrade section must both create
// the same durable checkpoint as the existing-install Go migration.
func TestTrafficHourlyBackfillSchemaSync(t *testing.T) {
	const prefix = "CREATE TABLE IF NOT EXISTS public.traffic_hourly_backfill ("
	var want string
	for _, sql := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.HasPrefix(sql, prefix) {
			if want != "" {
				t.Fatal("multiple traffic_hourly_backfill definitions in migration.go")
			}
			want = sql
		}
	}
	if want == "" {
		t.Fatal("missing traffic_hourly_backfill definition in migration.go")
	}
	initSQL := mustReadFile(t, "migrations/001_init.sql")
	sections := strings.SplitN(initSQL, "-- UPGRADE SECTION", 2)
	if len(sections) != 2 {
		t.Fatal("missing UPGRADE SECTION in 001_init.sql")
	}
	normalize := func(sql string) string {
		return strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(sql), ";")), " ")
	}
	definition := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(prefix) + `.*?;`)
	for i, name := range []string{"initial schema", "upgrade section"} {
		t.Run(name, func(t *testing.T) {
			matches := definition.FindAllString(stripLineComments(sections[i]), -1)
			if len(matches) != 1 {
				t.Fatalf("got %d traffic_hourly_backfill definitions, want 1", len(matches))
			}
			if got := normalize(matches[0]); got != normalize(want) {
				t.Errorf("checkpoint schema differs from migration.go:\ngot  %s\nwant %s", got, normalize(want))
			}
		})
	}
}
