package database

import (
	"regexp"
	"strings"
	"testing"
)

// Seven logs_partitioned btrees are retired. These guards keep them from
// coming back by either route that builds indexes on every boot, keep the
// twin indexes out of the retirement, and keep what the retirement must not
// take: the trigram indexes and every index TimescaleDB derives a sparse index
// from when it compresses a chunk.
func TestRetiredLogsIndexesStayRetired(t *testing.T) {
	retired := map[string]bool{}
	for _, idx := range retiredLogsPartitionedIndexes {
		if idx.Reason == "" {
			t.Errorf("retired index %s has no reason", idx.Name)
		}
		retired[idx.Name] = true
	}
	for _, name := range []string{
		"idx_logs_part_log_type", "idx_logs_part_timestamp", "idx_logs_part_type_timestamp",
		"idx_logs_part_host_ts", "idx_logs_part_status_ts", "idx_logs_part_status_code",
		"idx_logs_part_block_reason_ts",
	} {
		if !retired[name] {
			t.Errorf("%s is no longer retired", name)
		}
	}

	// Not rebuilt by ensureLogsPartitionedIndexes...
	for _, idx := range logsPartitionedIndexes {
		if retired[idx.Name] {
			t.Errorf("%s is retired but still in logsPartitionedIndexes, so every boot would rebuild it", idx.Name)
		}
	}
	// ...nor by an upgrades entry, which also runs on every boot.
	createIndex := regexp.MustCompile(`(?i)CREATE\s+(UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	for _, sql := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		for _, m := range createIndex.FindAllStringSubmatch(sql, -1) {
			if retired[m[4]] {
				t.Errorf("an upgrades entry still creates retired index %s", m[4])
			}
		}
	}

	// The twins. A chunk created after both of a twin pair existed carries
	// one physical index for the pair, so dropping either can leave it with
	// none.
	for name := range retired {
		if strings.HasPrefix(name, "idx_logs_ht_") || name == "logs_hypertable_created_at_idx" {
			t.Errorf("%s must never be retired: it shares physical chunk indexes with its canonical twin", name)
		}
	}

	src := funcSource(t, "migration.go", "retireLogsPartitionedIndexes")
	for _, want := range []string{"SET LOCAL lock_timeout", "indexDefWithoutName", "twins > 0"} {
		if !strings.Contains(src, want) {
			t.Errorf("retireLogsPartitionedIndexes lost %q", want)
		}
	}
	if !strings.Contains(funcSource(t, "migration.go", "ensureLogsPartitionedIndexes"), "db.retireLogsPartitionedIndexes()") {
		t.Error("ensureLogsPartitionedIndexes no longer retires the old indexes")
	}
}

// What stays. Without the trigram indexes URI and User-Agent filters and
// autocomplete searches take seconds instead of milliseconds. TimescaleDB
// derives the bloom and minmax sparse indexes of a compressed chunk from the
// btrees that lead with a column, so each of those columns must keep one.
func TestKeptLogsIndexesStillServeSearchAndCompressedChunks(t *testing.T) {
	kept := map[string]string{}
	for _, idx := range logsPartitionedIndexes {
		kept[idx.Name] = idx.Def
	}
	for _, name := range []string{"idx_logs_part_host_trgm", "idx_logs_part_uri_trgm", "idx_logs_part_ua_trgm", "idx_logs_part_status_created"} {
		if _, ok := kept[name]; !ok {
			t.Errorf("%s must stay in logsPartitionedIndexes", name)
		}
	}
	for _, col := range []string{"client_ip", "status_code", "proxy_host_id", "geo_country_code", "block_reason", "exploit_rule"} {
		found := false
		for _, def := range kept {
			if strings.HasPrefix(def, "USING btree ("+col+",") || strings.HasPrefix(def, "USING btree ("+col+")") {
				found = true
			}
		}
		if !found {
			t.Errorf("no kept btree leads with %s, so compressed chunks would lose its bloom filter", col)
		}
	}
	minmax := false
	for _, def := range kept {
		if strings.HasPrefix(def, "USING btree") && strings.Contains(def, `"timestamp"`) {
			minmax = true
		}
	}
	if !minmax {
		t.Error("no kept btree covers timestamp, so compressed chunks would lose minmax(timestamp)")
	}
}
