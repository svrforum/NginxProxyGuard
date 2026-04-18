# Log Query Memory Optimization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix memory exhaustion (SWAP 100%) caused by unbounded log queries, missing cleanup schedulers, and excessive DB polling — GitHub Issue #96.

**Architecture:** Apply server-side default time bounds to all stats queries, convert unbounded INSERTs to UPSERTs with cleanup, increase cache TTL to decouple from UI polling, and add missing partition creation for current month.

**Tech Stack:** Go 1.24 (backend changes only), PostgreSQL/TimescaleDB

---

### Task 1: Add Default Time Bound to Stats Queries

**Problem:** `GetStatsWithFilter` runs 7 parallel full-table-scan aggregations when no `start_time` is provided. The current 7-day default only applies when `filter.Search` is non-empty.

**Files:**
- Modify: `api/internal/handler/log.go:152-156`

- [ ] **Step 1: Move the default time range to apply unconditionally**

In `parseLogFilter`, change the default time range logic so it applies to ALL requests without a `start_time`, not just search requests:

```go
// Replace lines 151-156 with:
// Default time range: always apply a 24-hour window when no start_time specified
// to prevent full table scans on large datasets (GitHub Issue #96)
if filter.StartTime == nil {
    defaultStart := time.Now().Add(-24 * time.Hour)
    filter.StartTime = &defaultStart
}
```

This ensures `/api/v1/logs/stats` (called by `GetStats` handler at line 248) and `/api/v1/logs` (called by `List` handler at line 178) both get a bounded time range. The UI already sends `start_time`/`end_time` from `getDefaultDateRange()` (~48h window), so this only catches edge cases where the UI filter is empty.

- [ ] **Step 2: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 2: Increase Stats Cache TTL

**Problem:** `statsCacheTTL = 30s` exactly matches the UI auto-refresh interval (30s), causing cache misses on every poll. Each miss triggers 7 parallel aggregate queries.

**Files:**
- Modify: `api/internal/repository/log.go:21`

- [ ] **Step 1: Increase cache TTL to 2 minutes**

```go
// Replace line 21:
const statsCacheTTL = 2 * time.Minute
```

The UI polls every 30s, but with a 2-minute TTL the expensive 7-query computation runs at most once per 2 minutes instead of every 30 seconds. This is a 4x reduction in DB load. Stats are inherently approximate, so a 2-minute staleness window is acceptable.

- [ ] **Step 2: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 3: Convert StatsCollector INSERT to UPSERT + Add system_health Cleanup

**Problem 1:** `stats_collector.go:524` does a plain `INSERT INTO dashboard_stats_hourly` every 30s, creating duplicate rows. Should be UPSERT like `RecordHourlyStats` (dashboard.go:606).

**Problem 2:** `system_health` gets a new row every 30s (2,880/day) with no cleanup. `CleanupOldStats()` at `dashboard.go:692` exists but is never called.

**Files:**
- Modify: `api/internal/service/stats_collector.go:523-533`
- Modify: `api/internal/service/stats_collector.go:491-505`

- [ ] **Step 1: Convert dashboard_stats_hourly INSERT to UPSERT**

Replace lines 523-533 in `stats_collector.go`:

```go
	// Upsert hourly stats (global, not per proxy host)
	// Use ON CONFLICT to accumulate stats within the same hour bucket
	_, err = sc.db.Exec(`
		INSERT INTO dashboard_stats_hourly (
			proxy_host_id, hour_bucket, total_requests,
			status_2xx, status_3xx, status_4xx, status_5xx,
			avg_response_time, bytes_sent,
			waf_blocked, rate_limited, bot_blocked
		) VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, 0, 0, 0)
		ON CONFLICT (proxy_host_id, hour_bucket) DO UPDATE SET
			total_requests = dashboard_stats_hourly.total_requests + EXCLUDED.total_requests,
			status_2xx = dashboard_stats_hourly.status_2xx + EXCLUDED.status_2xx,
			status_3xx = dashboard_stats_hourly.status_3xx + EXCLUDED.status_3xx,
			status_4xx = dashboard_stats_hourly.status_4xx + EXCLUDED.status_4xx,
			status_5xx = dashboard_stats_hourly.status_5xx + EXCLUDED.status_5xx,
			bytes_sent = dashboard_stats_hourly.bytes_sent + EXCLUDED.bytes_sent
	`, hourBucket, stats.TotalRequests,
		stats.Status2xx, stats.Status3xx, stats.Status4xx, stats.Status5xx,
		avgResponseTime, stats.TotalBytes)
```

- [ ] **Step 2: Add system_health cleanup after INSERT**

After the system_health INSERT block (after line 510), add cleanup:

```go
	// Cleanup old system_health records (keep last 24 hours)
	sc.db.ExecContext(ctx, `DELETE FROM system_health WHERE recorded_at < NOW() - INTERVAL '24 hours'`)
```

- [ ] **Step 3: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 4: Wire CleanupOldStats into PartitionScheduler

**Problem:** `DashboardRepository.CleanupOldStats()` is defined but never called. `dashboard_stats_hourly` and `dashboard_stats_daily` grow without bound.

**Files:**
- Modify: `api/internal/scheduler/partition.go:14-19` (add dashboardRepo field)
- Modify: `api/internal/scheduler/partition.go:22-33` (add constructor param)
- Modify: `api/internal/scheduler/partition.go:78-82` (add cleanup call in run())
- Modify: `api/cmd/server/main.go` (pass dashboardRepo to PartitionScheduler)

- [ ] **Step 1: Add dashboardRepo to PartitionScheduler struct**

Update the struct and constructor in `partition.go`:

```go
type PartitionScheduler struct {
	db                 *sql.DB
	systemSettingsRepo *repository.SystemSettingsRepository
	systemLogRepo      *repository.SystemLogRepository
	dashboardRepo      *repository.DashboardRepository
	interval           time.Duration
	stopCh             chan struct{}
}

func NewPartitionScheduler(
	db *sql.DB,
	systemSettingsRepo *repository.SystemSettingsRepository,
	systemLogRepo *repository.SystemLogRepository,
	dashboardRepo *repository.DashboardRepository,
) *PartitionScheduler {
	return &PartitionScheduler{
		db:                 db,
		systemSettingsRepo: systemSettingsRepo,
		systemLogRepo:      systemLogRepo,
		dashboardRepo:      dashboardRepo,
		interval:           24 * time.Hour,
		stopCh:             make(chan struct{}),
	}
}
```

- [ ] **Step 2: Add cleanupDashboardStats method and call in run()**

Add to `partition.go` after the `cleanupLogsTable` method:

```go
// cleanupDashboardStats removes old dashboard stats to prevent unbounded growth
func (s *PartitionScheduler) cleanupDashboardStats() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	settings, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to get settings for stats cleanup: %v", err)
		return
	}

	// Hourly stats: keep based on stats retention (default 90 days)
	// Daily stats: keep 2x the hourly retention
	hourlyRetention := settings.StatsRetentionDays
	if hourlyRetention <= 0 {
		hourlyRetention = 90
	}
	dailyRetention := hourlyRetention * 2
	if dailyRetention <= 0 {
		dailyRetention = 180
	}

	if err := s.dashboardRepo.CleanupOldStats(ctx, hourlyRetention, dailyRetention); err != nil {
		log.Printf("[PartitionScheduler] Failed to cleanup dashboard stats: %v", err)
	} else {
		log.Printf("[PartitionScheduler] Dashboard stats cleanup completed (hourly: %d days, daily: %d days)", hourlyRetention, dailyRetention)
	}
}
```

Update `run()` method:

```go
func (s *PartitionScheduler) run() {
	s.createPartitions()
	s.enforceRetention()
	s.cleanupLogsTable()
	s.cleanupDashboardStats()
}
```

- [ ] **Step 3: Update main.go to pass dashboardRepo**

Find the `NewPartitionScheduler` call in `main.go` and add the `dashboardRepo` argument. Need to read main.go to find exact location.

- [ ] **Step 4: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 5: Optimize Dashboard Direct Scans

**Problem:** `dashboard.go` GetSummary always runs expensive direct queries on `logs_partitioned` (lines 84-105): `COUNT(*)` with FILTER and `COUNT(DISTINCT client_ip)`. These fire every 30s from the dashboard.

**Files:**
- Modify: `api/internal/repository/dashboard.go:84-105`

- [ ] **Step 1: Make the blocked requests query conditional (only when stats are zero)**

Wrap the two always-on direct scan queries (lines 84-105) in a conditional, similar to the WAF fallback pattern at line 68:

```go
	// Blocked requests stats - only fall back to logs_partitioned when hourly stats are incomplete
	if summary.TotalRequests24h == 0 {
		row = r.db.QueryRowContext(ctx, `
			SELECT
				COUNT(*) FILTER (WHERE status_code = 403 OR log_type = 'modsec'),
				COUNT(*) FILTER (WHERE log_type = 'access')
			FROM logs_partitioned
			WHERE created_at >= $1
		`, last24h)
		var totalAccessFromLogs int64
		row.Scan(&summary.BlockedRequests24h, &totalAccessFromLogs)
		if totalAccessFromLogs > summary.TotalRequests24h {
			summary.TotalRequests24h = totalAccessFromLogs
		}
	} else {
		// Estimate blocked requests from error stats
		summary.BlockedRequests24h = summary.WAFBlocked24h + summary.RateLimited24h + summary.BotBlocked24h
	}

	// Blocked unique IPs - only query when we have blocked requests to count
	if summary.BlockedRequests24h > 0 {
		r.db.QueryRowContext(ctx, `
			SELECT COUNT(DISTINCT client_ip)
			FROM logs_partitioned
			WHERE created_at >= $1
			  AND (status_code = 403 OR log_type = 'modsec')
		`, last24h).Scan(&summary.BlockedUniqueIPs24h)
	}
```

- [ ] **Step 2: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 6: Add Autocomplete Query Time Bounds

**Problem:** Autocomplete queries (`GetDistinctHosts`, `GetDistinctIPs`, etc.) use `SELECT DISTINCT` over 30 days of `logs_partitioned` without supporting indexes. Reduce to 7 days.

**Files:**
- Modify: `api/internal/repository/log.go` — lines 1313, 1369, 1424, 1471, 1525, 1573

- [ ] **Step 1: Change 30-day windows to 7-day windows in all autocomplete queries**

Replace all occurrences of `INTERVAL '30 days'` in the autocomplete functions with `INTERVAL '7 days'`:

- Line 1313: `GetDistinctHosts` — `AND created_at >= NOW() - INTERVAL '7 days'`
- Line 1369: `GetDistinctIPs` — `AND created_at >= NOW() - INTERVAL '7 days'`
- Line 1424: `GetDistinctUserAgents` — `AND created_at >= NOW() - INTERVAL '7 days'`
- Line 1471: `GetDistinctCountries` — `AND created_at >= NOW() - INTERVAL '7 days'`
- Line 1525: `GetDistinctURIs` — `AND created_at >= NOW() - INTERVAL '7 days'`
- Line 1573: `GetDistinctMethods` — `AND created_at >= NOW() - INTERVAL '7 days'`

- [ ] **Step 2: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 7: Add Missing Database Indexes via Migration

**Problem:** `logs_partitioned` queries filter on `created_at`, `client_ip`, `block_reason`, `status_code`, `geo_country_code` but these columns lack indexes. This forces sequential scans on large partitions.

**Files:**
- Modify: `api/internal/database/migrations/001_init.sql` — UPGRADE SECTION at bottom
- Modify: `api/internal/database/migration.go` — `upgradeSQL` variable

- [ ] **Step 1: Add index creation to migration.go upgradeSQL**

Add these index creation statements to the `upgradeSQL` block in `migration.go`:

```sql
-- Performance indexes for log queries (GitHub Issue #96)
CREATE INDEX IF NOT EXISTS idx_logs_partitioned_created_at ON logs_partitioned (created_at);
CREATE INDEX IF NOT EXISTS idx_logs_partitioned_block_reason ON logs_partitioned (block_reason) WHERE block_reason != 'none';
CREATE INDEX IF NOT EXISTS idx_logs_partitioned_status_created ON logs_partitioned (status_code, created_at);
CREATE INDEX IF NOT EXISTS idx_logs_partitioned_geo_country ON logs_partitioned (geo_country_code) WHERE geo_country_code IS NOT NULL AND geo_country_code != '';
```

- [ ] **Step 2: Add same indexes to 001_init.sql UPGRADE SECTION**

Add the same `CREATE INDEX IF NOT EXISTS` statements to the UPGRADE SECTION at the bottom of `001_init.sql`.

- [ ] **Step 3: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 8: Ensure Dynamic Partition Creation for Current Month

**Problem:** `createPartitions()` in `partition.go` was disabled (line 88-91). Only partitions up to `logs_p2026_03` exist in schema. Since April 2026, all data goes to `logs_p_default` which cannot benefit from partition pruning.

**Files:**
- Modify: `api/internal/scheduler/partition.go:84-95`
- Modify: `api/internal/database/migrations/001_init.sql` — add April 2026+ partitions

- [ ] **Step 1: Re-enable dynamic partition creation in partition.go**

Replace the `createPartitions()` method body:

```go
func (s *PartitionScheduler) createPartitions() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Ensure partitions exist for current month and next 2 months
	// This prevents data from falling into logs_p_default
	now := time.Now()
	for i := 0; i < 3; i++ {
		t := now.AddDate(0, i, 0)
		partitionName := fmt.Sprintf("logs_p%d_%02d", t.Year(), t.Month())
		startDate := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate := startDate.AddDate(0, 1, 0)

		query := fmt.Sprintf(`
			DO $$
			BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM pg_tables WHERE tablename = '%s' AND schemaname = 'public'
				) THEN
					EXECUTE format(
						'CREATE TABLE IF NOT EXISTS %s PARTITION OF logs_partitioned FOR VALUES FROM (''%s'') TO (''%s'')',
						'%s',
						'%s'
					);
					RAISE NOTICE 'Created partition: %s';
				END IF;
			END $$;
		`, partitionName,
			partitionName,
			startDate.Format("2006-01-02"), endDate.Format("2006-01-02"),
			partitionName,
			partitionName,
			partitionName)

		_, err := s.db.ExecContext(ctx, query)
		if err != nil {
			log.Printf("[PartitionScheduler] Failed to create partition %s: %v", partitionName, err)
		}
	}

	// Migrate data from default partition to proper partitions if needed
	s.migrateDefaultPartitionData(ctx)

	// Log partition statistics for monitoring
	s.logPartitionStats(ctx)
}
```

- [ ] **Step 2: Add migrateDefaultPartitionData method**

Add after `createPartitions()`:

```go
// migrateDefaultPartitionData moves data from logs_p_default to proper monthly partitions
func (s *PartitionScheduler) migrateDefaultPartitionData(ctx context.Context) {
	// Check if default partition exists and has data
	var exists bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'logs_p_default' AND schemaname = 'public')
	`).Scan(&exists)
	if err != nil || !exists {
		return
	}

	var count int64
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logs_p_default`).Scan(&count)
	if err != nil || count == 0 {
		return
	}

	log.Printf("[PartitionScheduler] Found %d rows in logs_p_default, migrating to proper partitions...", count)

	// Move data in batches using INSERT ... SELECT + DELETE
	// The partition routing will automatically direct rows to the correct partition
	batchSize := 10000
	totalMoved := int64(0)

	for {
		result, err := s.db.ExecContext(ctx, fmt.Sprintf(`
			WITH moved AS (
				DELETE FROM logs_p_default
				WHERE id IN (SELECT id FROM logs_p_default LIMIT %d)
				RETURNING *
			)
			INSERT INTO logs_partitioned SELECT * FROM moved
			ON CONFLICT DO NOTHING
		`, batchSize))
		if err != nil {
			log.Printf("[PartitionScheduler] Error migrating default partition data: %v", err)
			break
		}
		moved, _ := result.RowsAffected()
		totalMoved += moved
		if moved < int64(batchSize) {
			break
		}
		time.Sleep(100 * time.Millisecond) // Reduce DB load
	}

	if totalMoved > 0 {
		log.Printf("[PartitionScheduler] Migrated %d rows from logs_p_default to proper partitions", totalMoved)
	}
}
```

- [ ] **Step 3: Add `fmt` to imports if not present**

Check if `"fmt"` is in the import block of `partition.go`. If not, add it.

- [ ] **Step 4: Add partition definitions to 001_init.sql for new installs**

In the partition definitions section of `001_init.sql`, add partitions for April-December 2026 (following the existing pattern for 2025-12 through 2026-03).

- [ ] **Step 5: Verify build**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds

---

### Task 9: Final Verification

- [ ] **Step 1: Build full stack**

```bash
docker compose -f docker-compose.dev.yml build api
```
Expected: Build succeeds with no errors

- [ ] **Step 2: Run E2E test environment build**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
sudo docker compose -f docker-compose.e2e-test.yml up -d api
```

- [ ] **Step 3: Run relevant E2E tests**

```bash
cd test/e2e && npx playwright test specs/logs/
```

- [ ] **Step 4: Update ARCHITECTURE.md**

Document the new indexes, the re-enabled partition scheduler, and the cleanup changes.

---

## Summary of Changes

| Issue | Fix | Impact |
|-------|-----|--------|
| Stats queries scan full table | Default 24h time bound on all queries | 7 parallel full-table scans eliminated |
| Cache TTL = poll interval (30s) | Cache TTL → 2 minutes | 4x reduction in stats query frequency |
| `dashboard_stats_hourly` unbounded INSERT | Convert to UPSERT with ON CONFLICT | Stops duplicate row accumulation |
| `system_health` unbounded growth | Add cleanup after each INSERT | Keeps table to ~2,880 rows max |
| `CleanupOldStats()` never called | Wire into PartitionScheduler daily run | Hourly/daily stats tables now pruned |
| Dashboard always scans logs_partitioned | Conditional fallback only when stats are zero | Eliminates unnecessary COUNT DISTINCT |
| Autocomplete scans 30 days | Reduce to 7 days | Smaller scan window |
| No indexes on filter columns | Add created_at, block_reason, status+created_at, geo indexes | Index-based lookups instead of seq scans |
| No partitions after 2026-03 | Re-enable dynamic partition creation + data migration | Partition pruning works again |
