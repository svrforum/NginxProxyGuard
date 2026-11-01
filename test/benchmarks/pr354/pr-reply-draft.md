Draft only — not posted to GitHub.

I have addressed the review items:

1. Top hosts now consistently uses the existing raw-log hostname grouping, keeping aliases separate and including unregistered domains even after host rollups are populated.
2. The hourly stats endpoint returns only global (`proxy_host_id IS NULL`) rows by default, or only the requested host's rows when an ID is supplied.
3. Both the CREATE TABLE area and UPGRADE SECTION of `001_init.sql` now define the backfill checkpoint with the same columns/defaults/constraints as `migration.go`.
4. The 24h summary and chart now use complete UTC hourly rollups plus raw partial-hour edges. Backfill reads and locks an existing checkpoint before considering initialization, so resumed batches skip MIN. Per-batch progress messages are removed; start, completion and errors remain.

I also measured the three rollup statements on an isolated PostgreSQL 17.11 arm64 container: 3 million synthetic logs over 72 hours, 200 configured hosts (190 with classified traffic), daily partitions, 128MB shared buffers / 4MB work_mem. The host was an M1 Pro; Docker had 10 CPUs / 7.65 GiB RAM, and test PGDATA used tmpfs. These are local synthetic measurements, not production performance claims.

The cleanup plan repeatedly probed raw logs for each host/hour; the boot-window plan also scanned outside the rebuild window and spilled its hash. Cleanup now materializes the bounded active host/hour pairs once. Paired three-run median cleanup times were 319.610 → 29.189ms (1h), 703.400 → 58.344ms (2h), and 4,054.389 → 900.814ms (26h). Global and host UPSERTs were retained. The 24h summary was 512.292 → 26.456ms, and the chart 1,076.274 → 51.709ms, including the intended move to hourly chart buckets.

The reproducible fixture, all timings and execution-plan details are in `api/internal/repository/traffic_performance_test.go` and `test/benchmarks/pr354/`.

Go non-integration tests and vet, PostgreSQL repository/schema tests, UI build/lint (10 existing lint warnings), and all four traffic utility tests passed. Regression coverage includes hostname semantics, hourly row scope, UTC edge boundaries, global = classified + unclassified totals, replay idempotence, retained global history, restart, concurrent backfill and transactional rollback/retry. The release-only integration stack was not started, and live Nginx ingestion was not repeated. Version remains 2.65.3; no application image build or deployment was performed.
