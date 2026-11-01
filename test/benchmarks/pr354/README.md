# PR #354 review follow-up measurements

Measured on 2026-11-01. These are local synthetic PostgreSQL measurements, not production throughput, latency guarantees, or a TimescaleDB benchmark.

## Environment and workload

- Host: Apple M1 Pro, 32 GiB RAM. Docker Linux VM: arm64, 10 CPUs, 8,218,034,176 bytes RAM (7.65 GiB).
- PostgreSQL 17.11, Debian arm64; `shared_buffers=128MB`, `work_mem=4MB`, `max_parallel_workers_per_gather=2`.
- Dedicated PostgreSQL container, no existing mounts/volumes. Test PGDATA was a 4 GiB tmpfs. Default durability settings; no concurrent ingestion, compression, retention, application traffic, or other tests during the final measured run.
- Go 1.26.10 linux/arm64, official Go tool container; Node 26.12.0 for UI checks.
- 3,000,000 synthetic access logs across 72 hours (1,000,000/day), three daily range partitions. 200 configured proxy hosts, 190 with classified requests; 5% of logs have no host ID, 1% are health requests excluded by the production filter. Mostly 200 responses, some 404s; 180-byte synthetic raw-log payloads.
- Log tables plus indexes: 1,442,832,384 bytes (1.34 GiB). The fixture includes only the columns needed here and relevant production index shapes: `(created_at DESC)`, `(log_type, created_at DESC)`, partial `(proxy_host_id, timestamp DESC)`, plus hourly host/bucket uniqueness, NULL-host uniqueness, and hour-bucket lookup.
- This intentionally omits unrelated log columns/indexes, skew, host churn, deleted-row bloat, compressed chunks and competing workloads. Real installations need their own measurements.

## Method

`TestTrafficPerformance` creates and drops a private schema on `NPG_TEST_DATABASE_URL`. It is disabled unless `NPG_TRAFFIC_PERF=1`. The final run was performed after compilation and all other tests finished. The fixture is analyzed before measurements. Each group runs three times without forcing OS/database cache eviction; both shared hits and reads occur. Reported values are execution-time medians, excluding planning, API/network overhead and transaction commit.

Global and host UPSERTs use the production SQL. Original and revised cleanup run consecutively against the **same** rows, indexes and connection, after each host UPSERT. There are no stale rows in this workload, so the legacy DELETE cannot improve the next DELETE by removing data. Correct deletion of stale/filtered rows and empty replays is covered separately by regression tests. The statements commit independently for EXPLAIN; their summed times below are not end-to-end collector transaction timings.

Rollup windows end at `2026-10-31T00:00:00Z`: 1 hour (normal), 2 hours (late-arrival repair), 26 hours (boot sweep). The 24-hour view uses `[2026-10-29T23:30:00Z, 2026-10-30T23:30:00Z)`: 23 complete rollup hours plus two 30-minute raw edges. Both summary and chart cover the same interval. The raw chart uses the former five-minute aggregation; the revised chart uses the exact current repository query and hour buckets, including partial edge buckets. This intended resolution change is included in the measured benefit.

## Results

Milliseconds; median of three executions. [Every sample and buffer count](results.csv), [median sample execution plans](explain.txt).

| Window | Global UPSERT | Host UPSERT | Original cleanup | Revised cleanup | Sum of 3 SQL, original → revised |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1h | 38.997 | 47.988 | 319.610 | 29.189 | 406.260 → 115.975 |
| 2h | 74.354 | 85.187 | 703.400 | 58.344 | 855.422 → 218.936 |
| 26h | 1,122.351 | 1,331.486 | 4,054.389 | 900.814 | 6,499.558 → 3,362.526 |

The sum column is the median of each run's three statement times, not the sum of independent column medians.

| 24h view | Original raw query | Revised hourly + raw edges |
| --- | ---: | ---: |
| Summary | 512.292 | 26.456 |
| Chart | 1,076.274 | 51.709 |

## Execution-plan findings and change

- In the 1h median legacy cleanup, PostgreSQL used a nested-loop anti join with 190 correlated raw-log probes, repeatedly building index bitmaps (48,205 shared hits). Revised cleanup reads the bounded raw window once, materializes 190 active host/hour pairs, then uses a hash anti join (1,820 shared hits).
- In the 26h median legacy cleanup, the hash anti join reads all three raw partitions: 2,970,000 filtered rows / 2,850,000 with matching host IDs enter the inner hash, which spills 32,242 temp blocks each read/written. The revised query explicitly bounds the raw scan to the rebuild window and groups it into 4,940 host/hour pairs. It uses no temporary blocks in this measurement. It still scans about a day for the boot sweep; that cost has not disappeared.
- Global and host UPSERTs were measured and retained. No index or unrelated schema changes were needed. Cleanup remains a separate statement so it executes even on an empty replay window.
- The median 24h raw summary and chart touch approximately 39,368 shared hit/read blocks each. Revised queries touch 2,135 and 2,151 blocks respectively, reading only the two partial hours from raw logs and 23 full hours from the hourly table. Host and unclassified correctness is independently tested.

## Reproduction

Use an isolated PostgreSQL database, never a production endpoint. No application or image build is needed. From this repository, create a new test container with no existing volumes (choose another name if it already exists):

```sh
rtk proxy docker run -d --name npg-pr354-db \
  -e POSTGRES_PASSWORD=pr354-test -e POSTGRES_DB=npg_review \
  --tmpfs /var/lib/postgresql/data:rw,size=4g postgres:17
rtk proxy docker exec npg-pr354-db pg_isready -U postgres
```

Once PostgreSQL is ready, run:

```sh
rtk proxy docker run --rm --network container:npg-pr354-db \
  -e 'NPG_TEST_DATABASE_URL=postgres://postgres:pr354-test@127.0.0.1:5432/npg_review?sslmode=disable' \
  -e NPG_TRAFFIC_PERF=1 \
  -e NPG_TRAFFIC_PERF_OUTPUT=/workspace/docs/benchmarks/pr354/reproduced \
  -v "$PWD:/workspace" -w /workspace/api \
  golang:1.26 go test ./internal/repository -run '^TestTrafficPerformance$' -count=1 -v -timeout 20m
```

`NPG_TRAFFIC_PERF_OUTPUT` optionally writes every full JSON EXPLAIN plan. The reproduction path intentionally uses ignored `docs/` to preserve the checked-in measurement snapshot. The checked-in text retains every node and relevant predicates/buffer counters for the median sample in each group. The CSV retains every timing, including first executions. Runs without the opt-in flag skip this benchmark.

## Verification

- Go non-integration suite passed: `go test ./cmd/... ./internal/... ./pkg/... -count=1 -timeout 5m`, with the isolated database initialized by the full `001_init.sql`. This matches the scope in `.github/workflows/checks.yml`, which excludes `tests/integration`.
- `go vet ./...` passed.
- All repository and migration tests passed on PostgreSQL. New tests cover Top hosts aliases/unregistered domains, default/explicit-host hourly queries, executable checkpoint DDL in both SQL sections, schema-definition parity, exact/partial UTC 24h windows and timezone offsets, retained rollups after raw expiry, stale host/hour pair deletion and empty replay cleanup.
- Existing backfill restart, empty history, initialization rollback and concurrent-worker tests passed. The new existing-checkpoint save-failure rollback/retry test and the concurrent-worker test passed 10 repetitions.
- Full initial SQL executed successfully in a fresh isolated database. Upgrade-only recreation of the checkpoint was checked against the initial schema's columns/defaults/constraints.
- UI build passed (existing font-import ordering and duplicate static/dynamic i18n import warnings); ESLint passed with 0 errors / 10 existing warnings; `node --test ui/test/traffic.test.mjs` passed 4/4.
- Independent read-only review found no actionable correctness or requirement gaps. Live Nginx ingestion was not repeated; no deployment was performed.

An initial overly broad `go test ./...` included release-only integration tests. `TestIntegrationSuite`, `TestHealthEndpoint`, `TestAPIDocsAvailable`, `TestDatabaseHealth`, `TestPartitionedTables`, `TestPartitionCreation`, `TestEnumTypes`, and `TestTimezoneHandling` failed because no API on `:8080` or `release-test-db` stack was running. These are intentionally excluded by the repository's regular CI. Before initializing the public schema, `TestImportExploitBlockRuleInsertsUserRulesIncludingDuplicateNames`, `TestImportExploitBlockRuleSkipsUnknownBuiltin`, and `TestCertificateMaterialRoundTrip` also failed due to missing tables; all three passed after schema initialization, along with the complete non-integration suite. No release stack was built or deployed for this change.
