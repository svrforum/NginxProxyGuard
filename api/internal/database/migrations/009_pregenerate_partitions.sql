-- Migration 009: Pre-generate partitions for 10 years
--
-- Problem: Dynamic partition creation via create_monthly_partitions() function
-- is susceptible to timezone bugs where servers in non-UTC timezones create
-- partitions with incorrect boundaries, causing overlap errors.
--
-- Solution: Pre-generate all partitions with explicit UTC boundaries.
-- This migration:
-- 1. Safely drops incorrectly created partitions (only if empty or conflicting)
-- 2. Creates missing partitions from 2026_04 to 2035_12 with correct UTC boundaries
--
-- Note: This migration is safe to run multiple times (idempotent).

-- Helper function to safely drop and recreate a partition if it has incorrect bounds
CREATE OR REPLACE FUNCTION fix_partition_bounds(
    parent_table TEXT,
    partition_name TEXT,
    expected_start TIMESTAMPTZ,
    expected_end TIMESTAMPTZ
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    actual_bounds TEXT;
    has_data BOOLEAN;
    row_count BIGINT;
    is_partitioned BOOLEAN;
    is_hypertable BOOLEAN := FALSE;
BEGIN
    -- Check if parent table is a TimescaleDB hypertable (skip if so)
    BEGIN
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = parent_table
        ) INTO is_hypertable;
    EXCEPTION WHEN OTHERS THEN
        is_hypertable := FALSE;
    END;

    IF is_hypertable THEN
        RAISE NOTICE 'Table % is a TimescaleDB hypertable, skipping partition fix', parent_table;
        RETURN;
    END IF;

    -- Check if parent table is a partitioned table
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = parent_table
    ) INTO is_partitioned;

    IF NOT is_partitioned THEN
        RAISE NOTICE 'Table % is not a partitioned table, skipping partition fix', parent_table;
        RETURN;
    END IF;

    -- Check if partition exists
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = partition_name) THEN
        -- Partition doesn't exist, create it
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            partition_name, parent_table, expected_start, expected_end
        );
        RAISE NOTICE 'Created new partition: %', partition_name;
        RETURN;
    END IF;

    -- Get actual bounds (set timezone to UTC for comparison)
    SET LOCAL timezone = 'UTC';
    SELECT pg_get_expr(c.relpartbound, c.oid)
    INTO actual_bounds
    FROM pg_class c
    WHERE c.relname = partition_name;

    -- Check if bounds are correct (contains +00 for UTC)
    IF actual_bounds LIKE '%+00%' THEN
        RAISE NOTICE 'Partition % already has correct UTC bounds', partition_name;
        RETURN;
    END IF;

    -- Bounds are incorrect, check if partition has data
    EXECUTE format('SELECT COUNT(*) FROM %I', partition_name) INTO row_count;
    has_data := row_count > 0;

    IF has_data THEN
        -- Has data - cannot safely drop. Log warning.
        RAISE WARNING 'Partition % has % rows with incorrect bounds. Manual intervention may be needed.',
            partition_name, row_count;
        RETURN;
    END IF;

    -- Empty partition with incorrect bounds - safe to recreate
    RAISE NOTICE 'Recreating partition % with correct UTC bounds (was empty)', partition_name;

    BEGIN
        -- Detach and drop
        EXECUTE format('ALTER TABLE %I DETACH PARTITION %I', parent_table, partition_name);
        EXECUTE format('DROP TABLE %I', partition_name);

        -- Create with correct bounds
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            partition_name, parent_table, expected_start, expected_end
        );
        RAISE NOTICE 'Successfully recreated partition: %', partition_name;
    EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'Could not recreate partition %: %', partition_name, SQLERRM;
    END;
END;
$$;

-- Function to create a partition if it doesn't exist
CREATE OR REPLACE FUNCTION ensure_partition_exists(
    parent_table TEXT,
    partition_name TEXT,
    start_ts TIMESTAMPTZ,
    end_ts TIMESTAMPTZ
) RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = partition_name) THEN
        BEGIN
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                partition_name, parent_table, start_ts, end_ts
            );
            RAISE NOTICE 'Created partition: % (% to %)', partition_name, start_ts, end_ts;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'Could not create partition %: %', partition_name, SQLERRM;
        END;
    END IF;
END;
$$;

-- =============================================================================
-- FIX POTENTIALLY BROKEN PARTITIONS (2026_04 onwards that may have been
-- created with wrong timezone)
-- =============================================================================

DO $$
DECLARE
    year INT;
    month INT;
    month_str TEXT;
    partition_name TEXT;
    start_ts TIMESTAMPTZ;
    end_ts TIMESTAMPTZ;
BEGIN
    -- Fix stats_hourly partitions that may have incorrect bounds (2026_04, 2026_05, etc.)
    FOR year IN 2026..2026 LOOP
        FOR month IN 4..12 LOOP
            month_str := LPAD(month::TEXT, 2, '0');
            partition_name := 'stats_hourly_p' || year || '_' || month_str;
            start_ts := (year || '-' || month_str || '-01 00:00:00+00')::TIMESTAMPTZ;
            end_ts := start_ts + INTERVAL '1 month';

            PERFORM fix_partition_bounds(
                'dashboard_stats_hourly_partitioned',
                partition_name,
                start_ts,
                end_ts
            );
        END LOOP;
    END LOOP;

    -- Fix logs partitions that may have incorrect bounds (2026_04, 2026_05, etc.)
    FOR year IN 2026..2026 LOOP
        FOR month IN 4..12 LOOP
            month_str := LPAD(month::TEXT, 2, '0');
            partition_name := 'logs_p' || year || '_' || month_str;
            start_ts := (year || '-' || month_str || '-01 00:00:00+00')::TIMESTAMPTZ;
            end_ts := start_ts + INTERVAL '1 month';

            PERFORM fix_partition_bounds(
                'logs_partitioned',
                partition_name,
                start_ts,
                end_ts
            );
        END LOOP;
    END LOOP;
END $$;

-- =============================================================================
-- PRE-GENERATE STATS_HOURLY PARTITIONS (2026_04 to 2035_12)
-- =============================================================================

DO $$
DECLARE
    year INT;
    month INT;
    month_str TEXT;
    partition_name TEXT;
    start_ts TIMESTAMPTZ;
    end_ts TIMESTAMPTZ;
    is_partitioned BOOLEAN;
BEGIN
    -- Check if dashboard_stats_hourly_partitioned is a partitioned table
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = 'dashboard_stats_hourly_partitioned'
    ) INTO is_partitioned;

    IF NOT is_partitioned THEN
        RAISE NOTICE 'dashboard_stats_hourly_partitioned is not a partitioned table, skipping';
        RETURN;
    END IF;

    -- Generate partitions from 2026-04 to 2035-12
    FOR year IN 2026..2035 LOOP
        FOR month IN 1..12 LOOP
            -- Skip months before April 2026 (already handled or not needed)
            IF year = 2026 AND month < 4 THEN
                CONTINUE;
            END IF;

            month_str := LPAD(month::TEXT, 2, '0');
            partition_name := 'stats_hourly_p' || year || '_' || month_str;
            start_ts := (year || '-' || month_str || '-01 00:00:00+00')::TIMESTAMPTZ;
            end_ts := start_ts + INTERVAL '1 month';

            PERFORM ensure_partition_exists(
                'dashboard_stats_hourly_partitioned',
                partition_name,
                start_ts,
                end_ts
            );
        END LOOP;
    END LOOP;

    RAISE NOTICE 'Stats hourly partitions pre-generated up to 2035-12';
END $$;

-- =============================================================================
-- PRE-GENERATE LOGS PARTITIONS (2026_04 to 2035_12)
-- Note: If using TimescaleDB hypertable, logs_partitioned may not need manual partitions
-- =============================================================================

DO $$
DECLARE
    year INT;
    month INT;
    month_str TEXT;
    partition_name TEXT;
    start_ts TIMESTAMPTZ;
    end_ts TIMESTAMPTZ;
    is_partitioned BOOLEAN;
    is_hypertable BOOLEAN := FALSE;
BEGIN
    -- Check if logs_partitioned is a TimescaleDB hypertable (chunks are auto-managed)
    BEGIN
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'logs_partitioned'
        ) INTO is_hypertable;
    EXCEPTION WHEN OTHERS THEN
        is_hypertable := FALSE;
    END;

    IF is_hypertable THEN
        RAISE NOTICE 'logs_partitioned is a TimescaleDB hypertable, chunks are auto-managed';
        RETURN;
    END IF;

    -- Check if logs_partitioned is a native PostgreSQL partitioned table
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = 'logs_partitioned'
    ) INTO is_partitioned;

    IF NOT is_partitioned THEN
        RAISE NOTICE 'logs_partitioned is not a partitioned table, skipping';
        RETURN;
    END IF;

    -- Generate partitions from 2026-04 to 2035-12
    FOR year IN 2026..2035 LOOP
        FOR month IN 1..12 LOOP
            -- Skip months before April 2026 (already handled or not needed)
            IF year = 2026 AND month < 4 THEN
                CONTINUE;
            END IF;

            month_str := LPAD(month::TEXT, 2, '0');
            partition_name := 'logs_p' || year || '_' || month_str;
            start_ts := (year || '-' || month_str || '-01 00:00:00+00')::TIMESTAMPTZ;
            end_ts := start_ts + INTERVAL '1 month';

            PERFORM ensure_partition_exists(
                'logs_partitioned',
                partition_name,
                start_ts,
                end_ts
            );
        END LOOP;
    END LOOP;

    RAISE NOTICE 'Logs partitions pre-generated up to 2035-12';
END $$;

-- Cleanup helper functions (keep them for future use)
-- DROP FUNCTION IF EXISTS fix_partition_bounds(TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ);
-- DROP FUNCTION IF EXISTS ensure_partition_exists(TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ);

-- Log completion
DO $$ BEGIN RAISE NOTICE 'Migration 009 completed: Partitions pre-generated for 10 years (to 2035-12)'; END $$;
