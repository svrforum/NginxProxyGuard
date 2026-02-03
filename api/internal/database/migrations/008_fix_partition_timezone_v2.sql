-- Migration 008: Fix partition timezone detection bug
--
-- Problem: The timezone detection logic in 007 incorrectly detects local timezone
-- when pg_get_expr() displays UTC timestamps in the session's timezone.
--
-- Example: In KST environment, '2026-04-01 00:00:00+00' is displayed as
-- '2026-04-01 09:00:00+09', causing the detection to incorrectly use local timezone.
--
-- Solution: Remove timezone detection and always use UTC for consistency.

CREATE OR REPLACE FUNCTION public.create_monthly_partitions(
    table_name text,
    partition_prefix text,
    months_ahead integer DEFAULT 3
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    start_ts TIMESTAMPTZ;
    end_ts TIMESTAMPTZ;
    partition_name TEXT;
    i INT;
    is_partitioned BOOLEAN;
    is_hypertable BOOLEAN := FALSE;
BEGIN
    -- Check if TimescaleDB hypertable (skip if so - chunks are auto-managed)
    BEGIN
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = table_name
        ) INTO is_hypertable;
    EXCEPTION WHEN OTHERS THEN
        is_hypertable := FALSE;
    END;

    IF is_hypertable THEN
        RAISE NOTICE 'Table % is a TimescaleDB hypertable, chunks are auto-managed', table_name;
        RETURN;
    END IF;

    -- Check if the table is a native PostgreSQL partitioned table
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = table_name
    ) INTO is_partitioned;

    IF NOT is_partitioned THEN
        RAISE NOTICE 'Table % is not a partitioned table, skipping', table_name;
        RETURN;
    END IF;

    -- Always use UTC for partition boundaries to ensure consistency
    -- This matches the initial partition creation in 001_init.sql
    FOR i IN 0..months_ahead LOOP
        -- Calculate first day of month at 00:00:00 UTC
        start_ts := DATE_TRUNC('month',
            (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') + (i || ' months')::INTERVAL
        ) AT TIME ZONE 'UTC';
        end_ts := start_ts + INTERVAL '1 month';
        partition_name := partition_prefix || TO_CHAR(start_ts AT TIME ZONE 'UTC', 'YYYY_MM');

        -- Check if partition already exists
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = partition_name
        ) THEN
            BEGIN
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                    partition_name, table_name, start_ts, end_ts
                );
                RAISE NOTICE 'Created partition: % (% to %)', partition_name, start_ts, end_ts;
            EXCEPTION WHEN OTHERS THEN
                -- Log but continue - partition might exist with different name or overlap
                RAISE NOTICE 'Could not create partition %: %', partition_name, SQLERRM;
            END;
        END IF;
    END LOOP;
END;
$$;

-- Create missing May 2026 partition if April exists but May doesn't
-- This fixes the immediate issue caused by the bug
DO $$
DECLARE
    apr_exists BOOLEAN;
    may_exists BOOLEAN;
BEGIN
    SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = 'stats_hourly_p2026_04') INTO apr_exists;
    SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = 'stats_hourly_p2026_05') INTO may_exists;

    -- If April partition exists and May doesn't, create May with correct UTC boundaries
    IF apr_exists AND NOT may_exists THEN
        EXECUTE 'CREATE TABLE stats_hourly_p2026_05 PARTITION OF dashboard_stats_hourly_partitioned
            FOR VALUES FROM (''2026-05-01 00:00:00+00'') TO (''2026-06-01 00:00:00+00'')';
        RAISE NOTICE 'Created stats_hourly_p2026_05 partition with UTC boundaries';
    END IF;
END $$;
