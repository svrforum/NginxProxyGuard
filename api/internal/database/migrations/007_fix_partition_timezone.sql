-- Migration 007: DEPRECATED - DO NOT USE
-- This migration has a bug where pg_get_expr() displays UTC timestamps
-- in the session's timezone (e.g., +00 shown as +09 in KST), causing
-- incorrect timezone detection.
--
-- Use 008_fix_partition_timezone_v2.sql instead.
--
-- Original description:
-- Migration 007: Fix partition creation to detect and match existing timezone format
-- This prevents overlap errors when existing partitions use local timezone

CREATE OR REPLACE FUNCTION public.create_monthly_partitions(table_name text, partition_prefix text, months_ahead integer DEFAULT 3) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    start_ts TIMESTAMPTZ;
    end_ts TIMESTAMPTZ;
    partition_name TEXT;
    i INT;
    is_partitioned BOOLEAN;
    is_hypertable BOOLEAN := FALSE;
    existing_bound_text TEXT;
    use_local_tz BOOLEAN := FALSE;
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

    -- Detect existing partition timezone format by checking the first non-default partition
    BEGIN
        SELECT pg_get_expr(c.relpartbound, c.oid) INTO existing_bound_text
        FROM pg_class c
        JOIN pg_inherits i ON c.oid = i.inhrelid
        JOIN pg_class p ON i.inhparent = p.oid
        WHERE p.relname = table_name
          AND c.relname LIKE partition_prefix || '%'
          AND c.relname NOT LIKE '%_default'
        LIMIT 1;

        -- Check if existing partitions use non-UTC timezone (e.g., +09)
        IF existing_bound_text IS NOT NULL AND existing_bound_text NOT LIKE '%+00%' AND existing_bound_text ~ '\+[0-9]{2}\)' THEN
            use_local_tz := TRUE;
            RAISE NOTICE 'Detected local timezone in existing partitions, using local timezone for new partitions';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        use_local_tz := FALSE;
    END;

    FOR i IN 0..months_ahead LOOP
        IF use_local_tz THEN
            -- Use local timezone to match existing partition ranges
            start_ts := DATE_TRUNC('month', CURRENT_TIMESTAMP + (i || ' months')::INTERVAL);
            end_ts := start_ts + INTERVAL '1 month';
            partition_name := partition_prefix || TO_CHAR(start_ts, 'YYYY_MM');
        ELSE
            -- Use UTC timezone (default for new installations)
            start_ts := DATE_TRUNC('month', (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') + (i || ' months')::INTERVAL) AT TIME ZONE 'UTC';
            end_ts := start_ts + INTERVAL '1 month';
            partition_name := partition_prefix || TO_CHAR(start_ts AT TIME ZONE 'UTC', 'YYYY_MM');
        END IF;

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
