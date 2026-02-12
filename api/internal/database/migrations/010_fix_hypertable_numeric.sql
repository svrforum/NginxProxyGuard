-- Migration 010: Fix hypertable numeric type after TimescaleDB migration (Issue #55)
-- The migrateToTimescaleDB() function previously created logs_hypertable with numeric(10,6)
-- which overrode the double precision fix from migration 006.
-- This migration detects and fixes the column types if needed.

DO $$
DECLARE
    current_type text;
    is_hyper boolean;
    chunk_record RECORD;
    decompressed_count int := 0;
BEGIN
    -- Check if logs_partitioned exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'logs_partitioned'
    ) THEN
        RAISE NOTICE 'logs_partitioned table not found, skipping';
        RETURN;
    END IF;

    -- Check current column type
    SELECT data_type INTO current_type
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'logs_partitioned' AND column_name = 'request_time';

    IF current_type = 'double precision' THEN
        RAISE NOTICE 'request_time already uses double precision, no fix needed';
        RETURN;
    END IF;

    RAISE NOTICE 'request_time type is %, fixing to double precision...', current_type;

    -- Check if it's a hypertable
    is_hyper := EXISTS (
        SELECT 1 FROM timescaledb_information.hypertables
        WHERE hypertable_name = 'logs_partitioned'
    );

    IF is_hyper THEN
        -- Decompress all chunks first
        RAISE NOTICE 'Decompressing chunks...';
        FOR chunk_record IN
            SELECT format('%I.%I', chunk_schema, chunk_name) as full_name
            FROM timescaledb_information.chunks
            WHERE hypertable_name = 'logs_partitioned' AND is_compressed = true
        LOOP
            EXECUTE format('SELECT decompress_chunk(%L, true)', chunk_record.full_name);
            decompressed_count := decompressed_count + 1;
        END LOOP;
        RAISE NOTICE 'Decompressed % chunks', decompressed_count;

        -- Disable compression temporarily
        ALTER TABLE logs_partitioned SET (timescaledb.compress = false);
    END IF;

    -- Alter column types
    ALTER TABLE logs_partitioned
        ALTER COLUMN request_time TYPE DOUBLE PRECISION,
        ALTER COLUMN upstream_response_time TYPE DOUBLE PRECISION;

    RAISE NOTICE 'Column types changed to double precision';

    IF is_hyper THEN
        -- Re-enable compression
        ALTER TABLE logs_partitioned SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'host, log_type',
            timescaledb.compress_orderby = 'created_at DESC'
        );
        RAISE NOTICE 'Compression re-enabled';
    END IF;
END;
$$;
