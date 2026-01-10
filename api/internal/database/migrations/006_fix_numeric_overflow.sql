-- Migration: Fix numeric field overflow for request_time and upstream_response_time
-- Problem: NUMERIC(10,6) can only store values up to 9999.999999 (10 seconds max)
-- Solution: Change to DOUBLE PRECISION to support larger response times

-- This migration handles TimescaleDB hypertables with compression enabled

-- Step 1: Decompress all chunks
DO $$
DECLARE
    chunk_record RECORD;
BEGIN
    FOR chunk_record IN
        SELECT format('%I.%I', chunk_schema, chunk_name) as full_name
        FROM timescaledb_information.chunks
        WHERE hypertable_name = 'logs_partitioned' AND is_compressed = true
    LOOP
        EXECUTE format('SELECT decompress_chunk(%L, true)', chunk_record.full_name);
        RAISE NOTICE 'Decompressed: %', chunk_record.full_name;
    END LOOP;
END;
$$;

-- Step 2: Disable compression temporarily
ALTER TABLE logs_partitioned SET (timescaledb.compress = false);

-- Step 3: Alter column types to DOUBLE PRECISION
ALTER TABLE logs_partitioned
    ALTER COLUMN request_time TYPE DOUBLE PRECISION,
    ALTER COLUMN upstream_response_time TYPE DOUBLE PRECISION;

-- Step 4: Re-enable compression with same settings
ALTER TABLE logs_partitioned SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'host, log_type',
    timescaledb.compress_orderby = 'created_at DESC'
);

-- Step 5: Recompress all chunks
DO $$
DECLARE
    chunk_record RECORD;
BEGIN
    FOR chunk_record IN
        SELECT format('%I.%I', chunk_schema, chunk_name) as full_name
        FROM timescaledb_information.chunks
        WHERE hypertable_name = 'logs_partitioned' AND is_compressed = false
    LOOP
        EXECUTE format('SELECT compress_chunk(%L)', chunk_record.full_name);
        RAISE NOTICE 'Compressed: %', chunk_record.full_name;
    END LOOP;
END;
$$;
