package database

import (
	"context"
	"embed"
	"fmt"
	"log"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// RunMigrations executes schema migrations
// 001_init.sql runs only once (on fresh install)
// Upgrade statements run every time for existing installations
func (db *DB) RunMigrations() error {
	// Create migrations tracking table (for version tracking only)
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Enable TimescaleDB extension (safe to run multiple times)
	if err := db.enableTimescaleDB(); err != nil {
		log.Printf("Warning: TimescaleDB not available, using standard PostgreSQL: %v", err)
	}

	// Check if base schema already exists
	var exists bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = '001_init')`).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}

	if !exists {
		// Fresh install - run full schema
		content, err := migrationFS.ReadFile("migrations/001_init.sql")
		if err != nil {
			return fmt.Errorf("failed to read 001_init.sql: %w", err)
		}

		log.Println("Running initial schema migration (001_init.sql)...")
		_, err = db.Exec(string(content))
		if err != nil {
			return fmt.Errorf("failed to apply schema migration: %w", err)
		}

		// Mark as applied
		_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ('001_init')`)
		if err != nil {
			return fmt.Errorf("failed to update migration version: %w", err)
		}
		log.Println("Initial schema migration completed successfully")
	} else {
		log.Println("Schema already initialized, running upgrades only...")
	}

	// Always run upgrade statements for existing installations
	upgradeSQL := `
		-- Enum upgrades (safe to run multiple times)
		ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'cloud_provider_challenge';
		ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'uri_block';

		-- Column upgrades
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS cache_static_only boolean DEFAULT true NOT NULL;
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS cache_ttl character varying(20) DEFAULT '7d' NOT NULL;
		ALTER TABLE public.geo_restrictions ADD COLUMN IF NOT EXISTS allow_search_bots_cloud_providers boolean DEFAULT false;
	`
	_, err = db.Exec(upgradeSQL)
	if err != nil {
		log.Printf("Warning: upgrade statements had errors (may be already applied): %v", err)
	}

	// Migrate logs table to logs_partitioned in background (for existing installations)
	// This allows API to start immediately while migration runs
	go db.migrateLogsToPartitioned()

	// Migrate to TimescaleDB hypertable in background (for existing installations)
	go db.migrateToTimescaleDB()

	log.Println("Schema migration completed")
	return nil
}

// enableTimescaleDB enables the TimescaleDB extension
func (db *DB) enableTimescaleDB() error {
	_, err := db.Exec(`CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE`)
	if err != nil {
		return err
	}
	log.Println("[TimescaleDB] Extension enabled successfully")
	return nil
}

// isTimescaleDBAvailable checks if TimescaleDB extension is available
func (db *DB) isTimescaleDBAvailable() bool {
	var available bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&available)
	return err == nil && available
}

// isHypertable checks if a table is already a TimescaleDB hypertable
func (db *DB) isHypertable(tableName string) bool {
	var isHyper bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM timescaledb_information.hypertables
			WHERE hypertable_name = $1
		)
	`, tableName).Scan(&isHyper)
	return err == nil && isHyper
}

// migrateLogsToPartitioned migrates data from old logs table to logs_partitioned
func (db *DB) migrateLogsToPartitioned() {
	// Check if old logs table exists
	var logsExists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs'
		)
	`).Scan(&logsExists)
	if err != nil || !logsExists {
		return // No old logs table, nothing to migrate
	}

	// Check if there's data to migrate
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM logs LIMIT 1`).Scan(&count)
	if err != nil || count == 0 {
		// No data, just drop the old table
		log.Println("[Migration] Dropping empty logs table...")
		db.Exec(`DROP TABLE IF EXISTS logs CASCADE`)
		return
	}

	log.Printf("[Migration] Found old logs table with data, migrating to logs_partitioned...")

	// Migrate in batches
	batchSize := 50000
	totalMigrated := 0

	for {
		result, err := db.Exec(`
			WITH batch AS (
				SELECT id FROM logs
				WHERE NOT EXISTS (SELECT 1 FROM logs_partitioned lp WHERE lp.id = logs.id)
				LIMIT $1
			)
			INSERT INTO logs_partitioned (
				id, log_type, timestamp, host, client_ip,
				request_method, request_uri, request_protocol, status_code,
				body_bytes_sent, request_time, upstream_response_time,
				http_referer, http_user_agent, http_x_forwarded_for,
				severity, error_message,
				rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
				proxy_host_id, raw_log, created_at,
				geo_country, geo_country_code, geo_city, geo_asn, geo_org,
				block_reason, bot_category, exploit_rule
			)
			SELECT
				l.id, l.log_type, l.timestamp, l.host, l.client_ip,
				l.request_method, l.request_uri, l.request_protocol, l.status_code,
				l.body_bytes_sent, l.request_time, l.upstream_response_time,
				l.http_referer, l.http_user_agent, l.http_x_forwarded_for,
				l.severity, l.error_message,
				l.rule_id, l.rule_message, l.rule_severity, l.rule_data, l.attack_type, l.action_taken,
				l.proxy_host_id, l.raw_log, l.created_at,
				l.geo_country, l.geo_country_code, l.geo_city, l.geo_asn, l.geo_org,
				l.block_reason, l.bot_category, l.exploit_rule
			FROM logs l
			WHERE l.id IN (SELECT id FROM batch)
		`, batchSize)

		if err != nil {
			log.Printf("[Migration] Error migrating logs batch: %v", err)
			break
		}

		rowsAffected, _ := result.RowsAffected()
		totalMigrated += int(rowsAffected)

		if rowsAffected < int64(batchSize) {
			break
		}

		log.Printf("[Migration] Migrated %d logs so far...", totalMigrated)
	}

	if totalMigrated > 0 {
		log.Printf("[Migration] Migrated %d logs to logs_partitioned", totalMigrated)
	}

	// Drop old logs table
	log.Println("[Migration] Dropping old logs table...")
	_, err = db.Exec(`DROP TABLE IF EXISTS logs CASCADE`)
	if err != nil {
		log.Printf("[Migration] Warning: failed to drop old logs table: %v", err)
	} else {
		log.Println("[Migration] Old logs table dropped successfully")
	}
}

// migrateToTimescaleDB migrates existing partitioned logs to TimescaleDB hypertable
func (db *DB) migrateToTimescaleDB() {
	// Wait a bit for other migrations to complete
	time.Sleep(5 * time.Second)

	// Check if TimescaleDB is available
	if !db.isTimescaleDBAvailable() {
		log.Println("[TimescaleDB] Extension not available, skipping migration")
		return
	}

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 'timescaledb_hypertable')`).Scan(&migrated)
	if err == nil && migrated {
		log.Println("[TimescaleDB] Already migrated to hypertable")
		// Still set up compression policy
		db.setupTimescaleDBCompression()
		return
	}

	// Check if logs_hypertable already exists (indicates in-progress or completed migration)
	if db.isHypertable("logs_hypertable") {
		log.Println("[TimescaleDB] Hypertable already exists")
		db.setupTimescaleDBCompression()
		return
	}

	// Check if logs_partitioned exists and has data
	var hasData bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs_partitioned'
		)
	`).Scan(&hasData)
	if err != nil || !hasData {
		log.Println("[TimescaleDB] No logs_partitioned table found, will create hypertable on fresh install")
		return
	}

	log.Println("[TimescaleDB] Starting migration from partitioned table to hypertable...")
	ctx := context.Background()

	// Use transaction for safety
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()

	// Step 1: Create new hypertable with same structure
	log.Println("[TimescaleDB] Creating hypertable structure...")
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS logs_hypertable (
			id uuid NOT NULL DEFAULT gen_random_uuid(),
			log_type log_type NOT NULL,
			timestamp timestamp with time zone NOT NULL DEFAULT now(),
			host text,
			client_ip inet,
			request_method text,
			request_uri text,
			request_protocol text,
			status_code integer,
			body_bytes_sent bigint,
			request_time numeric(10,6),
			upstream_response_time numeric(10,6),
			http_referer text,
			http_user_agent text,
			http_x_forwarded_for text,
			severity log_severity,
			error_message text,
			rule_id integer,
			rule_message text,
			rule_severity text,
			rule_data text,
			attack_type text,
			action_taken text,
			proxy_host_id uuid,
			raw_log text,
			created_at timestamp with time zone NOT NULL DEFAULT now(),
			geo_country text,
			geo_country_code varchar(2),
			geo_city text,
			geo_asn text,
			geo_org text,
			block_reason block_reason DEFAULT 'none',
			bot_category text,
			exploit_rule varchar(50)
		)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to create table structure: %v", err)
		return
	}

	// Step 2: Convert to hypertable
	log.Println("[TimescaleDB] Converting to hypertable...")
	_, err = tx.Exec(`
		SELECT create_hypertable(
			'logs_hypertable',
			by_range('created_at', INTERVAL '1 day'),
			if_not_exists => TRUE
		)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to create hypertable: %v", err)
		return
	}

	if err = tx.Commit(); err != nil {
		log.Printf("[TimescaleDB] Failed to commit hypertable creation: %v", err)
		return
	}

	// Step 3: Migrate data in batches (outside transaction for large data)
	log.Println("[TimescaleDB] Migrating data from partitioned table...")
	batchSize := 50000
	totalMigrated := 0

	// Get total count for progress reporting
	var totalCount int64
	db.QueryRow(`SELECT COUNT(*) FROM logs_partitioned`).Scan(&totalCount)
	log.Printf("[TimescaleDB] Total logs to migrate: %d", totalCount)

	// Use OFFSET-based pagination for efficiency
	offset := 0
	for {
		result, err := db.Exec(`
			INSERT INTO logs_hypertable (
				id, log_type, timestamp, host, client_ip, request_method, request_uri,
				request_protocol, status_code, body_bytes_sent, request_time,
				upstream_response_time, http_referer, http_user_agent, http_x_forwarded_for,
				severity, error_message, rule_id, rule_message, rule_severity, rule_data,
				attack_type, action_taken, proxy_host_id, raw_log, created_at,
				geo_country, geo_country_code, geo_city, geo_asn, geo_org,
				block_reason, bot_category, exploit_rule
			)
			SELECT
				id, log_type, timestamp, host, client_ip, request_method, request_uri,
				request_protocol, status_code, body_bytes_sent, request_time,
				upstream_response_time, http_referer, http_user_agent, http_x_forwarded_for,
				severity, error_message, rule_id, rule_message, rule_severity, rule_data,
				attack_type, action_taken, proxy_host_id, raw_log, created_at,
				geo_country, geo_country_code, geo_city, geo_asn, geo_org,
				block_reason, bot_category, exploit_rule
			FROM logs_partitioned
			ORDER BY created_at
			LIMIT $1 OFFSET $2
		`, batchSize, offset)

		if err != nil {
			log.Printf("[TimescaleDB] Error migrating batch: %v", err)
			break
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			break
		}

		totalMigrated += int(rowsAffected)
		offset += batchSize
		progress := float64(totalMigrated) / float64(totalCount) * 100
		log.Printf("[TimescaleDB] Migrated %d/%d logs (%.1f%%)...", totalMigrated, totalCount, progress)

		// Small delay to reduce load
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("[TimescaleDB] Migration complete: %d logs migrated", totalMigrated)

	// Step 4: Create indexes on hypertable
	log.Println("[TimescaleDB] Creating indexes...")
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_timestamp ON logs_hypertable (created_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_host ON logs_hypertable (host)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_type_time ON logs_hypertable (log_type, created_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_exploit ON logs_hypertable (exploit_rule) WHERE exploit_rule IS NOT NULL AND exploit_rule <> '-'`)

	// Step 5: Swap tables (rename)
	log.Println("[TimescaleDB] Swapping tables...")
	tx2, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to begin swap transaction: %v", err)
		return
	}
	defer tx2.Rollback()

	// Rename old table as backup
	_, err = tx2.Exec(`ALTER TABLE logs_partitioned RENAME TO logs_partitioned_backup`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to rename old table: %v", err)
		return
	}

	// Rename hypertable to logs_partitioned
	_, err = tx2.Exec(`ALTER TABLE logs_hypertable RENAME TO logs_partitioned`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to rename hypertable: %v", err)
		// Rollback the rename
		tx2.Rollback()
		db.Exec(`ALTER TABLE logs_partitioned_backup RENAME TO logs_partitioned`)
		return
	}

	if err = tx2.Commit(); err != nil {
		log.Printf("[TimescaleDB] Failed to commit table swap: %v", err)
		return
	}

	// Mark migration as complete
	db.Exec(`INSERT INTO schema_migrations (version) VALUES ('timescaledb_hypertable') ON CONFLICT DO NOTHING`)

	log.Println("[TimescaleDB] Migration to hypertable completed successfully!")

	// Set up compression
	db.setupTimescaleDBCompression()

	// Clean up backup table after successful migration (optional - keep for safety)
	log.Println("[TimescaleDB] Backup table 'logs_partitioned_backup' kept for safety. Drop manually when verified.")
}

// setupTimescaleDBCompression sets up compression policy for the hypertable
func (db *DB) setupTimescaleDBCompression() {
	if !db.isTimescaleDBAvailable() {
		return
	}

	// Check if logs_partitioned is a hypertable
	if !db.isHypertable("logs_partitioned") {
		log.Println("[TimescaleDB] logs_partitioned is not a hypertable, skipping compression setup")
		return
	}

	log.Println("[TimescaleDB] Setting up compression policy...")

	// Enable compression on the hypertable
	_, err := db.Exec(`
		ALTER TABLE logs_partitioned SET (
			timescaledb.compress,
			timescaledb.compress_segmentby = 'host, log_type',
			timescaledb.compress_orderby = 'created_at DESC'
		)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to enable compression: %v", err)
		return
	}

	// Add compression policy (compress chunks older than 7 days)
	_, err = db.Exec(`
		SELECT add_compression_policy('logs_partitioned', INTERVAL '7 days', if_not_exists => true)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to add compression policy: %v", err)
		return
	}

	log.Println("[TimescaleDB] Compression policy enabled: chunks older than 7 days will be compressed")

	// Show current compression status
	var compressedChunks, totalChunks int
	err = db.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE is_compressed) as compressed,
			COUNT(*) as total
		FROM timescaledb_information.chunks
		WHERE hypertable_name = 'logs_partitioned'
	`).Scan(&compressedChunks, &totalChunks)
	if err == nil {
		log.Printf("[TimescaleDB] Compression status: %d/%d chunks compressed", compressedChunks, totalChunks)
	}
}
