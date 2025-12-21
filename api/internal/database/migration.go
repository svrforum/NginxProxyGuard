package database

import (
	"embed"
	"fmt"
	"log"
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

	log.Println("Schema migration completed")
	return nil
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
