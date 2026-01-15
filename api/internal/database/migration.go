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

		-- Host-level proxy settings (v1.3.4+)
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_connect_timeout integer DEFAULT 0;
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_send_timeout integer DEFAULT 0;
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_read_timeout integer DEFAULT 0;
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_buffering character varying(10) DEFAULT '';
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS client_max_body_size character varying(20) DEFAULT '';
		ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_max_temp_file_size character varying(20) DEFAULT '';

		-- Default exploit block rules (seed if not exists)
		INSERT INTO public.exploit_block_rules (id, category, name, pattern, pattern_type, description, severity, enabled, is_system, sort_order) VALUES
		('4243721e-8f8d-4a2b-8496-0be62d50163f', 'sql_injection', 'SQL Union Select', E'(\\"|''|` + "`" + `)(.*)(union)(.*)(select)(\\"|''|` + "`" + `)' , 'query_string', 'Blocks SQL UNION SELECT injection attempts', 'critical', true, true, 1),
		('a5cb921c-2c10-475b-8753-a56e2af1e5ba', 'sql_injection', 'SQL Commands', E'(;|\\||` + "`" + `|>|<|\\^|@)', 'query_string', 'Blocks SQL command characters (semicolon, pipe, backtick, redirects)', 'warning', true, true, 2),
		('41d1f7bf-9179-44cb-b41a-1685ce88d965', 'sql_injection', 'SQL Keywords', E'\\b(select|insert|update|delete|drop|truncate|alter|create|exec)\\b', 'query_string', 'Blocks common SQL keywords in query strings', 'warning', true, true, 3),
		('b890779f-757c-4461-a64a-dce59fb469e3', 'xss', 'Script Tags', '<script', 'query_string', 'Blocks script tag injection', 'critical', true, true, 10),
		('27ed45b1-e030-4212-bc34-edc7e13a9695', 'xss', 'Event Handlers', 'on(click|load|error|mouseover|focus|blur|change|submit)=', 'query_string', 'Blocks JavaScript event handler injection', 'critical', true, true, 11),
		('aa90285b-2986-46f9-80e6-99946327cd24', 'xss', 'Special Characters', '(;|<|>|"|%0A|%0D|%22|%3C|%3E|%00)', 'query_string', 'Blocks XSS special characters (semicolon, angle brackets, encoded newlines/quotes/null)', 'warning', true, true, 12),
		('23b31cc1-0e43-49af-b9c9-4093fd0cbcdc', 'rfi', 'URL Parameter Injection', '[a-zA-Z0-9_]=https?://', 'query_string', 'Blocks URL values in query parameters (RFI)', 'critical', true, true, 20),
		('7db3e194-8731-40c1-afaa-b7555c017a3f', 'rfi', 'Path Traversal Sequences', E'[a-zA-Z0-9_]=(\\.\\./)+', 'query_string', 'Blocks path traversal in parameters', 'critical', true, true, 21),
		('650c5e4a-c373-4d99-9cac-9e86b55bcb33', 'rfi', 'Directory Traversal', E'\\.\\./', 'query_string', 'Blocks directory traversal patterns', 'warning', true, true, 22),
		('f055a131-0596-419f-944a-cb7fa40f5c59', 'scanner', 'Nikto Scanner', 'nikto', 'user_agent', 'Blocks Nikto vulnerability scanner', 'critical', true, true, 30),
		('f13159ab-0e9a-45ea-aa4b-03fde63bb3e6', 'scanner', 'SQLMap Tool', 'sqlmap', 'user_agent', 'Blocks SQLMap SQL injection tool', 'critical', true, true, 31),
		('a9baaa39-ccd9-4f8a-82c0-e7d85f02cc2f', 'scanner', 'DirBuster', 'dirbuster', 'user_agent', 'Blocks DirBuster directory scanner', 'critical', true, true, 32),
		('8208101f-eb91-4b86-8396-f295cd16d04b', 'scanner', 'Nmap Scanner', 'nmap', 'user_agent', 'Blocks Nmap network scanner', 'warning', true, true, 33),
		('7efe59af-2d2a-405e-bbe8-951757e72ef4', 'scanner', 'Nessus Scanner', 'nessus', 'user_agent', 'Blocks Nessus vulnerability scanner', 'warning', true, true, 34),
		('9a5f6bcb-ceec-47f1-9f8c-dadb815711fa', 'scanner', 'OpenVAS Scanner', 'openvas', 'user_agent', 'Blocks OpenVAS security scanner', 'warning', true, true, 35),
		('ab3b4e85-08fd-49fe-b76d-3dc5cdf5a248', 'scanner', 'W3AF Scanner', 'w3af', 'user_agent', 'Blocks W3AF web scanner', 'warning', true, true, 36),
		('eb60d9dd-1d53-4a42-b571-cef1d1314d4d', 'scanner', 'Acunetix Scanner', 'acunetix', 'user_agent', 'Blocks Acunetix web scanner', 'warning', true, true, 37),
		('86fddcd3-30ca-43d3-bd46-34875e018395', 'scanner', 'Havij Tool', 'havij', 'user_agent', 'Blocks Havij SQL injection tool', 'critical', true, true, 38),
		('bd7eeece-8f91-41a6-b06c-1ad69900512d', 'scanner', 'AppScan', 'appscan', 'user_agent', 'Blocks IBM AppScan', 'warning', true, true, 39),
		('6ee9b160-9472-4584-9c83-8de7b955a4b5', 'scanner', 'WebScarab', 'webscarab', 'user_agent', 'Blocks WebScarab proxy', 'warning', true, true, 40),
		('e78e2ef1-d710-409b-8a44-a03db3999b19', 'scanner', 'WebInspect', 'webinspect', 'user_agent', 'Blocks HP WebInspect', 'warning', true, true, 41),
		('8ec83a35-dea8-4f51-9185-37035f0a4501', 'http_method', 'Dangerous Methods', '^(TRACE|TRACK|DEBUG|CONNECT)$', 'request_method', 'Blocks dangerous HTTP methods', 'warning', true, true, 50)
		ON CONFLICT (id) DO NOTHING;
	`
	_, err = db.Exec(upgradeSQL)
	if err != nil {
		log.Printf("Warning: upgrade statements had errors (may be already applied): %v", err)
	}

	// Run 006_fix_numeric_overflow migration for existing installations (Issue #29 fix)
	if err := db.runNumericOverflowMigration(); err != nil {
		log.Printf("Warning: numeric overflow migration had issues: %v", err)
	}

	// Migrate logs table to logs_partitioned in background (for existing installations)
	// This allows API to start immediately while migration runs
	go db.migrateLogsToPartitioned()

	// Migrate to TimescaleDB hypertable in background (for existing installations)
	go db.migrateToTimescaleDB()

	// Migrate other log tables to hypertables
	go db.migrateLogTablesToHypertables()

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

// migrateLogTablesToHypertables migrates system_logs, challenge_logs, audit_logs to hypertables
func (db *DB) migrateLogTablesToHypertables() {
	// Wait for main migration to complete
	time.Sleep(10 * time.Second)

	if !db.isTimescaleDBAvailable() {
		log.Println("[TimescaleDB] Extension not available, skipping log tables migration")
		return
	}

	// Define log tables to migrate
	logTables := []struct {
		name      string
		segmentBy string
	}{
		{"system_logs", "source, level"},
		{"challenge_logs", "result"},
		{"audit_logs", "action"},
	}

	for _, table := range logTables {
		db.migrateTableToHypertable(table.name, table.segmentBy)
	}
}

// migrateTableToHypertable converts a regular table to a TimescaleDB hypertable
func (db *DB) migrateTableToHypertable(tableName, segmentBy string) {
	migrationKey := fmt.Sprintf("timescaledb_%s", tableName)

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationKey).Scan(&migrated)
	if err == nil && migrated {
		log.Printf("[TimescaleDB] %s already migrated to hypertable", tableName)
		db.setupTableCompression(tableName, segmentBy)
		return
	}

	// Check if table exists
	var tableExists bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)
	`, tableName).Scan(&tableExists)
	if err != nil || !tableExists {
		log.Printf("[TimescaleDB] Table %s not found, skipping", tableName)
		return
	}

	// Check if already a hypertable
	if db.isHypertable(tableName) {
		log.Printf("[TimescaleDB] %s is already a hypertable", tableName)
		db.setupTableCompression(tableName, segmentBy)
		db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationKey)
		return
	}

	log.Printf("[TimescaleDB] Starting migration of %s to hypertable...", tableName)

	// Get row count
	var rowCount int64
	db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, tableName)).Scan(&rowCount)
	log.Printf("[TimescaleDB] %s has %d rows", tableName, rowCount)

	// For tables with foreign keys, we need to handle them carefully
	// Drop foreign key constraints temporarily
	var fkConstraints []struct {
		name       string
		definition string
	}
	rows, err := db.Query(`
		SELECT conname, pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = $1::regclass AND contype = 'f'
	`, tableName)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, def string
			rows.Scan(&name, &def)
			fkConstraints = append(fkConstraints, struct {
				name       string
				definition string
			}{name, def})
		}
	}

	// Drop primary key (will recreate with created_at)
	db.Exec(fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_pkey`, tableName, tableName))

	// Drop foreign keys temporarily
	for _, fk := range fkConstraints {
		log.Printf("[TimescaleDB] Dropping FK %s temporarily", fk.name)
		db.Exec(fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s`, tableName, fk.name))
	}

	// Convert to hypertable
	_, err = db.Exec(fmt.Sprintf(`
		SELECT create_hypertable(
			'%s',
			by_range('created_at', INTERVAL '1 day'),
			migrate_data => true,
			if_not_exists => true
		)
	`, tableName))
	if err != nil {
		log.Printf("[TimescaleDB] Failed to convert %s to hypertable: %v", tableName, err)
		// Restore primary key
		db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id)`, tableName))
		// Restore foreign keys
		for _, fk := range fkConstraints {
			db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s %s`, tableName, fk.name, fk.definition))
		}
		return
	}

	log.Printf("[TimescaleDB] %s converted to hypertable successfully", tableName)

	// Recreate primary key with created_at (required for hypertables)
	db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id, created_at)`, tableName))

	// Restore foreign keys
	for _, fk := range fkConstraints {
		log.Printf("[TimescaleDB] Restoring FK %s", fk.name)
		_, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s %s`, tableName, fk.name, fk.definition))
		if err != nil {
			log.Printf("[TimescaleDB] Warning: failed to restore FK %s: %v", fk.name, err)
		}
	}

	// Mark as migrated
	db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationKey)

	// Setup compression
	db.setupTableCompression(tableName, segmentBy)
}

// setupTableCompression sets up compression for a specific hypertable
func (db *DB) setupTableCompression(tableName, segmentBy string) {
	if !db.isHypertable(tableName) {
		return
	}

	// Check if compression is already enabled
	var compressionEnabled bool
	db.QueryRow(`
		SELECT compression_enabled
		FROM timescaledb_information.hypertables
		WHERE hypertable_name = $1
	`, tableName).Scan(&compressionEnabled)

	if compressionEnabled {
		log.Printf("[TimescaleDB] Compression already enabled for %s", tableName)
		return
	}

	log.Printf("[TimescaleDB] Setting up compression for %s...", tableName)

	// Enable compression
	_, err := db.Exec(fmt.Sprintf(`
		ALTER TABLE %s SET (
			timescaledb.compress,
			timescaledb.compress_segmentby = '%s',
			timescaledb.compress_orderby = 'created_at DESC'
		)
	`, tableName, segmentBy))
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to enable compression for %s: %v", tableName, err)
		return
	}

	// Add compression policy
	_, err = db.Exec(fmt.Sprintf(`
		SELECT add_compression_policy('%s', INTERVAL '7 days', if_not_exists => true)
	`, tableName))
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to add compression policy for %s: %v", tableName, err)
		return
	}

	log.Printf("[TimescaleDB] Compression enabled for %s", tableName)

	// Compress existing old chunks immediately
	db.Exec(fmt.Sprintf(`SELECT compress_chunk(c) FROM show_chunks('%s', older_than => INTERVAL '7 days') c`, tableName))

	// Show compression status
	var compressedChunks, totalChunks int
	err = db.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE is_compressed) as compressed,
			COUNT(*) as total
		FROM timescaledb_information.chunks
		WHERE hypertable_name = $1
	`, tableName).Scan(&compressedChunks, &totalChunks)
	if err == nil && totalChunks > 0 {
		log.Printf("[TimescaleDB] %s compression status: %d/%d chunks compressed", tableName, compressedChunks, totalChunks)
	}
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

// runNumericOverflowMigration fixes the numeric field overflow issue (Issue #29)
// This migration changes request_time and upstream_response_time from NUMERIC(10,6) to DOUBLE PRECISION
func (db *DB) runNumericOverflowMigration() error {
	const migrationVersion = "006_fix_numeric_overflow"

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationVersion).Scan(&migrated)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	if migrated {
		log.Printf("[Migration] %s already applied", migrationVersion)
		return nil
	}

	// Check if logs_partitioned table exists
	var tableExists bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs_partitioned'
		)
	`).Scan(&tableExists)
	if err != nil || !tableExists {
		log.Printf("[Migration] logs_partitioned table not found, skipping %s", migrationVersion)
		// Mark as applied since new installations already have DOUBLE PRECISION
		db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
		return nil
	}

	// Check current column type
	var dataType string
	err = db.QueryRow(`
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'logs_partitioned' AND column_name = 'request_time'
	`).Scan(&dataType)
	if err != nil {
		return fmt.Errorf("failed to check column type: %w", err)
	}

	// If already DOUBLE PRECISION, mark as migrated and skip
	if dataType == "double precision" {
		log.Printf("[Migration] request_time already uses double precision, marking %s as applied", migrationVersion)
		db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
		return nil
	}

	log.Printf("[Migration] Starting %s: changing NUMERIC to DOUBLE PRECISION...", migrationVersion)
	log.Printf("[Migration] Current request_time type: %s", dataType)

	// Check if this is a TimescaleDB hypertable
	isHypertable := db.isHypertable("logs_partitioned")

	if isHypertable {
		log.Println("[Migration] logs_partitioned is a TimescaleDB hypertable, handling compression...")

		// Step 1: Decompress all chunks
		log.Println("[Migration] Decompressing compressed chunks...")
		_, err = db.Exec(`
			DO $$
			DECLARE
				chunk_record RECORD;
				decompressed_count INT := 0;
			BEGIN
				FOR chunk_record IN
					SELECT format('%I.%I', chunk_schema, chunk_name) as full_name
					FROM timescaledb_information.chunks
					WHERE hypertable_name = 'logs_partitioned' AND is_compressed = true
				LOOP
					EXECUTE format('SELECT decompress_chunk(%L, true)', chunk_record.full_name);
					decompressed_count := decompressed_count + 1;
					RAISE NOTICE 'Decompressed: %', chunk_record.full_name;
				END LOOP;
				RAISE NOTICE 'Total chunks decompressed: %', decompressed_count;
			END;
			$$
		`)
		if err != nil {
			log.Printf("[Migration] Warning: error during decompression (may be no compressed chunks): %v", err)
		}

		// Step 2: Disable compression temporarily
		log.Println("[Migration] Disabling compression temporarily...")
		_, err = db.Exec(`ALTER TABLE logs_partitioned SET (timescaledb.compress = false)`)
		if err != nil {
			log.Printf("[Migration] Warning: failed to disable compression: %v", err)
		}
	}

	// Step 3: Alter column types to DOUBLE PRECISION
	log.Println("[Migration] Altering column types to DOUBLE PRECISION...")
	_, err = db.Exec(`
		ALTER TABLE logs_partitioned
			ALTER COLUMN request_time TYPE DOUBLE PRECISION,
			ALTER COLUMN upstream_response_time TYPE DOUBLE PRECISION
	`)
	if err != nil {
		return fmt.Errorf("failed to alter column types: %w", err)
	}
	log.Println("[Migration] Column types changed successfully")

	if isHypertable {
		// Step 4: Re-enable compression with same settings
		log.Println("[Migration] Re-enabling compression...")
		_, err = db.Exec(`
			ALTER TABLE logs_partitioned SET (
				timescaledb.compress,
				timescaledb.compress_segmentby = 'host, log_type',
				timescaledb.compress_orderby = 'created_at DESC'
			)
		`)
		if err != nil {
			log.Printf("[Migration] Warning: failed to re-enable compression: %v", err)
		}

		// Step 5: Recompress old chunks (optional, in background)
		log.Println("[Migration] Recompressing chunks older than 7 days in background...")
		go func() {
			time.Sleep(5 * time.Second)
			_, err := db.Exec(`SELECT compress_chunk(c) FROM show_chunks('logs_partitioned', older_than => INTERVAL '7 days') c`)
			if err != nil {
				log.Printf("[Migration] Warning: background recompression had issues: %v", err)
			} else {
				log.Println("[Migration] Background recompression completed")
			}
		}()
	}

	// Mark migration as complete
	_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	log.Printf("[Migration] %s completed successfully!", migrationVersion)
	return nil
}
