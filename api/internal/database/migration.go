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
	`
	_, err = db.Exec(upgradeSQL)
	if err != nil {
		log.Printf("Warning: upgrade statements had errors (may be already applied): %v", err)
	}

	log.Println("Schema migration completed")
	return nil
}
