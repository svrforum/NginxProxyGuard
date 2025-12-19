package database

import (
	"embed"
	"fmt"
	"log"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// RunMigrations executes the idempotent schema migration
// Only 001_init.sql is used - it's designed to be run multiple times safely
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

	// Always run 001_init.sql - it's fully idempotent
	// Uses CREATE TABLE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, etc.
	content, err := migrationFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		return fmt.Errorf("failed to read 001_init.sql: %w", err)
	}

	log.Println("Running schema migration (001_init.sql)...")
	_, err = db.Exec(string(content))
	if err != nil {
		return fmt.Errorf("failed to apply schema migration: %w", err)
	}

	// Update version tracking
	_, err = db.Exec(`
		INSERT INTO schema_migrations (version, applied_at)
		VALUES ('001_init', NOW())
		ON CONFLICT (version) DO UPDATE SET applied_at = NOW()
	`)
	if err != nil {
		return fmt.Errorf("failed to update migration version: %w", err)
	}

	log.Println("Schema migration completed successfully")
	return nil
}
