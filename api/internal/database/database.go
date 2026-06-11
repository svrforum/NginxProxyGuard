package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Initial-connect retry budget. TimescaleDB crash recovery (WAL replay after
// power loss) can outlast the compose healthcheck window on large installs;
// a bounded in-app retry lets the api ride it out instead of relying solely
// on Docker restart semantics.
const (
	connectRetryBudget   = 60 * time.Second
	connectRetryInterval = 2 * time.Second
)

type DB struct {
	*sql.DB

	// bgCtx is cancelled by Close() so any background migration goroutines
	// spawned from RunMigrations honour graceful shutdown instead of
	// running unconstrained for up to their 30-minute timeout. Without
	// this they would happily continue draining logs_p_default across a
	// SIGTERM, risking partial-write corruption on container restart.
	bgCtx    context.Context
	bgCancel context.CancelFunc
	bgWG     sync.WaitGroup

	// Upgrade-migration failures recorded by RunMigrations' warn-and-continue
	// path. count > 0 means the schema may be partially migrated (affected
	// features can 500 until the next boot retries the idempotent statements).
	// Surfaced via MigrationHealth(); must never fail the liveness probe.
	migMu           sync.Mutex
	migFailureCount int
	migLastError    string
}

func New(databaseURL string) (*DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Default pool sizing. Bootstrap can override via SetPool() with values
	// from NPG_DB_MAX_OPEN / NPG_DB_MAX_IDLE env vars.
	db.SetMaxOpenConns(80)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection, retrying within a bounded budget (see constants
	// above) so a recovering database doesn't fail the whole container boot.
	deadline := time.Now().Add(connectRetryBudget)
	for {
		err = db.Ping()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = db.Close()
			return nil, fmt.Errorf("failed to ping database: %w", err)
		}
		log.Printf("[DB] Database not reachable yet (%v) — retrying in %v", err, connectRetryInterval)
		time.Sleep(connectRetryInterval)
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	return &DB{DB: db, bgCtx: bgCtx, bgCancel: bgCancel}, nil
}

// RecordMigrationFailure accumulates a failed upgrade-migration statement.
// Called from RunMigrations' per-statement warn-and-continue loop; the
// statements are idempotent and retried on every boot, so this state always
// reflects the current process' boot.
func (db *DB) RecordMigrationFailure(desc string, err error) {
	db.migMu.Lock()
	defer db.migMu.Unlock()
	db.migFailureCount++
	db.migLastError = fmt.Sprintf("%s: %v", desc, err)
}

// MigrationHealth reports upgrade-migration failures from this boot:
// count == 0 means every upgrade statement applied cleanly. Intended for the
// detailed health endpoint to report a degraded (NOT unhealthy) state — the
// liveness probe must stay green while the app serves.
func (db *DB) MigrationHealth() (count int, lastError string) {
	db.migMu.Lock()
	defer db.migMu.Unlock()
	return db.migFailureCount, db.migLastError
}

// SetPool overrides the default connection pool sizing. Idle is clamped to
// ≤ maxOpen so the pool config is internally consistent regardless of env input.
func (db *DB) SetPool(maxOpen, maxIdle int) {
	if maxOpen <= 0 {
		return
	}
	if maxIdle <= 0 {
		maxIdle = maxOpen / 4
	}
	if maxIdle > maxOpen {
		maxIdle = maxOpen
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
}

// BackgroundContext returns a context that is cancelled when the DB is
// closed. Long-running background migration goroutines should derive their
// timeout from this context so SIGTERM stops them cleanly.
func (db *DB) BackgroundContext() context.Context {
	return db.bgCtx
}

// TrackBackground registers a background goroutine that Close() should wait
// for. Each caller must call db.bgWG.Done() (via defer) inside its goroutine.
func (db *DB) TrackBackground() {
	db.bgWG.Add(1)
}

// BackgroundDone signals one tracked background goroutine has finished.
func (db *DB) BackgroundDone() {
	db.bgWG.Done()
}

func (db *DB) Close() error {
	// Signal background goroutines first, then wait briefly for them to
	// unwind. Cap the wait so a stuck migration cannot block process exit.
	db.bgCancel()
	done := make(chan struct{})
	go func() {
		db.bgWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return db.DB.Close()
}

func (db *DB) Health() error {
	return db.Ping()
}
