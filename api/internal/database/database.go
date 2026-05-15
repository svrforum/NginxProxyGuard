package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq"
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
}

func New(databaseURL string) (*DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(40)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	return &DB{DB: db, bgCtx: bgCtx, bgCancel: bgCancel}, nil
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
