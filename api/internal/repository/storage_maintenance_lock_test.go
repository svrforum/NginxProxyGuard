package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/lib/pq"
)

// Closing a *sql.Conn hands the connection back to the pool with its session
// alive, and an advisory lock belongs to the session. A release that did not
// release must therefore end the session, or the lock stays held by an idle
// pooled connection — blocking the emergency compression and the raw_log
// reclaim — until the pool happens to retire it.

func expectMaintenanceLock(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT pg_try_advisory_lock\(\$1\)`).WithArgs(StorageMaintenanceLockKey).
		WillReturnRows(sqlmock.NewRows([]string{"pg_try_advisory_lock"}).AddRow(true))
}

func expectMaintenanceUnlock(mock sqlmock.Sqlmock) *sqlmock.ExpectedQuery {
	return mock.ExpectQuery(`SELECT pg_advisory_unlock\(\$1\)`).WithArgs(StorageMaintenanceLockKey)
}

func TestReleaseMaintenanceLockEndsTheSessionWhenTheUnlockFails(t *testing.T) {
	for name, unlock := range map[string]func(*sqlmock.ExpectedQuery){
		"the unlock fails": func(q *sqlmock.ExpectedQuery) {
			q.WillReturnError(errors.New("pq: current transaction is aborted, commands ignored until end of transaction block"))
		},
		"the session did not hold it": func(q *sqlmock.ExpectedQuery) {
			q.WillReturnRows(sqlmock.NewRows([]string{"pg_advisory_unlock"}).AddRow(false))
		},
	} {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ctx := context.Background()
			expectMaintenanceLock(mock)
			unlock(expectMaintenanceUnlock(mock))
			mock.ExpectExec(`SELECT pg_advisory_unlock_all\(\)`).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectClose() // the driver connection itself, not db

			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := TryMaintenanceLock(ctx, conn); !got || err != nil {
				t.Fatalf("TryMaintenanceLock = %v, %v", got, err)
			}
			if err := ReleaseMaintenanceLock(conn); err == nil {
				t.Fatal("a release that did not release reported success")
			}
			_ = conn.Close()
			if n := db.Stats().OpenConnections; n != 0 {
				t.Fatalf("%d connection(s) left in the pool; the session that may still hold the lock must end", n)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWithMaintenanceLockEndsTheSessionWhenTheUnlockFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectMaintenanceLock(mock)
	expectMaintenanceUnlock(mock).WillReturnError(errors.New("pq: current transaction is aborted, commands ignored until end of transaction block"))
	mock.ExpectExec(`SELECT pg_advisory_unlock_all\(\)`).WillReturnError(errors.New("pq: current transaction is aborted, commands ignored until end of transaction block"))
	mock.ExpectClose()

	ran := false
	acquired, err := NewStorageMaintenanceRepository(db).WithMaintenanceLock(context.Background(), func(context.Context, ChunkCompressor) error {
		ran = true
		return nil
	})
	if !acquired || err != nil || !ran {
		t.Fatalf("acquired %v, err %v, ran %v", acquired, err, ran)
	}
	if n := db.Stats().OpenConnections; n != 0 {
		t.Fatalf("%d connection(s) left in the pool after a failed unlock", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A lock that was released leaves a healthy session, which goes back to the
// pool as usual.
func TestWithMaintenanceLockKeepsTheConnectionAfterARelease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectMaintenanceLock(mock)
	expectMaintenanceUnlock(mock).WillReturnRows(sqlmock.NewRows([]string{"pg_advisory_unlock"}).AddRow(true))

	if acquired, err := NewStorageMaintenanceRepository(db).WithMaintenanceLock(context.Background(),
		func(context.Context, ChunkCompressor) error { return nil }); !acquired || err != nil {
		t.Fatalf("acquired %v, err %v", acquired, err)
	}
	if st := db.Stats(); st.OpenConnections != 1 || st.Idle != 1 {
		t.Fatalf("pool after a clean release: %+v, want the connection back and idle", st)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Against a real server: a session whose unlock fails — here because it was
// left in a failed transaction, which keeps the session and its lock alive —
// must not keep the lock, nor go back to the pool. Skipped without
// NPG_TEST_DATABASE_URL, as in CI; any PostgreSQL will do.
func TestMaintenanceLockFailedReleaseAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed storage maintenance lock test")
	}
	open := func() *sql.DB {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err := db.Ping(); err != nil {
			t.Fatalf("ping test database: %v", err)
		}
		return db
	}
	db, observer := open(), open()
	db.SetMaxOpenConns(1) // whatever the pool hands out next is the session that held the lock, if it survived
	ctx := context.Background()

	var pid int
	acquired, err := NewStorageMaintenanceRepository(db).WithMaintenanceLock(ctx, func(ctx context.Context, c ChunkCompressor) error {
		conn := c.(connCompressor).conn
		if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `BEGIN`); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `SELECT 1/0`); err == nil {
			return errors.New("the failing statement succeeded")
		}
		return nil
	})
	if !acquired || err != nil {
		t.Fatalf("acquired %v, err %v", acquired, err)
	}

	// Another session can take the lock, at once rather than whenever the
	// pool retires a connection.
	oc, err := observer.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer oc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := TryMaintenanceLock(ctx, oc)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			if err := ReleaseMaintenanceLock(oc); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the storage maintenance lock is still held by session %d after its release failed", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The pool does not hand that session out again.
	var next int
	if err := db.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&next); err != nil {
		t.Fatalf("the pool handed out a broken session: %v", err)
	}
	if next == pid {
		t.Fatalf("session %d went back to the pool", pid)
	}
}
