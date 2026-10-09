package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
)

// StorageMaintenanceRepository holds the SQL behind DiskGuard's handling of
// the database disk: where the data directory is (D1), and the emergency
// compression of closed log chunks (D3). Every statement was run against
// TimescaleDB 2.24.0 (production), 2.26.1 (dev) and 2.30.1 (what a fresh
// install pulls today).
type StorageMaintenanceRepository struct {
	db *sql.DB
}

func NewStorageMaintenanceRepository(db *sql.DB) *StorageMaintenanceRepository {
	return &StorageMaintenanceRepository{db: db}
}

// DataDirectory is SHOW data_directory: where the database container keeps
// its files, which DiskGuard measures through docker exec. It needs superuser
// or pg_read_all_settings; callers fall back to the image default.
func (r *StorageMaintenanceRepository) DataDirectory(ctx context.Context) (string, error) {
	var dir string
	err := r.db.QueryRowContext(ctx, `SELECT current_setting('data_directory')`).Scan(&dir)
	return dir, err
}

// ── the shared maintenance lock ────────────────────────────────────────────

// StorageMaintenanceLockKey is a session-level advisory lock taken by anything
// that rewrites chunks in bulk: DiskGuard's emergency compression (D3) for a
// whole pass, and the raw_log reclaim job (C6) for each chunk it rewrites.
// Rewriting a chunk needs temporary space for the new copy plus its WAL, so
// two of these at once would need twice the headroom on a disk that is short
// of it already.
//
// Hold it briefly: one pass, or one chunk. A holder that keeps it while it
// waits for something else (a vacuum horizon, a pause between chunks) blocks
// the emergency compression while the disk fills.
const StorageMaintenanceLockKey int64 = 0x6e70675f73746f72 // "npg_stor"

// maintenanceUnlockTimeout bounds the unlock: it runs on a fresh context so a
// cancelled caller still releases.
const maintenanceUnlockTimeout = 5 * time.Second

// discardUnlockTimeout bounds the best-effort pg_advisory_unlock_all of a
// session that is being ended anyway.
const discardUnlockTimeout = 2 * time.Second

// TryMaintenanceLock takes StorageMaintenanceLockKey on conn without waiting.
// false means another job holds it; wait and try again.
//
// An advisory lock belongs to the database session, so conn must be a
// connection the caller pins (sql.DB.Conn) for as long as it holds the lock,
// and the lock is released by ReleaseMaintenanceLock on that same conn.
// Closing conn does not release it: Close hands the connection back to the
// pool with its session, and the lock, still alive. It is re-entrant per
// session: every successful call needs its own release.
func TryMaintenanceLock(ctx context.Context, conn *sql.Conn) (bool, error) {
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, StorageMaintenanceLockKey).Scan(&got); err != nil {
		return false, fmt.Errorf("failed to take the storage maintenance lock: %w", err)
	}
	return got, nil
}

// ReleaseMaintenanceLock releases what TryMaintenanceLock took on conn. When
// the unlock fails, or reports that this session did not hold the lock, it
// ends conn's session (discardSession) and returns the error: the server
// drops a session's advisory locks when the session ends, whereas a session
// handed back to the pool would keep a lock the unlock left behind until the
// pool retires the connection. conn is unusable after a failed release.
func ReleaseMaintenanceLock(conn *sql.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), maintenanceUnlockTimeout)
	defer cancel()
	var released bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, StorageMaintenanceLockKey).Scan(&released); err != nil {
		discardSession(conn)
		return fmt.Errorf("failed to release the storage maintenance lock: %w", err)
	}
	if !released {
		discardSession(conn)
		return errors.New("the storage maintenance lock was not held by this session")
	}
	return nil
}

// discardSession ends conn's database session instead of handing the
// connection back to the pool, which is all sql.Conn.Close does. A Raw
// callback that reports driver.ErrBadConn makes database/sql close the driver
// connection, and the server then releases every advisory lock the session
// held. pg_advisory_unlock_all first frees them at once rather than when the
// server notices the session is gone; it is best effort (in a failed
// transaction, for one, it errors too), and the connection is closed either
// way.
func discardSession(conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), discardUnlockTimeout)
	_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock_all()`)
	cancel()
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

// WithMaintenanceLock runs fn while holding StorageMaintenanceLockKey on a
// dedicated connection, which fn compresses on. acquired=false (and fn not
// run) means another job holds the lock.
func (r *StorageMaintenanceRepository) WithMaintenanceLock(ctx context.Context, fn func(ctx context.Context, c ChunkCompressor) error) (acquired bool, err error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	// Back to the pool after the unlock below. Close alone would not release
	// the lock; a failed unlock ends the session instead.
	defer conn.Close()
	got, err := TryMaintenanceLock(ctx, conn)
	if err != nil || !got {
		return false, err
	}
	defer func() {
		if err := ReleaseMaintenanceLock(conn); err != nil {
			log.Printf("[StorageMaintenance] %s; its database session was ended instead, which frees the lock",
				database.ScrubDriverText(err.Error()))
		}
	}()
	return true, fn(ctx, connCompressor{conn: conn})
}

// IsLockTimeout reports lock_timeout firing (SQLSTATE 55P03): another job
// holds the chunk, so skip it this time rather than wait.
func IsLockTimeout(err error) bool { return sqlStateOf(err) == "55P03" }

// IsDiskFull reports SQLSTATE 53100 (disk_full), e.g. "could not extend file
// ... No space left on device". Verified on 2.24.0: compress_chunk rolls back
// cleanly, removes its partial output and leaves the chunk uncompressed.
func IsDiskFull(err error) bool { return sqlStateOf(err) == "53100" }

func sqlStateOf(err error) string {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code)
	}
	return ""
}

// ── emergency compression (D3) ─────────────────────────────────────────────

// ChunkCandidate is a closed, uncompressed chunk of a hypertable that has
// compression enabled.
type ChunkCandidate struct {
	Hypertable string
	Schema     string
	Name       string
	RangeStart time.Time
	RangeEnd   time.Time
	Bytes      int64
}

// CompressionCandidates lists closed, uncompressed chunks of at least minBytes,
// smallest first, of every hypertable that has compression enabled. "Closed"
// is range_end <= now(): rows get created_at = now() on insert, so the chunk
// containing now() is the only one still being written, and it is never
// returned.
func (r *StorageMaintenanceRepository) CompressionCandidates(ctx context.Context, minBytes int64) ([]ChunkCandidate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.hypertable_name, c.chunk_schema, c.chunk_name, c.range_start, c.range_end,
		       pg_total_relation_size(format('%I.%I', c.chunk_schema, c.chunk_name)::regclass)
		FROM timescaledb_information.chunks c
		JOIN timescaledb_information.hypertables h
		  ON h.hypertable_schema = c.hypertable_schema AND h.hypertable_name = c.hypertable_name
		WHERE h.compression_enabled
		  AND NOT c.is_compressed
		  AND c.range_end <= now()
		  AND pg_total_relation_size(format('%I.%I', c.chunk_schema, c.chunk_name)::regclass) >= $1
		ORDER BY 6 ASC`, minBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to list compression candidates: %w", err)
	}
	defer rows.Close()
	var out []ChunkCandidate
	for rows.Next() {
		var c ChunkCandidate
		if err := rows.Scan(&c.Hypertable, &c.Schema, &c.Name, &c.RangeStart, &c.RangeEnd, &c.Bytes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CompressionRatios returns before/after per hypertable from what is already
// compressed. A hypertable with nothing compressed yet is absent; the caller
// uses its floor.
func (r *StorageMaintenanceRepository) CompressionRatios(ctx context.Context) (map[string]float64, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT h.hypertable_name, s.before_compression_total_bytes, s.after_compression_total_bytes
		FROM timescaledb_information.hypertables h
		CROSS JOIN LATERAL hypertable_compression_stats(format('%I.%I', h.hypertable_schema, h.hypertable_name)::regclass) s
		WHERE h.compression_enabled`)
	if err != nil {
		return nil, fmt.Errorf("failed to read compression ratios: %w", err)
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var name string
		var before, after sql.NullInt64
		if err := rows.Scan(&name, &before, &after); err != nil {
			return nil, err
		}
		if before.Valid && after.Valid && after.Int64 > 0 {
			out[name] = float64(before.Int64) / float64(after.Int64)
		}
	}
	return out, rows.Err()
}

// CompressionPolicyRunning reports whether any compression policy job is
// mid-run. While it runs, timescaledb_information.job_stats.job_status is
// 'Running' (and pg_stat_activity shows "Columnstore Policy [<job_id>]").
func (r *StorageMaintenanceRepository) CompressionPolicyRunning(ctx context.Context) (bool, error) {
	var running bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM timescaledb_information.job_stats s
		  JOIN timescaledb_information.jobs j USING (job_id)
		  WHERE j.proc_name = 'policy_compression' AND s.job_status = 'Running')`).Scan(&running)
	if err != nil {
		return false, fmt.Errorf("failed to read compression job status: %w", err)
	}
	return running, nil
}

// ChunkCompressor compresses on the connection that holds the lock.
type ChunkCompressor interface {
	CompressChunk(ctx context.Context, schema, name string) error
}

type connCompressor struct{ conn *sql.Conn }

// CompressChunk runs in its own transaction with SET LOCAL timeouts, so the
// connection goes back to the pool with its session settings untouched
// (verified: lock_timeout and statement_timeout read "0" after a pass).
// lock_timeout 5s skips a chunk another job is busy with instead of queueing
// behind it; IsLockTimeout classifies that.
func (c connCompressor) CompressChunk(ctx context.Context, schema, name string) error {
	tx, err := c.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout = '30min'`); err != nil {
		return err
	}
	var out sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT compress_chunk(format('%I.%I', $1::text, $2::text)::regclass, if_not_compressed => true)::text`,
		schema, name).Scan(&out); err != nil {
		return err
	}
	return tx.Commit()
}
