package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"time"

	"nginx-proxy-guard/internal/database"
)

// Raw log reclaim: removing the raw_log copies of access and error lines that
// old compressed log history still carries.
//
// Rewriting a compressed day through the hypertable (decompress, UPDATE,
// recompress) costs about 17 KB of WAL per row; UPDATE through the hypertable
// fails at 100k decompressed rows and saves nothing. What works is the
// compressed relation itself: segmentby includes log_type, so every batch
// holds one log type, and
//
//	UPDATE <compressed> SET raw_log = NULL WHERE log_type <> 'modsec' AND raw_log IS NOT NULL
//
// empties the access/error batches' raw_log in one short transaction (3,003
// batches in 8.6 s, 9 MB of WAL for a 3M-row day). The space comes back with
// VACUUM FULL of that relation (29 s, 498 MB -> 267 MB), but only once no
// snapshot older than the UPDATE exists anywhere in the cluster: until then
// it copies the old versions as RECENTLY_DEAD and frees nothing, silently.
// Every row decompresses to the same values as before except raw_log, and
// ModSecurity batches keep theirs. Measured on TimescaleDB 2.24.0 and 2.30.1.
//
// The compressed relation is looked up in the catalog each time
// (compression_settings.compress_relid; it is renamed and recreated when a day
// is decompressed and compressed again), never taken from input, and its name
// must be a plain identifier pair before it is put into SQL.

// RawLogReclaimJobLockKey is the session advisory lock the one runner of the
// reclaim job holds for its whole run. It is not StorageMaintenanceLockKey:
// that one the runner takes only around each chunk rewrite, so the emergency
// compression is never kept waiting behind a pause or a horizon wait.
const RawLogReclaimJobLockKey int64 = 0x6e70675f72617772 // "npg_rawr"

// Which days are old enough. The compression policy compresses a day once it
// is a day old; two leaves a day of margin for late rows.
const reclaimMinAgeSQL = `interval '2 days'`

// Why a day is left alone (raw_log_reclaim_chunks.last_error of a skipped day).
const (
	ReclaimSkipNotCompressed = "not compressed"
	ReclaimSkipPartial       = "rows were added after it was compressed (partially compressed)"
	ReclaimSkipTooRecent     = "newer than two days"
	ReclaimSkipSegmentBy     = "compressed without log_type in segmentby"
	ReclaimSkipLayout        = "its compressed table does not have the expected columns"
)

// Why the job cannot run on this database (LogRawReclaimStatus.UnsupportedReason).
const (
	ReclaimUnsupportedNoTimescale   = "timescaledb_missing"
	ReclaimUnsupportedCatalog       = "catalog_changed"
	ReclaimUnsupportedNotHypertable = "not_hypertable"
	ReclaimUnsupportedNoCompression = "compression_disabled"
	ReclaimUnsupportedSegmentBy     = "segmentby_without_log_type"
)

// validRelName accepts what format('%I.%I') prints for names that need no
// quoting — every TimescaleDB-generated name (compress_hyper_2_3_chunk on
// 2.24, _hyper_1_42_chunk_compressed on 2.30). Anything else is refused rather
// than interpolated.
var validRelName = regexp.MustCompile(`^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$`)

// ValidReclaimRelation reports whether rel may be put into SQL as is.
func ValidReclaimRelation(rel string) bool { return validRelName.MatchString(rel) }

type RawLogReclaimRepository struct {
	db *sql.DB
	// The hypertable whose history is reclaimed: public.logs_partitioned,
	// overridden only by tests that build their own.
	schema, table string
}

func NewRawLogReclaimRepository(db *sql.DB) *RawLogReclaimRepository {
	return &RawLogReclaimRepository{db: db, schema: "public", table: "logs_partitioned"}
}

// ── catalog ────────────────────────────────────────────────────────────────

// Support checks every catalog piece the job reads. ok=false with a reason
// code means the job must not run here; it never guesses.
func (r *RawLogReclaimRepository) Support(ctx context.Context) (ok bool, reason string, err error) {
	var ext bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&ext); err != nil {
		return false, "", fmt.Errorf("failed to check for TimescaleDB: %w", err)
	}
	if !ext {
		return false, ReclaimUnsupportedNoTimescale, nil
	}
	var pieces bool
	if err := r.db.QueryRowContext(ctx, `
		SELECT to_regclass('_timescaledb_catalog.compression_settings') IS NOT NULL
		   AND to_regclass('timescaledb_information.chunks') IS NOT NULL
		   AND to_regclass('timescaledb_information.hypertables') IS NOT NULL
		   AND to_regprocedure('_timescaledb_functions.chunk_status(regclass)') IS NOT NULL
		   AND to_regtype('_timescaledb_internal.compressed_data') IS NOT NULL
		   AND (SELECT count(*) FROM pg_attribute
		         WHERE attrelid = to_regclass('_timescaledb_catalog.compression_settings')
		           AND attname IN ('relid', 'compress_relid', 'segmentby') AND NOT attisdropped) = 3`).Scan(&pieces); err != nil {
		return false, "", fmt.Errorf("failed to check the TimescaleDB catalog: %w", err)
	}
	if !pieces {
		return false, ReclaimUnsupportedCatalog, nil
	}
	var compression bool
	err = r.db.QueryRowContext(ctx, `
		SELECT compression_enabled FROM timescaledb_information.hypertables
		 WHERE hypertable_schema = $1 AND hypertable_name = $2`, r.schema, r.table).Scan(&compression)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ReclaimUnsupportedNotHypertable, nil
	}
	if err != nil {
		return false, "", fmt.Errorf("failed to read the log hypertable: %w", err)
	}
	if !compression {
		return false, ReclaimUnsupportedNoCompression, nil
	}
	var segOK bool
	err = r.db.QueryRowContext(ctx, `
		SELECT COALESCE('log_type' = ANY (segmentby), false) FROM _timescaledb_catalog.compression_settings
		 WHERE relid = to_regclass(format('%I.%I', $1::text, $2::text))`, r.schema, r.table).Scan(&segOK)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, "", fmt.Errorf("failed to read the log compression settings: %w", err)
	}
	if !segOK {
		return false, ReclaimUnsupportedSegmentBy, nil
	}
	return true, "", nil
}

// ReclaimChunkInfo is one day (chunk) of the log hypertable as the catalog
// describes it now.
type ReclaimChunkInfo struct {
	Name             string // schema-qualified chunk, format('%I.%I'): the raw_log_reclaim_chunks key
	RangeStart       time.Time
	RangeEnd         time.Time
	Compressed       bool
	Partial          bool // rows were added after compression (chunk_status bit 8)
	OldEnough        bool // range_end older than two days
	SegmentByLogType bool
	CompressedRel    string // schema-qualified compressed relation; "" when there is none
	Bytes            int64  // pg_total_relation_size of the compressed relation
	LayoutOK         bool   // raw_log is a compressed column and log_type a plain one
}

// SkipReason is "" when the day can be reclaimed, else why not.
func (c ReclaimChunkInfo) SkipReason() string {
	switch {
	case !c.Compressed || c.CompressedRel == "":
		return ReclaimSkipNotCompressed
	case c.Partial:
		return ReclaimSkipPartial
	case !c.OldEnough:
		return ReclaimSkipTooRecent
	case !c.SegmentByLogType:
		return ReclaimSkipSegmentBy
	case !c.LayoutOK || !ValidReclaimRelation(c.CompressedRel):
		return ReclaimSkipLayout
	}
	return ""
}

// chunkInfoSQL lists the hypertable's chunks with what decides whether each
// can be reclaimed. format('%I', NULL) raises, hence the CASE.
const chunkInfoSQL = `
	SELECT format('%I.%I', ch.chunk_schema, ch.chunk_name),
	       ch.range_start, ch.range_end, COALESCE(ch.is_compressed, false),
	       COALESCE(ch.range_end < now() - ` + reclaimMinAgeSQL + `, false),
	       COALESCE((_timescaledb_functions.chunk_status(format('%I.%I', ch.chunk_schema, ch.chunk_name)::regclass) & 8) <> 0, false),
	       COALESCE('log_type' = ANY (cs.segmentby), false),
	       CASE WHEN c.oid IS NULL THEN '' ELSE format('%I.%I', n.nspname, c.relname) END,
	       COALESCE(pg_total_relation_size(cs.compress_relid), 0),
	       (SELECT count(*) = 2 FROM pg_attribute a
	         WHERE a.attrelid = cs.compress_relid AND NOT a.attisdropped
	           AND ((a.attname = 'raw_log' AND a.atttypid = to_regtype('_timescaledb_internal.compressed_data'))
	             OR (a.attname = 'log_type' AND a.atttypid IS DISTINCT FROM to_regtype('_timescaledb_internal.compressed_data'))))
	  FROM timescaledb_information.chunks ch
	  LEFT JOIN _timescaledb_catalog.compression_settings cs
	         ON ch.is_compressed AND cs.relid = format('%I.%I', ch.chunk_schema, ch.chunk_name)::regclass
	  LEFT JOIN pg_class c ON c.oid = cs.compress_relid
	  LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE ch.hypertable_schema = $1 AND ch.hypertable_name = $2`

func scanChunkInfo(sc interface{ Scan(...any) error }) (ReclaimChunkInfo, error) {
	var c ReclaimChunkInfo
	err := sc.Scan(&c.Name, &c.RangeStart, &c.RangeEnd, &c.Compressed, &c.OldEnough, &c.Partial,
		&c.SegmentByLogType, &c.CompressedRel, &c.Bytes, &c.LayoutOK)
	return c, err
}

// ListChunks returns every chunk of the log hypertable, oldest first.
func (r *RawLogReclaimRepository) ListChunks(ctx context.Context) ([]ReclaimChunkInfo, error) {
	rows, err := r.db.QueryContext(ctx, chunkInfoSQL+` ORDER BY ch.range_start`, r.schema, r.table)
	if err != nil {
		return nil, fmt.Errorf("failed to list log chunks: %w", err)
	}
	defer rows.Close()
	var out []ReclaimChunkInfo
	for rows.Next() {
		c, err := scanChunkInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LookupChunk re-reads one chunk right before the job works on it. nil means
// the chunk no longer exists (retention dropped it).
func (r *RawLogReclaimRepository) LookupChunk(ctx context.Context, name string) (*ReclaimChunkInfo, error) {
	c, err := scanChunkInfo(r.db.QueryRowContext(ctx,
		chunkInfoSQL+` AND format('%I.%I', ch.chunk_schema, ch.chunk_name) = $3`, r.schema, r.table, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up log chunk: %w", err)
	}
	return &c, nil
}

// RawLogStats is what a compressed day holds in raw_log, as stored (after
// TOAST compression) — read from the TOAST pointers, without fetching them.
type RawLogStats struct {
	RawBytes       int64 // access/error raw_log: what the job removes
	ModSecBytes    int64 // ModSecurity raw_log: kept
	PendingBatches int64 // access/error batches whose raw_log is not NULL yet
}

// RawLogStats reads one compressed relation (about 2 ms per prod-size day).
func (r *RawLogReclaimRepository) RawLogStats(ctx context.Context, rel string) (RawLogStats, error) {
	var st RawLogStats
	if !ValidReclaimRelation(rel) {
		return st, fmt.Errorf("refusing unexpected relation name %q", rel)
	}
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(sum(pg_column_size(raw_log)) FILTER (WHERE log_type <> 'modsec'), 0)::bigint,
		       COALESCE(sum(pg_column_size(raw_log)) FILTER (WHERE log_type = 'modsec'), 0)::bigint,
		       count(*) FILTER (WHERE log_type <> 'modsec' AND raw_log IS NOT NULL)
		  FROM `+rel).Scan(&st.RawBytes, &st.ModSecBytes, &st.PendingBatches)
	if err != nil {
		return st, fmt.Errorf("failed to measure raw_log: %w", err)
	}
	return st, nil
}

// SnapshotBlockers describes what still holds the vacuum horizon at or before
// a transaction: while Count > 0, VACUUM FULL would keep the removed values.
type SnapshotBlockers struct {
	Count int
	// The oldest one: a backend (PID > 0), a prepared transaction or a
	// replication slot.
	PID   int
	Kind  string
	State string
	Since *time.Time
}

// OlderSnapshots counts what could still see the versions transaction xid
// replaced: a snapshot (backend_xmin) or a running transaction (backend_xid)
// at or before it, in any database of the cluster, plus prepared transactions
// and replication slots holding xmin. Seeing other sessions' backend_xmin
// needs superuser or pg_read_all_stats; with less this under-counts and the
// size check after VACUUM FULL catches the result.
func (r *RawLogReclaimRepository) OlderSnapshots(ctx context.Context, xid int64) (SnapshotBlockers, error) {
	var b SnapshotBlockers
	var pid sql.NullInt64
	var since sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		WITH x AS (SELECT $1::text::xid AS v),
		blockers AS (
		  SELECT a.pid, COALESCE(a.backend_type, '') AS kind, COALESCE(a.state, '') AS state, a.xact_start AS since
		    FROM pg_stat_activity a, x
		   WHERE a.pid <> pg_backend_pid()
		     AND ((a.backend_xmin IS NOT NULL AND age(a.backend_xmin) >= age(x.v))
		       OR (a.backend_xid IS NOT NULL AND age(a.backend_xid) >= age(x.v)))
		  UNION ALL
		  SELECT NULL, 'prepared transaction', '', p.prepared
		    FROM pg_prepared_xacts p, x WHERE age(p.transaction) >= age(x.v)
		  UNION ALL
		  SELECT NULL, 'replication slot ' || s.slot_name, '', NULL
		    FROM pg_replication_slots s, x WHERE s.xmin IS NOT NULL AND age(s.xmin) >= age(x.v))
		SELECT (SELECT count(*) FROM blockers), pid, kind, state, since
		  FROM blockers ORDER BY since NULLS LAST LIMIT 1`, fmt.Sprint(xid)).Scan(&b.Count, &pid, &b.Kind, &b.State, &since)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotBlockers{}, nil
	}
	if err != nil {
		return b, fmt.Errorf("failed to check for older transactions: %w", err)
	}
	b.PID = int(pid.Int64)
	if since.Valid {
		t := since.Time
		b.Since = &t
	}
	return b, nil
}

// HorizonNow stands in for the xid of an UPDATE that committed but was never
// recorded: the newest xid already assigned. Nothing that could still see the
// lost UPDATE's old versions is newer than it, so waiting on it waits for
// every transaction open now — longer than needed, never too short.
func (r *RawLogReclaimRepository) HorizonNow(ctx context.Context) (int64, error) {
	var x int64
	if err := r.db.QueryRowContext(ctx,
		`SELECT (pg_snapshot_xmax(pg_current_snapshot())::text::bigint - 1) % 4294967296`).Scan(&x); err != nil {
		return 0, fmt.Errorf("failed to read the transaction horizon: %w", err)
	}
	return x, nil
}

// ── the runner's session ───────────────────────────────────────────────────

// ReclaimSession is the runner's own database session. The job lock is held
// on it for the whole run, the shared maintenance lock only around a rewrite,
// and both rewrites run on it.
type ReclaimSession interface {
	// TryJobLock takes RawLogReclaimJobLockKey; false means another runner has it.
	TryJobLock(ctx context.Context) (bool, error)
	// TrySharedLock takes StorageMaintenanceLockKey; false means another job
	// (the emergency compression) is rewriting chunks.
	TrySharedLock(ctx context.Context) (bool, error)
	ReleaseSharedLock() error
	// NullRawLog empties the access/error batches' raw_log in rel in one
	// transaction and returns the batches changed and the transaction's xid.
	NullRawLog(ctx context.Context, rel string) (batches int64, xid int64, err error)
	// VacuumFull rewrites rel and returns its size afterwards.
	VacuumFull(ctx context.Context, rel string) (bytesAfter int64, err error)
	// Close ends the session, and with it every lock it holds.
	Close() error
}

// OpenSession pins a connection for one run.
func (r *RawLogReclaimRepository) OpenSession(ctx context.Context) (ReclaimSession, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open a database session: %w", err)
	}
	return &reclaimSession{conn: conn}, nil
}

type reclaimSession struct {
	conn       *sql.Conn
	sharedHeld bool
	closed     bool
}

func (s *reclaimSession) TryJobLock(ctx context.Context) (bool, error) {
	var got bool
	if err := s.conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, RawLogReclaimJobLockKey).Scan(&got); err != nil {
		return false, fmt.Errorf("failed to take the raw log reclaim lock: %w", err)
	}
	return got, nil
}

func (s *reclaimSession) TrySharedLock(ctx context.Context) (bool, error) {
	got, err := TryMaintenanceLock(ctx, s.conn)
	if got {
		s.sharedHeld = true
	}
	return got, err
}

func (s *reclaimSession) ReleaseSharedLock() error {
	if !s.sharedHeld {
		return nil
	}
	err := ReleaseMaintenanceLock(s.conn)
	if err != nil {
		// Unlocking failed, so end the session: the server drops its locks
		// with it, and the next statement fails instead of running unlocked.
		s.discard()
	}
	s.sharedHeld = false
	return err
}

func (s *reclaimSession) NullRawLog(ctx context.Context, rel string) (int64, int64, error) {
	if !ValidReclaimRelation(rel) {
		return 0, 0, fmt.Errorf("refusing unexpected relation name %q", rel)
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	// The UPDATE takes only ROW EXCLUSIVE on the compressed relation, which
	// readers do not conflict with; lock_timeout keeps it from queueing behind
	// a decompression or recompression of the same day.
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return 0, 0, err
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout = '15min'`); err != nil {
		return 0, 0, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE `+rel+` SET raw_log = NULL WHERE log_type <> 'modsec' AND raw_log IS NOT NULL`)
	if err != nil {
		return 0, 0, err
	}
	batches, err := res.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	var xid int64
	if err := tx.QueryRowContext(ctx, `SELECT xid(pg_current_xact_id())::text::bigint`).Scan(&xid); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return batches, xid, nil
}

func (s *reclaimSession) VacuumFull(ctx context.Context, rel string) (int64, error) {
	if !ValidReclaimRelation(rel) {
		return 0, fmt.Errorf("refusing unexpected relation name %q", rel)
	}
	// VACUUM cannot run in a transaction, so these are session settings, put
	// back below. VACUUM FULL holds ACCESS EXCLUSIVE on the day's compressed
	// relation for its whole run (about 30 s per 500 MB); lock_timeout only
	// keeps it from queueing behind a long reader, during which new readers
	// would queue behind it.
	if _, err := s.conn.ExecContext(ctx, `SET lock_timeout = '3s'`); err != nil {
		return 0, err
	}
	if _, err := s.conn.ExecContext(ctx, `SET statement_timeout = '30min'`); err != nil {
		s.resetTimeouts()
		return 0, err
	}
	_, verr := s.conn.ExecContext(ctx, `VACUUM FULL `+rel)
	s.resetTimeouts()
	if verr != nil {
		return 0, verr
	}
	var size int64
	if err := s.conn.QueryRowContext(ctx, `SELECT pg_total_relation_size($1::regclass)`, rel).Scan(&size); err != nil {
		return 0, err
	}
	return size, nil
}

// resetTimeouts runs on a fresh context so a cancelled run still restores the
// session; if it cannot, the session ends.
func (s *reclaimSession) resetTimeouts() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.conn.ExecContext(ctx, `RESET lock_timeout`); err != nil {
		s.discard()
		return
	}
	if _, err := s.conn.ExecContext(ctx, `RESET statement_timeout`); err != nil {
		s.discard()
	}
}

// Close ends the database session instead of handing the connection back to
// the pool: advisory locks belong to the session, and a pooled connection
// would carry the job lock into whatever borrowed it next. The explicit
// unlock first makes the locks free by the time Close returns, rather than
// whenever the server notices the connection is gone.
func (s *reclaimSession) Close() error {
	if !s.closed {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = s.conn.ExecContext(ctx, `SELECT pg_advisory_unlock_all()`)
		cancel()
	}
	s.discard()
	return nil
}

func (s *reclaimSession) discard() {
	if s.closed {
		return
	}
	s.closed = true
	_ = s.conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = s.conn.Close()
}

// ── job and day state ──────────────────────────────────────────────────────

// ReclaimJob is the raw_log_reclaim_job row; a missing row reads as idle.
type ReclaimJob struct {
	Status      string
	MaxChunks   *int
	RequestedAt *time.Time
	RequestedBy string
	StartedAt   *time.Time
	FinishedAt  *time.Time
	LastError   string
}

const jobColumns = `status, max_chunks, requested_at, COALESCE(requested_by, ''), started_at, finished_at, COALESCE(last_error, '')`

func scanJob(sc interface{ Scan(...any) error }) (ReclaimJob, error) {
	var j ReclaimJob
	var maxChunks sql.NullInt64
	var requested, started, finished sql.NullTime
	if err := sc.Scan(&j.Status, &maxChunks, &requested, &j.RequestedBy, &started, &finished, &j.LastError); err != nil {
		return j, err
	}
	if maxChunks.Valid {
		n := int(maxChunks.Int64)
		j.MaxChunks = &n
	}
	j.RequestedAt = nullTimePtr(requested)
	j.StartedAt = nullTimePtr(started)
	j.FinishedAt = nullTimePtr(finished)
	return j, nil
}

func nullTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func (r *RawLogReclaimRepository) LoadJob(ctx context.Context) (ReclaimJob, error) {
	j, err := scanJob(r.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM raw_log_reclaim_job WHERE id`))
	if errors.Is(err, sql.ErrNoRows) {
		return ReclaimJob{Status: "idle"}, nil
	}
	if err != nil {
		return j, fmt.Errorf("failed to read the raw log reclaim job: %w", err)
	}
	return j, nil
}

// BeginJob records a new request: running, requested now by `by`.
func (r *RawLogReclaimRepository) BeginJob(ctx context.Context, by string, maxChunks *int) (ReclaimJob, error) {
	var mc sql.NullInt64
	if maxChunks != nil {
		mc = sql.NullInt64{Int64: int64(*maxChunks), Valid: true}
	}
	j, err := scanJob(r.db.QueryRowContext(ctx, `
		INSERT INTO raw_log_reclaim_job (id, status, max_chunks, requested_at, requested_by, started_at, finished_at, last_error, updated_at)
		VALUES (true, 'running', $1, now(), NULLIF($2, ''), now(), NULL, NULL, now())
		ON CONFLICT (id) DO UPDATE SET status = 'running', max_chunks = EXCLUDED.max_chunks,
		    requested_at = EXCLUDED.requested_at, requested_by = EXCLUDED.requested_by,
		    started_at = EXCLUDED.started_at, finished_at = NULL, last_error = NULL, updated_at = now()
		RETURNING `+jobColumns, mc, by))
	if err != nil {
		return j, fmt.Errorf("failed to record the raw log reclaim job: %w", err)
	}
	return j, nil
}

// ResumeJob marks a run that is picking up an interrupted request. found is
// false when the job is no longer running (stopped in the meantime).
func (r *RawLogReclaimRepository) ResumeJob(ctx context.Context) (ReclaimJob, bool, error) {
	j, err := scanJob(r.db.QueryRowContext(ctx, `
		UPDATE raw_log_reclaim_job SET started_at = now(), finished_at = NULL, last_error = NULL, updated_at = now()
		 WHERE id AND status = 'running'
		RETURNING `+jobColumns))
	if errors.Is(err, sql.ErrNoRows) {
		return j, false, nil
	}
	if err != nil {
		return j, false, fmt.Errorf("failed to resume the raw log reclaim job: %w", err)
	}
	return j, true, nil
}

// FinishJob ends the job as done, paused or failed. The error text is stored
// and shown later, so driver text is cut out here, where it is written.
func (r *RawLogReclaimRepository) FinishJob(ctx context.Context, status, lastError string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO raw_log_reclaim_job (id, status, finished_at, last_error, updated_at)
		VALUES (true, $1, now(), NULLIF($2, ''), now())
		ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, finished_at = now(),
		    last_error = EXCLUDED.last_error, updated_at = now()`,
		status, database.ScrubDriverText(lastError))
	if err != nil {
		return fmt.Errorf("failed to record the raw log reclaim job: %w", err)
	}
	return nil
}

// ReclaimChunk is a raw_log_reclaim_chunks row.
type ReclaimChunk struct {
	Name        string
	RangeStart  time.Time
	RangeEnd    time.Time
	State       string // pending | nulled | done | skipped | gone | failed
	BytesBefore int64
	BytesAfter  int64
	RawBytes    int64
	UpdateXID   *int64
	Attempts    int
	LastError   string
	WorkedAt    *time.Time
	UpdatedAt   time.Time
}

// ListChunkRows returns every recorded day (one per day of retained history
// at most).
func (r *RawLogReclaimRepository) ListChunkRows(ctx context.Context) ([]ReclaimChunk, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT chunk_name, range_start, range_end, state, COALESCE(bytes_before, 0), COALESCE(bytes_after, 0),
		       COALESCE(raw_bytes, 0), update_xid, attempts, COALESCE(last_error, ''), worked_at, updated_at
		  FROM raw_log_reclaim_chunks ORDER BY range_start`)
	if err != nil {
		return nil, fmt.Errorf("failed to read the raw log reclaim days: %w", err)
	}
	defer rows.Close()
	var out []ReclaimChunk
	for rows.Next() {
		var c ReclaimChunk
		var xid sql.NullInt64
		var worked sql.NullTime
		if err := rows.Scan(&c.Name, &c.RangeStart, &c.RangeEnd, &c.State, &c.BytesBefore, &c.BytesAfter,
			&c.RawBytes, &xid, &c.Attempts, &c.LastError, &worked, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if xid.Valid {
			v := xid.Int64
			c.UpdateXID = &v
		}
		c.WorkedAt = nullTimePtr(worked)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReclaimPlanRow is a day that has raw_log to remove.
type ReclaimPlanRow struct {
	Name        string
	RangeStart  time.Time
	RangeEnd    time.Time
	BytesBefore int64
	RawBytes    int64
}

// PlanChunk records a day as pending. A day recorded earlier is left alone,
// except a skipped one, which comes back: as nulled when its raw_log was
// already removed (it still needs its VACUUM FULL), else as pending.
func (r *RawLogReclaimRepository) PlanChunk(ctx context.Context, p ReclaimPlanRow) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO raw_log_reclaim_chunks AS c (chunk_name, range_start, range_end, state, bytes_before, raw_bytes, updated_at)
		VALUES ($1, $2, $3, 'pending', $4, $5, now())
		ON CONFLICT (chunk_name) DO UPDATE
		   SET state = CASE WHEN c.update_xid IS NULL THEN 'pending' ELSE 'nulled' END,
		       bytes_before = CASE WHEN c.update_xid IS NULL THEN EXCLUDED.bytes_before ELSE c.bytes_before END,
		       raw_bytes = CASE WHEN c.update_xid IS NULL THEN EXCLUDED.raw_bytes ELSE c.raw_bytes END,
		       range_start = EXCLUDED.range_start, range_end = EXCLUDED.range_end,
		       last_error = NULL, updated_at = now()
		 WHERE c.state = 'skipped'`, p.Name, p.RangeStart, p.RangeEnd, p.BytesBefore, p.RawBytes)
	if err != nil {
		return fmt.Errorf("failed to record a raw log reclaim day: %w", err)
	}
	return nil
}

// MarkGoneChunks retires unfinished days whose chunk retention has dropped.
func (r *RawLogReclaimRepository) MarkGoneChunks(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE raw_log_reclaim_chunks SET state = 'gone', updated_at = now()
		 WHERE state IN ('pending', 'nulled', 'skipped', 'failed') AND to_regclass(chunk_name) IS NULL`)
	if err != nil {
		return fmt.Errorf("failed to update dropped raw log reclaim days: %w", err)
	}
	return nil
}

func (r *RawLogReclaimRepository) exec(ctx context.Context, what, query string, args ...any) error {
	if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to %s: %w", what, err)
	}
	return nil
}

// MarkGone records that one day's chunk no longer exists.
func (r *RawLogReclaimRepository) MarkGone(ctx context.Context, name string) error {
	return r.exec(ctx, "mark a dropped day", `
		UPDATE raw_log_reclaim_chunks SET state = 'gone', updated_at = now() WHERE chunk_name = $1`, name)
}

// MarkSkipped leaves an unfinished day alone, with why.
func (r *RawLogReclaimRepository) MarkSkipped(ctx context.Context, name, reason string) error {
	return r.exec(ctx, "skip a day", `
		UPDATE raw_log_reclaim_chunks SET state = 'skipped', last_error = $2, updated_at = now()
		 WHERE chunk_name = $1 AND state IN ('pending', 'nulled')`, name, "skipped: "+reason)
}

// MarkWorked counts the day against the current request's max_chunks.
func (r *RawLogReclaimRepository) MarkWorked(ctx context.Context, name string) error {
	return r.exec(ctx, "record work on a day", `
		UPDATE raw_log_reclaim_chunks SET worked_at = now(), updated_at = now() WHERE chunk_name = $1`, name)
}

// MarkNulled records the committed UPDATE and its transaction id.
func (r *RawLogReclaimRepository) MarkNulled(ctx context.Context, name string, bytesBefore, rawBytes, batches, xid int64) error {
	return r.exec(ctx, "record removed raw_log", `
		UPDATE raw_log_reclaim_chunks
		   SET state = 'nulled', bytes_before = $2, raw_bytes = $3, batches_nulled = $4, update_xid = $5,
		       last_error = NULL, updated_at = now()
		 WHERE chunk_name = $1`, name, bytesBefore, rawBytes, batches, xid)
}

// MarkDone records a day whose space came back (or that had nothing left).
func (r *RawLogReclaimRepository) MarkDone(ctx context.Context, name string, bytesBefore, bytesAfter, rawBytes int64) error {
	return r.exec(ctx, "record a finished day", `
		UPDATE raw_log_reclaim_chunks
		   SET state = 'done', bytes_before = $2, bytes_after = $3, raw_bytes = $4, last_error = NULL, updated_at = now()
		 WHERE chunk_name = $1`, name, bytesBefore, bytesAfter, rawBytes)
}

// MarkVacuumIneffective records a VACUUM FULL that freed too little; the day
// stays nulled for the next run.
func (r *RawLogReclaimRepository) MarkVacuumIneffective(ctx context.Context, name string, bytesAfter int64, msg string) error {
	return r.exec(ctx, "record an ineffective VACUUM FULL", `
		UPDATE raw_log_reclaim_chunks
		   SET attempts = attempts + 1, bytes_after = $2, last_error = $3, updated_at = now()
		 WHERE chunk_name = $1`, name, bytesAfter, msg)
}

// NoteChunkError stores why a day did not finish. countAttempt adds to its
// attempts, and a day that reaches failAfter of them becomes failed and is
// left alone by later runs. Returns the day's state afterwards.
func (r *RawLogReclaimRepository) NoteChunkError(ctx context.Context, name, msg string, countAttempt bool, failAfter int) (string, error) {
	var state string
	err := r.db.QueryRowContext(ctx, `
		UPDATE raw_log_reclaim_chunks
		   SET attempts = attempts + CASE WHEN $3 THEN 1 ELSE 0 END,
		       state = CASE WHEN $3 AND $4 > 0 AND attempts + 1 >= $4 AND state IN ('pending', 'nulled') THEN 'failed' ELSE state END,
		       last_error = $2, updated_at = now()
		 WHERE chunk_name = $1
		RETURNING state`, name, database.ScrubDriverText(msg), countAttempt, failAfter).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to record a raw log reclaim error: %w", err)
	}
	return state, nil
}

// SQL states the reclaim job tells apart.

// IsQueryCanceled is SQLSTATE 57014: statement_timeout fired, or the
// statement was cancelled (the caller tells them apart by its context).
func IsQueryCanceled(err error) bool { return sqlStateOf(err) == "57014" }

// IsUndefinedTable is SQLSTATE 42P01: the relation went away under us (the
// day was dropped, or decompressed and compressed again under a new name).
func IsUndefinedTable(err error) bool { return sqlStateOf(err) == "42P01" }

// SQLState is the error's SQLSTATE, "" when it carries none.
func SQLState(err error) string { return sqlStateOf(err) }
