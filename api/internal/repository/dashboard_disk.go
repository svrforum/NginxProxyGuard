package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// DiskUsedNear returns disk_used from the system_health row closest to at,
// within tol, for the filesystem DiskGuard reports as primary. It is how the
// growth-per-day estimate survives an API restart (rows are kept 24-48h).
//
// Matched by path first and by total size second: an upgrade changes the
// recorded path from "/" to the database's, but on a single-disk install the
// size is the same disk's. Served by idx_system_health_recorded (0.75 ms on
// dev).
func (r *DashboardRepository) DiskUsedNear(ctx context.Context, path string, total uint64, at time.Time, tol time.Duration) (uint64, time.Time, bool, error) {
	var used int64
	var recorded time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT disk_used, recorded_at FROM system_health
		WHERE recorded_at BETWEEN $1 AND $2
		  AND disk_used > 0
		  AND (disk_path = $3 OR abs(disk_total - $4) <= $4 / 1000)
		ORDER BY (disk_path = $3) DESC, abs(extract(epoch FROM recorded_at - $5::timestamptz))
		LIMIT 1`, at.Add(-tol), at.Add(tol), path, int64(total), at).Scan(&used, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, time.Time{}, false, nil
	}
	if err != nil {
		return 0, time.Time{}, false, err
	}
	return uint64(used), recorded, true, nil
}
