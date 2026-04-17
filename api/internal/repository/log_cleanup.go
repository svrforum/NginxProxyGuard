package repository

import (
	"context"
	"fmt"
)

func (r *LogRepository) DeleteOld(ctx context.Context, retentionDays int) (int64, error) {
	// Use partition DROP instead of row-level DELETE for efficiency.
	// drop_old_partitions() drops entire monthly partitions older than the cutoff,
	// which is orders of magnitude faster than DELETE on large tables.
	retentionMonths := retentionDays / 30
	if retentionMonths < 1 {
		retentionMonths = 1
	}
	var dropped int
	err := r.db.QueryRowContext(ctx, `SELECT drop_old_partitions('logs_p', $1)`, retentionMonths).Scan(&dropped)
	if err != nil {
		return 0, fmt.Errorf("failed to drop old log partitions: %w", err)
	}
	return int64(dropped), nil
}
