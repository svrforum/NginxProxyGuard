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
	if r.db.IsMySQLFamily() {
		// MySQL 계열에는 PL/pgSQL 헬퍼가 없다. 파티션 단위 보존은 파티션
		// 스케줄러가 맡으므로(scheduler/partition_mariadb.go 참고) 이 진입점은
		// 경계에 걸친 행만 정리한다.
		result, err := r.db.ExecContext(ctx,
			`DELETE FROM logs_partitioned WHERE created_at < NOW() - ($1 || ' days')::INTERVAL`,
			retentionDays)
		if err != nil {
			return 0, fmt.Errorf("failed to delete old logs: %w", err)
		}
		deleted, _ := result.RowsAffected()
		return deleted, nil
	}

	var dropped int
	err := r.db.QueryRowContext(ctx, `SELECT drop_old_partitions('logs_p', $1)`, retentionMonths).Scan(&dropped)
	if err != nil {
		return 0, fmt.Errorf("failed to drop old log partitions: %w", err)
	}
	return int64(dropped), nil
}
