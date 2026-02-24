package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type SystemLogSource string
type SystemLogLevel string

const (
	SourceDockerAPI      SystemLogSource = "docker_api"
	SourceDockerNginx    SystemLogSource = "docker_nginx"
	SourceDockerDB       SystemLogSource = "docker_db"
	SourceDockerUI       SystemLogSource = "docker_ui"
	SourceHealthCheck    SystemLogSource = "health_check"
	SourceInternal       SystemLogSource = "internal"
	SourceScheduler      SystemLogSource = "scheduler"
	SourceBackup         SystemLogSource = "backup"
	SourceCertificate    SystemLogSource = "certificate"
	SourceAdmin          SystemLogSource = "admin"
)

const (
	LevelDebug SystemLogLevel = "debug"
	LevelInfo  SystemLogLevel = "info"
	LevelWarn  SystemLogLevel = "warn"
	LevelError SystemLogLevel = "error"
	LevelFatal SystemLogLevel = "fatal"
)

type SystemLog struct {
	ID            string          `json:"id"`
	Source        SystemLogSource `json:"source"`
	Level         SystemLogLevel  `json:"level"`
	Message       string          `json:"message"`
	Details       json.RawMessage `json:"details,omitempty"`
	ContainerName string          `json:"container_name,omitempty"`
	Component     string          `json:"component,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

type SystemLogFilter struct {
	Source        SystemLogSource `json:"source,omitempty"`
	Level         SystemLogLevel  `json:"level,omitempty"`
	ContainerName string          `json:"container_name,omitempty"`
	Component     string          `json:"component,omitempty"`
	Search        string          `json:"search,omitempty"`
	StartTime     *time.Time      `json:"start_time,omitempty"`
	EndTime       *time.Time      `json:"end_time,omitempty"`
	Limit         int             `json:"limit,omitempty"`
	Offset        int             `json:"offset,omitempty"`
}

type SystemLogRepository struct {
	db *sql.DB
}

func NewSystemLogRepository(db *sql.DB) *SystemLogRepository {
	return &SystemLogRepository{db: db}
}

// Create inserts a new system log entry
func (r *SystemLogRepository) Create(ctx context.Context, log *SystemLog) error {
	query := `
		INSERT INTO system_logs (source, level, message, details, container_name, component)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`

	var details interface{}
	if log.Details != nil {
		details = log.Details
	}

	return r.db.QueryRowContext(ctx, query,
		log.Source, log.Level, log.Message, details,
		nullString(log.ContainerName), nullString(log.Component),
	).Scan(&log.ID, &log.CreatedAt)
}

// CreateBatch inserts multiple system log entries efficiently
func (r *SystemLogRepository) CreateBatch(ctx context.Context, logs []SystemLog) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO system_logs (source, level, message, details, container_name, component)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, log := range logs {
		var details interface{}
		if log.Details != nil {
			details = log.Details
		}

		_, err := stmt.ExecContext(ctx,
			log.Source, log.Level, log.Message, details,
			nullString(log.ContainerName), nullString(log.Component),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// List retrieves system logs with filters
func (r *SystemLogRepository) List(ctx context.Context, filter SystemLogFilter) ([]SystemLog, int, error) {
	// Build WHERE clause
	where := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if filter.Source != "" {
		where += " AND source = $" + itoa(argIdx)
		args = append(args, filter.Source)
		argIdx++
	}

	if filter.Level != "" {
		where += " AND level = $" + itoa(argIdx)
		args = append(args, filter.Level)
		argIdx++
	}

	if filter.ContainerName != "" {
		where += " AND container_name = $" + itoa(argIdx)
		args = append(args, filter.ContainerName)
		argIdx++
	}

	if filter.Component != "" {
		where += " AND component = $" + itoa(argIdx)
		args = append(args, filter.Component)
		argIdx++
	}

	if filter.Search != "" {
		where += " AND message ILIKE $" + itoa(argIdx)
		args = append(args, "%"+filter.Search+"%")
		argIdx++
	}

	if filter.StartTime != nil {
		where += " AND created_at >= $" + itoa(argIdx)
		args = append(args, *filter.StartTime)
		argIdx++
	}

	if filter.EndTime != nil {
		where += " AND created_at <= $" + itoa(argIdx)
		args = append(args, *filter.EndTime)
		argIdx++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM system_logs " + where
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get logs with bounded limit to prevent excessive memory usage
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	query := `
		SELECT id, source, level, message, details, container_name, component, created_at
		FROM system_logs ` + where + `
		ORDER BY created_at DESC
		LIMIT $` + itoa(argIdx) + ` OFFSET $` + itoa(argIdx+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []SystemLog
	for rows.Next() {
		var log SystemLog
		var details sql.NullString
		var containerName, component sql.NullString

		err := rows.Scan(
			&log.ID, &log.Source, &log.Level, &log.Message,
			&details, &containerName, &component, &log.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		if details.Valid {
			log.Details = json.RawMessage(details.String)
		}
		log.ContainerName = containerName.String
		log.Component = component.String

		logs = append(logs, log)
	}

	return logs, total, rows.Err()
}

// GetStats returns statistics about system logs
func (r *SystemLogRepository) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get totals in single query
	var total, last24h int64
	err := r.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')
		FROM system_logs
	`).Scan(&total, &last24h)
	if err != nil {
		return nil, err
	}
	stats["total"] = total
	stats["last_24h"] = last24h

	// Count by source (last 24h)
	sourceRows, err := r.db.QueryContext(ctx, `
		SELECT source, COUNT(*) as count
		FROM system_logs
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY source
	`)
	if err != nil {
		return nil, err
	}
	defer sourceRows.Close()

	sourceCounts := make(map[string]int64)
	for sourceRows.Next() {
		var source string
		var count int64
		if err := sourceRows.Scan(&source, &count); err != nil {
			return nil, err
		}
		sourceCounts[source] = count
	}
	stats["by_source"] = sourceCounts

	// Count by level (last 24h)
	levelRows, err := r.db.QueryContext(ctx, `
		SELECT level, COUNT(*) as count
		FROM system_logs
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY level
	`)
	if err != nil {
		return nil, err
	}
	defer levelRows.Close()

	levelCounts := make(map[string]int64)
	for levelRows.Next() {
		var level string
		var count int64
		if err := levelRows.Scan(&level, &count); err != nil {
			return nil, err
		}
		levelCounts[level] = count
	}
	stats["by_level"] = levelCounts

	return stats, nil
}

// Cleanup removes old system logs based on retention days
func (r *SystemLogRepository) Cleanup(ctx context.Context, retentionDays int) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM system_logs
		WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
	`, retentionDays)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Helper function
func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
