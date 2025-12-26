package repository

import (
	"context"
	"database/sql"

	"nginx-proxy-guard/internal/model"
)

type BackupRepository struct {
	db *sql.DB
}

func NewBackupRepository(db *sql.DB) *BackupRepository {
	return &BackupRepository{db: db}
}

func (r *BackupRepository) Create(ctx context.Context, backup *model.Backup) (*model.Backup, error) {
	query := `
		INSERT INTO backups (filename, file_size, file_path, includes_config, includes_certificates,
		                     includes_database, backup_type, description, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at
	`

	err := r.db.QueryRowContext(ctx, query,
		backup.Filename, backup.FileSize, backup.FilePath, backup.IncludesConfig,
		backup.IncludesCertificates, backup.IncludesDatabase, backup.BackupType,
		backup.Description, backup.Status,
	).Scan(&backup.ID, &backup.CreatedAt)
	if err != nil {
		return nil, err
	}

	return backup, nil
}

func (r *BackupRepository) GetByID(ctx context.Context, id string) (*model.Backup, error) {
	query := `
		SELECT id, filename, file_size, file_path, includes_config, includes_certificates,
		       includes_database, backup_type, description, status, error_message,
		       checksum_sha256, created_at, completed_at
		FROM backups
		WHERE id = $1
	`

	var b model.Backup
	var description, errorMsg, checksum sql.NullString
	var completedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&b.ID, &b.Filename, &b.FileSize, &b.FilePath, &b.IncludesConfig, &b.IncludesCertificates,
		&b.IncludesDatabase, &b.BackupType, &description, &b.Status, &errorMsg,
		&checksum, &b.CreatedAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	b.Description = description.String
	b.ErrorMessage = errorMsg.String
	b.ChecksumSHA256 = checksum.String
	if completedAt.Valid {
		b.CompletedAt = &completedAt.Time
	}

	return &b, nil
}

func (r *BackupRepository) List(ctx context.Context, page, perPage int) (*model.BackupListResponse, error) {
	// Get total count
	var total int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM backups").Scan(&total)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, filename, file_size, file_path, includes_config, includes_certificates,
		       includes_database, backup_type, description, status, error_message,
		       checksum_sha256, created_at, completed_at
		FROM backups
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, perPage, (page-1)*perPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backups []model.Backup
	for rows.Next() {
		var b model.Backup
		var description, errorMsg, checksum sql.NullString
		var completedAt sql.NullTime

		err := rows.Scan(
			&b.ID, &b.Filename, &b.FileSize, &b.FilePath, &b.IncludesConfig, &b.IncludesCertificates,
			&b.IncludesDatabase, &b.BackupType, &description, &b.Status, &errorMsg,
			&checksum, &b.CreatedAt, &completedAt,
		)
		if err != nil {
			return nil, err
		}

		b.Description = description.String
		b.ErrorMessage = errorMsg.String
		b.ChecksumSHA256 = checksum.String
		if completedAt.Valid {
			b.CompletedAt = &completedAt.Time
		}

		backups = append(backups, b)
	}

	totalPages := (total + perPage - 1) / perPage
	return &model.BackupListResponse{
		Data:       backups,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

func (r *BackupRepository) UpdateStatus(ctx context.Context, id, status, errorMsg string) error {
	query := `
		UPDATE backups
		SET status = $2, error_message = $3
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id, status, errorMsg)
	return err
}

func (r *BackupRepository) Complete(ctx context.Context, id string, fileSize int64, checksum string) error {
	query := `
		UPDATE backups
		SET status = 'completed', file_size = $2, checksum_sha256 = $3, completed_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id, fileSize, checksum)
	return err
}

func (r *BackupRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM backups WHERE id = $1", id)
	return err
}

// ListByType returns all backups of a specific type (manual, auto, scheduled)
func (r *BackupRepository) ListByType(ctx context.Context, backupType string) ([]model.Backup, error) {
	query := `
		SELECT id, filename, file_size, file_path, includes_config, includes_certificates,
		       includes_database, backup_type, description, status, error_message,
		       checksum_sha256, created_at, completed_at
		FROM backups
		WHERE backup_type = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, backupType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backups []model.Backup
	for rows.Next() {
		var b model.Backup
		var description, errorMsg, checksum sql.NullString
		var completedAt sql.NullTime

		err := rows.Scan(
			&b.ID, &b.Filename, &b.FileSize, &b.FilePath, &b.IncludesConfig, &b.IncludesCertificates,
			&b.IncludesDatabase, &b.BackupType, &description, &b.Status, &errorMsg,
			&checksum, &b.CreatedAt, &completedAt,
		)
		if err != nil {
			return nil, err
		}

		b.Description = description.String
		b.ErrorMessage = errorMsg.String
		b.ChecksumSHA256 = checksum.String
		if completedAt.Valid {
			b.CompletedAt = &completedAt.Time
		}

		backups = append(backups, b)
	}

	return backups, nil
}

func (r *BackupRepository) GetStats(ctx context.Context) (*model.BackupStats, error) {
	stats := &model.BackupStats{}

	// Total backups and size
	r.db.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM backups").Scan(&stats.TotalBackups, &stats.TotalSize)

	// Last backup
	var lastBackup sql.NullTime
	r.db.QueryRowContext(ctx, "SELECT MAX(created_at) FROM backups").Scan(&lastBackup)
	if lastBackup.Valid {
		stats.LastBackup = &lastBackup.Time
	}

	// Last successful backup
	var lastSuccess sql.NullTime
	r.db.QueryRowContext(ctx, "SELECT MAX(completed_at) FROM backups WHERE status = 'completed'").Scan(&lastSuccess)
	if lastSuccess.Valid {
		stats.LastSuccessful = &lastSuccess.Time
	}

	// Default retention
	stats.RetentionDays = 30

	return stats, nil
}

func (r *BackupRepository) CleanupOld(ctx context.Context, retentionDays int) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM backups
		WHERE created_at < NOW() - INTERVAL '1 day' * $1
	`, retentionDays)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *BackupRepository) GetLatestCompleted(ctx context.Context) (*model.Backup, error) {
	query := `
		SELECT id, filename, file_size, file_path, includes_config, includes_certificates,
		       includes_database, backup_type, description, status, error_message,
		       checksum_sha256, created_at, completed_at
		FROM backups
		WHERE status = 'completed'
		ORDER BY completed_at DESC
		LIMIT 1
	`

	var b model.Backup
	var description, errorMsg, checksum sql.NullString
	var completedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query).Scan(
		&b.ID, &b.Filename, &b.FileSize, &b.FilePath, &b.IncludesConfig, &b.IncludesCertificates,
		&b.IncludesDatabase, &b.BackupType, &description, &b.Status, &errorMsg,
		&checksum, &b.CreatedAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	b.Description = description.String
	b.ErrorMessage = errorMsg.String
	b.ChecksumSHA256 = checksum.String
	if completedAt.Valid {
		b.CompletedAt = &completedAt.Time
	}

	return &b, nil
}
