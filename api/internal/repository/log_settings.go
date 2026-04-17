package repository

import (
	"context"
	"database/sql"
	"fmt"

	"nginx-proxy-guard/internal/model"
)

func (r *LogRepository) GetSettings(ctx context.Context) (*model.LogSettings, error) {
	query := `
		SELECT id, retention_days, max_logs_per_type, auto_cleanup_enabled, created_at, updated_at
		FROM log_settings
		LIMIT 1
	`

	var settings model.LogSettings
	var maxLogsPerType sql.NullInt64

	err := r.db.QueryRowContext(ctx, query).Scan(
		&settings.ID, &settings.RetentionDays, &maxLogsPerType,
		&settings.AutoCleanupEnabled, &settings.CreatedAt, &settings.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		// Auto-create default settings if not exists
		return r.createDefaultSettings(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get log settings: %w", err)
	}

	if maxLogsPerType.Valid {
		settings.MaxLogsPerType = &maxLogsPerType.Int64
	}

	return &settings, nil
}

// createDefaultSettings creates default log settings if none exist
func (r *LogRepository) createDefaultSettings(ctx context.Context) (*model.LogSettings, error) {
	query := `
		INSERT INTO log_settings (retention_days, auto_cleanup_enabled, system_log_retention_days, enable_docker_logs, filter_health_checks)
		VALUES (30, true, 7, true, true)
		RETURNING id, retention_days, max_logs_per_type, auto_cleanup_enabled, created_at, updated_at
	`

	var settings model.LogSettings
	var maxLogsPerType sql.NullInt64

	err := r.db.QueryRowContext(ctx, query).Scan(
		&settings.ID, &settings.RetentionDays, &maxLogsPerType,
		&settings.AutoCleanupEnabled, &settings.CreatedAt, &settings.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create default log settings: %w", err)
	}

	if maxLogsPerType.Valid {
		settings.MaxLogsPerType = &maxLogsPerType.Int64
	}

	return &settings, nil
}

func (r *LogRepository) UpdateSettings(ctx context.Context, req *model.UpdateLogSettingsRequest) (*model.LogSettings, error) {
	settings, err := r.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	if req.RetentionDays != nil {
		settings.RetentionDays = *req.RetentionDays
	}
	if req.MaxLogsPerType != nil {
		settings.MaxLogsPerType = req.MaxLogsPerType
	}
	if req.AutoCleanupEnabled != nil {
		settings.AutoCleanupEnabled = *req.AutoCleanupEnabled
	}

	query := `
		UPDATE log_settings SET
			retention_days = $1,
			max_logs_per_type = $2,
			auto_cleanup_enabled = $3
		WHERE id = $4
		RETURNING updated_at
	`

	err = r.db.QueryRowContext(ctx, query,
		settings.RetentionDays, settings.MaxLogsPerType, settings.AutoCleanupEnabled, settings.ID,
	).Scan(&settings.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to update log settings: %w", err)
	}

	return settings, nil
}
