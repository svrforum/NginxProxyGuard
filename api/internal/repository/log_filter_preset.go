package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"nginx-proxy-guard/internal/model"
)

// LogFilterPresetRepository manages saved log-viewer filter presets (#210).
type LogFilterPresetRepository struct {
	db *sql.DB
}

func NewLogFilterPresetRepository(db *sql.DB) *LogFilterPresetRepository {
	return &LogFilterPresetRepository{db: db}
}

const logFilterPresetCols = `id, name, log_type, filter, created_at, updated_at`

func scanLogFilterPreset(s interface {
	Scan(dest ...interface{}) error
}) (*model.LogFilterPreset, error) {
	var p model.LogFilterPreset
	var filter []byte
	if err := s.Scan(&p.ID, &p.Name, &p.LogType, &filter, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Filter = json.RawMessage(filter)
	return &p, nil
}

// List returns presets, optionally scoped to a log type (empty = all), newest name first.
func (r *LogFilterPresetRepository) List(ctx context.Context, logType string) ([]model.LogFilterPreset, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+logFilterPresetCols+`
		FROM log_filter_presets
		WHERE ($1 = '' OR log_type = $1)
		ORDER BY name ASC`, logType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	presets := []model.LogFilterPreset{}
	for rows.Next() {
		p, err := scanLogFilterPreset(rows)
		if err != nil {
			return nil, err
		}
		presets = append(presets, *p)
	}
	return presets, rows.Err()
}

// Create inserts a new preset and returns it.
func (r *LogFilterPresetRepository) Create(ctx context.Context, req *model.CreateLogFilterPresetRequest) (*model.LogFilterPreset, error) {
	logType := req.LogType
	if logType == "" {
		logType = "access"
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO log_filter_presets (name, log_type, filter)
		VALUES ($1, $2, $3::jsonb)
		RETURNING `+logFilterPresetCols, req.Name, logType, string(req.Filter))
	return scanLogFilterPreset(row)
}

// Update applies a partial change (rename and/or replace filter). Returns
// sql.ErrNoRows if the preset does not exist.
func (r *LogFilterPresetRepository) Update(ctx context.Context, id string, req *model.UpdateLogFilterPresetRequest) (*model.LogFilterPreset, error) {
	var name interface{}
	if req.Name != nil {
		name = *req.Name
	}
	var filter interface{}
	if req.Filter != nil {
		filter = string(*req.Filter)
	}
	row := r.db.QueryRowContext(ctx, `
		UPDATE log_filter_presets
		SET name = COALESCE($2, name),
		    filter = COALESCE($3::jsonb, filter),
		    updated_at = now()
		WHERE id = $1
		RETURNING `+logFilterPresetCols, id, name, filter)
	return scanLogFilterPreset(row)
}

// Delete removes a preset. Returns sql.ErrNoRows if it did not exist.
func (r *LogFilterPresetRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM log_filter_presets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
