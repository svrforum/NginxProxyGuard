package repository

import (
	"context"
	"fmt"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// CustomErrorPageRepository stores the operator's error page HTML (#335).
type CustomErrorPageRepository struct {
	db *database.DB
}

func NewCustomErrorPageRepository(db *database.DB) *CustomErrorPageRepository {
	return &CustomErrorPageRepository{db: db}
}

// List returns the custom pages, by status code.
func (r *CustomErrorPageRepository) List(ctx context.Context) ([]model.CustomErrorPage, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status_code, html, updated_at FROM custom_error_pages ORDER BY status_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pages := []model.CustomErrorPage{}
	for rows.Next() {
		var p model.CustomErrorPage
		if err := rows.Scan(&p.StatusCode, &p.HTML, &p.UpdatedAt); err != nil {
			return nil, err
		}
		pages = append(pages, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate custom error pages: %w", err)
	}
	return pages, nil
}

// Upsert sets the HTML of one page.
func (r *CustomErrorPageRepository) Upsert(ctx context.Context, code int, html string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO custom_error_pages (status_code, html, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (status_code) DO UPDATE SET html = EXCLUDED.html, updated_at = now()
	`, code, html)
	return err
}

// Delete puts one page back to the built-in one.
func (r *CustomErrorPageRepository) Delete(ctx context.Context, code int) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM custom_error_pages WHERE status_code = $1`, code)
	return err
}
