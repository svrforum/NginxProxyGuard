package repository

import (
	"context"
	"database/sql"
	"log"

	"nginx-proxy-guard/internal/model"
)

// exportCustomErrorPages reads the custom error pages (#335). Never nil, so a
// backup without custom pages still says so and its restore resets them.
func (r *BackupRepository) exportCustomErrorPages(ctx context.Context) ([]model.CustomErrorPageExport, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status_code, html FROM custom_error_pages ORDER BY status_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pages := []model.CustomErrorPageExport{}
	for rows.Next() {
		var p model.CustomErrorPageExport
		if err := rows.Scan(&p.StatusCode, &p.HTML); err != nil {
			return nil, err
		}
		pages = append(pages, p)
	}
	return pages, rows.Err()
}

// importCustomErrorPages replaces the custom error pages with a backup's. A
// page the API would refuse is skipped, so the built-in one stays.
func (r *BackupRepository) importCustomErrorPages(ctx context.Context, tx *sql.Tx, pages []model.CustomErrorPageExport) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM custom_error_pages`); err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, p := range pages {
		if !model.IsCustomErrorPageStatus(p.StatusCode) || seen[p.StatusCode] {
			log.Printf("[Backup] Skipped custom error page %d: not a page that can be replaced, or repeated", p.StatusCode)
			continue
		}
		if err := model.ValidateCustomErrorPageHTML(p.HTML); err != nil {
			log.Printf("[Backup] Skipped custom error page %d: %v", p.StatusCode, err)
			continue
		}
		seen[p.StatusCode] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO custom_error_pages (status_code, html) VALUES ($1, $2)`, p.StatusCode, p.HTML); err != nil {
			return err
		}
	}
	return nil
}

// CustomErrorPages reads the custom error pages for the config files a
// restore writes.
func (r *BackupRepository) CustomErrorPages(ctx context.Context) ([]model.CustomErrorPage, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status_code, html, updated_at FROM custom_error_pages ORDER BY status_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pages []model.CustomErrorPage
	for rows.Next() {
		var p model.CustomErrorPage
		if err := rows.Scan(&p.StatusCode, &p.HTML, &p.UpdatedAt); err != nil {
			return nil, err
		}
		pages = append(pages, p)
	}
	return pages, rows.Err()
}
