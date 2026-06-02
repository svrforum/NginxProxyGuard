package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// DDNSRepository persists DDNS records (#154).
type DDNSRepository struct {
	db *database.DB
}

func NewDDNSRepository(db *database.DB) *DDNSRepository {
	return &DDNSRepository{db: db}
}

const ddnsColumns = `id, hostname, dns_provider_id, record_type, proxied, ttl, enabled,
	last_ip, last_synced_at, last_status, last_error, created_at, updated_at`

// scanDDNSRow scans a single row into a DDNSRecord, mapping NULL last_synced_at to *time.Time.
func scanDDNSRow(scan func(dest ...interface{}) error) (*model.DDNSRecord, error) {
	rec := &model.DDNSRecord{}
	var lastSyncedAt sql.NullTime
	err := scan(
		&rec.ID, &rec.Hostname, &rec.DNSProviderID, &rec.RecordType, &rec.Proxied, &rec.TTL, &rec.Enabled,
		&rec.LastIP, &lastSyncedAt, &rec.LastStatus, &rec.LastError, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if lastSyncedAt.Valid {
		rec.LastSyncedAt = &lastSyncedAt.Time
	}
	return rec, nil
}

// scanDDNSRows scans all rows from a query into a slice of DDNSRecord.
func scanDDNSRows(rows *sql.Rows) ([]model.DDNSRecord, error) {
	var records []model.DDNSRecord
	for rows.Next() {
		rec, err := scanDDNSRow(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan ddns record: %w", err)
		}
		records = append(records, *rec)
	}
	return records, rows.Err()
}

func (r *DDNSRepository) Create(ctx context.Context, req *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	recordType := "A"
	ttl := req.TTL
	if ttl < 1 {
		ttl = 1
	}

	query := `
		INSERT INTO ddns_records (hostname, dns_provider_id, record_type, proxied, ttl, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + ddnsColumns

	rec, err := scanDDNSRow(r.db.QueryRowContext(ctx, query,
		req.Hostname, req.DNSProviderID, recordType, req.Proxied, ttl, req.Enabled,
	).Scan)
	if err != nil {
		return nil, fmt.Errorf("failed to create ddns record: %w", err)
	}
	return rec, nil
}

func (r *DDNSRepository) GetByID(ctx context.Context, id string) (*model.DDNSRecord, error) {
	query := `SELECT ` + ddnsColumns + ` FROM ddns_records WHERE id = $1`

	rec, err := scanDDNSRow(r.db.QueryRowContext(ctx, query, id).Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ddns record: %w", err)
	}
	return rec, nil
}

func (r *DDNSRepository) List(ctx context.Context, page, perPage int) ([]model.DDNSRecord, int, error) {
	offset := (page - 1) * perPage

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ddns_records`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count ddns records: %w", err)
	}

	query := `SELECT ` + ddnsColumns + ` FROM ddns_records ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := r.db.QueryContext(ctx, query, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list ddns records: %w", err)
	}
	defer rows.Close()

	records, err := scanDDNSRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return records, total, nil
}

func (r *DDNSRepository) Update(ctx context.Context, id string, req *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	setClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	if req.Hostname != nil {
		setClauses = append(setClauses, fmt.Sprintf("hostname = $%d", argIndex))
		args = append(args, *req.Hostname)
		argIndex++
	}
	if req.DNSProviderID != nil {
		setClauses = append(setClauses, fmt.Sprintf("dns_provider_id = $%d", argIndex))
		args = append(args, *req.DNSProviderID)
		argIndex++
	}
	if req.Proxied != nil {
		setClauses = append(setClauses, fmt.Sprintf("proxied = $%d", argIndex))
		args = append(args, *req.Proxied)
		argIndex++
	}
	if req.TTL != nil {
		ttl := *req.TTL
		if ttl < 1 {
			ttl = 1
		}
		setClauses = append(setClauses, fmt.Sprintf("ttl = $%d", argIndex))
		args = append(args, ttl)
		argIndex++
	}
	if req.Enabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *req.Enabled)
		argIndex++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, "updated_at = now()")

	query := fmt.Sprintf(`
		UPDATE ddns_records
		SET %s
		WHERE id = $%d
		RETURNING `+ddnsColumns, joinStrings(setClauses, ", "), argIndex)

	args = append(args, id)

	rec, err := scanDDNSRow(r.db.QueryRowContext(ctx, query, args...).Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update ddns record: %w", err)
	}
	return rec, nil
}

func (r *DDNSRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM ddns_records WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete ddns record: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return model.ErrNotFound
	}
	return nil
}

// ListEnabled returns all enabled DDNS records (used by the sync scheduler).
func (r *DDNSRepository) ListEnabled(ctx context.Context) ([]model.DDNSRecord, error) {
	query := `SELECT ` + ddnsColumns + ` FROM ddns_records WHERE enabled = true ORDER BY hostname`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list enabled ddns records: %w", err)
	}
	defer rows.Close()

	return scanDDNSRows(rows)
}

// UpdateStatus records the outcome of a sync attempt for a single record.
func (r *DDNSRepository) UpdateStatus(ctx context.Context, id, ip, status, errMsg string, syncedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ddns_records
		SET last_ip = $2, last_status = $3, last_error = $4, last_synced_at = $5, updated_at = now()
		WHERE id = $1`,
		id, ip, status, errMsg, syncedAt)
	if err != nil {
		return fmt.Errorf("failed to update ddns status: %w", err)
	}
	return nil
}
