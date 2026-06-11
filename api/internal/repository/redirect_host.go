package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type RedirectHostRepository struct {
	db *database.DB
}

func NewRedirectHostRepository(db *database.DB) *RedirectHostRepository {
	return &RedirectHostRepository{db: db}
}

func (r *RedirectHostRepository) Create(ctx context.Context, req *model.CreateRedirectHostRequest) (*model.RedirectHost, error) {
	forwardScheme := "auto"
	if req.ForwardScheme != "" {
		forwardScheme = req.ForwardScheme
	}
	preservePath := true
	if req.PreservePath != nil {
		preservePath = *req.PreservePath
	}
	redirectCode := 301
	if req.RedirectCode != 0 {
		redirectCode = req.RedirectCode
	}
	sslForceHTTPS := true
	if req.SSLForceHTTPS != nil {
		sslForceHTTPS = *req.SSLForceHTTPS
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	metaJSON, _ := json.Marshal(req.Meta)

	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO redirect_hosts (
			domain_names, forward_scheme, forward_domain_name, forward_path,
			preserve_path, redirect_code, ssl_enabled, certificate_id,
			ssl_force_https, enabled, block_exploits, meta
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`,
		pq.Array(req.DomainNames), forwardScheme, req.ForwardDomainName, req.ForwardPath,
		preservePath, redirectCode, req.SSLEnabled, req.CertificateID,
		sslForceHTTPS, enabled, req.BlockExploits, metaJSON,
	).Scan(&id)
	if err != nil {
		return nil, err
	}

	return r.GetByID(ctx, id)
}

func (r *RedirectHostRepository) GetByID(ctx context.Context, id string) (*model.RedirectHost, error) {
	var host model.RedirectHost
	var domainNames pq.StringArray
	var metaJSON []byte

	err := r.db.QueryRowContext(ctx, `
		SELECT id, domain_names, forward_scheme, forward_domain_name, forward_path,
			preserve_path, redirect_code, ssl_enabled, certificate_id,
			ssl_force_https, enabled, block_exploits, meta, created_at, updated_at
		FROM redirect_hosts WHERE id = $1
	`, id).Scan(
		&host.ID, &domainNames, &host.ForwardScheme, &host.ForwardDomainName, &host.ForwardPath,
		&host.PreservePath, &host.RedirectCode, &host.SSLEnabled, &host.CertificateID,
		&host.SSLForceHTTPS, &host.Enabled, &host.BlockExploits, &metaJSON, &host.CreatedAt, &host.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	host.DomainNames = []string(domainNames)
	json.Unmarshal(metaJSON, &host.Meta)

	return &host, nil
}

func (r *RedirectHostRepository) List(ctx context.Context, page, perPage int) ([]model.RedirectHost, int, error) {
	var total int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM redirect_hosts`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain_names, forward_scheme, forward_domain_name, forward_path,
			preserve_path, redirect_code, ssl_enabled, certificate_id,
			ssl_force_https, enabled, block_exploits, meta, created_at, updated_at
		FROM redirect_hosts
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var hosts []model.RedirectHost
	for rows.Next() {
		var host model.RedirectHost
		var domainNames pq.StringArray
		var metaJSON []byte

		if err := rows.Scan(
			&host.ID, &domainNames, &host.ForwardScheme, &host.ForwardDomainName, &host.ForwardPath,
			&host.PreservePath, &host.RedirectCode, &host.SSLEnabled, &host.CertificateID,
			&host.SSLForceHTTPS, &host.Enabled, &host.BlockExploits, &metaJSON, &host.CreatedAt, &host.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		host.DomainNames = []string(domainNames)
		json.Unmarshal(metaJSON, &host.Meta)
		hosts = append(hosts, host)
	}

	return hosts, total, nil
}

func (r *RedirectHostRepository) Update(ctx context.Context, id string, req *model.UpdateRedirectHostRequest) (*model.RedirectHost, error) {
	existing, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}

	// Apply updates
	if len(req.DomainNames) > 0 {
		existing.DomainNames = req.DomainNames
	}
	if req.ForwardScheme != nil {
		existing.ForwardScheme = *req.ForwardScheme
	}
	if req.ForwardDomainName != nil {
		existing.ForwardDomainName = *req.ForwardDomainName
	}
	if req.ForwardPath != nil {
		existing.ForwardPath = *req.ForwardPath
	}
	if req.PreservePath != nil {
		existing.PreservePath = *req.PreservePath
	}
	if req.RedirectCode != nil {
		existing.RedirectCode = *req.RedirectCode
	}
	if req.SSLEnabled != nil {
		existing.SSLEnabled = *req.SSLEnabled
	}
	if req.CertificateID != nil {
		existing.CertificateID = req.CertificateID
	}
	if req.SSLForceHTTPS != nil {
		existing.SSLForceHTTPS = *req.SSLForceHTTPS
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.BlockExploits != nil {
		existing.BlockExploits = *req.BlockExploits
	}

	metaJSON, _ := json.Marshal(existing.Meta)

	_, err = r.db.ExecContext(ctx, `
		UPDATE redirect_hosts SET
			domain_names = $1, forward_scheme = $2, forward_domain_name = $3, forward_path = $4,
			preserve_path = $5, redirect_code = $6, ssl_enabled = $7, certificate_id = $8,
			ssl_force_https = $9, enabled = $10, block_exploits = $11, meta = $12, updated_at = $13
		WHERE id = $14
	`,
		pq.Array(existing.DomainNames), existing.ForwardScheme, existing.ForwardDomainName, existing.ForwardPath,
		existing.PreservePath, existing.RedirectCode, existing.SSLEnabled, existing.CertificateID,
		existing.SSLForceHTTPS, existing.Enabled, existing.BlockExploits, metaJSON, time.Now(), id,
	)
	if err != nil {
		return nil, err
	}

	return r.GetByID(ctx, id)
}

func (r *RedirectHostRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM redirect_hosts WHERE id = $1`, id)
	return err
}

func (r *RedirectHostRepository) GetAllEnabled(ctx context.Context) ([]model.RedirectHost, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain_names, forward_scheme, forward_domain_name, forward_path,
			preserve_path, redirect_code, ssl_enabled, certificate_id,
			ssl_force_https, enabled, block_exploits, meta, created_at, updated_at
		FROM redirect_hosts WHERE enabled = true
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []model.RedirectHost
	for rows.Next() {
		var host model.RedirectHost
		var domainNames pq.StringArray
		var metaJSON []byte

		if err := rows.Scan(
			&host.ID, &domainNames, &host.ForwardScheme, &host.ForwardDomainName, &host.ForwardPath,
			&host.PreservePath, &host.RedirectCode, &host.SSLEnabled, &host.CertificateID,
			&host.SSLForceHTTPS, &host.Enabled, &host.BlockExploits, &metaJSON, &host.CreatedAt, &host.UpdatedAt,
		); err != nil {
			return nil, err
		}
		host.DomainNames = []string(domainNames)
		json.Unmarshal(metaJSON, &host.Meta)
		hosts = append(hosts, host)
	}

	return hosts, nil
}

// GetByCertificateID returns all redirect hosts referencing a certificate.
// Used by the certificate-ready fan-out so a renewed cert that serves redirect
// hosts (possibly only redirect hosts) still triggers a config regen + reload.
func (r *RedirectHostRepository) GetByCertificateID(ctx context.Context, certificateID string) ([]model.RedirectHost, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain_names, forward_scheme, forward_domain_name, forward_path,
			preserve_path, redirect_code, ssl_enabled, certificate_id,
			ssl_force_https, enabled, block_exploits, meta, created_at, updated_at
		FROM redirect_hosts WHERE certificate_id = $1
	`, certificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get redirect hosts by certificate: %w", err)
	}
	defer rows.Close()

	var hosts []model.RedirectHost
	for rows.Next() {
		var host model.RedirectHost
		var domainNames pq.StringArray
		var metaJSON []byte

		if err := rows.Scan(
			&host.ID, &domainNames, &host.ForwardScheme, &host.ForwardDomainName, &host.ForwardPath,
			&host.PreservePath, &host.RedirectCode, &host.SSLEnabled, &host.CertificateID,
			&host.SSLForceHTTPS, &host.Enabled, &host.BlockExploits, &metaJSON, &host.CreatedAt, &host.UpdatedAt,
		); err != nil {
			return nil, err
		}
		host.DomainNames = []string(domainNames)
		json.Unmarshal(metaJSON, &host.Meta)
		hosts = append(hosts, host)
	}

	return hosts, nil
}

// CountByCertificateID returns how many redirect hosts reference a certificate.
func (r *RedirectHostRepository) CountByCertificateID(ctx context.Context, certificateID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM redirect_hosts WHERE certificate_id = $1`, certificateID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count redirect hosts by certificate: %w", err)
	}
	return count, nil
}
