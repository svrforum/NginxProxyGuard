package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type CertificateRepository struct {
	db *database.DB
}

func NewCertificateRepository(db *database.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

func (r *CertificateRepository) Create(ctx context.Context, cert *model.Certificate) (*model.Certificate, error) {
	query := `
		INSERT INTO certificates (
			domain_names, dns_provider_id, status, provider, auto_renew,
			expires_at, issued_at, certificate_path, private_key_path,
			certificate_pem, private_key_pem, issuer_certificate_pem, acme_account
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, domain_names, dns_provider_id, status, provider, auto_renew,
			expires_at, issued_at, renewal_attempted_at, error_message,
			certificate_path, private_key_path, created_at, updated_at
	`

	result := &model.Certificate{}
	var dnsProviderID sql.NullString
	var expiresAt, issuedAt, renewalAttemptedAt sql.NullTime
	var errorMessage, certPath, keyPath sql.NullString

	// Ensure acme_account is valid JSON
	acmeAccount := cert.AcmeAccount
	if acmeAccount == nil || len(acmeAccount) == 0 {
		acmeAccount = []byte("{}")
	}

	err := r.db.QueryRowContext(ctx, query,
		pq.Array(cert.DomainNames),
		toNullString(cert.DNSProviderID),
		cert.Status,
		cert.Provider,
		cert.AutoRenew,
		toNullTime(cert.ExpiresAt),
		toNullTime(cert.IssuedAt),
		toNullString(cert.CertificatePath),
		toNullString(cert.PrivateKeyPath),
		cert.CertificatePEM,
		cert.PrivateKeyPEM,
		cert.IssuerCertificatePEM,
		acmeAccount,
	).Scan(
		&result.ID,
		&result.DomainNames,
		&dnsProviderID,
		&result.Status,
		&result.Provider,
		&result.AutoRenew,
		&expiresAt,
		&issuedAt,
		&renewalAttemptedAt,
		&errorMessage,
		&certPath,
		&keyPath,
		&result.CreatedAt,
		&result.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	result.DNSProviderID = fromNullString(dnsProviderID)
	result.ExpiresAt = fromNullTime(expiresAt)
	result.IssuedAt = fromNullTime(issuedAt)
	result.RenewalAttemptedAt = fromNullTime(renewalAttemptedAt)
	result.ErrorMessage = fromNullString(errorMessage)
	result.CertificatePath = fromNullString(certPath)
	result.PrivateKeyPath = fromNullString(keyPath)

	return result, nil
}

func (r *CertificateRepository) GetByID(ctx context.Context, id string) (*model.Certificate, error) {
	query := `
		SELECT c.id, c.domain_names, c.dns_provider_id, c.status, c.provider, c.auto_renew,
			c.expires_at, c.issued_at, c.renewal_attempted_at, c.error_message,
			c.certificate_path, c.private_key_path,
			c.certificate_pem, c.private_key_pem, c.issuer_certificate_pem,
			c.created_at, c.updated_at,
			d.id, d.name, d.provider_type, d.is_default, d.created_at, d.updated_at
		FROM certificates c
		LEFT JOIN dns_providers d ON c.dns_provider_id = d.id
		WHERE c.id = $1
	`

	cert := &model.Certificate{}
	var dnsProviderID sql.NullString
	var expiresAt, issuedAt, renewalAttemptedAt sql.NullTime
	var errorMessage, certPath, keyPath sql.NullString
	var certPEM, keyPEM, issuerPEM sql.NullString

	// DNS Provider fields (nullable)
	var dpID, dpName, dpType sql.NullString
	var dpIsDefault sql.NullBool
	var dpCreatedAt, dpUpdatedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&cert.ID,
		&cert.DomainNames,
		&dnsProviderID,
		&cert.Status,
		&cert.Provider,
		&cert.AutoRenew,
		&expiresAt,
		&issuedAt,
		&renewalAttemptedAt,
		&errorMessage,
		&certPath,
		&keyPath,
		&certPEM,
		&keyPEM,
		&issuerPEM,
		&cert.CreatedAt,
		&cert.UpdatedAt,
		&dpID,
		&dpName,
		&dpType,
		&dpIsDefault,
		&dpCreatedAt,
		&dpUpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	cert.DNSProviderID = fromNullString(dnsProviderID)
	cert.ExpiresAt = fromNullTime(expiresAt)
	cert.IssuedAt = fromNullTime(issuedAt)
	cert.RenewalAttemptedAt = fromNullTime(renewalAttemptedAt)
	cert.ErrorMessage = fromNullString(errorMessage)
	cert.CertificatePath = fromNullString(certPath)
	cert.PrivateKeyPath = fromNullString(keyPath)
	cert.CertificatePEM = fromNullStringValue(certPEM)
	cert.PrivateKeyPEM = fromNullStringValue(keyPEM)
	cert.IssuerCertificatePEM = fromNullStringValue(issuerPEM)

	// Attach DNS provider if exists
	if dpID.Valid {
		cert.DNSProvider = &model.DNSProvider{
			ID:           dpID.String,
			Name:         dpName.String,
			ProviderType: dpType.String,
			IsDefault:    dpIsDefault.Bool,
			CreatedAt:    dpCreatedAt.Time,
			UpdatedAt:    dpUpdatedAt.Time,
		}
	}

	return cert, nil
}

func (r *CertificateRepository) List(ctx context.Context, page, perPage int, search, sortBy, sortOrder, status, provider string) ([]model.Certificate, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	// Build WHERE clause
	var conditions []string
	var args []interface{}
	argIndex := 1

	if search != "" {
		conditions = append(conditions, fmt.Sprintf("array_to_string(c.domain_names, ',') ILIKE $%d", argIndex))
		args = append(args, "%"+search+"%")
		argIndex++
	}

	validStatuses := map[string]bool{"pending": true, "issued": true, "expired": true, "error": true, "renewing": true}
	if status != "" && validStatuses[status] {
		conditions = append(conditions, fmt.Sprintf("c.status = $%d", argIndex))
		args = append(args, status)
		argIndex++
	}

	validProviders := map[string]bool{"letsencrypt": true, "selfsigned": true, "custom": true}
	if provider != "" && validProviders[provider] {
		conditions = append(conditions, fmt.Sprintf("c.provider = $%d", argIndex))
		args = append(args, provider)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	var total int
	countQuery := `SELECT COUNT(*) FROM certificates c` + whereClause
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count certificates: %w", err)
	}

	// Build ORDER BY clause
	orderByClause := "c.created_at DESC" // default
	validSortFields := map[string]string{
		"domain":  "c.domain_names[1]",
		"expires": "c.expires_at",
		"created": "c.created_at",
	}
	if sortField, ok := validSortFields[sortBy]; ok {
		order := "DESC"
		if sortOrder == "asc" {
			order = "ASC"
		}
		if sortBy == "expires" {
			orderByClause = fmt.Sprintf("%s %s NULLS LAST", sortField, order)
		} else {
			orderByClause = fmt.Sprintf("%s %s", sortField, order)
		}
	}

	query := fmt.Sprintf(`
		SELECT c.id, c.domain_names, c.dns_provider_id, c.status, c.provider, c.auto_renew,
			c.expires_at, c.issued_at, c.renewal_attempted_at, c.error_message,
			c.certificate_path, c.private_key_path, c.created_at, c.updated_at,
			d.id, d.name, d.provider_type
		FROM certificates c
		LEFT JOIN dns_providers d ON c.dns_provider_id = d.id
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderByClause, argIndex, argIndex+1)

	args = append(args, perPage, offset)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	var certs []model.Certificate
	for rows.Next() {
		var cert model.Certificate
		var dnsProviderID sql.NullString
		var expiresAt, issuedAt, renewalAttemptedAt sql.NullTime
		var errorMessage, certPath, keyPath sql.NullString
		var dpID, dpName, dpType sql.NullString

		err := rows.Scan(
			&cert.ID,
			&cert.DomainNames,
			&dnsProviderID,
			&cert.Status,
			&cert.Provider,
			&cert.AutoRenew,
			&expiresAt,
			&issuedAt,
			&renewalAttemptedAt,
			&errorMessage,
			&certPath,
			&keyPath,
			&cert.CreatedAt,
			&cert.UpdatedAt,
			&dpID,
			&dpName,
			&dpType,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan certificate: %w", err)
		}

		cert.DNSProviderID = fromNullString(dnsProviderID)
		cert.ExpiresAt = fromNullTime(expiresAt)
		cert.IssuedAt = fromNullTime(issuedAt)
		cert.RenewalAttemptedAt = fromNullTime(renewalAttemptedAt)
		cert.ErrorMessage = fromNullString(errorMessage)
		cert.CertificatePath = fromNullString(certPath)
		cert.PrivateKeyPath = fromNullString(keyPath)

		if dpID.Valid {
			cert.DNSProvider = &model.DNSProvider{
				ID:           dpID.String,
				Name:         dpName.String,
				ProviderType: dpType.String,
			}
		}

		certs = append(certs, cert)
	}

	return certs, total, nil
}

func (r *CertificateRepository) DeleteByErrorStatus(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE status = 'error'`)
	if err != nil {
		return 0, fmt.Errorf("failed to delete error certificates: %w", err)
	}
	return result.RowsAffected()
}

func (r *CertificateRepository) ListByStatus(ctx context.Context, status string) ([]model.Certificate, error) {
	query := `
		SELECT id, domain_names, dns_provider_id, status, provider, auto_renew,
			expires_at, issued_at, certificate_path, private_key_path,
			created_at, updated_at
		FROM certificates
		WHERE status = $1
	`

	rows, err := r.db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates by status: %w", err)
	}
	defer rows.Close()

	var certs []model.Certificate
	for rows.Next() {
		var cert model.Certificate
		var dnsProviderID sql.NullString
		var expiresAt, issuedAt sql.NullTime
		var certPath, keyPath sql.NullString

		err := rows.Scan(
			&cert.ID,
			&cert.DomainNames,
			&dnsProviderID,
			&cert.Status,
			&cert.Provider,
			&cert.AutoRenew,
			&expiresAt,
			&issuedAt,
			&certPath,
			&keyPath,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}

		cert.DNSProviderID = fromNullString(dnsProviderID)
		cert.ExpiresAt = fromNullTime(expiresAt)
		cert.IssuedAt = fromNullTime(issuedAt)
		cert.CertificatePath = fromNullString(certPath)
		cert.PrivateKeyPath = fromNullString(keyPath)

		certs = append(certs, cert)
	}

	return certs, nil
}

func (r *CertificateRepository) Update(ctx context.Context, cert *model.Certificate) error {
	query := `
		UPDATE certificates
		SET status = $1, expires_at = $2, issued_at = $3, renewal_attempted_at = $4,
			error_message = $5, certificate_path = $6, private_key_path = $7,
			certificate_pem = $8, private_key_pem = $9, issuer_certificate_pem = $10,
			auto_renew = $11, acme_account = $12
		WHERE id = $13
	`

	// Ensure acme_account is valid JSON
	acmeAccount := cert.AcmeAccount
	if acmeAccount == nil || len(acmeAccount) == 0 {
		acmeAccount = []byte("{}")
	}

	_, err := r.db.ExecContext(ctx, query,
		cert.Status,
		toNullTime(cert.ExpiresAt),
		toNullTime(cert.IssuedAt),
		toNullTime(cert.RenewalAttemptedAt),
		toNullString(cert.ErrorMessage),
		toNullString(cert.CertificatePath),
		toNullString(cert.PrivateKeyPath),
		cert.CertificatePEM,
		cert.PrivateKeyPEM,
		cert.IssuerCertificatePEM,
		cert.AutoRenew,
		acmeAccount,
		cert.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	return nil
}

func (r *CertificateRepository) ClearError(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `UPDATE certificates SET error_message = NULL WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to clear certificate error: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("certificate not found")
	}
	return nil
}

func (r *CertificateRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return model.ErrNotFound
	}

	return nil
}

func (r *CertificateRepository) GetByDomains(ctx context.Context, domains []string) (*model.Certificate, error) {
	// Find certificate that matches any of the domains
	query := `
		SELECT id, domain_names, dns_provider_id, status, provider, auto_renew,
			expires_at, issued_at, certificate_path, private_key_path,
			created_at, updated_at
		FROM certificates
		WHERE domain_names && $1 AND status = 'issued'
		ORDER BY created_at DESC
		LIMIT 1
	`

	cert := &model.Certificate{}
	var dnsProviderID sql.NullString
	var expiresAt, issuedAt sql.NullTime
	var certPath, keyPath sql.NullString

	err := r.db.QueryRowContext(ctx, query, pq.Array(domains)).Scan(
		&cert.ID,
		&cert.DomainNames,
		&dnsProviderID,
		&cert.Status,
		&cert.Provider,
		&cert.AutoRenew,
		&expiresAt,
		&issuedAt,
		&certPath,
		&keyPath,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate by domains: %w", err)
	}

	cert.DNSProviderID = fromNullString(dnsProviderID)
	cert.ExpiresAt = fromNullTime(expiresAt)
	cert.IssuedAt = fromNullTime(issuedAt)
	cert.CertificatePath = fromNullString(certPath)
	cert.PrivateKeyPath = fromNullString(keyPath)

	return cert, nil
}

func (r *CertificateRepository) GetExpiringSoon(ctx context.Context, days int) ([]model.Certificate, error) {
	query := `
		SELECT id, domain_names, dns_provider_id, status, provider, auto_renew,
			expires_at, issued_at, certificate_path, private_key_path,
			created_at, updated_at
		FROM certificates
		WHERE status = 'issued'
			AND auto_renew = true
			AND expires_at <= NOW() + INTERVAL '1 day' * $1
		ORDER BY expires_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []model.Certificate
	for rows.Next() {
		var cert model.Certificate
		var dnsProviderID sql.NullString
		var expiresAt, issuedAt sql.NullTime
		var certPath, keyPath sql.NullString

		err := rows.Scan(
			&cert.ID,
			&cert.DomainNames,
			&dnsProviderID,
			&cert.Status,
			&cert.Provider,
			&cert.AutoRenew,
			&expiresAt,
			&issuedAt,
			&certPath,
			&keyPath,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}

		cert.DNSProviderID = fromNullString(dnsProviderID)
		cert.ExpiresAt = fromNullTime(expiresAt)
		cert.IssuedAt = fromNullTime(issuedAt)
		cert.CertificatePath = fromNullString(certPath)
		cert.PrivateKeyPath = fromNullString(keyPath)

		certs = append(certs, cert)
	}

	return certs, nil
}

// Helper functions
func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func fromNullStringValue(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func fromNullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

// CreateHistory creates a new certificate history entry
func (r *CertificateRepository) CreateHistory(ctx context.Context, history *model.CertificateHistory) (*model.CertificateHistory, error) {
	query := `
		INSERT INTO certificate_history (certificate_id, action, status, message, domain_names, provider, expires_at, logs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, certificate_id, action, status, message, domain_names, provider, expires_at, logs, created_at
	`

	result := &model.CertificateHistory{}
	var expiresAt sql.NullTime
	var message, logs sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		history.CertificateID,
		history.Action,
		history.Status,
		toNullString(&history.Message),
		pq.Array(history.DomainNames),
		history.Provider,
		toNullTime(history.ExpiresAt),
		toNullString(&history.Logs),
	).Scan(
		&result.ID,
		&result.CertificateID,
		&result.Action,
		&result.Status,
		&message,
		&result.DomainNames,
		&result.Provider,
		&expiresAt,
		&logs,
		&result.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create certificate history: %w", err)
	}

	result.Message = fromNullStringValue(message)
	result.ExpiresAt = fromNullTime(expiresAt)
	result.Logs = fromNullStringValue(logs)

	return result, nil
}

// ListHistory returns paginated certificate history
func (r *CertificateRepository) ListHistory(ctx context.Context, page, perPage int, certificateID string) ([]model.CertificateHistory, int, error) {
	offset := (page - 1) * perPage

	// Count total
	var total int
	countQuery := `SELECT COUNT(*) FROM certificate_history`
	args := []interface{}{}

	if certificateID != "" {
		countQuery += ` WHERE certificate_id = $1`
		args = append(args, certificateID)
	}

	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count certificate history: %w", err)
	}

	query := `
		SELECT id, certificate_id, action, status, message, domain_names, provider, expires_at, logs, created_at
		FROM certificate_history
	`

	args = []interface{}{}
	argIdx := 1

	if certificateID != "" {
		query += fmt.Sprintf(` WHERE certificate_id = $%d`, argIdx)
		args = append(args, certificateID)
		argIdx++
	}

	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
	args = append(args, perPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list certificate history: %w", err)
	}
	defer rows.Close()

	var histories []model.CertificateHistory
	for rows.Next() {
		var h model.CertificateHistory
		var expiresAt sql.NullTime
		var message, logs sql.NullString

		err := rows.Scan(
			&h.ID,
			&h.CertificateID,
			&h.Action,
			&h.Status,
			&message,
			&h.DomainNames,
			&h.Provider,
			&expiresAt,
			&logs,
			&h.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan certificate history: %w", err)
		}

		h.Message = fromNullStringValue(message)
		h.ExpiresAt = fromNullTime(expiresAt)
		h.Logs = fromNullStringValue(logs)

		histories = append(histories, h)
	}

	return histories, total, nil
}
