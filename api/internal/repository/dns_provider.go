package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type DNSProviderRepository struct {
	db *database.DB
}

func NewDNSProviderRepository(db *database.DB) *DNSProviderRepository {
	return &DNSProviderRepository{db: db}
}

func (r *DNSProviderRepository) Create(ctx context.Context, req *model.CreateDNSProviderRequest) (*model.DNSProvider, error) {
	query := `
		INSERT INTO dns_providers (name, provider_type, credentials, is_default)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, provider_type, credentials, is_default, created_at, updated_at
	`

	// If setting as default, unset other defaults first
	if req.IsDefault {
		_, err := r.db.ExecContext(ctx, `UPDATE dns_providers SET is_default = false WHERE is_default = true`)
		if err != nil {
			return nil, fmt.Errorf("failed to unset default provider: %w", err)
		}
	}

	provider := &model.DNSProvider{}
	err := r.db.QueryRowContext(ctx, query,
		req.Name,
		req.ProviderType,
		req.Credentials,
		req.IsDefault,
	).Scan(
		&provider.ID,
		&provider.Name,
		&provider.ProviderType,
		&provider.Credentials,
		&provider.IsDefault,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	return provider, nil
}

func (r *DNSProviderRepository) GetByID(ctx context.Context, id string) (*model.DNSProvider, error) {
	query := `
		SELECT id, name, provider_type, credentials, is_default, created_at, updated_at
		FROM dns_providers
		WHERE id = $1
	`

	provider := &model.DNSProvider{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&provider.ID,
		&provider.Name,
		&provider.ProviderType,
		&provider.Credentials,
		&provider.IsDefault,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS provider: %w", err)
	}

	return provider, nil
}

func (r *DNSProviderRepository) GetDefault(ctx context.Context) (*model.DNSProvider, error) {
	query := `
		SELECT id, name, provider_type, credentials, is_default, created_at, updated_at
		FROM dns_providers
		WHERE is_default = true
		LIMIT 1
	`

	provider := &model.DNSProvider{}
	err := r.db.QueryRowContext(ctx, query).Scan(
		&provider.ID,
		&provider.Name,
		&provider.ProviderType,
		&provider.Credentials,
		&provider.IsDefault,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get default DNS provider: %w", err)
	}

	return provider, nil
}

func (r *DNSProviderRepository) List(ctx context.Context, page, perPage int) ([]model.DNSProvider, int, error) {
	offset := (page - 1) * perPage

	// Count total
	var total int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_providers`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count DNS providers: %w", err)
	}

	query := `
		SELECT id, name, provider_type, credentials, is_default, created_at, updated_at
		FROM dns_providers
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list DNS providers: %w", err)
	}
	defer rows.Close()

	var providers []model.DNSProvider
	for rows.Next() {
		var provider model.DNSProvider
		err := rows.Scan(
			&provider.ID,
			&provider.Name,
			&provider.ProviderType,
			&provider.Credentials,
			&provider.IsDefault,
			&provider.CreatedAt,
			&provider.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan DNS provider: %w", err)
		}
		providers = append(providers, provider)
	}

	return providers, total, nil
}

func (r *DNSProviderRepository) Update(ctx context.Context, id string, req *model.UpdateDNSProviderRequest) (*model.DNSProvider, error) {
	// If setting as default, unset other defaults first
	if req.IsDefault != nil && *req.IsDefault {
		_, err := r.db.ExecContext(ctx, `UPDATE dns_providers SET is_default = false WHERE is_default = true AND id != $1`, id)
		if err != nil {
			return nil, fmt.Errorf("failed to unset default provider: %w", err)
		}
	}

	// Build dynamic update query
	setClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *req.Name)
		argIndex++
	}
	if req.Credentials != nil {
		setClauses = append(setClauses, fmt.Sprintf("credentials = $%d", argIndex))
		args = append(args, *req.Credentials)
		argIndex++
	}
	if req.IsDefault != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_default = $%d", argIndex))
		args = append(args, *req.IsDefault)
		argIndex++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	query := fmt.Sprintf(`
		UPDATE dns_providers
		SET %s
		WHERE id = $%d
		RETURNING id, name, provider_type, credentials, is_default, created_at, updated_at
	`, joinStrings(setClauses, ", "), argIndex)

	args = append(args, id)

	provider := &model.DNSProvider{}
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&provider.ID,
		&provider.Name,
		&provider.ProviderType,
		&provider.Credentials,
		&provider.IsDefault,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update DNS provider: %w", err)
	}

	return provider, nil
}

func (r *DNSProviderRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM dns_providers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete DNS provider: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return model.ErrNotFound
	}

	return nil
}

func (r *DNSProviderRepository) TestConnection(ctx context.Context, providerType string, credentials json.RawMessage) error {
	// Implementation depends on provider type
	// For now, just validate credentials format
	switch providerType {
	case model.DNSProviderCloudflare:
		var creds model.CloudflareCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return fmt.Errorf("invalid cloudflare credentials: %w", err)
		}
		if creds.APIToken == "" && (creds.APIKey == "" || creds.Email == "") {
			return model.ErrInvalidCredentials
		}
	case model.DNSProviderRoute53:
		var creds model.Route53Credentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return fmt.Errorf("invalid route53 credentials: %w", err)
		}
		if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			return model.ErrInvalidCredentials
		}
	case model.DNSProviderDuckDNS:
		var creds model.DuckDNSCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return fmt.Errorf("invalid duckdns credentials: %w", err)
		}
		if creds.Token == "" {
			return model.ErrInvalidCredentials
		}
	case model.DNSProviderDynu:
		var creds model.DynuCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return fmt.Errorf("invalid dynu credentials: %w", err)
		}
		if creds.APIKey == "" {
			return model.ErrInvalidCredentials
		}
	}
	return nil
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
