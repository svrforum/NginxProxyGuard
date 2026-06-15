package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type AuthProviderRepository struct {
	db *database.DB
}

func NewAuthProviderRepository(db *database.DB) *AuthProviderRepository {
	return &AuthProviderRepository{db: db}
}

func (r *AuthProviderRepository) Create(ctx context.Context, req *model.CreateAuthProviderRequest) (*model.AuthProvider, error) {
	timeout := 5000
	if req.TimeoutMs != nil && *req.TimeoutMs > 0 {
		timeout = *req.TimeoutMs
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	cfg := model.AuthProviderConfig{}
	if req.Config != nil {
		cfg = *req.Config
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	var id string
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO auth_providers (name, type, provider_url, config, timeout_ms, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, req.Name, req.Type, req.ProviderURL, cfgJSON, timeout, enabled).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetByID(ctx, id)
}

func (r *AuthProviderRepository) GetByID(ctx context.Context, id string) (*model.AuthProvider, error) {
	var ap model.AuthProvider
	var cfgRaw []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, type, provider_url, config, timeout_ms, enabled, created_at, updated_at
		FROM auth_providers WHERE id = $1
	`, id).Scan(&ap.ID, &ap.Name, &ap.Type, &ap.ProviderURL, &cfgRaw, &ap.TimeoutMs, &ap.Enabled, &ap.CreatedAt, &ap.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(cfgRaw) > 0 {
		_ = json.Unmarshal(cfgRaw, &ap.Config)
	}
	return &ap, nil
}

func (r *AuthProviderRepository) List(ctx context.Context, page, perPage int) ([]model.AuthProvider, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_providers`).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * perPage
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, type, provider_url, config, timeout_ms, enabled, created_at, updated_at
		FROM auth_providers
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var providers []model.AuthProvider
	for rows.Next() {
		var ap model.AuthProvider
		var cfgRaw []byte
		if err := rows.Scan(&ap.ID, &ap.Name, &ap.Type, &ap.ProviderURL, &cfgRaw, &ap.TimeoutMs, &ap.Enabled, &ap.CreatedAt, &ap.UpdatedAt); err != nil {
			return nil, 0, err
		}
		if len(cfgRaw) > 0 {
			_ = json.Unmarshal(cfgRaw, &ap.Config)
		}
		providers = append(providers, ap)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate auth providers: %w", err)
	}
	return providers, total, nil
}

func (r *AuthProviderRepository) Update(ctx context.Context, id string, req *model.UpdateAuthProviderRequest) (*model.AuthProvider, error) {
	existing, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Type != nil {
		existing.Type = *req.Type
	}
	if req.ProviderURL != nil {
		existing.ProviderURL = *req.ProviderURL
	}
	if req.Config != nil {
		existing.Config = *req.Config
	}
	if req.TimeoutMs != nil && *req.TimeoutMs > 0 {
		existing.TimeoutMs = *req.TimeoutMs
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	cfgJSON, err := json.Marshal(existing.Config)
	if err != nil {
		return nil, err
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE auth_providers
		SET name = $1, type = $2, provider_url = $3, config = $4, timeout_ms = $5, enabled = $6, updated_at = now()
		WHERE id = $7
	`, existing.Name, existing.Type, existing.ProviderURL, cfgJSON, existing.TimeoutMs, existing.Enabled, id)
	if err != nil {
		return nil, err
	}
	return r.GetByID(ctx, id)
}

func (r *AuthProviderRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM auth_providers WHERE id = $1`, id)
	return err
}
