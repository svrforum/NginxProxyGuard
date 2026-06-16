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

// authProviderColumns is the canonical SELECT column order consumed by scanAuthProvider.
const authProviderColumns = `id, name, type, provider_url, config, timeout_ms, enabled,
	container_name, container_network, container_port, container_scheme, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

// scanAuthProvider scans a row selected with authProviderColumns, mapping the
// nullable Docker-container columns (#181) back to optional pointers.
func scanAuthProvider(s rowScanner) (*model.AuthProvider, error) {
	var ap model.AuthProvider
	var cfgRaw []byte
	var cName, cNetwork, cScheme sql.NullString
	var cPort sql.NullInt64
	if err := s.Scan(&ap.ID, &ap.Name, &ap.Type, &ap.ProviderURL, &cfgRaw, &ap.TimeoutMs, &ap.Enabled,
		&cName, &cNetwork, &cPort, &cScheme, &ap.CreatedAt, &ap.UpdatedAt); err != nil {
		return nil, err
	}
	if len(cfgRaw) > 0 {
		_ = json.Unmarshal(cfgRaw, &ap.Config)
	}
	if cName.Valid && cName.String != "" {
		v := cName.String
		ap.ContainerName = &v
	}
	if cNetwork.Valid && cNetwork.String != "" {
		v := cNetwork.String
		ap.ContainerNetwork = &v
	}
	if cScheme.Valid && cScheme.String != "" {
		v := cScheme.String
		ap.ContainerScheme = &v
	}
	if cPort.Valid {
		v := int(cPort.Int64)
		ap.ContainerPort = &v
	}
	return &ap, nil
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
		INSERT INTO auth_providers (name, type, provider_url, config, timeout_ms, enabled,
			container_name, container_network, container_port, container_scheme)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`, req.Name, req.Type, req.ProviderURL, cfgJSON, timeout, enabled,
		req.ContainerName, req.ContainerNetwork, req.ContainerPort, req.ContainerScheme).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetByID(ctx, id)
}

func (r *AuthProviderRepository) GetByID(ctx context.Context, id string) (*model.AuthProvider, error) {
	ap, err := scanAuthProvider(r.db.QueryRowContext(ctx,
		`SELECT `+authProviderColumns+` FROM auth_providers WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ap, nil
}

func (r *AuthProviderRepository) List(ctx context.Context, page, perPage int) ([]model.AuthProvider, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_providers`).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * perPage
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+authProviderColumns+` FROM auth_providers ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var providers []model.AuthProvider
	for rows.Next() {
		ap, err := scanAuthProvider(rows)
		if err != nil {
			return nil, 0, err
		}
		providers = append(providers, *ap)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate auth providers: %w", err)
	}
	return providers, total, nil
}

// ListContainerBacked returns providers whose verify endpoint is a Docker container
// target, for the reconcile scheduler (#181). Mirrors ProxyHost ListContainerBackedHosts.
func (r *AuthProviderRepository) ListContainerBacked(ctx context.Context) ([]model.AuthProvider, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+authProviderColumns+` FROM auth_providers
		 WHERE container_name IS NOT NULL AND container_name <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var providers []model.AuthProvider
	for rows.Next() {
		ap, err := scanAuthProvider(rows)
		if err != nil {
			return nil, err
		}
		providers = append(providers, *ap)
	}
	return providers, rows.Err()
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
	// Container binding: a non-nil ContainerName with empty string clears the binding
	// (back to manual URL); otherwise the four fields are replaced as a set. (#181)
	if req.ContainerName != nil {
		if *req.ContainerName == "" {
			existing.ContainerName, existing.ContainerNetwork, existing.ContainerPort, existing.ContainerScheme = nil, nil, nil, nil
		} else {
			existing.ContainerName = req.ContainerName
			existing.ContainerNetwork = req.ContainerNetwork
			existing.ContainerPort = req.ContainerPort
			existing.ContainerScheme = req.ContainerScheme
		}
	}
	cfgJSON, err := json.Marshal(existing.Config)
	if err != nil {
		return nil, err
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE auth_providers
		SET name = $1, type = $2, provider_url = $3, config = $4, timeout_ms = $5, enabled = $6,
			container_name = $7, container_network = $8, container_port = $9, container_scheme = $10,
			updated_at = now()
		WHERE id = $11
	`, existing.Name, existing.Type, existing.ProviderURL, cfgJSON, existing.TimeoutMs, existing.Enabled,
		existing.ContainerName, existing.ContainerNetwork, existing.ContainerPort, existing.ContainerScheme, id)
	if err != nil {
		return nil, err
	}
	return r.GetByID(ctx, id)
}

// UpdateProviderURL writes only the resolved provider_url, used by the reconcile
// scheduler when a container's IP changes. (#181)
func (r *AuthProviderRepository) UpdateProviderURL(ctx context.Context, id, url string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE auth_providers SET provider_url = $1, updated_at = now() WHERE id = $2`, url, id)
	return err
}

func (r *AuthProviderRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM auth_providers WHERE id = $1`, id)
	return err
}
