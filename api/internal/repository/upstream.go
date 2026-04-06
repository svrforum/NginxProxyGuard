package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"nginx-proxy-guard/internal/model"
)

var validUpstreamName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

type UpstreamRepository struct {
	db *sql.DB
}

func NewUpstreamRepository(db *sql.DB) *UpstreamRepository {
	return &UpstreamRepository{db: db}
}

func (r *UpstreamRepository) GetByProxyHostID(ctx context.Context, proxyHostID string) (*model.Upstream, error) {
	query := `
		SELECT id, proxy_host_id, name, servers, load_balance, health_check_enabled, health_check_interval,
		       health_check_timeout, health_check_path, health_check_expected_status, keepalive,
		       is_healthy, last_check_at, created_at, updated_at
		FROM upstreams
		WHERE proxy_host_id = $1
	`

	var u model.Upstream
	var serversJSON []byte
	var lastCheckAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&u.ID, &u.ProxyHostID, &u.Name, &serversJSON, &u.LoadBalance, &u.HealthCheckEnabled, &u.HealthCheckInterval,
		&u.HealthCheckTimeout, &u.HealthCheckPath, &u.HealthCheckExpectedStatus, &u.Keepalive,
		&u.IsHealthy, &lastCheckAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if lastCheckAt.Valid {
		u.LastCheckAt = &lastCheckAt.Time
	}

	if len(serversJSON) > 0 {
		if err := json.Unmarshal(serversJSON, &u.Servers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
	}

	return &u, nil
}

func (r *UpstreamRepository) GetByID(ctx context.Context, id string) (*model.Upstream, error) {
	query := `
		SELECT id, proxy_host_id, name, servers, load_balance, health_check_enabled, health_check_interval,
		       health_check_timeout, health_check_path, health_check_expected_status, keepalive,
		       is_healthy, last_check_at, created_at, updated_at
		FROM upstreams
		WHERE id = $1
	`

	var u model.Upstream
	var serversJSON []byte
	var lastCheckAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID, &u.ProxyHostID, &u.Name, &serversJSON, &u.LoadBalance, &u.HealthCheckEnabled, &u.HealthCheckInterval,
		&u.HealthCheckTimeout, &u.HealthCheckPath, &u.HealthCheckExpectedStatus, &u.Keepalive,
		&u.IsHealthy, &lastCheckAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if lastCheckAt.Valid {
		u.LastCheckAt = &lastCheckAt.Time
	}

	if len(serversJSON) > 0 {
		if err := json.Unmarshal(serversJSON, &u.Servers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
	}

	return &u, nil
}

func (r *UpstreamRepository) Upsert(ctx context.Context, proxyHostID string, req *model.CreateUpstreamRequest) (*model.Upstream, error) {
	serversJSON := []byte("[]")
	if req.Servers != nil && len(req.Servers) > 0 {
		servers := make([]model.UpstreamServer, len(req.Servers))
		for i, s := range req.Servers {
			servers[i] = model.UpstreamServer{
				Address:     s.Address,
				Port:        s.Port,
				Weight:      s.Weight,
				MaxFails:    s.MaxFails,
				FailTimeout: s.FailTimeout,
				IsBackup:    s.IsBackup,
				IsDown:      s.IsDown,
				IsHealthy:   true,
			}
			if servers[i].Port == 0 {
				servers[i].Port = 80
			}
			if servers[i].Weight == 0 {
				servers[i].Weight = 1
			}
			if servers[i].MaxFails == 0 {
				servers[i].MaxFails = 3
			}
			if servers[i].FailTimeout == 0 {
				servers[i].FailTimeout = 30
			}
		}
		var marshalErr error
		serversJSON, marshalErr = json.Marshal(servers)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to marshal servers JSON: %w", marshalErr)
		}
	}

	// Generate default name in Go to avoid PostgreSQL type inference issues
	name := req.Name
	if name == "" {
		if len(proxyHostID) >= 8 {
			name = "upstream_" + proxyHostID[:8]
		} else {
			name = "upstream_" + proxyHostID
		}
	}

	if !validUpstreamName.MatchString(name) {
		return nil, fmt.Errorf("invalid upstream name: only alphanumeric and underscore allowed")
	}

	query := `
		INSERT INTO upstreams (proxy_host_id, name, servers, load_balance, health_check_enabled, health_check_interval,
		                       health_check_timeout, health_check_path, health_check_expected_status, keepalive)
		VALUES ($1::UUID, $2, $3::JSONB, COALESCE(NULLIF($4, ''), 'round_robin'), COALESCE($5, FALSE),
		        COALESCE(NULLIF($6, 0), 30), COALESCE(NULLIF($7, 0), 5), COALESCE(NULLIF($8, ''), '/'),
		        COALESCE(NULLIF($9, 0), 200), COALESCE(NULLIF($10, 0), 32))
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			name = EXCLUDED.name,
			servers = EXCLUDED.servers,
			load_balance = EXCLUDED.load_balance,
			health_check_enabled = EXCLUDED.health_check_enabled,
			health_check_interval = EXCLUDED.health_check_interval,
			health_check_timeout = EXCLUDED.health_check_timeout,
			health_check_path = EXCLUDED.health_check_path,
			health_check_expected_status = EXCLUDED.health_check_expected_status,
			keepalive = EXCLUDED.keepalive,
			updated_at = NOW()
		RETURNING id, proxy_host_id, name, servers, load_balance, health_check_enabled, health_check_interval,
		          health_check_timeout, health_check_path, health_check_expected_status, keepalive,
		          is_healthy, last_check_at, created_at, updated_at
	`

	var u model.Upstream
	var returnedServersJSON []byte
	var lastCheckAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query,
		proxyHostID, name, serversJSON, req.LoadBalance, req.HealthCheckEnabled,
		req.HealthCheckInterval, req.HealthCheckTimeout, req.HealthCheckPath,
		req.HealthCheckExpectedStatus, req.Keepalive,
	).Scan(
		&u.ID, &u.ProxyHostID, &u.Name, &returnedServersJSON, &u.LoadBalance, &u.HealthCheckEnabled, &u.HealthCheckInterval,
		&u.HealthCheckTimeout, &u.HealthCheckPath, &u.HealthCheckExpectedStatus, &u.Keepalive,
		&u.IsHealthy, &lastCheckAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if lastCheckAt.Valid {
		u.LastCheckAt = &lastCheckAt.Time
	}

	if len(returnedServersJSON) > 0 {
		if err := json.Unmarshal(returnedServersJSON, &u.Servers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
	}

	return &u, nil
}

func (r *UpstreamRepository) Delete(ctx context.Context, proxyHostID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM upstreams WHERE proxy_host_id = $1", proxyHostID)
	return err
}

func (r *UpstreamRepository) UpdateHealthStatus(ctx context.Context, id string, isHealthy bool, lastError string) error {
	query := `
		UPDATE upstreams
		SET is_healthy = $2, last_check_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id, isHealthy)
	return err
}

func (r *UpstreamRepository) UpdateServerHealth(ctx context.Context, upstreamID, address string, port int, isHealthy bool, lastError string, responseTime int64) error {
	// First get current servers
	var serversJSON []byte
	err := r.db.QueryRowContext(ctx, "SELECT servers FROM upstreams WHERE id = $1", upstreamID).Scan(&serversJSON)
	if err != nil {
		return err
	}

	var servers []model.UpstreamServer
	if len(serversJSON) > 0 {
		if err := json.Unmarshal(serversJSON, &servers); err != nil {
			return fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
	}

	// Update the matching server
	now := time.Now()
	for i := range servers {
		if servers[i].Address == address && servers[i].Port == port {
			servers[i].IsHealthy = isHealthy
			servers[i].LastCheckAt = &now
			servers[i].LastError = lastError
			break
		}
	}

	// Save back
	updatedJSON, marshalErr := json.Marshal(servers)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal servers JSON: %w", marshalErr)
	}
	_, err = r.db.ExecContext(ctx, "UPDATE upstreams SET servers = $2, updated_at = NOW() WHERE id = $1", upstreamID, updatedJSON)
	return err
}

func (r *UpstreamRepository) ListWithHealthCheck(ctx context.Context) ([]model.Upstream, error) {
	query := `
		SELECT id, proxy_host_id, name, servers, load_balance, health_check_enabled, health_check_interval,
		       health_check_timeout, health_check_path, health_check_expected_status, keepalive,
		       is_healthy, last_check_at, created_at, updated_at
		FROM upstreams
		WHERE health_check_enabled = TRUE
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var upstreams []model.Upstream
	for rows.Next() {
		var u model.Upstream
		var serversJSON []byte
		var lastCheckAt sql.NullTime

		err := rows.Scan(
			&u.ID, &u.ProxyHostID, &u.Name, &serversJSON, &u.LoadBalance, &u.HealthCheckEnabled, &u.HealthCheckInterval,
			&u.HealthCheckTimeout, &u.HealthCheckPath, &u.HealthCheckExpectedStatus, &u.Keepalive,
			&u.IsHealthy, &lastCheckAt, &u.CreatedAt, &u.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if lastCheckAt.Valid {
			u.LastCheckAt = &lastCheckAt.Time
		}

		if len(serversJSON) > 0 {
			if err := json.Unmarshal(serversJSON, &u.Servers); err != nil {
				return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
			}
		}

		upstreams = append(upstreams, u)
	}

	return upstreams, nil
}
