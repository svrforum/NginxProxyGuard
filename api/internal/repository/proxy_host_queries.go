package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/model"
)

func (r *ProxyHostRepository) List(ctx context.Context, page, perPage int, search, sortBy, sortOrder string) ([]model.ProxyHost, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	// Build WHERE clause for search
	var whereClause string
	var args []interface{}
	argIndex := 1

	if search != "" {
		// Search in domain_names array and forward_host
		whereClause = fmt.Sprintf(" WHERE (array_to_string(domain_names, ',') ILIKE $%d OR forward_host ILIKE $%d)", argIndex, argIndex)
		args = append(args, "%"+search+"%")
		argIndex++
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM proxy_hosts` + whereClause
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count proxy hosts: %w", err)
	}

	// Build ORDER BY clause (always sort favorites first)
	orderByClause := "is_favorite DESC, created_at DESC" // default
	validSortFields := map[string]string{
		"name":    "domain_names[1]",
		"created": "created_at",
		"updated": "updated_at",
	}
	if sortField, ok := validSortFields[sortBy]; ok {
		order := "ASC"
		if sortOrder == "desc" {
			order = "DESC"
		}
		orderByClause = fmt.Sprintf("is_favorite DESC, %s %s", sortField, order)
	}

	// Get paginated data
	query := fmt.Sprintf(`
		SELECT id, domain_names, forward_scheme, forward_host, forward_port,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled,
			COALESCE(cache_static_only, true) as cache_static_only,
			COALESCE(cache_ttl, '7d') as cache_ttl,
			block_exploits,
			COALESCE(block_exploits_exceptions, '') as block_exploits_exceptions,
			custom_locations, advanced_config, waf_enabled, waf_mode,
			waf_paranoia_level, waf_anomaly_threshold,
			COALESCE(proxy_connect_timeout, 0) as proxy_connect_timeout,
			COALESCE(proxy_send_timeout, 0) as proxy_send_timeout,
			COALESCE(proxy_read_timeout, 0) as proxy_read_timeout,
			COALESCE(proxy_buffering, '') as proxy_buffering,
			COALESCE(proxy_request_buffering, '') as proxy_request_buffering,
			COALESCE(client_max_body_size, '') as client_max_body_size,
			COALESCE(proxy_max_temp_file_size, '') as proxy_max_temp_file_size,
			access_list_id, enabled, is_favorite, COALESCE(config_status, 'ok') as config_status, COALESCE(config_error, '') as config_error, meta, created_at, updated_at
		FROM proxy_hosts
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderByClause, argIndex, argIndex+1)

	args = append(args, perPage, offset)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list proxy hosts: %w", err)
	}
	defer rows.Close()

	var hosts []model.ProxyHost
	for rows.Next() {
		var host model.ProxyHost
		var certificateID, accessListID sql.NullString
		var customLocations, meta []byte

		err := rows.Scan(
			&host.ID,
			&host.DomainNames,
			&host.ForwardScheme,
			&host.ForwardHost,
			&host.ForwardPort,
			&host.SSLEnabled,
			&host.SSLForceHTTPS,
			&host.SSLHTTP2,
			&host.SSLHTTP3,
			&certificateID,
			&host.AllowWebsocketUpgrade,
			&host.CacheEnabled,
			&host.CacheStaticOnly,
			&host.CacheTTL,
			&host.BlockExploits,
			&host.BlockExploitsExceptions,
			&customLocations,
			&host.AdvancedConfig,
			&host.WAFEnabled,
			&host.WAFMode,
			&host.WAFParanoiaLevel,
			&host.WAFAnomalyThreshold,
			&host.ProxyConnectTimeout,
			&host.ProxySendTimeout,
			&host.ProxyReadTimeout,
			&host.ProxyBuffering,
			&host.ProxyRequestBuffering,
			&host.ClientMaxBodySize,
			&host.ProxyMaxTempFileSize,
			&accessListID,
			&host.Enabled,
			&host.IsFavorite,
			&host.ConfigStatus,
			&host.ConfigError,
			&meta,
			&host.CreatedAt,
			&host.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan proxy host: %w", err)
		}

		if certificateID.Valid {
			host.CertificateID = &certificateID.String
		}
		if accessListID.Valid {
			host.AccessListID = &accessListID.String
		}
		host.CustomLocations = json.RawMessage(customLocations)
		host.Meta = json.RawMessage(meta)

		hosts = append(hosts, host)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating proxy hosts: %w", err)
	}

	return hosts, total, nil
}

// CheckDomainExists checks if any of the given domains already exist in another proxy host
// excludeID can be empty string for create operations, or the host ID for update operations
func (r *ProxyHostRepository) CheckDomainExists(ctx context.Context, domains []string, excludeID string) ([]string, error) {
	var existingDomains []string

	for _, domain := range domains {
		query := `
			SELECT domain_names FROM proxy_hosts
			WHERE $1 = ANY(domain_names)
		`
		args := []interface{}{domain}

		if excludeID != "" {
			query += ` AND id != $2`
			args = append(args, excludeID)
		}

		var domainNames []string
		err := r.db.QueryRowContext(ctx, query, args...).Scan(pq.Array(&domainNames))
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to check domain existence: %w", err)
		}
		existingDomains = append(existingDomains, domain)
	}

	return existingDomains, nil
}

func (r *ProxyHostRepository) GetAllEnabled(ctx context.Context) ([]model.ProxyHost, error) {
	query := `
		SELECT id, domain_names, forward_scheme, forward_host, forward_port,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled,
			COALESCE(cache_static_only, true) as cache_static_only,
			COALESCE(cache_ttl, '7d') as cache_ttl,
			block_exploits,
			COALESCE(block_exploits_exceptions, '') as block_exploits_exceptions,
			custom_locations, advanced_config, waf_enabled, waf_mode,
			waf_paranoia_level, waf_anomaly_threshold,
			COALESCE(proxy_connect_timeout, 0) as proxy_connect_timeout,
			COALESCE(proxy_send_timeout, 0) as proxy_send_timeout,
			COALESCE(proxy_read_timeout, 0) as proxy_read_timeout,
			COALESCE(proxy_buffering, '') as proxy_buffering,
			COALESCE(proxy_request_buffering, '') as proxy_request_buffering,
			COALESCE(client_max_body_size, '') as client_max_body_size,
			COALESCE(proxy_max_temp_file_size, '') as proxy_max_temp_file_size,
			access_list_id, enabled, is_favorite, COALESCE(config_status, 'ok') as config_status, COALESCE(config_error, '') as config_error, meta, created_at, updated_at
		FROM proxy_hosts
		WHERE enabled = true
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled proxy hosts: %w", err)
	}
	defer rows.Close()

	var hosts []model.ProxyHost
	for rows.Next() {
		var host model.ProxyHost
		var certificateID, accessListID sql.NullString
		var customLocations, meta []byte

		err := rows.Scan(
			&host.ID,
			&host.DomainNames,
			&host.ForwardScheme,
			&host.ForwardHost,
			&host.ForwardPort,
			&host.SSLEnabled,
			&host.SSLForceHTTPS,
			&host.SSLHTTP2,
			&host.SSLHTTP3,
			&certificateID,
			&host.AllowWebsocketUpgrade,
			&host.CacheEnabled,
			&host.CacheStaticOnly,
			&host.CacheTTL,
			&host.BlockExploits,
			&host.BlockExploitsExceptions,
			&customLocations,
			&host.AdvancedConfig,
			&host.WAFEnabled,
			&host.WAFMode,
			&host.WAFParanoiaLevel,
			&host.WAFAnomalyThreshold,
			&host.ProxyConnectTimeout,
			&host.ProxySendTimeout,
			&host.ProxyReadTimeout,
			&host.ProxyBuffering,
			&host.ProxyRequestBuffering,
			&host.ClientMaxBodySize,
			&host.ProxyMaxTempFileSize,
			&accessListID,
			&host.Enabled,
			&host.IsFavorite,
			&host.ConfigStatus,
			&host.ConfigError,
			&meta,
			&host.CreatedAt,
			&host.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proxy host: %w", err)
		}

		if certificateID.Valid {
			host.CertificateID = &certificateID.String
		}
		if accessListID.Valid {
			host.AccessListID = &accessListID.String
		}
		host.CustomLocations = json.RawMessage(customLocations)
		host.Meta = json.RawMessage(meta)

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// GetByCertificateID returns all proxy hosts using the specified certificate
func (r *ProxyHostRepository) GetByCertificateID(ctx context.Context, certificateID string) ([]model.ProxyHost, error) {
	query := `
		SELECT id, domain_names, forward_scheme, forward_host, forward_port,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled,
			COALESCE(cache_static_only, true) as cache_static_only,
			COALESCE(cache_ttl, '7d') as cache_ttl,
			block_exploits,
			COALESCE(block_exploits_exceptions, '') as block_exploits_exceptions,
			custom_locations, advanced_config, waf_enabled, waf_mode,
			waf_paranoia_level, waf_anomaly_threshold,
			COALESCE(proxy_connect_timeout, 0) as proxy_connect_timeout,
			COALESCE(proxy_send_timeout, 0) as proxy_send_timeout,
			COALESCE(proxy_read_timeout, 0) as proxy_read_timeout,
			COALESCE(proxy_buffering, '') as proxy_buffering,
			COALESCE(proxy_request_buffering, '') as proxy_request_buffering,
			COALESCE(client_max_body_size, '') as client_max_body_size,
			COALESCE(proxy_max_temp_file_size, '') as proxy_max_temp_file_size,
			access_list_id, enabled, is_favorite, COALESCE(config_status, 'ok') as config_status, COALESCE(config_error, '') as config_error, meta, created_at, updated_at
		FROM proxy_hosts
		WHERE certificate_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, certificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy hosts by certificate: %w", err)
	}
	defer rows.Close()

	var hosts []model.ProxyHost
	for rows.Next() {
		var host model.ProxyHost
		var certificateID, accessListID sql.NullString
		var customLocations, meta []byte

		err := rows.Scan(
			&host.ID,
			&host.DomainNames,
			&host.ForwardScheme,
			&host.ForwardHost,
			&host.ForwardPort,
			&host.SSLEnabled,
			&host.SSLForceHTTPS,
			&host.SSLHTTP2,
			&host.SSLHTTP3,
			&certificateID,
			&host.AllowWebsocketUpgrade,
			&host.CacheEnabled,
			&host.CacheStaticOnly,
			&host.CacheTTL,
			&host.BlockExploits,
			&host.BlockExploitsExceptions,
			&customLocations,
			&host.AdvancedConfig,
			&host.WAFEnabled,
			&host.WAFMode,
			&host.WAFParanoiaLevel,
			&host.WAFAnomalyThreshold,
			&host.ProxyConnectTimeout,
			&host.ProxySendTimeout,
			&host.ProxyReadTimeout,
			&host.ProxyBuffering,
			&host.ProxyRequestBuffering,
			&host.ClientMaxBodySize,
			&host.ProxyMaxTempFileSize,
			&accessListID,
			&host.Enabled,
			&host.IsFavorite,
			&host.ConfigStatus,
			&host.ConfigError,
			&meta,
			&host.CreatedAt,
			&host.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proxy host: %w", err)
		}

		if certificateID.Valid {
			host.CertificateID = &certificateID.String
		}
		if accessListID.Valid {
			host.AccessListID = &accessListID.String
		}
		host.CustomLocations = json.RawMessage(customLocations)
		host.Meta = json.RawMessage(meta)

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// UpdateConfigStatus updates the config_status and config_error for a proxy host
func (r *ProxyHostRepository) UpdateConfigStatus(ctx context.Context, id, status, configError string) error {
	query := `UPDATE proxy_hosts SET config_status = $1, config_error = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, status, configError, id)
	if err != nil {
		return fmt.Errorf("failed to update config status: %w", err)
	}
	r.invalidateHostCache(ctx, id)
	return nil
}
