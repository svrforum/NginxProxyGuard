package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

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
		SELECT id, COALESCE(proxy_type, 'http') as proxy_type, domain_names, forward_scheme, forward_host, forward_port,
			COALESCE(stream_listen_host, '') as stream_listen_host,
			COALESCE(stream_listen_port, 0) as stream_listen_port,
			COALESCE(stream_protocol, 'tcp') as stream_protocol,
			COALESCE(stream_ssl_preread, false) as stream_ssl_preread,
			COALESCE(stream_accept_proxy_protocol, false) as stream_accept_proxy_protocol,
			COALESCE(stream_send_proxy_protocol, false) as stream_send_proxy_protocol,
			COALESCE(stream_proxy_connect_timeout, 0) as stream_proxy_connect_timeout,
			COALESCE(stream_proxy_timeout, 0) as stream_proxy_timeout,
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
			&host.ProxyType,
			&host.DomainNames,
			&host.ForwardScheme,
			&host.ForwardHost,
			&host.ForwardPort,
			&host.StreamListenHost,
			&host.StreamListenPort,
			&host.StreamProtocol,
			&host.StreamSSLPreread,
			&host.StreamAcceptProxyProtocol,
			&host.StreamSendProxyProtocol,
			&host.StreamProxyConnectTimeout,
			&host.StreamProxyTimeout,
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
	if len(domains) == 0 {
		return nil, nil
	}

	// Single query: unnest stored domain_names, intersect with input set in one pass.
	// Was: N round-trips (one SELECT per domain). Now: one SELECT.
	query := `
		SELECT DISTINCT d
		FROM proxy_hosts, UNNEST(domain_names) AS d
		WHERE d = ANY($1::text[])
		  AND COALESCE(proxy_type, 'http') = 'http'
	`
	args := []interface{}{pq.Array(domains)}

	if excludeID != "" {
		query += ` AND id != $2`
		args = append(args, excludeID)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to check domain existence: %w", err)
	}
	defer rows.Close()

	var existingDomains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("failed to scan existing domain: %w", err)
		}
		existingDomains = append(existingDomains, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate domain check rows: %w", err)
	}

	return existingDomains, nil
}

// CheckStreamListenConflicts validates TCP/UDP stream listener collisions.
// Multiple TLS-preread stream hosts may share a listener only when their
// server_name entries are disjoint; non-preread listeners own the whole port.
func (r *ProxyHostRepository) CheckStreamListenConflicts(ctx context.Context, domains []string, listenHost string, listenPort int, protocol string, sslPreread bool, excludeID string) ([]string, error) {
	if listenPort <= 0 {
		return nil, nil
	}

	query := `
		SELECT domain_names, COALESCE(stream_ssl_preread, false)
		FROM proxy_hosts
		WHERE COALESCE(proxy_type, 'http') = 'stream'
		  AND COALESCE(stream_listen_host, '') = $1
		  AND COALESCE(stream_listen_port, 0) = $2
		  AND COALESCE(stream_protocol, 'tcp') = $3
	`
	args := []interface{}{listenHost, listenPort, protocol}
	if excludeID != "" {
		query += ` AND id != $4`
		args = append(args, excludeID)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to check stream listener conflicts: %w", err)
	}
	defer rows.Close()

	requested := make(map[string]bool, len(domains))
	for _, domain := range domains {
		requested[strings.ToLower(strings.TrimSpace(domain))] = true
	}

	var conflicts []string
	for rows.Next() {
		var existingDomains pq.StringArray
		var existingSSLPreread bool
		if err := rows.Scan(&existingDomains, &existingSSLPreread); err != nil {
			return nil, fmt.Errorf("failed to scan stream listener conflict: %w", err)
		}
		if !sslPreread || !existingSSLPreread {
			conflicts = append(conflicts, fmt.Sprintf("%s:%d/%s", listenHost, listenPort, protocol))
			continue
		}
		for _, existing := range existingDomains {
			key := strings.ToLower(strings.TrimSpace(existing))
			if requested[key] {
				conflicts = append(conflicts, existing)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate stream listener conflicts: %w", err)
	}

	return conflicts, nil
}

func (r *ProxyHostRepository) GetAllEnabled(ctx context.Context) ([]model.ProxyHost, error) {
	query := `
		SELECT id, COALESCE(proxy_type, 'http') as proxy_type, domain_names, forward_scheme, forward_host, forward_port,
			COALESCE(stream_listen_host, '') as stream_listen_host,
			COALESCE(stream_listen_port, 0) as stream_listen_port,
			COALESCE(stream_protocol, 'tcp') as stream_protocol,
			COALESCE(stream_ssl_preread, false) as stream_ssl_preread,
			COALESCE(stream_accept_proxy_protocol, false) as stream_accept_proxy_protocol,
			COALESCE(stream_send_proxy_protocol, false) as stream_send_proxy_protocol,
			COALESCE(stream_proxy_connect_timeout, 0) as stream_proxy_connect_timeout,
			COALESCE(stream_proxy_timeout, 0) as stream_proxy_timeout,
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
			&host.ProxyType,
			&host.DomainNames,
			&host.ForwardScheme,
			&host.ForwardHost,
			&host.ForwardPort,
			&host.StreamListenHost,
			&host.StreamListenPort,
			&host.StreamProtocol,
			&host.StreamSSLPreread,
			&host.StreamAcceptProxyProtocol,
			&host.StreamSendProxyProtocol,
			&host.StreamProxyConnectTimeout,
			&host.StreamProxyTimeout,
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
		SELECT id, COALESCE(proxy_type, 'http') as proxy_type, domain_names, forward_scheme, forward_host, forward_port,
			COALESCE(stream_listen_host, '') as stream_listen_host,
			COALESCE(stream_listen_port, 0) as stream_listen_port,
			COALESCE(stream_protocol, 'tcp') as stream_protocol,
			COALESCE(stream_ssl_preread, false) as stream_ssl_preread,
			COALESCE(stream_accept_proxy_protocol, false) as stream_accept_proxy_protocol,
			COALESCE(stream_send_proxy_protocol, false) as stream_send_proxy_protocol,
			COALESCE(stream_proxy_connect_timeout, 0) as stream_proxy_connect_timeout,
			COALESCE(stream_proxy_timeout, 0) as stream_proxy_timeout,
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
			&host.ProxyType,
			&host.DomainNames,
			&host.ForwardScheme,
			&host.ForwardHost,
			&host.ForwardPort,
			&host.StreamListenHost,
			&host.StreamListenPort,
			&host.StreamProtocol,
			&host.StreamSSLPreread,
			&host.StreamAcceptProxyProtocol,
			&host.StreamSendProxyProtocol,
			&host.StreamProxyConnectTimeout,
			&host.StreamProxyTimeout,
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
