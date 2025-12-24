package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"

	"github.com/lib/pq"
)

type ProxyHostRepository struct {
	db    *database.DB
	cache *cache.RedisClient
}

func NewProxyHostRepository(db *database.DB) *ProxyHostRepository {
	return &ProxyHostRepository{db: db}
}

// SetCache sets the cache client for the repository
func (r *ProxyHostRepository) SetCache(c *cache.RedisClient) {
	r.cache = c
}

// invalidateHostCache invalidates cache for a specific host
func (r *ProxyHostRepository) invalidateHostCache(ctx context.Context, hostID string) {
	if r.cache != nil {
		if err := r.cache.InvalidateProxyHostConfig(ctx, hostID); err != nil {
			log.Printf("[Cache] Failed to invalidate proxy host cache for %s: %v", hostID, err)
		}
	}
}

// invalidateAllCache invalidates all proxy host caches
func (r *ProxyHostRepository) invalidateAllCache(ctx context.Context) {
	if r.cache != nil {
		if err := r.cache.InvalidateAllProxyHostConfigs(ctx); err != nil {
			log.Printf("[Cache] Failed to invalidate all proxy host caches: %v", err)
		}
	}
}

func (r *ProxyHostRepository) Create(ctx context.Context, req *model.CreateProxyHostRequest) (*model.ProxyHost, error) {
	query := `
		INSERT INTO proxy_hosts (
			domain_names, forward_scheme, forward_host, forward_port,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled, cache_static_only, cache_ttl,
			block_exploits, block_exploits_exceptions,
			waf_enabled, waf_mode, waf_paranoia_level, waf_anomaly_threshold,
			advanced_config, proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
			proxy_buffering, client_max_body_size, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
		RETURNING id, domain_names, forward_scheme, forward_host, forward_port,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled, cache_static_only, cache_ttl,
			block_exploits, block_exploits_exceptions,
			custom_locations, advanced_config, waf_enabled, waf_mode,
			waf_paranoia_level, waf_anomaly_threshold,
			proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
			proxy_buffering, client_max_body_size,
			access_list_id, enabled, meta, created_at, updated_at
	`

	var host model.ProxyHost
	var certificateID, accessListID sql.NullString
	var customLocations, meta []byte

	// Convert certificate_id to NullString
	var certIDParam sql.NullString
	if req.CertificateID != nil && *req.CertificateID != "" {
		certIDParam = sql.NullString{String: *req.CertificateID, Valid: true}
	}

	// Set default WAF mode if not provided
	wafMode := req.WAFMode
	if wafMode == "" {
		wafMode = "blocking"
	}

	// Set default WAF tuning values
	paranoiaLevel := req.WAFParanoiaLevel
	if paranoiaLevel < 1 || paranoiaLevel > 4 {
		paranoiaLevel = 1
	}
	anomalyThreshold := req.WAFAnomalyThreshold
	if anomalyThreshold < 1 {
		anomalyThreshold = 5
	}

	// Set default block_exploits_exceptions when block_exploits is enabled
	blockExploitsExceptions := req.BlockExploitsExceptions
	if req.BlockExploits && blockExploitsExceptions == "" {
		blockExploitsExceptions = "^/wp-json/\n^/api/v1/challenge/"
	}

	// Set default cache TTL if not provided
	cacheTTL := req.CacheTTL
	if cacheTTL == "" {
		cacheTTL = "7d"
	}

	err := r.db.QueryRowContext(ctx, query,
		pq.Array(req.DomainNames),
		req.ForwardScheme,
		req.ForwardHost,
		req.ForwardPort,
		req.SSLEnabled,
		req.SSLForceHTTPS,
		req.SSLHTTP2,
		req.SSLHTTP3,
		certIDParam,
		req.AllowWebsocketUpgrade,
		req.CacheEnabled,
		req.CacheStaticOnly,
		cacheTTL,
		req.BlockExploits,
		blockExploitsExceptions,
		req.WAFEnabled,
		wafMode,
		paranoiaLevel,
		anomalyThreshold,
		req.AdvancedConfig,
		req.ProxyConnectTimeout,
		req.ProxySendTimeout,
		req.ProxyReadTimeout,
		req.ProxyBuffering,
		req.ClientMaxBodySize,
		req.Enabled,
	).Scan(
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
		&host.ClientMaxBodySize,
		&accessListID,
		&host.Enabled,
		&meta,
		&host.CreatedAt,
		&host.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create proxy host: %w", err)
	}

	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	host.CustomLocations = json.RawMessage(customLocations)
	host.Meta = json.RawMessage(meta)

	// Cache the result
	if r.cache != nil {
		if err := r.cache.SetProxyHostConfig(ctx, host.ID, &host); err != nil {
			log.Printf("[Cache] Failed to cache proxy host config: %v", err)
		}
	}

	return &host, nil
}

func (r *ProxyHostRepository) GetByID(ctx context.Context, id string) (*model.ProxyHost, error) {
	// Try cache first
	if r.cache != nil {
		var cached model.ProxyHost
		if err := r.cache.GetProxyHostConfig(ctx, id, &cached); err == nil {
			return &cached, nil
		}
	}
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
			COALESCE(client_max_body_size, '') as client_max_body_size,
			access_list_id, enabled, meta, created_at, updated_at
		FROM proxy_hosts WHERE id = $1
	`

	var host model.ProxyHost
	var certificateID, accessListID sql.NullString
	var customLocations, meta []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
		&host.ClientMaxBodySize,
		&accessListID,
		&host.Enabled,
		&meta,
		&host.CreatedAt,
		&host.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy host: %w", err)
	}

	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	host.CustomLocations = json.RawMessage(customLocations)
	host.Meta = json.RawMessage(meta)

	// Cache the result
	if r.cache != nil {
		if err := r.cache.SetProxyHostConfig(ctx, host.ID, &host); err != nil {
			log.Printf("[Cache] Failed to cache proxy host config: %v", err)
		}
	}

	return &host, nil
}

func (r *ProxyHostRepository) List(ctx context.Context, page, perPage int, search string) ([]model.ProxyHost, int, error) {
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
			COALESCE(client_max_body_size, '') as client_max_body_size,
			access_list_id, enabled, meta, created_at, updated_at
		FROM proxy_hosts
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

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
			&host.ClientMaxBodySize,
			&accessListID,
			&host.Enabled,
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

func (r *ProxyHostRepository) Update(ctx context.Context, id string, req *model.UpdateProxyHostRequest) (*model.ProxyHost, error) {
	// First get existing host
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
	if req.ForwardScheme != "" {
		existing.ForwardScheme = req.ForwardScheme
	}
	if req.ForwardHost != "" {
		existing.ForwardHost = req.ForwardHost
	}
	if req.ForwardPort > 0 {
		existing.ForwardPort = req.ForwardPort
	}
	if req.SSLEnabled != nil {
		existing.SSLEnabled = *req.SSLEnabled
	}
	if req.SSLForceHTTPS != nil {
		existing.SSLForceHTTPS = *req.SSLForceHTTPS
	}
	if req.SSLHTTP2 != nil {
		existing.SSLHTTP2 = *req.SSLHTTP2
	}
	if req.SSLHTTP3 != nil {
		existing.SSLHTTP3 = *req.SSLHTTP3
	}
	if req.CertificateID != nil {
		existing.CertificateID = req.CertificateID
	}
	if req.AllowWebsocketUpgrade != nil {
		existing.AllowWebsocketUpgrade = *req.AllowWebsocketUpgrade
	}
	if req.CacheEnabled != nil {
		existing.CacheEnabled = *req.CacheEnabled
	}
	if req.CacheStaticOnly != nil {
		existing.CacheStaticOnly = *req.CacheStaticOnly
	}
	if req.CacheTTL != nil {
		existing.CacheTTL = *req.CacheTTL
	}
	if req.BlockExploits != nil {
		existing.BlockExploits = *req.BlockExploits
	}
	if req.BlockExploitsExceptions != nil {
		existing.BlockExploitsExceptions = *req.BlockExploitsExceptions
	}
	if req.WAFEnabled != nil {
		existing.WAFEnabled = *req.WAFEnabled
	}
	if req.WAFMode != nil {
		existing.WAFMode = *req.WAFMode
	}
	if req.WAFParanoiaLevel != nil {
		existing.WAFParanoiaLevel = *req.WAFParanoiaLevel
	}
	if req.WAFAnomalyThreshold != nil {
		existing.WAFAnomalyThreshold = *req.WAFAnomalyThreshold
	}
	if req.AdvancedConfig != nil {
		existing.AdvancedConfig = *req.AdvancedConfig
	}
	if req.ProxyConnectTimeout != nil {
		existing.ProxyConnectTimeout = *req.ProxyConnectTimeout
	}
	if req.ProxySendTimeout != nil {
		existing.ProxySendTimeout = *req.ProxySendTimeout
	}
	if req.ProxyReadTimeout != nil {
		existing.ProxyReadTimeout = *req.ProxyReadTimeout
	}
	if req.ProxyBuffering != nil {
		existing.ProxyBuffering = *req.ProxyBuffering
	}
	if req.ClientMaxBodySize != nil {
		existing.ClientMaxBodySize = *req.ClientMaxBodySize
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	query := `
		UPDATE proxy_hosts SET
			domain_names = $1,
			forward_scheme = $2,
			forward_host = $3,
			forward_port = $4,
			ssl_enabled = $5,
			ssl_force_https = $6,
			ssl_http2 = $7,
			ssl_http3 = $8,
			certificate_id = $9,
			allow_websocket_upgrade = $10,
			cache_enabled = $11,
			cache_static_only = $12,
			cache_ttl = $13,
			block_exploits = $14,
			block_exploits_exceptions = $15,
			waf_enabled = $16,
			waf_mode = $17,
			waf_paranoia_level = $18,
			waf_anomaly_threshold = $19,
			advanced_config = $20,
			proxy_connect_timeout = $21,
			proxy_send_timeout = $22,
			proxy_read_timeout = $23,
			proxy_buffering = $24,
			client_max_body_size = $25,
			enabled = $26
		WHERE id = $27
		RETURNING updated_at
	`

	// Convert certificate_id to NullString for update
	var certIDParam sql.NullString
	if existing.CertificateID != nil && *existing.CertificateID != "" {
		certIDParam = sql.NullString{String: *existing.CertificateID, Valid: true}
	}

	err = r.db.QueryRowContext(ctx, query,
		pq.Array(existing.DomainNames),
		existing.ForwardScheme,
		existing.ForwardHost,
		existing.ForwardPort,
		existing.SSLEnabled,
		existing.SSLForceHTTPS,
		existing.SSLHTTP2,
		existing.SSLHTTP3,
		certIDParam,
		existing.AllowWebsocketUpgrade,
		existing.CacheEnabled,
		existing.CacheStaticOnly,
		existing.CacheTTL,
		existing.BlockExploits,
		existing.BlockExploitsExceptions,
		existing.WAFEnabled,
		existing.WAFMode,
		existing.WAFParanoiaLevel,
		existing.WAFAnomalyThreshold,
		existing.AdvancedConfig,
		existing.ProxyConnectTimeout,
		existing.ProxySendTimeout,
		existing.ProxyReadTimeout,
		existing.ProxyBuffering,
		existing.ClientMaxBodySize,
		existing.Enabled,
		id,
	).Scan(&existing.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to update proxy host: %w", err)
	}

	// Invalidate cache and store updated value
	r.invalidateHostCache(ctx, id)
	if r.cache != nil {
		if err := r.cache.SetProxyHostConfig(ctx, id, existing); err != nil {
			log.Printf("[Cache] Failed to cache updated proxy host: %v", err)
		}
	}

	return existing, nil
}

func (r *ProxyHostRepository) Delete(ctx context.Context, id string) error {
	// Invalidate cache before delete
	r.invalidateHostCache(ctx, id)

	query := `DELETE FROM proxy_hosts WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete proxy host: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
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

func (r *ProxyHostRepository) GetByDomain(ctx context.Context, domain string) (*model.ProxyHost, error) {
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
			COALESCE(client_max_body_size, '') as client_max_body_size,
			access_list_id, enabled, meta, created_at, updated_at
		FROM proxy_hosts WHERE $1 = ANY(domain_names)
		LIMIT 1
	`

	var host model.ProxyHost
	var certificateID, accessListID sql.NullString
	var customLocations, meta []byte

	err := r.db.QueryRowContext(ctx, query, domain).Scan(
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
		&host.ClientMaxBodySize,
		&accessListID,
		&host.Enabled,
		&meta,
		&host.CreatedAt,
		&host.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy host by domain: %w", err)
	}

	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	host.CustomLocations = json.RawMessage(customLocations)
	host.Meta = json.RawMessage(meta)

	return &host, nil
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
			COALESCE(client_max_body_size, '') as client_max_body_size,
			access_list_id, enabled, meta, created_at, updated_at
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
			&host.ClientMaxBodySize,
			&accessListID,
			&host.Enabled,
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
			COALESCE(client_max_body_size, '') as client_max_body_size,
			access_list_id, enabled, meta, created_at, updated_at
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
			&host.ClientMaxBodySize,
			&accessListID,
			&host.Enabled,
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
