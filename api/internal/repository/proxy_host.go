package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"

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
			proxy_type, domain_names, forward_scheme, forward_host, forward_container_name, forward_container_network, forward_port,
			stream_listen_host, stream_listen_port, stream_protocol, stream_ssl_preread,
			stream_accept_proxy_protocol, stream_send_proxy_protocol,
			stream_proxy_connect_timeout, stream_proxy_timeout,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled, cache_static_only, cache_ttl,
			block_exploits, block_exploits_exceptions,
			waf_enabled, waf_mode, waf_paranoia_level, waf_anomaly_threshold,
			advanced_config, proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
			proxy_buffering, proxy_request_buffering, client_max_body_size, proxy_max_temp_file_size, access_list_id, enabled,
			ddns_enabled, ddns_provider_id, ddns_proxied
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43)
		RETURNING id, COALESCE(proxy_type, 'http') as proxy_type, domain_names, forward_scheme, forward_host, forward_container_name, forward_container_network, forward_port,
			COALESCE(stream_listen_host, '') as stream_listen_host,
			COALESCE(stream_listen_port, 0) as stream_listen_port,
			COALESCE(stream_protocol, 'tcp') as stream_protocol,
			COALESCE(stream_ssl_preread, false) as stream_ssl_preread,
			COALESCE(stream_accept_proxy_protocol, false) as stream_accept_proxy_protocol,
			COALESCE(stream_send_proxy_protocol, false) as stream_send_proxy_protocol,
			COALESCE(stream_proxy_connect_timeout, 0) as stream_proxy_connect_timeout,
			COALESCE(stream_proxy_timeout, 0) as stream_proxy_timeout,
			ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id,
			allow_websocket_upgrade, cache_enabled, cache_static_only, cache_ttl,
			block_exploits, block_exploits_exceptions,
			custom_locations, advanced_config, waf_enabled, waf_mode,
			waf_paranoia_level, waf_anomaly_threshold,
			proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
			proxy_buffering, COALESCE(proxy_request_buffering, '') as proxy_request_buffering,
			client_max_body_size, COALESCE(proxy_max_temp_file_size, '') as proxy_max_temp_file_size,
			access_list_id, enabled, is_favorite, COALESCE(config_status, 'ok') as config_status, COALESCE(config_error, '') as config_error, ddns_enabled, ddns_provider_id, ddns_proxied, meta, created_at, updated_at
	`

	var host model.ProxyHost
	var certificateID, accessListID sql.NullString
	var forwardContainerName, forwardContainerNetwork sql.NullString
	var ddnsProviderID sql.NullString
	var customLocations, meta []byte

	// Convert certificate_id to NullString
	var certIDParam sql.NullString
	if req.CertificateID != nil && *req.CertificateID != "" {
		certIDParam = sql.NullString{String: *req.CertificateID, Valid: true}
	}

	// Convert access_list_id to NullString
	var accessListIDParam sql.NullString
	if req.AccessListID != nil && *req.AccessListID != "" {
		accessListIDParam = sql.NullString{String: *req.AccessListID, Valid: true}
	}

	// Convert ddns_provider_id to NullString (#157)
	var ddnsProviderIDParam sql.NullString
	if req.DDNSProviderID != nil && *req.DDNSProviderID != "" {
		ddnsProviderIDParam = sql.NullString{String: *req.DDNSProviderID, Valid: true}
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
		blockExploitsExceptions = "^/wp-json/\n^/api/v1/challenge/\n^/webapi/"
	}

	// Set default cache TTL if not provided
	cacheTTL := req.CacheTTL
	if cacheTTL == "" {
		cacheTTL = "7d"
	}

	err := r.db.QueryRowContext(ctx, query,
		req.ProxyType,
		pq.Array(req.DomainNames),
		req.ForwardScheme,
		req.ForwardHost,
		req.ForwardContainerName,
		req.ForwardContainerNetwork,
		req.ForwardPort,
		req.StreamListenHost,
		req.StreamListenPort,
		req.StreamProtocol,
		req.StreamSSLPreread,
		req.StreamAcceptProxyProtocol,
		req.StreamSendProxyProtocol,
		req.StreamProxyConnectTimeout,
		req.StreamProxyTimeout,
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
		req.ProxyRequestBuffering,
		req.ClientMaxBodySize,
		req.ProxyMaxTempFileSize,
		accessListIDParam,
		req.Enabled,
		req.DDNSEnabled,
		ddnsProviderIDParam,
		req.DDNSProxied,
	).Scan(
		&host.ID,
		&host.ProxyType,
		&host.DomainNames,
		&host.ForwardScheme,
		&host.ForwardHost,
		&forwardContainerName,
		&forwardContainerNetwork,
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
		&host.DDNSEnabled,
		&ddnsProviderID,
		&host.DDNSProxied,
		&meta,
		&host.CreatedAt,
		&host.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create proxy host: %w", err)
	}

	if forwardContainerName.Valid {
		host.ForwardContainerName = &forwardContainerName.String
	}
	if forwardContainerNetwork.Valid {
		host.ForwardContainerNetwork = &forwardContainerNetwork.String
	}
	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	if ddnsProviderID.Valid {
		host.DDNSProviderID = &ddnsProviderID.String
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
		SELECT id, COALESCE(proxy_type, 'http') as proxy_type, domain_names, forward_scheme, forward_host, forward_container_name, forward_container_network, forward_port,
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
			access_list_id, enabled, is_favorite, COALESCE(config_status, 'ok') as config_status, COALESCE(config_error, '') as config_error, ddns_enabled, ddns_provider_id, ddns_proxied, meta, created_at, updated_at
		FROM proxy_hosts WHERE id = $1
	`

	var host model.ProxyHost
	var certificateID, accessListID sql.NullString
	var forwardContainerName, forwardContainerNetwork sql.NullString
	var ddnsProviderID sql.NullString
	var customLocations, meta []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&host.ID,
		&host.ProxyType,
		&host.DomainNames,
		&host.ForwardScheme,
		&host.ForwardHost,
		&forwardContainerName,
		&forwardContainerNetwork,
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
		&host.DDNSEnabled,
		&ddnsProviderID,
		&host.DDNSProxied,
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

	if forwardContainerName.Valid {
		host.ForwardContainerName = &forwardContainerName.String
	}
	if forwardContainerNetwork.Valid {
		host.ForwardContainerNetwork = &forwardContainerNetwork.String
	}
	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	if ddnsProviderID.Valid {
		host.DDNSProviderID = &ddnsProviderID.String
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
	if req.ProxyType != "" {
		existing.ProxyType = req.ProxyType
	}
	if len(req.DomainNames) > 0 {
		existing.DomainNames = req.DomainNames
	}
	if req.ForwardScheme != "" {
		existing.ForwardScheme = req.ForwardScheme
	}
	if req.ForwardHost != "" {
		existing.ForwardHost = req.ForwardHost
	}
	if req.ForwardContainerName != nil {
		if *req.ForwardContainerName == "" {
			existing.ForwardContainerName = nil // Clear container name
		} else {
			existing.ForwardContainerName = req.ForwardContainerName
		}
	}
	if req.ForwardContainerNetwork != nil {
		if *req.ForwardContainerNetwork == "" {
			existing.ForwardContainerNetwork = nil // Clear container network
		} else {
			existing.ForwardContainerNetwork = req.ForwardContainerNetwork
		}
	}
	if req.ForwardPort > 0 {
		existing.ForwardPort = req.ForwardPort
	}
	if req.StreamListenHost != nil {
		existing.StreamListenHost = *req.StreamListenHost
	}
	if req.StreamListenPort != nil {
		existing.StreamListenPort = *req.StreamListenPort
	}
	if req.StreamProtocol != nil {
		existing.StreamProtocol = *req.StreamProtocol
	}
	if req.StreamSSLPreread != nil {
		existing.StreamSSLPreread = *req.StreamSSLPreread
	}
	if req.StreamAcceptProxyProtocol != nil {
		existing.StreamAcceptProxyProtocol = *req.StreamAcceptProxyProtocol
	}
	if req.StreamSendProxyProtocol != nil {
		existing.StreamSendProxyProtocol = *req.StreamSendProxyProtocol
	}
	if req.StreamProxyConnectTimeout != nil {
		existing.StreamProxyConnectTimeout = *req.StreamProxyConnectTimeout
	}
	if req.StreamProxyTimeout != nil {
		existing.StreamProxyTimeout = *req.StreamProxyTimeout
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
		if *req.CertificateID == "" {
			existing.CertificateID = nil // Clear certificate
		} else {
			existing.CertificateID = req.CertificateID
		}
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
	if req.ProxyRequestBuffering != nil {
		existing.ProxyRequestBuffering = *req.ProxyRequestBuffering
	}
	if req.ClientMaxBodySize != nil {
		existing.ClientMaxBodySize = *req.ClientMaxBodySize
	}
	if req.ProxyMaxTempFileSize != nil {
		existing.ProxyMaxTempFileSize = *req.ProxyMaxTempFileSize
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.AccessListID != nil {
		if *req.AccessListID == "" {
			existing.AccessListID = nil // Clear access list
		} else {
			existing.AccessListID = req.AccessListID
		}
	}
	if req.DDNSEnabled != nil {
		existing.DDNSEnabled = *req.DDNSEnabled
	}
	if req.DDNSProviderID != nil {
		if *req.DDNSProviderID == "" {
			existing.DDNSProviderID = nil // Clear DDNS provider
		} else {
			existing.DDNSProviderID = req.DDNSProviderID
		}
	}
	if req.DDNSProxied != nil {
		existing.DDNSProxied = *req.DDNSProxied
	}

	query := `
		UPDATE proxy_hosts SET
			proxy_type = $1,
			domain_names = $2,
			forward_scheme = $3,
			forward_host = $4,
			forward_container_name = $5,
			forward_container_network = $6,
			forward_port = $7,
			stream_listen_host = $8,
			stream_listen_port = $9,
			stream_protocol = $10,
			stream_ssl_preread = $11,
			stream_accept_proxy_protocol = $12,
			stream_send_proxy_protocol = $13,
			stream_proxy_connect_timeout = $14,
			stream_proxy_timeout = $15,
			ssl_enabled = $16,
			ssl_force_https = $17,
			ssl_http2 = $18,
			ssl_http3 = $19,
			certificate_id = $20,
			allow_websocket_upgrade = $21,
			cache_enabled = $22,
			cache_static_only = $23,
			cache_ttl = $24,
			block_exploits = $25,
			block_exploits_exceptions = $26,
			waf_enabled = $27,
			waf_mode = $28,
			waf_paranoia_level = $29,
			waf_anomaly_threshold = $30,
			advanced_config = $31,
			proxy_connect_timeout = $32,
			proxy_send_timeout = $33,
			proxy_read_timeout = $34,
			proxy_buffering = $35,
			proxy_request_buffering = $36,
			client_max_body_size = $37,
			proxy_max_temp_file_size = $38,
			enabled = $39,
			access_list_id = $40,
			ddns_enabled = $41,
			ddns_provider_id = $42,
			ddns_proxied = $44
		WHERE id = $43
		RETURNING updated_at
	`

	// Convert certificate_id to NullString for update
	var certIDParam sql.NullString
	if existing.CertificateID != nil && *existing.CertificateID != "" {
		certIDParam = sql.NullString{String: *existing.CertificateID, Valid: true}
	}

	// Convert access_list_id to NullString for update
	var accessListIDParam sql.NullString
	if existing.AccessListID != nil && *existing.AccessListID != "" {
		accessListIDParam = sql.NullString{String: *existing.AccessListID, Valid: true}
	}

	// Convert ddns_provider_id to NullString for update (#157)
	var ddnsProviderIDParam sql.NullString
	if existing.DDNSProviderID != nil && *existing.DDNSProviderID != "" {
		ddnsProviderIDParam = sql.NullString{String: *existing.DDNSProviderID, Valid: true}
	}

	err = r.db.QueryRowContext(ctx, query,
		existing.ProxyType,
		pq.Array(existing.DomainNames),
		existing.ForwardScheme,
		existing.ForwardHost,
		existing.ForwardContainerName,
		existing.ForwardContainerNetwork,
		existing.ForwardPort,
		existing.StreamListenHost,
		existing.StreamListenPort,
		existing.StreamProtocol,
		existing.StreamSSLPreread,
		existing.StreamAcceptProxyProtocol,
		existing.StreamSendProxyProtocol,
		existing.StreamProxyConnectTimeout,
		existing.StreamProxyTimeout,
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
		existing.ProxyRequestBuffering,
		existing.ClientMaxBodySize,
		existing.ProxyMaxTempFileSize,
		existing.Enabled,
		accessListIDParam,
		existing.DDNSEnabled,
		ddnsProviderIDParam,
		id,
		existing.DDNSProxied,
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

func (r *ProxyHostRepository) GetByDomain(ctx context.Context, domain string) (*model.ProxyHost, error) {
	// Defensive: strip port suffix (e.g. "example.com:443" → "example.com")
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}

	query := `
		SELECT id, COALESCE(proxy_type, 'http') as proxy_type, domain_names, forward_scheme, forward_host, forward_container_name, forward_container_network, forward_port,
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
			access_list_id, enabled, is_favorite, COALESCE(config_status, 'ok') as config_status, COALESCE(config_error, '') as config_error, ddns_enabled, ddns_provider_id, ddns_proxied, meta, created_at, updated_at
		FROM proxy_hosts WHERE $1 = ANY(domain_names)
		LIMIT 1
	`

	var host model.ProxyHost
	var certificateID, accessListID sql.NullString
	var forwardContainerName, forwardContainerNetwork sql.NullString
	var ddnsProviderID sql.NullString
	var customLocations, meta []byte

	err := r.db.QueryRowContext(ctx, query, domain).Scan(
		&host.ID,
		&host.ProxyType,
		&host.DomainNames,
		&host.ForwardScheme,
		&host.ForwardHost,
		&forwardContainerName,
		&forwardContainerNetwork,
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
		&host.DDNSEnabled,
		&ddnsProviderID,
		&host.DDNSProxied,
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

	if forwardContainerName.Valid {
		host.ForwardContainerName = &forwardContainerName.String
	}
	if forwardContainerNetwork.Valid {
		host.ForwardContainerNetwork = &forwardContainerNetwork.String
	}
	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	if ddnsProviderID.Valid {
		host.DDNSProviderID = &ddnsProviderID.String
	}
	host.CustomLocations = json.RawMessage(customLocations)
	host.Meta = json.RawMessage(meta)

	return &host, nil
}
