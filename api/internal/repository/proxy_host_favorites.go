package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"nginx-proxy-guard/internal/model"
)

// ToggleFavorite toggles the is_favorite flag for a proxy host without updating updated_at
func (r *ProxyHostRepository) ToggleFavorite(ctx context.Context, id string) (*model.ProxyHost, error) {
	query := `
		UPDATE proxy_hosts SET is_favorite = NOT is_favorite
		WHERE id = $1
		RETURNING id, domain_names, forward_scheme, forward_host, forward_port,
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

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to toggle favorite: %w", err)
	}

	if certificateID.Valid {
		host.CertificateID = &certificateID.String
	}
	if accessListID.Valid {
		host.AccessListID = &accessListID.String
	}
	host.CustomLocations = json.RawMessage(customLocations)
	host.Meta = json.RawMessage(meta)

	// Invalidate cache
	r.invalidateHostCache(ctx, id)

	return &host, nil
}
