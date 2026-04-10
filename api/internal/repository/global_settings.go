package repository

import (
	"context"
	"database/sql"
	"log"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"
)

type GlobalSettingsRepository struct {
	db    *sql.DB
	cache *cache.RedisClient
}

func NewGlobalSettingsRepository(db *sql.DB) *GlobalSettingsRepository {
	return &GlobalSettingsRepository{db: db}
}

// SetCache sets the cache client for the repository
func (r *GlobalSettingsRepository) SetCache(c *cache.RedisClient) {
	r.cache = c
}

func (r *GlobalSettingsRepository) Get(ctx context.Context) (*model.GlobalSettings, error) {
	// Try cache first
	if r.cache != nil {
		var cached model.GlobalSettings
		if err := r.cache.GetGlobalSettings(ctx, &cached); err == nil {
			return &cached, nil
		}
	}

	return r.getFromDB(ctx)
}

// getFromDB retrieves settings from database and caches the result
func (r *GlobalSettingsRepository) getFromDB(ctx context.Context) (*model.GlobalSettings, error) {
	query := `
		SELECT id, worker_processes, worker_connections, worker_rlimit_nofile,
		       multi_accept, use_epoll, sendfile, tcp_nopush, tcp_nodelay,
		       keepalive_timeout, keepalive_requests, types_hash_max_size, server_tokens,
		       client_body_buffer_size, client_header_buffer_size, client_max_body_size, large_client_header_buffers,
		       client_body_timeout, client_header_timeout, send_timeout,
		       proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout,
		       gzip_enabled, gzip_vary, gzip_proxied, gzip_comp_level, gzip_buffers, gzip_http_version, gzip_min_length, gzip_types,
		       COALESCE(brotli_enabled, FALSE), COALESCE(brotli_static, TRUE), COALESCE(brotli_comp_level, 6), COALESCE(brotli_min_length, 1000), COALESCE(brotli_types, ''),
		       ssl_protocols, ssl_ciphers, ssl_prefer_server_ciphers, ssl_session_cache, ssl_session_timeout,
		       ssl_session_tickets, ssl_stapling, ssl_stapling_verify,
		       COALESCE(ssl_ecdh_curve, 'X25519MLKEM768:X25519:secp256r1:secp384r1') as ssl_ecdh_curve,
		       access_log_enabled, error_log_level, resolver, resolver_timeout,
		       custom_http_config, custom_stream_config,
		       COALESCE(direct_ip_access_action, 'allow') as direct_ip_access_action,
		       COALESCE(enable_ipv6, true) as enable_ipv6,
		       COALESCE(limit_conn_enabled, false) as limit_conn_enabled,
		       COALESCE(limit_conn_zone_size, '10m') as limit_conn_zone_size,
		       COALESCE(limit_conn_per_ip, 100) as limit_conn_per_ip,
		       COALESCE(limit_req_enabled, false) as limit_req_enabled,
		       COALESCE(limit_req_zone_size, '10m') as limit_req_zone_size,
		       COALESCE(limit_req_rate, 50) as limit_req_rate,
		       COALESCE(limit_req_burst, 100) as limit_req_burst,
		       COALESCE(reset_timedout_connection, true) as reset_timedout_connection,
		       COALESCE(limit_rate, 0) as limit_rate,
		       COALESCE(limit_rate_after, '0') as limit_rate_after,
		       COALESCE(proxy_buffer_size, '8k') as proxy_buffer_size,
		       COALESCE(proxy_buffers, '8 32k') as proxy_buffers,
		       COALESCE(proxy_busy_buffers_size, '128k') as proxy_busy_buffers_size,
		       COALESCE(proxy_max_temp_file_size, '1024m') as proxy_max_temp_file_size,
		       COALESCE(proxy_temp_file_write_size, '64k') as proxy_temp_file_write_size,
		       COALESCE(proxy_buffering, '') as proxy_buffering,
		       COALESCE(proxy_request_buffering, '') as proxy_request_buffering,
		       COALESCE(open_file_cache_enabled, true) as open_file_cache_enabled,
		       COALESCE(open_file_cache_max, 10000) as open_file_cache_max,
		       COALESCE(open_file_cache_inactive, '60s') as open_file_cache_inactive,
		       COALESCE(open_file_cache_valid, '30s') as open_file_cache_valid,
		       COALESCE(open_file_cache_min_uses, 2) as open_file_cache_min_uses,
		       COALESCE(open_file_cache_errors, true) as open_file_cache_errors,
		       created_at, updated_at
		FROM global_settings
		LIMIT 1
	`

	var s model.GlobalSettings
	var workerRlimitNofile sql.NullInt64
	var resolver, resolverTimeout sql.NullString
	var customHTTP, customStream sql.NullString

	err := r.db.QueryRowContext(ctx, query).Scan(
		&s.ID, &s.WorkerProcesses, &s.WorkerConnections, &workerRlimitNofile,
		&s.MultiAccept, &s.UseEpoll, &s.Sendfile, &s.TCPNopush, &s.TCPNodelay,
		&s.KeepaliveTimeout, &s.KeepaliveRequests, &s.TypesHashMaxSize, &s.ServerTokens,
		&s.ClientBodyBufferSize, &s.ClientHeaderBufferSize, &s.ClientMaxBodySize, &s.LargeClientHeaderBuffers,
		&s.ClientBodyTimeout, &s.ClientHeaderTimeout, &s.SendTimeout,
		&s.ProxyConnectTimeout, &s.ProxySendTimeout, &s.ProxyReadTimeout,
		&s.GzipEnabled, &s.GzipVary, &s.GzipProxied, &s.GzipCompLevel, &s.GzipBuffers, &s.GzipHTTPVersion, &s.GzipMinLength, &s.GzipTypes,
		&s.BrotliEnabled, &s.BrotliStatic, &s.BrotliCompLevel, &s.BrotliMinLength, &s.BrotliTypes,
		&s.SSLProtocols, &s.SSLCiphers, &s.SSLPreferServerCiphers, &s.SSLSessionCache, &s.SSLSessionTimeout,
		&s.SSLSessionTickets, &s.SSLStapling, &s.SSLStaplingVerify,
		&s.SSLECDHCurve,
		&s.AccessLogEnabled, &s.ErrorLogLevel, &resolver, &resolverTimeout,
		&customHTTP, &customStream,
		&s.DirectIPAccessAction,
		&s.EnableIPv6,
		&s.LimitConnEnabled, &s.LimitConnZoneSize, &s.LimitConnPerIP,
		&s.LimitReqEnabled, &s.LimitReqZoneSize, &s.LimitReqRate, &s.LimitReqBurst,
		&s.ResetTimedoutConnection,
		&s.LimitRate, &s.LimitRateAfter,
		&s.ProxyBufferSize, &s.ProxyBuffers, &s.ProxyBusyBuffersSize,
		&s.ProxyMaxTempFileSize, &s.ProxyTempFileWriteSize,
		&s.ProxyBuffering, &s.ProxyRequestBuffering,
		&s.OpenFileCacheEnabled, &s.OpenFileCacheMax, &s.OpenFileCacheInactive,
		&s.OpenFileCacheValid, &s.OpenFileCacheMinUses, &s.OpenFileCacheErrors,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		// Return defaults - synced with nginx.conf optimized values
		return &model.GlobalSettings{
			WorkerProcesses:          0,     // auto (matches CPU cores)
			WorkerConnections:        8192,  // high concurrency support
			MultiAccept:              true,
			UseEpoll:                 true,
			Sendfile:                 true,
			TCPNopush:                true,
			TCPNodelay:               true,
			KeepaliveTimeout:         65,    // optimized timeout (matches nginx.conf)
			KeepaliveRequests:        1000,  // better for HTTP/2
			TypesHashMaxSize:         2048,
			ServerTokens:             false, // hide nginx version
			ClientBodyBufferSize:     "16k", // optimized buffer (matches nginx.conf)
			ClientHeaderBufferSize:   "1k",  // optimized (matches nginx.conf)
			ClientMaxBodySize:        "100m",
			LargeClientHeaderBuffers: "4 8k", // optimized (matches nginx.conf)
			ClientBodyTimeout:        90,
			ClientHeaderTimeout:      90,
			SendTimeout:              90,
			ProxyConnectTimeout:      90,
			ProxySendTimeout:         90,
			ProxyReadTimeout:         90,
			GzipEnabled:              true,
			GzipVary:                 true,
			GzipProxied:              "any",
			GzipCompLevel:            6, // optimized (matches nginx.conf)
			GzipBuffers:              "16 8k",
			GzipHTTPVersion:          "1.1",
			GzipMinLength:            1000, // match nginx.conf
			GzipTypes:                "text/plain text/css text/xml text/javascript application/json application/javascript application/xml application/xml+rss application/x-javascript image/svg+xml",
			BrotliEnabled:            true,
			BrotliStatic:             true,
			BrotliCompLevel:          6, // match nginx.conf
			BrotliMinLength:          1000, // match nginx.conf
			BrotliTypes:              "text/plain text/css text/xml text/javascript application/json application/javascript application/xml application/xml+rss image/svg+xml",
			SSLProtocols:             "TLSv1.2 TLSv1.3",
			SSLCiphers:               "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
			SSLPreferServerCiphers:   true,
			SSLSessionCache:          "shared:SSL:10m", // optimized (matches nginx.conf)
			SSLSessionTimeout:        "1d",
			SSLSessionTickets:        false,
			SSLStapling:              true,
			SSLStaplingVerify:        true,
			SSLECDHCurve:             "X25519MLKEM768:X25519:secp256r1:secp384r1",
			AccessLogEnabled:         true,
			ErrorLogLevel:            "warn",
			Resolver:                 "8.8.8.8 8.8.4.4 valid=300s",
			ResolverTimeout:          "5s",
			DirectIPAccessAction:     "allow",
			EnableIPv6:               true,
			LimitConnEnabled:         false,
			LimitConnZoneSize:        "10m",
			LimitConnPerIP:           200, // more generous
			LimitReqEnabled:          false,
			LimitReqZoneSize:         "10m",
			LimitReqRate:             100, // more generous
			LimitReqBurst:            200, // more generous
			ResetTimedoutConnection:  true,
			LimitRate:                0,
			LimitRateAfter:           "0",
			// Performance tuning defaults
			ProxyBufferSize:        "8k",
			ProxyBuffers:           "8 32k",
			ProxyBusyBuffersSize:   "128k",
			ProxyMaxTempFileSize:   "1024m",
			ProxyTempFileWriteSize: "64k",
			OpenFileCacheEnabled:   true,
			OpenFileCacheMax:       10000,
			OpenFileCacheInactive:  "60s",
			OpenFileCacheValid:     "30s",
			OpenFileCacheMinUses:   2,
			OpenFileCacheErrors:    true,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if workerRlimitNofile.Valid {
		v := int(workerRlimitNofile.Int64)
		s.WorkerRlimitNofile = &v
	}
	s.Resolver = resolver.String
	s.ResolverTimeout = resolverTimeout.String
	s.CustomHTTPConfig = customHTTP.String
	s.CustomStreamConfig = customStream.String

	// Cache the result
	if r.cache != nil {
		if err := r.cache.SetGlobalSettings(ctx, &s); err != nil {
			log.Printf("[Cache] Failed to cache global settings: %v", err)
		}
	}

	return &s, nil
}

func (r *GlobalSettingsRepository) Update(ctx context.Context, req *model.UpdateGlobalSettingsRequest) (*model.GlobalSettings, error) {
	// First ensure a row exists
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO global_settings (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM global_settings LIMIT 1)
	`)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE global_settings SET
			worker_processes = CASE WHEN $1::INT IS NOT NULL THEN $1 ELSE worker_processes END,
			worker_connections = CASE WHEN $2::INT IS NOT NULL THEN $2 ELSE worker_connections END,
			worker_rlimit_nofile = COALESCE($3, worker_rlimit_nofile),
			multi_accept = CASE WHEN $4::BOOLEAN IS NOT NULL THEN $4 ELSE multi_accept END,
			use_epoll = CASE WHEN $5::BOOLEAN IS NOT NULL THEN $5 ELSE use_epoll END,
			sendfile = CASE WHEN $6::BOOLEAN IS NOT NULL THEN $6 ELSE sendfile END,
			tcp_nopush = CASE WHEN $7::BOOLEAN IS NOT NULL THEN $7 ELSE tcp_nopush END,
			tcp_nodelay = CASE WHEN $8::BOOLEAN IS NOT NULL THEN $8 ELSE tcp_nodelay END,
			keepalive_timeout = CASE WHEN $9::INT IS NOT NULL THEN $9 ELSE keepalive_timeout END,
			keepalive_requests = CASE WHEN $10::INT IS NOT NULL THEN $10 ELSE keepalive_requests END,
			types_hash_max_size = CASE WHEN $11::INT IS NOT NULL THEN $11 ELSE types_hash_max_size END,
			server_tokens = CASE WHEN $12::BOOLEAN IS NOT NULL THEN $12 ELSE server_tokens END,
			client_body_buffer_size = CASE WHEN $13 != '' THEN $13 ELSE client_body_buffer_size END,
			client_header_buffer_size = CASE WHEN $14 != '' THEN $14 ELSE client_header_buffer_size END,
			client_max_body_size = CASE WHEN $15 != '' THEN $15 ELSE client_max_body_size END,
			large_client_header_buffers = CASE WHEN $16 != '' THEN $16 ELSE large_client_header_buffers END,
			client_body_timeout = CASE WHEN $17::INT IS NOT NULL THEN $17 ELSE client_body_timeout END,
			client_header_timeout = CASE WHEN $18::INT IS NOT NULL THEN $18 ELSE client_header_timeout END,
			send_timeout = CASE WHEN $19::INT IS NOT NULL THEN $19 ELSE send_timeout END,
			proxy_connect_timeout = CASE WHEN $20::INT IS NOT NULL THEN $20 ELSE proxy_connect_timeout END,
			proxy_send_timeout = CASE WHEN $21::INT IS NOT NULL THEN $21 ELSE proxy_send_timeout END,
			proxy_read_timeout = CASE WHEN $22::INT IS NOT NULL THEN $22 ELSE proxy_read_timeout END,
			gzip_enabled = CASE WHEN $23::BOOLEAN IS NOT NULL THEN $23 ELSE gzip_enabled END,
			gzip_vary = CASE WHEN $24::BOOLEAN IS NOT NULL THEN $24 ELSE gzip_vary END,
			gzip_proxied = CASE WHEN $25 != '' THEN $25 ELSE gzip_proxied END,
			gzip_comp_level = CASE WHEN $26::INT IS NOT NULL THEN $26 ELSE gzip_comp_level END,
			gzip_buffers = CASE WHEN $27 != '' THEN $27 ELSE gzip_buffers END,
			gzip_http_version = CASE WHEN $28 != '' THEN $28 ELSE gzip_http_version END,
			gzip_min_length = CASE WHEN $29::INT IS NOT NULL THEN $29 ELSE gzip_min_length END,
			gzip_types = CASE WHEN $30 != '' THEN $30 ELSE gzip_types END,
			brotli_enabled = CASE WHEN $31::BOOLEAN IS NOT NULL THEN $31 ELSE brotli_enabled END,
			brotli_comp_level = CASE WHEN $32::INT IS NOT NULL THEN $32 ELSE brotli_comp_level END,
			brotli_min_length = CASE WHEN $33::INT IS NOT NULL THEN $33 ELSE brotli_min_length END,
			brotli_types = CASE WHEN $34 != '' THEN $34 ELSE brotli_types END,
			ssl_protocols = CASE WHEN $35 != '' THEN $35 ELSE ssl_protocols END,
			ssl_ciphers = CASE WHEN $36 != '' THEN $36 ELSE ssl_ciphers END,
			ssl_prefer_server_ciphers = CASE WHEN $37::BOOLEAN IS NOT NULL THEN $37 ELSE ssl_prefer_server_ciphers END,
			ssl_session_cache = CASE WHEN $38 != '' THEN $38 ELSE ssl_session_cache END,
			ssl_session_timeout = CASE WHEN $39 != '' THEN $39 ELSE ssl_session_timeout END,
			ssl_session_tickets = CASE WHEN $40::BOOLEAN IS NOT NULL THEN $40 ELSE ssl_session_tickets END,
			ssl_stapling = CASE WHEN $41::BOOLEAN IS NOT NULL THEN $41 ELSE ssl_stapling END,
			ssl_stapling_verify = CASE WHEN $42::BOOLEAN IS NOT NULL THEN $42 ELSE ssl_stapling_verify END,
			access_log_enabled = CASE WHEN $43::BOOLEAN IS NOT NULL THEN $43 ELSE access_log_enabled END,
			error_log_level = CASE WHEN $44 != '' THEN $44 ELSE error_log_level END,
			resolver = CASE WHEN $45 != '' THEN $45 ELSE resolver END,
			resolver_timeout = CASE WHEN $46 != '' THEN $46 ELSE resolver_timeout END,
			custom_http_config = COALESCE(NULLIF($47, ''), custom_http_config),
			custom_stream_config = COALESCE(NULLIF($48, ''), custom_stream_config),
			direct_ip_access_action = CASE WHEN $49 != '' THEN $49 ELSE direct_ip_access_action END,
			limit_conn_enabled = CASE WHEN $50::BOOLEAN IS NOT NULL THEN $50 ELSE limit_conn_enabled END,
			limit_conn_zone_size = CASE WHEN $51 != '' THEN $51 ELSE limit_conn_zone_size END,
			limit_conn_per_ip = CASE WHEN $52::INT IS NOT NULL THEN $52 ELSE limit_conn_per_ip END,
			limit_req_enabled = CASE WHEN $53::BOOLEAN IS NOT NULL THEN $53 ELSE limit_req_enabled END,
			limit_req_zone_size = CASE WHEN $54 != '' THEN $54 ELSE limit_req_zone_size END,
			limit_req_rate = CASE WHEN $55::INT IS NOT NULL THEN $55 ELSE limit_req_rate END,
			limit_req_burst = CASE WHEN $56::INT IS NOT NULL THEN $56 ELSE limit_req_burst END,
			reset_timedout_connection = CASE WHEN $57::BOOLEAN IS NOT NULL THEN $57 ELSE reset_timedout_connection END,
			limit_rate = CASE WHEN $58::INT IS NOT NULL THEN $58 ELSE limit_rate END,
			limit_rate_after = CASE WHEN $59 != '' THEN $59 ELSE limit_rate_after END,
			proxy_buffer_size = CASE WHEN $60 != '' THEN $60 ELSE proxy_buffer_size END,
			proxy_buffers = CASE WHEN $61 != '' THEN $61 ELSE proxy_buffers END,
			proxy_busy_buffers_size = CASE WHEN $62 != '' THEN $62 ELSE proxy_busy_buffers_size END,
			proxy_max_temp_file_size = CASE WHEN $63 != '' THEN $63 ELSE proxy_max_temp_file_size END,
			proxy_temp_file_write_size = CASE WHEN $64 != '' THEN $64 ELSE proxy_temp_file_write_size END,
			proxy_buffering = CASE WHEN $65 != '' THEN $65 ELSE proxy_buffering END,
			proxy_request_buffering = CASE WHEN $66 != '' THEN $66 ELSE proxy_request_buffering END,
			ssl_ecdh_curve = CASE WHEN $67 != '' THEN $67 ELSE ssl_ecdh_curve END,
			enable_ipv6 = COALESCE($68, enable_ipv6),
			updated_at = NOW()
	`

	directIPAction := ""
	if req.DirectIPAccessAction != nil {
		directIPAction = *req.DirectIPAccessAction
	}
	limitConnZoneSize := ""
	if req.LimitConnZoneSize != nil {
		limitConnZoneSize = *req.LimitConnZoneSize
	}
	limitReqZoneSize := ""
	if req.LimitReqZoneSize != nil {
		limitReqZoneSize = *req.LimitReqZoneSize
	}
	limitRateAfter := ""
	if req.LimitRateAfter != nil {
		limitRateAfter = *req.LimitRateAfter
	}

	_, err = r.db.ExecContext(ctx, query,
		req.WorkerProcesses, req.WorkerConnections, req.WorkerRlimitNofile,
		req.MultiAccept, req.UseEpoll, req.Sendfile, req.TCPNopush, req.TCPNodelay,
		req.KeepaliveTimeout, req.KeepaliveRequests, req.TypesHashMaxSize, req.ServerTokens,
		req.ClientBodyBufferSize, req.ClientHeaderBufferSize, req.ClientMaxBodySize, req.LargeClientHeaderBuffers,
		req.ClientBodyTimeout, req.ClientHeaderTimeout, req.SendTimeout,
		req.ProxyConnectTimeout, req.ProxySendTimeout, req.ProxyReadTimeout,
		req.GzipEnabled, req.GzipVary, req.GzipProxied, req.GzipCompLevel, req.GzipBuffers, req.GzipHTTPVersion, req.GzipMinLength, req.GzipTypes,
		req.BrotliEnabled, req.BrotliCompLevel, req.BrotliMinLength, req.BrotliTypes,
		req.SSLProtocols, req.SSLCiphers, req.SSLPreferServerCiphers, req.SSLSessionCache, req.SSLSessionTimeout,
		req.SSLSessionTickets, req.SSLStapling, req.SSLStaplingVerify,
		req.AccessLogEnabled, req.ErrorLogLevel, req.Resolver, req.ResolverTimeout,
		req.CustomHTTPConfig, req.CustomStreamConfig,
		directIPAction,
		req.LimitConnEnabled, limitConnZoneSize, req.LimitConnPerIP,
		req.LimitReqEnabled, limitReqZoneSize, req.LimitReqRate, req.LimitReqBurst,
		req.ResetTimedoutConnection,
		req.LimitRate, limitRateAfter,
		req.ProxyBufferSize, req.ProxyBuffers, req.ProxyBusyBuffersSize,
		req.ProxyMaxTempFileSize, req.ProxyTempFileWriteSize,
		req.ProxyBuffering, req.ProxyRequestBuffering,
		req.SSLECDHCurve,
		req.EnableIPv6,
	)
	if err != nil {
		return nil, err
	}

	// Invalidate cache
	if r.cache != nil {
		_ = r.cache.InvalidateGlobalSettings(ctx)
	}

	return r.getFromDB(ctx)
}

func (r *GlobalSettingsRepository) Reset(ctx context.Context) (*model.GlobalSettings, error) {
	// Delete current settings and insert defaults
	_, err := r.db.ExecContext(ctx, "DELETE FROM global_settings")
	if err != nil {
		return nil, err
	}

	// Invalidate cache
	if r.cache != nil {
		_ = r.cache.InvalidateGlobalSettings(ctx)
	}

	_, err = r.db.ExecContext(ctx, "INSERT INTO global_settings (id) VALUES (gen_random_uuid())")
	if err != nil {
		return nil, err
	}

	return r.getFromDB(ctx)
}
