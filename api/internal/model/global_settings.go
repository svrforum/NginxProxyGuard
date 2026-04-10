package model

import "time"

// GlobalSettings represents the global nginx configuration
type GlobalSettings struct {
	ID string `json:"id" db:"id"`

	// Worker settings
	WorkerProcesses    int  `json:"worker_processes" db:"worker_processes"`
	WorkerConnections  int  `json:"worker_connections" db:"worker_connections"`
	WorkerRlimitNofile *int `json:"worker_rlimit_nofile,omitempty" db:"worker_rlimit_nofile"`

	// Event settings
	MultiAccept bool `json:"multi_accept" db:"multi_accept"`
	UseEpoll    bool `json:"use_epoll" db:"use_epoll"`

	// HTTP settings
	Sendfile          bool `json:"sendfile" db:"sendfile"`
	TCPNopush         bool `json:"tcp_nopush" db:"tcp_nopush"`
	TCPNodelay        bool `json:"tcp_nodelay" db:"tcp_nodelay"`
	KeepaliveTimeout  int  `json:"keepalive_timeout" db:"keepalive_timeout"`
	KeepaliveRequests int  `json:"keepalive_requests" db:"keepalive_requests"`
	TypesHashMaxSize  int  `json:"types_hash_max_size" db:"types_hash_max_size"`
	ServerTokens      bool `json:"server_tokens" db:"server_tokens"`

	// Buffer settings
	ClientBodyBufferSize     string `json:"client_body_buffer_size" db:"client_body_buffer_size"`
	ClientHeaderBufferSize   string `json:"client_header_buffer_size" db:"client_header_buffer_size"`
	ClientMaxBodySize        string `json:"client_max_body_size" db:"client_max_body_size"`
	LargeClientHeaderBuffers string `json:"large_client_header_buffers" db:"large_client_header_buffers"`

	// Timeout settings
	ClientBodyTimeout   int `json:"client_body_timeout" db:"client_body_timeout"`
	ClientHeaderTimeout int `json:"client_header_timeout" db:"client_header_timeout"`
	SendTimeout         int `json:"send_timeout" db:"send_timeout"`
	ProxyConnectTimeout int `json:"proxy_connect_timeout" db:"proxy_connect_timeout"`
	ProxySendTimeout    int `json:"proxy_send_timeout" db:"proxy_send_timeout"`
	ProxyReadTimeout    int `json:"proxy_read_timeout" db:"proxy_read_timeout"`

	// Gzip settings
	GzipEnabled     bool   `json:"gzip_enabled" db:"gzip_enabled"`
	GzipVary        bool   `json:"gzip_vary" db:"gzip_vary"`
	GzipProxied     string `json:"gzip_proxied" db:"gzip_proxied"`
	GzipCompLevel   int    `json:"gzip_comp_level" db:"gzip_comp_level"`
	GzipBuffers     string `json:"gzip_buffers" db:"gzip_buffers"`
	GzipHTTPVersion string `json:"gzip_http_version" db:"gzip_http_version"`
	GzipMinLength   int    `json:"gzip_min_length" db:"gzip_min_length"`
	GzipTypes       string `json:"gzip_types" db:"gzip_types"`

	// Brotli settings
	BrotliEnabled   bool   `json:"brotli_enabled" db:"brotli_enabled"`
	BrotliStatic    bool   `json:"brotli_static" db:"brotli_static"`
	BrotliCompLevel int    `json:"brotli_comp_level" db:"brotli_comp_level"`
	BrotliMinLength int    `json:"brotli_min_length" db:"brotli_min_length"`
	BrotliTypes     string `json:"brotli_types" db:"brotli_types"`

	// Proxy buffer settings
	ProxyBufferSize        string `json:"proxy_buffer_size" db:"proxy_buffer_size"`
	ProxyBuffers           string `json:"proxy_buffers" db:"proxy_buffers"`
	ProxyBusyBuffersSize   string `json:"proxy_busy_buffers_size" db:"proxy_busy_buffers_size"`
	ProxyMaxTempFileSize   string `json:"proxy_max_temp_file_size" db:"proxy_max_temp_file_size"`
	ProxyTempFileWriteSize string `json:"proxy_temp_file_write_size" db:"proxy_temp_file_write_size"`

	// Proxy buffering settings (on/off)
	ProxyBuffering        string `json:"proxy_buffering" db:"proxy_buffering"`
	ProxyRequestBuffering string `json:"proxy_request_buffering" db:"proxy_request_buffering"`

	// Open file cache settings
	OpenFileCacheEnabled  bool   `json:"open_file_cache_enabled" db:"open_file_cache_enabled"`
	OpenFileCacheMax      int    `json:"open_file_cache_max" db:"open_file_cache_max"`
	OpenFileCacheInactive string `json:"open_file_cache_inactive" db:"open_file_cache_inactive"`
	OpenFileCacheValid    string `json:"open_file_cache_valid" db:"open_file_cache_valid"`
	OpenFileCacheMinUses  int    `json:"open_file_cache_min_uses" db:"open_file_cache_min_uses"`
	OpenFileCacheErrors   bool   `json:"open_file_cache_errors" db:"open_file_cache_errors"`

	// SSL/TLS settings
	SSLProtocols            string `json:"ssl_protocols" db:"ssl_protocols"`
	SSLCiphers              string `json:"ssl_ciphers" db:"ssl_ciphers"`
	SSLPreferServerCiphers  bool   `json:"ssl_prefer_server_ciphers" db:"ssl_prefer_server_ciphers"`
	SSLSessionCache         string `json:"ssl_session_cache" db:"ssl_session_cache"`
	SSLSessionTimeout       string `json:"ssl_session_timeout" db:"ssl_session_timeout"`
	SSLSessionTickets       bool   `json:"ssl_session_tickets" db:"ssl_session_tickets"`
	SSLStapling             bool   `json:"ssl_stapling" db:"ssl_stapling"`
	SSLStaplingVerify       bool   `json:"ssl_stapling_verify" db:"ssl_stapling_verify"`
	SSLECDHCurve            string `json:"ssl_ecdh_curve" db:"ssl_ecdh_curve"`

	// Logging settings
	AccessLogEnabled bool   `json:"access_log_enabled" db:"access_log_enabled"`
	ErrorLogLevel    string `json:"error_log_level" db:"error_log_level"`

	// Resolver settings
	Resolver        string `json:"resolver,omitempty" db:"resolver"`
	ResolverTimeout string `json:"resolver_timeout,omitempty" db:"resolver_timeout"`

	// Custom config
	CustomHTTPConfig   string `json:"custom_http_config,omitempty" db:"custom_http_config"`
	CustomStreamConfig string `json:"custom_stream_config,omitempty" db:"custom_stream_config"`

	// Direct IP Access settings
	DirectIPAccessAction string `json:"direct_ip_access_action" db:"direct_ip_access_action"` // allow, block_403, block_444

	// IPv6 settings
	EnableIPv6 bool `json:"enable_ipv6" db:"enable_ipv6"`

	// DDoS Protection - Connection limiting
	LimitConnEnabled  bool   `json:"limit_conn_enabled" db:"limit_conn_enabled"`
	LimitConnZoneSize string `json:"limit_conn_zone_size" db:"limit_conn_zone_size"`
	LimitConnPerIP    int    `json:"limit_conn_per_ip" db:"limit_conn_per_ip"`

	// DDoS Protection - Request rate limiting (global)
	LimitReqEnabled  bool   `json:"limit_req_enabled" db:"limit_req_enabled"`
	LimitReqZoneSize string `json:"limit_req_zone_size" db:"limit_req_zone_size"`
	LimitReqRate     int    `json:"limit_req_rate" db:"limit_req_rate"`
	LimitReqBurst    int    `json:"limit_req_burst" db:"limit_req_burst"`

	// DDoS Protection - Timeout/Connection reset
	ResetTimedoutConnection bool `json:"reset_timedout_connection" db:"reset_timedout_connection"`

	// DDoS Protection - Response rate limiting (bandwidth throttling)
	LimitRate      int    `json:"limit_rate" db:"limit_rate"`             // bytes/s, 0 = unlimited
	LimitRateAfter string `json:"limit_rate_after" db:"limit_rate_after"` // e.g., "500k", "1m"

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// UpdateGlobalSettingsRequest is the request to update global settings
type UpdateGlobalSettingsRequest struct {
	// Worker settings
	WorkerProcesses    *int `json:"worker_processes,omitempty"`
	WorkerConnections  *int `json:"worker_connections,omitempty"`
	WorkerRlimitNofile *int `json:"worker_rlimit_nofile,omitempty"`

	// Event settings
	MultiAccept *bool `json:"multi_accept,omitempty"`
	UseEpoll    *bool `json:"use_epoll,omitempty"`

	// HTTP settings
	Sendfile          *bool `json:"sendfile,omitempty"`
	TCPNopush         *bool `json:"tcp_nopush,omitempty"`
	TCPNodelay        *bool `json:"tcp_nodelay,omitempty"`
	KeepaliveTimeout  *int  `json:"keepalive_timeout,omitempty"`
	KeepaliveRequests *int  `json:"keepalive_requests,omitempty"`
	TypesHashMaxSize  *int  `json:"types_hash_max_size,omitempty"`
	ServerTokens      *bool `json:"server_tokens,omitempty"`

	// Buffer settings
	ClientBodyBufferSize     string `json:"client_body_buffer_size,omitempty"`
	ClientHeaderBufferSize   string `json:"client_header_buffer_size,omitempty"`
	ClientMaxBodySize        string `json:"client_max_body_size,omitempty"`
	LargeClientHeaderBuffers string `json:"large_client_header_buffers,omitempty"`

	// Timeout settings
	ClientBodyTimeout   *int `json:"client_body_timeout,omitempty"`
	ClientHeaderTimeout *int `json:"client_header_timeout,omitempty"`
	SendTimeout         *int `json:"send_timeout,omitempty"`
	ProxyConnectTimeout *int `json:"proxy_connect_timeout,omitempty"`
	ProxySendTimeout    *int `json:"proxy_send_timeout,omitempty"`
	ProxyReadTimeout    *int `json:"proxy_read_timeout,omitempty"`

	// Gzip settings
	GzipEnabled     *bool  `json:"gzip_enabled,omitempty"`
	GzipVary        *bool  `json:"gzip_vary,omitempty"`
	GzipProxied     string `json:"gzip_proxied,omitempty"`
	GzipCompLevel   *int   `json:"gzip_comp_level,omitempty"`
	GzipBuffers     string `json:"gzip_buffers,omitempty"`
	GzipHTTPVersion string `json:"gzip_http_version,omitempty"`
	GzipMinLength   *int   `json:"gzip_min_length,omitempty"`
	GzipTypes       string `json:"gzip_types,omitempty"`

	// Brotli settings
	BrotliEnabled   *bool  `json:"brotli_enabled,omitempty"`
	BrotliStatic    *bool  `json:"brotli_static,omitempty"`
	BrotliCompLevel *int   `json:"brotli_comp_level,omitempty"`
	BrotliMinLength *int   `json:"brotli_min_length,omitempty"`
	BrotliTypes     string `json:"brotli_types,omitempty"`

	// Proxy buffer settings
	ProxyBufferSize        string `json:"proxy_buffer_size,omitempty"`
	ProxyBuffers           string `json:"proxy_buffers,omitempty"`
	ProxyBusyBuffersSize   string `json:"proxy_busy_buffers_size,omitempty"`
	ProxyMaxTempFileSize   string `json:"proxy_max_temp_file_size,omitempty"`
	ProxyTempFileWriteSize string `json:"proxy_temp_file_write_size,omitempty"`

	// Proxy buffering settings (on/off)
	ProxyBuffering        string `json:"proxy_buffering,omitempty"`
	ProxyRequestBuffering string `json:"proxy_request_buffering,omitempty"`

	// Open file cache settings
	OpenFileCacheEnabled  *bool  `json:"open_file_cache_enabled,omitempty"`
	OpenFileCacheMax      *int   `json:"open_file_cache_max,omitempty"`
	OpenFileCacheInactive string `json:"open_file_cache_inactive,omitempty"`
	OpenFileCacheValid    string `json:"open_file_cache_valid,omitempty"`
	OpenFileCacheMinUses  *int   `json:"open_file_cache_min_uses,omitempty"`
	OpenFileCacheErrors   *bool  `json:"open_file_cache_errors,omitempty"`

	// SSL/TLS settings
	SSLProtocols           string `json:"ssl_protocols,omitempty"`
	SSLCiphers             string `json:"ssl_ciphers,omitempty"`
	SSLPreferServerCiphers *bool  `json:"ssl_prefer_server_ciphers,omitempty"`
	SSLSessionCache        string `json:"ssl_session_cache,omitempty"`
	SSLSessionTimeout      string `json:"ssl_session_timeout,omitempty"`
	SSLSessionTickets      *bool  `json:"ssl_session_tickets,omitempty"`
	SSLStapling            *bool  `json:"ssl_stapling,omitempty"`
	SSLStaplingVerify      *bool  `json:"ssl_stapling_verify,omitempty"`
	SSLECDHCurve           string `json:"ssl_ecdh_curve,omitempty"`

	// Logging settings
	AccessLogEnabled *bool  `json:"access_log_enabled,omitempty"`
	ErrorLogLevel    string `json:"error_log_level,omitempty"`

	// Resolver settings
	Resolver        string `json:"resolver,omitempty"`
	ResolverTimeout string `json:"resolver_timeout,omitempty"`

	// Custom config
	CustomHTTPConfig   string `json:"custom_http_config,omitempty"`
	CustomStreamConfig string `json:"custom_stream_config,omitempty"`

	// Direct IP Access settings
	DirectIPAccessAction *string `json:"direct_ip_access_action,omitempty"`

	// IPv6 settings
	EnableIPv6 *bool `json:"enable_ipv6,omitempty"`

	// DDoS Protection - Connection limiting
	LimitConnEnabled  *bool   `json:"limit_conn_enabled,omitempty"`
	LimitConnZoneSize *string `json:"limit_conn_zone_size,omitempty"`
	LimitConnPerIP    *int    `json:"limit_conn_per_ip,omitempty"`

	// DDoS Protection - Request rate limiting (global)
	LimitReqEnabled  *bool   `json:"limit_req_enabled,omitempty"`
	LimitReqZoneSize *string `json:"limit_req_zone_size,omitempty"`
	LimitReqRate     *int    `json:"limit_req_rate,omitempty"`
	LimitReqBurst    *int    `json:"limit_req_burst,omitempty"`

	// DDoS Protection - Timeout/Connection reset
	ResetTimedoutConnection *bool `json:"reset_timedout_connection,omitempty"`

	// DDoS Protection - Response rate limiting (bandwidth throttling)
	LimitRate      *int    `json:"limit_rate,omitempty"`
	LimitRateAfter *string `json:"limit_rate_after,omitempty"`
}

// GlobalSettingsPresets provides preset configurations
var GlobalSettingsPresets = map[string]GlobalSettings{
	"performance": {
		WorkerProcesses:        0, // auto
		WorkerConnections:      8192,
		MultiAccept:            true,
		UseEpoll:               true,
		Sendfile:               true,
		TCPNopush:              true,
		TCPNodelay:             true,
		KeepaliveTimeout:       30,
		KeepaliveRequests:      1000,
		GzipEnabled:            true,
		GzipCompLevel:          4,
		GzipMinLength:          1024,
		BrotliEnabled:          true,
		BrotliStatic:           true,
		BrotliCompLevel:        4,
		BrotliMinLength:        1024,
		ProxyBufferSize:        "8k",
		ProxyBuffers:           "8 32k",
		ProxyBusyBuffersSize:   "128k",
		OpenFileCacheEnabled:   true,
		OpenFileCacheMax:       10000,
		OpenFileCacheInactive:  "60s",
		OpenFileCacheValid:     "30s",
		OpenFileCacheMinUses:   2,
		OpenFileCacheErrors:    true,
	},
	"security": {
		ServerTokens:           false,
		SSLProtocols:           "TLSv1.2 TLSv1.3",
		SSLPreferServerCiphers: true,
		SSLSessionTickets:      false,
		SSLStapling:            true,
		SSLStaplingVerify:      true,
		SSLECDHCurve:           "X25519MLKEM768:X25519:secp256r1:secp384r1",
		ClientMaxBodySize:      "10m",
		BrotliStatic:           true,
	},
	"balanced": {
		WorkerProcesses:        0,
		WorkerConnections:      8192,
		MultiAccept:            true,
		UseEpoll:               true,
		Sendfile:               true,
		TCPNopush:              true,
		TCPNodelay:             true,
		KeepaliveTimeout:       65,
		KeepaliveRequests:      1000,
		GzipEnabled:            true,
		GzipCompLevel:          6,
		GzipMinLength:          1000,
		BrotliEnabled:          true,
		BrotliStatic:           true,
		BrotliCompLevel:        6,
		BrotliMinLength:        1000,
		ServerTokens:           false,
		SSLProtocols:           "TLSv1.2 TLSv1.3",
		SSLECDHCurve:           "X25519MLKEM768:X25519:secp256r1:secp384r1",
		ProxyBufferSize:        "8k",
		ProxyBuffers:           "8 32k",
		ProxyBusyBuffersSize:   "128k",
		OpenFileCacheEnabled:   true,
		OpenFileCacheMax:       10000,
		OpenFileCacheInactive:  "60s",
		OpenFileCacheValid:     "30s",
		OpenFileCacheMinUses:   2,
		OpenFileCacheErrors:    true,
	},
}
