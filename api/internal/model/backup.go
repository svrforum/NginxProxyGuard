package model

import "time"

// Backup represents a backup record
type Backup struct {
	ID       string `json:"id" db:"id"`
	Filename string `json:"filename" db:"filename"`
	FileSize int64  `json:"file_size" db:"file_size"`
	FilePath string `json:"file_path" db:"file_path"`

	// Backup contents
	IncludesConfig       bool `json:"includes_config" db:"includes_config"`
	IncludesCertificates bool `json:"includes_certificates" db:"includes_certificates"`
	IncludesDatabase     bool `json:"includes_database" db:"includes_database"`

	// Metadata
	BackupType  string `json:"backup_type" db:"backup_type"` // manual, scheduled, auto
	Description string `json:"description,omitempty" db:"description"`

	// Status
	Status       string `json:"status" db:"status"` // pending, in_progress, completed, failed
	ErrorMessage string `json:"error_message,omitempty" db:"error_message"`

	// Checksum
	ChecksumSHA256 string `json:"checksum_sha256,omitempty" db:"checksum_sha256"`

	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// CreateBackupRequest is the request to create a backup
type CreateBackupRequest struct {
	IncludesConfig       bool   `json:"includes_config"`
	IncludesCertificates bool   `json:"includes_certificates"`
	IncludesDatabase     bool   `json:"includes_database"`
	Description          string `json:"description,omitempty"`
}

// RestoreRequest is the request to restore from a backup
type RestoreRequest struct {
	BackupID string `json:"backup_id"`

	// What to restore (default: all that were backed up)
	RestoreConfig       *bool `json:"restore_config,omitempty"`
	RestoreCertificates *bool `json:"restore_certificates,omitempty"`
	RestoreDatabase     *bool `json:"restore_database,omitempty"`
}

// BackupListResponse is the paginated list of backups
type BackupListResponse struct {
	Data       []Backup `json:"data"`
	Total      int      `json:"total"`
	Page       int      `json:"page"`
	PerPage    int      `json:"per_page"`
	TotalPages int      `json:"total_pages"`
}

// BackupStats represents backup statistics
type BackupStats struct {
	TotalBackups       int       `json:"total_backups"`
	TotalSize          int64     `json:"total_size"`
	LastBackup         *time.Time `json:"last_backup,omitempty"`
	LastSuccessful     *time.Time `json:"last_successful,omitempty"`
	ScheduledEnabled   bool      `json:"scheduled_enabled"`
	ScheduleInterval   string    `json:"schedule_interval,omitempty"`
	RetentionDays      int       `json:"retention_days"`
}

// BackupContents represents the contents of a backup for preview
type BackupContents struct {
	BackupID string `json:"backup_id"`

	// Config files
	ConfigFiles []string `json:"config_files,omitempty"`

	// Certificates
	Certificates []CertificateInfo `json:"certificates,omitempty"`

	// Database tables and counts
	DatabaseTables []TableInfo `json:"database_tables,omitempty"`
}

// CertificateInfo represents certificate info in backup
type CertificateInfo struct {
	Domain    string    `json:"domain"`
	ExpiresAt time.Time `json:"expires_at"`
	Type      string    `json:"type"`
}

// TableInfo represents database table info in backup
type TableInfo struct {
	TableName string `json:"table_name"`
	RowCount  int    `json:"row_count"`
}

// RestoreProgress represents the progress of a restore operation
type RestoreProgress struct {
	BackupID     string    `json:"backup_id"`
	Status       string    `json:"status"` // in_progress, completed, failed
	CurrentStep  string    `json:"current_step"`
	TotalSteps   int       `json:"total_steps"`
	CurrentStepN int       `json:"current_step_n"`
	Progress     float64   `json:"progress"` // 0-100
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// RestoreResult represents the detailed result of a restore operation (Issue #28 fix)
type RestoreResult struct {
	Status           string `json:"status"`             // "success", "partial", "failed"
	Message          string `json:"message"`
	IsPartialRestore bool   `json:"is_partial_restore"`

	// Database restore
	DatabaseRestored bool   `json:"database_restored"`
	DatabaseError    string `json:"database_error,omitempty"`

	// Config regeneration results
	ProxyHostsTotal     int      `json:"proxy_hosts_total"`
	ProxyHostsSuccess   int      `json:"proxy_hosts_success"`
	ProxyHostsFailed    []string `json:"proxy_hosts_failed,omitempty"`

	RedirectHostsTotal   int      `json:"redirect_hosts_total"`
	RedirectHostsSuccess int      `json:"redirect_hosts_success"`
	RedirectHostsFailed  []string `json:"redirect_hosts_failed,omitempty"`

	// Nginx status
	NginxConfigValid bool   `json:"nginx_config_valid"`
	NginxConfigError string `json:"nginx_config_error,omitempty"`
	NginxReloaded    bool   `json:"nginx_reloaded"`
	NginxReloadError string `json:"nginx_reload_error,omitempty"`

	// File restoration
	FilesRestored int      `json:"files_restored"`
	FileErrors    []string `json:"file_errors,omitempty"`
}

// NewRestoreResult creates a new RestoreResult with default values
func NewRestoreResult() *RestoreResult {
	return &RestoreResult{
		Status:              "success",
		Message:             "Restore completed successfully",
		IsPartialRestore:    false,
		DatabaseRestored:    false,
		NginxConfigValid:    true,
		NginxReloaded:       false,
		ProxyHostsFailed:    []string{},
		RedirectHostsFailed: []string{},
		FileErrors:          []string{},
	}
}

// DetermineStatus calculates the final status based on results
func (r *RestoreResult) DetermineStatus() {
	// Check for failures
	hasFailures := len(r.ProxyHostsFailed) > 0 ||
		len(r.RedirectHostsFailed) > 0 ||
		!r.NginxConfigValid ||
		!r.NginxReloaded ||
		len(r.FileErrors) > 0

	hasPartialSuccess := r.DatabaseRestored ||
		r.ProxyHostsSuccess > 0 ||
		r.RedirectHostsSuccess > 0

	if !r.DatabaseRestored && !hasPartialSuccess {
		r.Status = "failed"
		r.Message = "Restore failed completely"
	} else if hasFailures {
		r.Status = "partial"
		r.IsPartialRestore = true
		r.Message = "Restore completed with some failures"
	} else {
		r.Status = "success"
		r.Message = "Restore completed successfully"
	}
}

// ExportData represents data for export/import
type ExportData struct {
	Version    string    `json:"version"`
	ExportedAt time.Time `json:"exported_at"`

	// Configuration
	GlobalSettings *GlobalSettingsExport `json:"global_settings,omitempty"`
	SystemSettings *SystemSettingsExport `json:"system_settings,omitempty"`

	// Proxy hosts with all related data
	ProxyHosts []ProxyHostExport `json:"proxy_hosts,omitempty"`

	// DNS Providers
	DNSProviders []DNSProviderExport `json:"dns_providers,omitempty"`

	// Access Lists
	AccessLists []AccessListExport `json:"access_lists,omitempty"`

	// Redirect Hosts
	RedirectHosts []RedirectHostExport `json:"redirect_hosts,omitempty"`

	// Certificates
	Certificates []CertificateExport `json:"certificates,omitempty"`

	// WAF Rule Exclusions
	WAFExclusions []WAFExclusionExport `json:"waf_exclusions,omitempty"`

	// Security: Banned IPs
	BannedIPs []BannedIPExport `json:"banned_ips,omitempty"`

	// Security: URI Blocks (per proxy host)
	URIBlocks []URIBlockExport `json:"uri_blocks,omitempty"`

	// Security: Global URI Blocks
	GlobalURIBlock *GlobalURIBlockExport `json:"global_uri_block,omitempty"`

	// Cloud Providers
	CloudProviders []CloudProviderExport `json:"cloud_providers,omitempty"`

	// Exploit Block Rules
	ExploitBlockRules []ExploitBlockRuleExport `json:"exploit_block_rules,omitempty"`

	// Global WAF Rule Exclusions
	GlobalWAFExclusions []GlobalWAFExclusionExport `json:"global_waf_exclusions,omitempty"`

	// Global Exploit Rule Exclusions
	GlobalExploitExclusions []GlobalExploitExclusionExport `json:"global_exploit_exclusions,omitempty"`

	// Host Exploit Rule Exclusions
	HostExploitExclusions []HostExploitExclusionExport `json:"host_exploit_exclusions,omitempty"`

	// Global Challenge Config (CAPTCHA)
	GlobalChallengeConfig *ChallengeConfigExport `json:"global_challenge_config,omitempty"`
}

// GlobalSettingsExport represents global settings for export
type GlobalSettingsExport struct {
	// Worker settings
	WorkerProcesses    int  `json:"worker_processes"`
	WorkerConnections  int  `json:"worker_connections"`
	WorkerRlimitNofile *int `json:"worker_rlimit_nofile,omitempty"`

	// Event settings
	MultiAccept bool `json:"multi_accept"`
	UseEpoll    bool `json:"use_epoll"`

	// HTTP settings
	Sendfile          bool `json:"sendfile"`
	TCPNopush         bool `json:"tcp_nopush"`
	TCPNodelay        bool `json:"tcp_nodelay"`
	KeepaliveTimeout  int  `json:"keepalive_timeout"`
	KeepaliveRequests int  `json:"keepalive_requests"`
	TypesHashMaxSize  int  `json:"types_hash_max_size"`
	ServerTokens      bool `json:"server_tokens"`

	// Buffer settings
	ClientBodyBufferSize     string `json:"client_body_buffer_size"`
	ClientHeaderBufferSize   string `json:"client_header_buffer_size"`
	ClientMaxBodySize        string `json:"client_max_body_size"`
	LargeClientHeaderBuffers string `json:"large_client_header_buffers"`

	// Timeout settings
	ClientBodyTimeout   int `json:"client_body_timeout"`
	ClientHeaderTimeout int `json:"client_header_timeout"`
	SendTimeout         int `json:"send_timeout"`
	ProxyConnectTimeout int `json:"proxy_connect_timeout"`
	ProxySendTimeout    int `json:"proxy_send_timeout"`
	ProxyReadTimeout    int `json:"proxy_read_timeout"`

	// Gzip settings
	GzipEnabled     bool   `json:"gzip_enabled"`
	GzipVary        bool   `json:"gzip_vary"`
	GzipProxied     string `json:"gzip_proxied"`
	GzipCompLevel   int    `json:"gzip_comp_level"`
	GzipBuffers     string `json:"gzip_buffers"`
	GzipHTTPVersion string `json:"gzip_http_version"`
	GzipMinLength   int    `json:"gzip_min_length"`
	GzipTypes       string `json:"gzip_types"`

	// SSL/TLS settings
	SSLProtocols           string `json:"ssl_protocols"`
	SSLCiphers             string `json:"ssl_ciphers"`
	SSLPreferServerCiphers bool   `json:"ssl_prefer_server_ciphers"`
	SSLSessionCache        string `json:"ssl_session_cache"`
	SSLSessionTimeout      string `json:"ssl_session_timeout"`
	SSLSessionTickets      bool   `json:"ssl_session_tickets"`
	SSLStapling            bool   `json:"ssl_stapling"`
	SSLStaplingVerify      bool   `json:"ssl_stapling_verify"`

	// Logging settings
	AccessLogEnabled bool   `json:"access_log_enabled"`
	ErrorLogLevel    string `json:"error_log_level"`

	// Resolver settings
	Resolver        string `json:"resolver,omitempty"`
	ResolverTimeout string `json:"resolver_timeout,omitempty"`

	// Custom config
	CustomHTTPConfig   string `json:"custom_http_config,omitempty"`
	CustomStreamConfig string `json:"custom_stream_config,omitempty"`
}

// ProxyHostData represents proxy host data for export
type ProxyHostData struct {
	ID                    string                 `json:"id"`
	DomainNames           []string               `json:"domain_names"`
	ForwardScheme         string                 `json:"forward_scheme"`
	ForwardHost           string                 `json:"forward_host"`
	ForwardPort           int                    `json:"forward_port"`
	SSLEnabled            bool                   `json:"ssl_enabled"`
	SSLForceHTTPS         bool                   `json:"ssl_force_https"`
	SSLHTTP2              bool                   `json:"ssl_http2"`
	CertificateID         string                 `json:"certificate_id,omitempty"`
	AllowWebsocketUpgrade bool                   `json:"allow_websocket_upgrade"`
	CacheEnabled          bool                   `json:"cache_enabled"`
	CacheStaticOnly       bool                   `json:"cache_static_only"`
	CacheTTL              string                 `json:"cache_ttl"`
	BlockExploits         bool                   `json:"block_exploits"`
	CustomLocations       []interface{}          `json:"custom_locations,omitempty"`
	AdvancedConfig        string                 `json:"advanced_config,omitempty"`
	WAFEnabled            bool                   `json:"waf_enabled"`
	WAFMode               string                 `json:"waf_mode,omitempty"`
	AccessListID          string                 `json:"access_list_id,omitempty"`
	Enabled               bool                   `json:"enabled"`
	Meta                  map[string]interface{} `json:"meta,omitempty"`
}

// ProxyHostExport represents a proxy host with related configs for export
type ProxyHostExport struct {
	ProxyHost       ProxyHostData           `json:"proxy_host"`
	RateLimit       *RateLimitExport        `json:"rate_limit,omitempty"`
	Fail2ban        *Fail2banExport         `json:"fail2ban,omitempty"`
	BotFilter       *BotFilterExport        `json:"bot_filter,omitempty"`
	SecurityHeaders *SecurityHeadersExport  `json:"security_headers,omitempty"`
	GeoRestriction  *GeoRestrictionExport   `json:"geo_restriction,omitempty"`
	Upstream        *UpstreamExport         `json:"upstream,omitempty"`
	ChallengeConfig *ChallengeConfigExport  `json:"challenge_config,omitempty"`
}

// RateLimitExport represents rate limit config for export
type RateLimitExport struct {
	Enabled           bool   `json:"enabled"`
	RequestsPerSecond int    `json:"requests_per_second"`
	BurstSize         int    `json:"burst_size"`
	ZoneSize          string `json:"zone_size"`
	LimitBy           string `json:"limit_by"`
	LimitResponse     int    `json:"limit_response"`
	WhitelistIPs      string `json:"whitelist_ips,omitempty"`
}

// Fail2banExport represents fail2ban config for export
type Fail2banExport struct {
	Enabled    bool   `json:"enabled"`
	MaxRetries int    `json:"max_retries"`
	FindTime   int    `json:"find_time"`
	BanTime    int    `json:"ban_time"`
	FailCodes  string `json:"fail_codes"`
	Action     string `json:"action"`
}

// BotFilterExport represents bot filter config for export
type BotFilterExport struct {
	Enabled             bool   `json:"enabled"`
	BlockBadBots        bool   `json:"block_bad_bots"`
	BlockAIBots         bool   `json:"block_ai_bots"`
	AllowSearchEngines  bool   `json:"allow_search_engines"`
	CustomBlockedAgents string `json:"custom_blocked_agents,omitempty"`
	CustomAllowedAgents string `json:"custom_allowed_agents,omitempty"`
	ChallengeSuspicious bool   `json:"challenge_suspicious"`
}

// SecurityHeadersExport represents security headers config for export
type SecurityHeadersExport struct {
	Enabled               bool                   `json:"enabled"`
	HSTSEnabled           bool                   `json:"hsts_enabled"`
	HSTSMaxAge            int                    `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool                   `json:"hsts_include_subdomains"`
	HSTSPreload           bool                   `json:"hsts_preload"`
	XFrameOptions         string                 `json:"x_frame_options"`
	XContentTypeOptions   bool                   `json:"x_content_type_options"`
	XXSSProtection        bool                   `json:"x_xss_protection"`
	ReferrerPolicy        string                 `json:"referrer_policy"`
	ContentSecurityPolicy string                 `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string                 `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]interface{} `json:"custom_headers,omitempty"`
}

// GeoRestrictionExport represents geo restriction config for export
type GeoRestrictionExport struct {
	Mode            string   `json:"mode"`
	Countries       []string `json:"countries"`
	Enabled         bool     `json:"enabled"`
	ChallengeMode   bool     `json:"challenge_mode"`
	AllowPrivateIPs bool     `json:"allow_private_ips"`
	AllowSearchBots bool     `json:"allow_search_bots"`
}

// UpstreamExport represents upstream config for export
type UpstreamExport struct {
	Name                      string        `json:"name"`
	Servers                   []interface{} `json:"servers"`
	LoadBalance               string        `json:"load_balance"`
	HealthCheckEnabled        bool          `json:"health_check_enabled"`
	HealthCheckInterval       int           `json:"health_check_interval"`
	HealthCheckTimeout        int           `json:"health_check_timeout"`
	HealthCheckPath           string        `json:"health_check_path"`
	HealthCheckExpectedStatus int           `json:"health_check_expected_status"`
	Keepalive                 int           `json:"keepalive"`
}

// DNSProviderExport represents a DNS provider for export
type DNSProviderExport struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Credentials map[string]interface{} `json:"credentials,omitempty"`
	IsDefault   bool                   `json:"is_default"`
}

// AccessListData represents access list data for export
type AccessListData struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	SatisfyAny  bool                 `json:"satisfy_any"`
	PassAuth    bool                 `json:"pass_auth"`
	Items       []AccessListItemData `json:"items,omitempty"`
}

// AccessListItemData represents access list item for export
type AccessListItemData struct {
	Directive   string `json:"directive"`
	Address     string `json:"address"`
	Description string `json:"description,omitempty"`
	SortOrder   int    `json:"sort_order"`
}

// AccessListExport represents an access list for export
type AccessListExport struct {
	AccessList AccessListData `json:"access_list"`
}

// RedirectHostData represents redirect host data for export
type RedirectHostData struct {
	ID                string                 `json:"id"`
	DomainNames       []string               `json:"domain_names"`
	ForwardScheme     string                 `json:"forward_scheme"`
	ForwardDomainName string                 `json:"forward_domain_name"`
	ForwardPath       string                 `json:"forward_path,omitempty"`
	PreservePath      bool                   `json:"preserve_path"`
	RedirectCode      int                    `json:"redirect_code"`
	SSLEnabled        bool                   `json:"ssl_enabled"`
	CertificateID     string                 `json:"certificate_id,omitempty"`
	SSLForceHTTPS     bool                   `json:"ssl_force_https"`
	Enabled           bool                   `json:"enabled"`
	BlockExploits     bool                   `json:"block_exploits"`
	Meta              map[string]interface{} `json:"meta,omitempty"`
}

// RedirectHostExport represents a redirect host for export
type RedirectHostExport struct {
	RedirectHost RedirectHostData `json:"redirect_host"`
}

// CertificateExport represents a certificate for export
type CertificateExport struct {
	ID                   string     `json:"id"`
	DomainNames          []string   `json:"domain_names"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	CertificatePath      string     `json:"certificate_path,omitempty"`
	PrivateKeyPath       string     `json:"private_key_path,omitempty"`
	Provider             string     `json:"provider,omitempty"`
	DNSProviderID        string     `json:"dns_provider_id,omitempty"`
	Status               string     `json:"status"`
	AutoRenew            bool       `json:"auto_renew"`
	CertificatePEM       string     `json:"certificate_pem,omitempty"`
	PrivateKeyPEM        string     `json:"private_key_pem,omitempty"`
	IssuerCertificatePEM string     `json:"issuer_certificate_pem,omitempty"`
}

// WAFExclusionExport represents a WAF rule exclusion for export
type WAFExclusionExport struct {
	ProxyHostID     string `json:"proxy_host_id"`
	RuleID          int    `json:"rule_id"`
	RuleCategory    string `json:"rule_category,omitempty"`
	RuleDescription string `json:"rule_description,omitempty"`
	Reason          string `json:"reason,omitempty"`
	DisabledBy      string `json:"disabled_by,omitempty"`
}

// BannedIPExport represents a banned IP for export
type BannedIPExport struct {
	ProxyHostID  string     `json:"proxy_host_id,omitempty"`
	IPAddress    string     `json:"ip_address"`
	Reason       string     `json:"reason,omitempty"`
	FailCount    int        `json:"fail_count"`
	BannedAt     time.Time  `json:"banned_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	IsPermanent  bool       `json:"is_permanent"`
	IsAutoBanned bool       `json:"is_auto_banned"`
}

// URIBlockExport represents URI blocking settings for a proxy host
type URIBlockExport struct {
	ProxyHostID     string        `json:"proxy_host_id"`
	Enabled         bool          `json:"enabled"`
	Rules           []interface{} `json:"rules"`
	ExceptionIPs    []string      `json:"exception_ips"`
	AllowPrivateIPs bool          `json:"allow_private_ips"`
}

// GlobalURIBlockExport represents global URI blocking settings
type GlobalURIBlockExport struct {
	Enabled         bool          `json:"enabled"`
	Rules           []interface{} `json:"rules"`
	ExceptionIPs    []string      `json:"exception_ips"`
	AllowPrivateIPs bool          `json:"allow_private_ips"`
}

// ChallengeConfigExport represents challenge/CAPTCHA config for export
type ChallengeConfigExport struct {
	Enabled       bool    `json:"enabled"`
	ChallengeType string  `json:"challenge_type"`
	SiteKey       string  `json:"site_key,omitempty"`
	SecretKey     string  `json:"secret_key,omitempty"`
	TokenValidity int     `json:"token_validity"`
	MinScore      float64 `json:"min_score"`
	ApplyTo       string  `json:"apply_to"`
	PageTitle     string  `json:"page_title"`
	PageMessage   string  `json:"page_message"`
	Theme         string  `json:"theme"`
}

// CloudProviderExport represents cloud provider for export
type CloudProviderExport struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Region      string `json:"region,omitempty"`
	IPRangesURL string `json:"ip_ranges_url,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ExploitBlockRuleExport represents exploit block rule for export
type ExploitBlockRuleExport struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity"`
	Enabled     bool   `json:"enabled"`
	IsBuiltin   bool   `json:"is_builtin"`
}

// GlobalWAFExclusionExport represents global WAF rule exclusion for export
type GlobalWAFExclusionExport struct {
	RuleID          int    `json:"rule_id"`
	RuleCategory    string `json:"rule_category,omitempty"`
	RuleDescription string `json:"rule_description,omitempty"`
	Reason          string `json:"reason,omitempty"`
	DisabledBy      string `json:"disabled_by,omitempty"`
}

// GlobalExploitExclusionExport represents global exploit rule exclusion for export
type GlobalExploitExclusionExport struct {
	RuleID     string `json:"rule_id"`
	Reason     string `json:"reason,omitempty"`
	DisabledBy string `json:"disabled_by,omitempty"`
}

// HostExploitExclusionExport represents host-level exploit rule exclusion for export
type HostExploitExclusionExport struct {
	ProxyHostID string `json:"proxy_host_id"`
	RuleID      string `json:"rule_id"`
	Reason      string `json:"reason,omitempty"`
	DisabledBy  string `json:"disabled_by,omitempty"`
}

// SystemSettingsExport represents system settings for export
type SystemSettingsExport struct {
	// GeoIP Settings
	GeoIPEnabled        bool   `json:"geoip_enabled"`
	GeoIPAutoUpdate     bool   `json:"geoip_auto_update"`
	GeoIPUpdateInterval string `json:"geoip_update_interval"`
	MaxmindAccountID    string `json:"maxmind_account_id,omitempty"`
	MaxmindLicenseKey   string `json:"maxmind_license_key,omitempty"`

	// ACME Settings
	ACMEEnabled         bool   `json:"acme_enabled"`
	ACMEEmail           string `json:"acme_email,omitempty"`
	ACMEStaging         bool   `json:"acme_staging"`
	ACMEAutoRenew       bool   `json:"acme_auto_renew"`
	ACMERenewDaysBefore int    `json:"acme_renew_days_before"`

	// Notification Settings
	NotificationEmail      string `json:"notification_email,omitempty"`
	NotifyCertExpiry       bool   `json:"notify_cert_expiry"`
	NotifyCertExpiryDays   int    `json:"notify_cert_expiry_days"`
	NotifySecurityEvents   bool   `json:"notify_security_events"`
	NotifyBackupComplete   bool   `json:"notify_backup_complete"`

	// Retention Settings
	LogRetentionDays       int  `json:"log_retention_days"`
	StatsRetentionDays     int  `json:"stats_retention_days"`
	BackupRetentionCount   int  `json:"backup_retention_count"`
	AutoBackupEnabled      bool `json:"auto_backup_enabled"`
	AutoBackupSchedule     string `json:"auto_backup_schedule"`
	AccessLogRetentionDays int  `json:"access_log_retention_days"`
	WAFLogRetentionDays    int  `json:"waf_log_retention_days"`
	ErrorLogRetentionDays  int  `json:"error_log_retention_days"`
	SystemLogRetentionDays int  `json:"system_log_retention_days"`
	AuditLogRetentionDays  int  `json:"audit_log_retention_days"`

	// Raw Log Settings
	RawLogEnabled         bool `json:"raw_log_enabled"`
	RawLogRetentionDays   int  `json:"raw_log_retention_days"`
	RawLogMaxSizeMB       int  `json:"raw_log_max_size_mb"`
	RawLogRotateCount     int  `json:"raw_log_rotate_count"`
	RawLogCompressRotated bool `json:"raw_log_compress_rotated"`

	// Bot Filter Defaults
	BotFilterDefaultEnabled                bool   `json:"bot_filter_default_enabled"`
	BotFilterDefaultBlockBadBots           bool   `json:"bot_filter_default_block_bad_bots"`
	BotFilterDefaultBlockAIBots            bool   `json:"bot_filter_default_block_ai_bots"`
	BotFilterDefaultAllowSearchEngines     bool   `json:"bot_filter_default_allow_search_engines"`
	BotFilterDefaultBlockSuspiciousClients bool   `json:"bot_filter_default_block_suspicious_clients"`
	BotFilterDefaultChallengeSuspicious    bool   `json:"bot_filter_default_challenge_suspicious"`
	BotFilterDefaultCustomBlockedAgents    string `json:"bot_filter_default_custom_blocked_agents,omitempty"`

	// Bot Lists
	BotListBadBots            string `json:"bot_list_bad_bots,omitempty"`
	BotListAIBots             string `json:"bot_list_ai_bots,omitempty"`
	BotListSearchEngines      string `json:"bot_list_search_engines,omitempty"`
	BotListSuspiciousClients  string `json:"bot_list_suspicious_clients,omitempty"`

	// WAF Auto-Ban Settings
	WAFAutoBanEnabled   bool `json:"waf_auto_ban_enabled"`
	WAFAutoBanThreshold int  `json:"waf_auto_ban_threshold"`
	WAFAutoBanWindow    int  `json:"waf_auto_ban_window"`
	WAFAutoBanDuration  int  `json:"waf_auto_ban_duration"`

	// Direct IP Access
	DirectIPAccessAction string `json:"direct_ip_access_action"`

	// System Log Settings
	SystemLogsEnabled bool `json:"system_logs_enabled"`
}
