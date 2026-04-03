package model

import (
	"encoding/json"
	"time"
)

// SystemSettings represents system-level settings (GeoIP, ACME, notifications, etc.)
type SystemSettings struct {
	ID string `json:"id" db:"id"`

	// GeoIP Settings
	GeoIPEnabled         bool       `json:"geoip_enabled" db:"geoip_enabled"`
	MaxmindLicenseKey    string     `json:"maxmind_license_key" db:"maxmind_license_key"`
	MaxmindAccountID     string     `json:"maxmind_account_id" db:"maxmind_account_id"`
	GeoIPAutoUpdate      bool       `json:"geoip_auto_update" db:"geoip_auto_update"`
	GeoIPUpdateInterval  string     `json:"geoip_update_interval" db:"geoip_update_interval"`
	GeoIPLastUpdated     *time.Time `json:"geoip_last_updated,omitempty" db:"geoip_last_updated"`
	GeoIPDatabaseVersion string     `json:"geoip_database_version" db:"geoip_database_version"`

	// ACME / Let's Encrypt Settings
	ACMEEnabled        bool            `json:"acme_enabled" db:"acme_enabled"`
	ACMEEmail          string          `json:"acme_email" db:"acme_email"`
	ACMEStaging        bool            `json:"acme_staging" db:"acme_staging"`
	ACMEAutoRenew      bool            `json:"acme_auto_renew" db:"acme_auto_renew"`
	ACMERenewDaysBefore int            `json:"acme_renew_days_before" db:"acme_renew_days_before"`
	ACMEDNSProvider    string          `json:"acme_dns_provider" db:"acme_dns_provider"`
	ACMEDNSCredentials json.RawMessage `json:"acme_dns_credentials" db:"acme_dns_credentials"`

	// Notification Settings
	NotificationEmail     string `json:"notification_email" db:"notification_email"`
	NotifyCertExpiry      bool   `json:"notify_cert_expiry" db:"notify_cert_expiry"`
	NotifyCertExpiryDays  int    `json:"notify_cert_expiry_days" db:"notify_cert_expiry_days"`
	NotifySecurityEvents  bool   `json:"notify_security_events" db:"notify_security_events"`
	NotifyBackupComplete  bool   `json:"notify_backup_complete" db:"notify_backup_complete"`

	// Maintenance Settings (legacy - kept for backwards compatibility)
	LogRetentionDays     int    `json:"log_retention_days" db:"log_retention_days"`
	StatsRetentionDays   int    `json:"stats_retention_days" db:"stats_retention_days"`
	BackupRetentionCount int    `json:"backup_retention_count" db:"backup_retention_count"`
	AutoBackupEnabled    bool   `json:"auto_backup_enabled" db:"auto_backup_enabled"`
	AutoBackupSchedule   string `json:"auto_backup_schedule" db:"auto_backup_schedule"`

	// Log Retention Settings (per log type)
	AccessLogRetentionDays int `json:"access_log_retention_days" db:"access_log_retention_days"` // Default: 1095 (3 years)
	WAFLogRetentionDays    int `json:"waf_log_retention_days" db:"waf_log_retention_days"`       // Default: 90 (3 months)
	ErrorLogRetentionDays  int `json:"error_log_retention_days" db:"error_log_retention_days"`   // Default: 30 (1 month)
	SystemLogRetentionDays int `json:"system_log_retention_days" db:"system_log_retention_days"` // Default: 30 (1 month)
	AuditLogRetentionDays  int `json:"audit_log_retention_days" db:"audit_log_retention_days"`   // Default: 1095 (3 years)

	// Raw Log File Settings (nginx log files on disk)
	RawLogEnabled         bool `json:"raw_log_enabled" db:"raw_log_enabled"`                   // Enable raw log file storage
	RawLogRetentionDays   int  `json:"raw_log_retention_days" db:"raw_log_retention_days"`     // Default: 7 days
	RawLogMaxSizeMB       int  `json:"raw_log_max_size_mb" db:"raw_log_max_size_mb"`           // Default: 100MB
	RawLogRotateCount     int  `json:"raw_log_rotate_count" db:"raw_log_rotate_count"`         // Default: 5 files
	RawLogCompressRotated bool `json:"raw_log_compress_rotated" db:"raw_log_compress_rotated"` // Default: true

	// Bot Filter Default Settings (applied to new proxy hosts)
	BotFilterDefaultEnabled               bool   `json:"bot_filter_default_enabled" db:"bot_filter_default_enabled"`
	BotFilterDefaultBlockBadBots          bool   `json:"bot_filter_default_block_bad_bots" db:"bot_filter_default_block_bad_bots"`
	BotFilterDefaultBlockAIBots           bool   `json:"bot_filter_default_block_ai_bots" db:"bot_filter_default_block_ai_bots"`
	BotFilterDefaultAllowSearchEngines    bool   `json:"bot_filter_default_allow_search_engines" db:"bot_filter_default_allow_search_engines"`
	BotFilterDefaultBlockSuspiciousClients bool  `json:"bot_filter_default_block_suspicious_clients" db:"bot_filter_default_block_suspicious_clients"`
	BotFilterDefaultChallengeSuspicious   bool   `json:"bot_filter_default_challenge_suspicious" db:"bot_filter_default_challenge_suspicious"`
	BotFilterDefaultCustomBlockedAgents   string `json:"bot_filter_default_custom_blocked_agents" db:"bot_filter_default_custom_blocked_agents"`

	// Bot Lists (global lists used by all proxy hosts)
	BotListBadBots           string `json:"bot_list_bad_bots" db:"bot_list_bad_bots"`                       // Line-separated list of bad bot patterns
	BotListAIBots            string `json:"bot_list_ai_bots" db:"bot_list_ai_bots"`                         // Line-separated list of AI bot patterns
	BotListSearchEngines     string `json:"bot_list_search_engines" db:"bot_list_search_engines"`           // Line-separated list of allowed search engines
	BotListSuspiciousClients string `json:"bot_list_suspicious_clients" db:"bot_list_suspicious_clients"` // Line-separated list of suspicious HTTP clients

	// WAF Auto-Ban Settings
	WAFAutoBanEnabled   bool `json:"waf_auto_ban_enabled" db:"waf_auto_ban_enabled"`     // Enable auto-banning based on WAF events
	WAFAutoBanThreshold int  `json:"waf_auto_ban_threshold" db:"waf_auto_ban_threshold"` // Number of WAF events to trigger ban (default: 10)
	WAFAutoBanWindow    int  `json:"waf_auto_ban_window" db:"waf_auto_ban_window"`       // Time window in seconds (default: 300 = 5 minutes)
	WAFAutoBanDuration  int  `json:"waf_auto_ban_duration" db:"waf_auto_ban_duration"`   // Ban duration in seconds (default: 3600 = 1 hour, 0 = permanent)

	// Global Trusted IPs (bypass all security: fail2ban, WAF auto-ban, banned IPs, bot filter, rate limit)
	GlobalTrustedIPs string `json:"global_trusted_ips" db:"global_trusted_ips"` // Newline-separated IP addresses or CIDRs that bypass all security features

	// Global Block Exploits Exceptions
	GlobalBlockExploitsExceptions string `json:"global_block_exploits_exceptions" db:"global_block_exploits_exceptions"` // Line-separated regex patterns for URI paths that bypass RFI/exploit blocking globally

	// Direct IP Access Settings
	DirectIPAccessAction string `json:"direct_ip_access_action" db:"direct_ip_access_action"` // How to handle direct IP access: allow, block_403, block_444

	// UI Settings (global)
	UIFontFamily string `json:"ui_font_family" db:"ui_font_family"` // Global font family: system, gowun-batang, noto-sans-kr, pretendard, inter

	// System Log Settings
	SystemLogsEnabled         bool            `json:"system_logs_enabled" db:"system_logs_enabled"`
	SystemLogsLevels          json.RawMessage `json:"system_logs_levels" db:"system_logs_levels"`                     // JSONB: container -> level
	SystemLogsExcludePatterns []string        `json:"system_logs_exclude_patterns" db:"system_logs_exclude_patterns"` // TEXT[]
	SystemLogsStdoutExcluded  []string        `json:"system_logs_stdout_excluded" db:"system_logs_stdout_excluded"`   // TEXT[]

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SystemSettingsResponse is the API response (hides sensitive data)
type SystemSettingsResponse struct {
	ID string `json:"id"`

	// GeoIP Settings
	GeoIPEnabled         bool       `json:"geoip_enabled"`
	MaxmindLicenseKey    string     `json:"maxmind_license_key"`    // Will be masked
	MaxmindAccountID     string     `json:"maxmind_account_id"`
	GeoIPAutoUpdate      bool       `json:"geoip_auto_update"`
	GeoIPUpdateInterval  string     `json:"geoip_update_interval"`
	GeoIPLastUpdated     *time.Time `json:"geoip_last_updated,omitempty"`
	GeoIPDatabaseVersion string     `json:"geoip_database_version"`
	GeoIPStatus          string     `json:"geoip_status"` // "active", "inactive", "error"

	// ACME / Let's Encrypt Settings
	ACMEEnabled         bool   `json:"acme_enabled"`
	ACMEEmail           string `json:"acme_email"`
	ACMEStaging         bool   `json:"acme_staging"`
	ACMEAutoRenew       bool   `json:"acme_auto_renew"`
	ACMERenewDaysBefore int    `json:"acme_renew_days_before"`
	ACMEDNSProvider     string `json:"acme_dns_provider"`
	ACMEDNSConfigured   bool   `json:"acme_dns_configured"` // Whether DNS credentials are set

	// Notification Settings
	NotificationEmail    string `json:"notification_email"`
	NotifyCertExpiry     bool   `json:"notify_cert_expiry"`
	NotifyCertExpiryDays int    `json:"notify_cert_expiry_days"`
	NotifySecurityEvents bool   `json:"notify_security_events"`
	NotifyBackupComplete bool   `json:"notify_backup_complete"`

	// Maintenance Settings
	LogRetentionDays     int    `json:"log_retention_days"`
	StatsRetentionDays   int    `json:"stats_retention_days"`
	BackupRetentionCount int    `json:"backup_retention_count"`
	AutoBackupEnabled    bool   `json:"auto_backup_enabled"`
	AutoBackupSchedule   string `json:"auto_backup_schedule"`

	// Log Retention Settings (per log type)
	AccessLogRetentionDays int `json:"access_log_retention_days"`
	WAFLogRetentionDays    int `json:"waf_log_retention_days"`
	ErrorLogRetentionDays  int `json:"error_log_retention_days"`
	SystemLogRetentionDays int `json:"system_log_retention_days"`
	AuditLogRetentionDays  int `json:"audit_log_retention_days"`

	// Raw Log File Settings
	RawLogEnabled         bool `json:"raw_log_enabled"`
	RawLogRetentionDays   int  `json:"raw_log_retention_days"`
	RawLogMaxSizeMB       int  `json:"raw_log_max_size_mb"`
	RawLogRotateCount     int  `json:"raw_log_rotate_count"`
	RawLogCompressRotated bool `json:"raw_log_compress_rotated"`

	// Bot Filter Default Settings
	BotFilterDefaultEnabled               bool   `json:"bot_filter_default_enabled"`
	BotFilterDefaultBlockBadBots          bool   `json:"bot_filter_default_block_bad_bots"`
	BotFilterDefaultBlockAIBots           bool   `json:"bot_filter_default_block_ai_bots"`
	BotFilterDefaultAllowSearchEngines    bool   `json:"bot_filter_default_allow_search_engines"`
	BotFilterDefaultBlockSuspiciousClients bool  `json:"bot_filter_default_block_suspicious_clients"`
	BotFilterDefaultChallengeSuspicious   bool   `json:"bot_filter_default_challenge_suspicious"`
	BotFilterDefaultCustomBlockedAgents   string `json:"bot_filter_default_custom_blocked_agents"`

	// Bot Lists
	BotListBadBots           string `json:"bot_list_bad_bots"`
	BotListAIBots            string `json:"bot_list_ai_bots"`
	BotListSearchEngines     string `json:"bot_list_search_engines"`
	BotListSuspiciousClients string `json:"bot_list_suspicious_clients"`

	// WAF Auto-Ban Settings
	WAFAutoBanEnabled   bool `json:"waf_auto_ban_enabled"`
	WAFAutoBanThreshold int  `json:"waf_auto_ban_threshold"`
	WAFAutoBanWindow    int  `json:"waf_auto_ban_window"`
	WAFAutoBanDuration  int  `json:"waf_auto_ban_duration"`

	// Global Trusted IPs
	GlobalTrustedIPs string `json:"global_trusted_ips"`

	// Global Block Exploits Exceptions
	GlobalBlockExploitsExceptions string `json:"global_block_exploits_exceptions"`

	// Direct IP Access Settings
	DirectIPAccessAction string `json:"direct_ip_access_action"`

	// System Log Settings
	SystemLogsEnabled         bool            `json:"system_logs_enabled"`
	SystemLogsLevels          json.RawMessage `json:"system_logs_levels"`
	SystemLogsExcludePatterns []string        `json:"system_logs_exclude_patterns"`
	SystemLogsStdoutExcluded  []string        `json:"system_logs_stdout_excluded"`

	UpdatedAt time.Time `json:"updated_at"`
}

// ToResponse converts SystemSettings to a safe API response
func (s *SystemSettings) ToResponse() *SystemSettingsResponse {
	resp := &SystemSettingsResponse{
		ID:                   s.ID,
		GeoIPEnabled:         s.GeoIPEnabled,
		MaxmindAccountID:     s.MaxmindAccountID,
		GeoIPAutoUpdate:      s.GeoIPAutoUpdate,
		GeoIPUpdateInterval:  s.GeoIPUpdateInterval,
		GeoIPLastUpdated:     s.GeoIPLastUpdated,
		GeoIPDatabaseVersion: s.GeoIPDatabaseVersion,
		ACMEEnabled:          s.ACMEEnabled,
		ACMEEmail:            s.ACMEEmail,
		ACMEStaging:          s.ACMEStaging,
		ACMEAutoRenew:        s.ACMEAutoRenew,
		ACMERenewDaysBefore:  s.ACMERenewDaysBefore,
		ACMEDNSProvider:      s.ACMEDNSProvider,
		NotificationEmail:    s.NotificationEmail,
		NotifyCertExpiry:     s.NotifyCertExpiry,
		NotifyCertExpiryDays: s.NotifyCertExpiryDays,
		NotifySecurityEvents: s.NotifySecurityEvents,
		NotifyBackupComplete: s.NotifyBackupComplete,
		LogRetentionDays:       s.LogRetentionDays,
		StatsRetentionDays:     s.StatsRetentionDays,
		BackupRetentionCount:   s.BackupRetentionCount,
		AutoBackupEnabled:      s.AutoBackupEnabled,
		AutoBackupSchedule:     s.AutoBackupSchedule,
		AccessLogRetentionDays: s.AccessLogRetentionDays,
		WAFLogRetentionDays:    s.WAFLogRetentionDays,
		ErrorLogRetentionDays:  s.ErrorLogRetentionDays,
		SystemLogRetentionDays: s.SystemLogRetentionDays,
		AuditLogRetentionDays:  s.AuditLogRetentionDays,
		RawLogEnabled:          s.RawLogEnabled,
		RawLogRetentionDays:    s.RawLogRetentionDays,
		RawLogMaxSizeMB:        s.RawLogMaxSizeMB,
		RawLogRotateCount:      s.RawLogRotateCount,
		RawLogCompressRotated:  s.RawLogCompressRotated,
		BotFilterDefaultEnabled:               s.BotFilterDefaultEnabled,
		BotFilterDefaultBlockBadBots:          s.BotFilterDefaultBlockBadBots,
		BotFilterDefaultBlockAIBots:           s.BotFilterDefaultBlockAIBots,
		BotFilterDefaultAllowSearchEngines:    s.BotFilterDefaultAllowSearchEngines,
		BotFilterDefaultBlockSuspiciousClients: s.BotFilterDefaultBlockSuspiciousClients,
		BotFilterDefaultChallengeSuspicious:   s.BotFilterDefaultChallengeSuspicious,
		BotFilterDefaultCustomBlockedAgents:   s.BotFilterDefaultCustomBlockedAgents,
		BotListBadBots:                      s.BotListBadBots,
		BotListAIBots:                       s.BotListAIBots,
		BotListSearchEngines:                s.BotListSearchEngines,
		BotListSuspiciousClients:            s.BotListSuspiciousClients,
		WAFAutoBanEnabled:                   s.WAFAutoBanEnabled,
		WAFAutoBanThreshold:                 s.WAFAutoBanThreshold,
		WAFAutoBanWindow:                    s.WAFAutoBanWindow,
		WAFAutoBanDuration:                  s.WAFAutoBanDuration,
		GlobalTrustedIPs:                    s.GlobalTrustedIPs,
		GlobalBlockExploitsExceptions:       s.GlobalBlockExploitsExceptions,

		DirectIPAccessAction:                s.DirectIPAccessAction,
		SystemLogsEnabled:                   s.SystemLogsEnabled,
		SystemLogsLevels:                    s.SystemLogsLevels,
		SystemLogsExcludePatterns:           s.SystemLogsExcludePatterns,
		SystemLogsStdoutExcluded:            s.SystemLogsStdoutExcluded,
		UpdatedAt:                           s.UpdatedAt,
	}

	// Mask license key
	if s.MaxmindLicenseKey != "" {
		if len(s.MaxmindLicenseKey) > 8 {
			resp.MaxmindLicenseKey = s.MaxmindLicenseKey[:4] + "****" + s.MaxmindLicenseKey[len(s.MaxmindLicenseKey)-4:]
		} else {
			resp.MaxmindLicenseKey = "****"
		}
	}

	// Determine GeoIP status
	if s.GeoIPEnabled && s.MaxmindLicenseKey != "" {
		if s.GeoIPLastUpdated != nil {
			resp.GeoIPStatus = "active"
		} else {
			resp.GeoIPStatus = "pending"
		}
	} else if s.GeoIPEnabled {
		resp.GeoIPStatus = "error" // Enabled but no license key
	} else {
		resp.GeoIPStatus = "inactive"
	}

	// Check if DNS credentials are configured
	if len(s.ACMEDNSCredentials) > 2 { // Not empty "{}"
		resp.ACMEDNSConfigured = true
	}

	return resp
}

// UpdateSystemSettingsRequest is the request to update system settings
type UpdateSystemSettingsRequest struct {
	// GeoIP Settings
	GeoIPEnabled        *bool   `json:"geoip_enabled,omitempty"`
	MaxmindLicenseKey   *string `json:"maxmind_license_key,omitempty"`
	MaxmindAccountID    *string `json:"maxmind_account_id,omitempty"`
	GeoIPAutoUpdate     *bool   `json:"geoip_auto_update,omitempty"`
	GeoIPUpdateInterval *string `json:"geoip_update_interval,omitempty"`

	// ACME / Let's Encrypt Settings
	ACMEEnabled         *bool            `json:"acme_enabled,omitempty"`
	ACMEEmail           *string          `json:"acme_email,omitempty"`
	ACMEStaging         *bool            `json:"acme_staging,omitempty"`
	ACMEAutoRenew       *bool            `json:"acme_auto_renew,omitempty"`
	ACMERenewDaysBefore *int             `json:"acme_renew_days_before,omitempty"`
	ACMEDNSProvider     *string          `json:"acme_dns_provider,omitempty"`
	ACMEDNSCredentials  *json.RawMessage `json:"acme_dns_credentials,omitempty"`

	// Notification Settings
	NotificationEmail    *string `json:"notification_email,omitempty"`
	NotifyCertExpiry     *bool   `json:"notify_cert_expiry,omitempty"`
	NotifyCertExpiryDays *int    `json:"notify_cert_expiry_days,omitempty"`
	NotifySecurityEvents *bool   `json:"notify_security_events,omitempty"`
	NotifyBackupComplete *bool   `json:"notify_backup_complete,omitempty"`

	// Maintenance Settings
	LogRetentionDays     *int    `json:"log_retention_days,omitempty"`
	StatsRetentionDays   *int    `json:"stats_retention_days,omitempty"`
	BackupRetentionCount *int    `json:"backup_retention_count,omitempty"`
	AutoBackupEnabled    *bool   `json:"auto_backup_enabled,omitempty"`
	AutoBackupSchedule   *string `json:"auto_backup_schedule,omitempty"`

	// Log Retention Settings (per log type)
	AccessLogRetentionDays *int `json:"access_log_retention_days,omitempty"`
	WAFLogRetentionDays    *int `json:"waf_log_retention_days,omitempty"`
	ErrorLogRetentionDays  *int `json:"error_log_retention_days,omitempty"`
	SystemLogRetentionDays *int `json:"system_log_retention_days,omitempty"`
	AuditLogRetentionDays  *int `json:"audit_log_retention_days,omitempty"`

	// Raw Log File Settings
	RawLogEnabled         *bool `json:"raw_log_enabled,omitempty"`
	RawLogRetentionDays   *int  `json:"raw_log_retention_days,omitempty"`
	RawLogMaxSizeMB       *int  `json:"raw_log_max_size_mb,omitempty"`
	RawLogRotateCount     *int  `json:"raw_log_rotate_count,omitempty"`
	RawLogCompressRotated *bool `json:"raw_log_compress_rotated,omitempty"`

	// Bot Filter Default Settings
	BotFilterDefaultEnabled               *bool   `json:"bot_filter_default_enabled,omitempty"`
	BotFilterDefaultBlockBadBots          *bool   `json:"bot_filter_default_block_bad_bots,omitempty"`
	BotFilterDefaultBlockAIBots           *bool   `json:"bot_filter_default_block_ai_bots,omitempty"`
	BotFilterDefaultAllowSearchEngines    *bool   `json:"bot_filter_default_allow_search_engines,omitempty"`
	BotFilterDefaultBlockSuspiciousClients *bool  `json:"bot_filter_default_block_suspicious_clients,omitempty"`
	BotFilterDefaultChallengeSuspicious   *bool   `json:"bot_filter_default_challenge_suspicious,omitempty"`
	BotFilterDefaultCustomBlockedAgents   *string `json:"bot_filter_default_custom_blocked_agents,omitempty"`

	// Bot Lists
	BotListBadBots           *string `json:"bot_list_bad_bots,omitempty"`
	BotListAIBots            *string `json:"bot_list_ai_bots,omitempty"`
	BotListSearchEngines     *string `json:"bot_list_search_engines,omitempty"`
	BotListSuspiciousClients *string `json:"bot_list_suspicious_clients,omitempty"`

	// WAF Auto-Ban Settings
	WAFAutoBanEnabled   *bool `json:"waf_auto_ban_enabled,omitempty"`
	WAFAutoBanThreshold *int  `json:"waf_auto_ban_threshold,omitempty"`
	WAFAutoBanWindow    *int  `json:"waf_auto_ban_window,omitempty"`
	WAFAutoBanDuration  *int  `json:"waf_auto_ban_duration,omitempty"`

	// Global Trusted IPs
	GlobalTrustedIPs *string `json:"global_trusted_ips,omitempty"`

	// Global Block Exploits Exceptions
	GlobalBlockExploitsExceptions *string `json:"global_block_exploits_exceptions,omitempty"`

	// Direct IP Access Settings
	DirectIPAccessAction *string `json:"direct_ip_access_action,omitempty"`

	// UI Settings (global)
	UIFontFamily *string `json:"ui_font_family,omitempty"`

	// System Log Settings
	SystemLogsEnabled         *bool            `json:"system_logs_enabled,omitempty"`
	SystemLogsLevels          *json.RawMessage `json:"system_logs_levels,omitempty"`
	SystemLogsExcludePatterns *[]string        `json:"system_logs_exclude_patterns,omitempty"`
	SystemLogsStdoutExcluded  *[]string        `json:"system_logs_stdout_excluded,omitempty"`
}

// GeoIPStatus represents the status of GeoIP databases
type GeoIPStatus struct {
	Enabled          bool       `json:"enabled"`
	Status           string     `json:"status"` // "active", "inactive", "updating", "error"
	CountryDB        bool       `json:"country_db"`
	ASNDB            bool       `json:"asn_db"`
	LastUpdated      *time.Time `json:"last_updated,omitempty"`
	DatabaseVersion  string     `json:"database_version"`
	NextUpdate       *time.Time `json:"next_update,omitempty"`
	ErrorMessage     string     `json:"error_message,omitempty"`
}

// GeoIPUpdateRequest is the request to trigger GeoIP database update
type GeoIPUpdateRequest struct {
	Force bool `json:"force"` // Force update even if recently updated
}
