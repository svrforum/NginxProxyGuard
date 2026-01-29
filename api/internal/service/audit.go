package service

import (
	"context"
	"net/http"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// AuditService logs admin activities to the audit_logs table
type AuditService struct {
	repo *repository.AuditLogRepository
}

func NewAuditService(repo *repository.AuditLogRepository) *AuditService {
	return &AuditService{repo: repo}
}

// AuditContext holds user context information for audit logging
type AuditContext struct {
	UserID    string
	Username  string
	IPAddress string
	UserAgent string
}

// GetAuditContextFromEcho extracts audit context from Echo context
func GetAuditContextFromEcho(c interface {
	Get(string) interface{}
	RealIP() string
	Request() interface{ UserAgent() string }
}) AuditContext {
	ctx := AuditContext{
		Username: "system",
	}

	if userID, ok := c.Get("user_id").(string); ok {
		ctx.UserID = userID
	}
	if username, ok := c.Get("username").(string); ok {
		ctx.Username = username
	}
	ctx.IPAddress = c.RealIP()
	if req := c.Request(); req != nil {
		ctx.UserAgent = req.UserAgent()
	}

	return ctx
}

// ContextWithAudit adds audit information to a context from Echo context
func ContextWithAudit(ctx context.Context, c interface {
	Get(string) interface{}
	RealIP() string
	Request() *http.Request
}) context.Context {
	if userID, ok := c.Get("user_id").(string); ok {
		ctx = context.WithValue(ctx, "user_id", userID)
	}
	if username, ok := c.Get("username").(string); ok {
		ctx = context.WithValue(ctx, "username", username)
	}
	ctx = context.WithValue(ctx, "client_ip", c.RealIP())
	if req := c.Request(); req != nil {
		ctx = context.WithValue(ctx, "user_agent", req.UserAgent())
	}
	return ctx
}

// logEntry creates an audit log entry
func (s *AuditService) logEntry(ctx context.Context, action, resource, resourceID, resourceName string, details map[string]interface{}) error {
	// Get user info from context if available
	username := "system"
	userID := ""
	ipAddress := ""
	userAgent := ""

	if user, ok := ctx.Value("user").(*model.User); ok && user != nil {
		username = user.Username
		userID = user.ID
	}
	if u, ok := ctx.Value("username").(string); ok && u != "" {
		username = u
	}
	if uid, ok := ctx.Value("user_id").(string); ok && uid != "" {
		userID = uid
	}
	if ip, ok := ctx.Value("client_ip").(string); ok {
		ipAddress = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok {
		userAgent = ua
	}

	// Add resource name to details if not already present
	if details == nil {
		details = make(map[string]interface{})
	}
	if resourceName != "" {
		details["name"] = resourceName
	}

	entry := &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	return s.repo.Log(ctx, entry)
}

// logEntryWithUser creates an audit log entry with explicit user info
func (s *AuditService) logEntryWithUser(ctx context.Context, userID, username, ipAddress, userAgent, action, resource, resourceID, resourceName string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	if resourceName != "" {
		details["name"] = resourceName
	}

	entry := &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	return s.repo.Log(ctx, entry)
}

// LogProxyHostCreate logs proxy host creation
func (s *AuditService) LogProxyHostCreate(ctx context.Context, domains []string, destination string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "proxy_host_created", "proxy_host", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"destination":  destination,
	})
}

// LogProxyHostUpdate logs proxy host update
func (s *AuditService) LogProxyHostUpdate(ctx context.Context, domains []string, changes map[string]interface{}) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "proxy_host_updated", "proxy_host", "", domainStr, changes)
}

// LogProxyHostDelete logs proxy host deletion
func (s *AuditService) LogProxyHostDelete(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "proxy_host_deleted", "proxy_host", "", domainStr, nil)
}

// LogProxyHostToggle logs proxy host enable/disable
func (s *AuditService) LogProxyHostToggle(ctx context.Context, domains []string, enabled bool) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	action := "proxy_host_enabled"
	if !enabled {
		action = "proxy_host_disabled"
	}
	return s.logEntry(ctx, action, "proxy_host", "", domainStr, map[string]interface{}{
		"enabled": enabled,
	})
}

// LogCertificateCreate logs certificate creation
func (s *AuditService) LogCertificateCreate(ctx context.Context, domains []string, certType string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_created", "certificate", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"type":         certType,
	})
}

// LogCertificateDelete logs certificate deletion
func (s *AuditService) LogCertificateDelete(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_deleted", "certificate", "", domainStr, nil)
}

// LogCertificateRenewed logs certificate renewal
func (s *AuditService) LogCertificateRenewed(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_renewed", "certificate", "", domainStr, map[string]interface{}{
		"domain_names": domains,
	})
}

// LogCertificateDownload logs certificate download
func (s *AuditService) LogCertificateDownload(ctx context.Context, domains []string, downloadType string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_downloaded", "certificate", "", domainStr, map[string]interface{}{
		"domain_names":  domains,
		"download_type": downloadType,
	})
}

// LogSettingsUpdate logs global settings update
func (s *AuditService) LogSettingsUpdate(ctx context.Context, settingName string, details map[string]interface{}) error {
	return s.logEntry(ctx, "settings_updated", "settings", "", settingName, details)
}

// LogSecurityFeatureUpdate logs security feature changes
func (s *AuditService) LogSecurityFeatureUpdate(ctx context.Context, resource string, hostDomain string, enabled bool, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["enabled"] = enabled
	details["host"] = hostDomain

	action := resource + "_updated"
	if enabled {
		action = resource + "_enabled"
	} else {
		action = resource + "_disabled"
	}

	return s.logEntry(ctx, action, resource, "", hostDomain, details)
}

// LogRateLimitUpdate logs rate limit changes
func (s *AuditService) LogRateLimitUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "rate_limit", hostDomain, enabled, details)
}

// LogBotFilterUpdate logs bot filter changes
func (s *AuditService) LogBotFilterUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "bot_filter", hostDomain, enabled, details)
}

// LogSecurityHeadersUpdate logs security headers changes
func (s *AuditService) LogSecurityHeadersUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "security_headers", hostDomain, enabled, details)
}

// LogUpstreamUpdate logs upstream changes
func (s *AuditService) LogUpstreamUpdate(ctx context.Context, hostDomain string, details map[string]interface{}) error {
	return s.logEntry(ctx, "upstream_updated", "upstream", "", hostDomain, details)
}

// LogBackupCreate logs backup creation
func (s *AuditService) LogBackupCreate(ctx context.Context, filename string) error {
	return s.logEntry(ctx, "backup_created", "backup", "", filename, nil)
}

// LogBackupRestore logs backup restoration
func (s *AuditService) LogBackupRestore(ctx context.Context, filename string) error {
	return s.logEntry(ctx, "backup_restored", "backup", "", filename, map[string]interface{}{
		"action": "restore",
	})
}

// LogBackupDelete logs backup deletion
func (s *AuditService) LogBackupDelete(ctx context.Context, filename string) error {
	return s.logEntry(ctx, "backup_deleted", "backup", "", filename, nil)
}

// LogWAFEnabled logs WAF being enabled
func (s *AuditService) LogWAFEnabled(ctx context.Context, hostDomain string) error {
	return s.logEntry(ctx, "waf_enabled", "waf", "", hostDomain, nil)
}

// LogWAFDisabled logs WAF being disabled
func (s *AuditService) LogWAFDisabled(ctx context.Context, hostDomain string) error {
	return s.logEntry(ctx, "waf_disabled", "waf", "", hostDomain, nil)
}

// LogWAFRulesUpdated logs WAF rules being updated
func (s *AuditService) LogWAFRulesUpdated(ctx context.Context, hostDomain string, details map[string]interface{}) error {
	return s.logEntry(ctx, "waf_rules_updated", "waf", "", hostDomain, details)
}

// LogUserLogin logs user login
func (s *AuditService) LogUserLogin(ctx context.Context, username, ipAddress, userAgent string) error {
	return s.logEntry(ctx, "user_login", "user", "", username, map[string]interface{}{
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})
}

// LogUserLogout logs user logout
func (s *AuditService) LogUserLogout(ctx context.Context, username string) error {
	return s.logEntry(ctx, "user_logout", "user", "", username, nil)
}

// LogPasswordChanged logs password change
func (s *AuditService) LogPasswordChanged(ctx context.Context, username string) error {
	return s.logEntry(ctx, "password_changed", "user", "", username, nil)
}

// LogUsernameChanged logs username change
func (s *AuditService) LogUsernameChanged(ctx context.Context, oldUsername, newUsername string) error {
	return s.logEntry(ctx, "username_changed", "user", "", newUsername, map[string]interface{}{
		"old_username": oldUsername,
		"new_username": newUsername,
	})
}

// Log2FAEnabled logs 2FA being enabled
func (s *AuditService) Log2FAEnabled(ctx context.Context, username string) error {
	return s.logEntry(ctx, "totp_enabled", "user", "", username, nil)
}

// Log2FADisabled logs 2FA being disabled
func (s *AuditService) Log2FADisabled(ctx context.Context, username string) error {
	return s.logEntry(ctx, "totp_disabled", "user", "", username, nil)
}

// LogAccessListCreated logs access list creation
func (s *AuditService) LogAccessListCreated(ctx context.Context, name string) error {
	return s.logEntry(ctx, "access_list_created", "access_list", "", name, nil)
}

// LogAccessListUpdated logs access list update
func (s *AuditService) LogAccessListUpdated(ctx context.Context, name string, details map[string]interface{}) error {
	return s.logEntry(ctx, "access_list_updated", "access_list", "", name, details)
}

// LogAccessListDeleted logs access list deletion
func (s *AuditService) LogAccessListDeleted(ctx context.Context, name string) error {
	return s.logEntry(ctx, "access_list_deleted", "access_list", "", name, nil)
}

// LogRedirectHostCreated logs redirect host creation
func (s *AuditService) LogRedirectHostCreated(ctx context.Context, domains []string, destination string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "redirect_host_created", "redirect_host", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"destination":  destination,
	})
}

// LogRedirectHostUpdated logs redirect host update
func (s *AuditService) LogRedirectHostUpdated(ctx context.Context, domains []string, details map[string]interface{}) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "redirect_host_updated", "redirect_host", "", domainStr, details)
}

// LogRedirectHostDeleted logs redirect host deletion
func (s *AuditService) LogRedirectHostDeleted(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "redirect_host_deleted", "redirect_host", "", domainStr, nil)
}

// LogAPITokenCreated logs API token creation
func (s *AuditService) LogAPITokenCreated(ctx context.Context, tokenName string) error {
	return s.logEntry(ctx, "api_token_created", "api_token", "", tokenName, map[string]interface{}{
		"token_name": tokenName,
	})
}

// LogAPITokenUpdated logs API token update
func (s *AuditService) LogAPITokenUpdated(ctx context.Context, tokenName string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["token_name"] = tokenName
	return s.logEntry(ctx, "api_token_updated", "api_token", "", tokenName, details)
}

// LogAPITokenRevoked logs API token revocation
func (s *AuditService) LogAPITokenRevoked(ctx context.Context, tokenName string) error {
	return s.logEntry(ctx, "api_token_revoked", "api_token", "", tokenName, map[string]interface{}{
		"token_name": tokenName,
	})
}

// LogAPITokenDeleted logs API token deletion
func (s *AuditService) LogAPITokenDeleted(ctx context.Context, tokenName string) error {
	return s.logEntry(ctx, "api_token_deleted", "api_token", "", tokenName, map[string]interface{}{
		"token_name": tokenName,
	})
}

// LogGeoRestrictionUpdated logs geo restriction changes
func (s *AuditService) LogGeoRestrictionUpdated(ctx context.Context, hostDomain string, details map[string]interface{}) error {
	return s.logEntry(ctx, "geo_restriction_updated", "geo_restriction", "", hostDomain, details)
}

// LogFail2banUpdate logs fail2ban changes
func (s *AuditService) LogFail2banUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "fail2ban", hostDomain, enabled, details)
}

// LogIPBanned logs IP ban action
func (s *AuditService) LogIPBanned(ctx context.Context, ipAddress string, reason string, banTime int) error {
	return s.logEntry(ctx, "ip_banned", "banned_ip", "", ipAddress, map[string]interface{}{
		"ip":       ipAddress,
		"reason":   reason,
		"ban_time": banTime,
	})
}

// LogIPUnbanned logs IP unban action
func (s *AuditService) LogIPUnbanned(ctx context.Context, ipAddress string) error {
	return s.logEntry(ctx, "ip_unbanned", "banned_ip", "", ipAddress, nil)
}
