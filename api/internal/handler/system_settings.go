package handler

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

const (
	nginxLogsPath    = "/etc/nginx/logs"
	rawLogConfigFile = "/etc/nginx/conf.d/.raw_log_config"
)

type SystemSettingsHandler struct {
	repo                 *repository.SystemSettingsRepository
	historyRepo          *repository.GeoIPHistoryRepository
	nginxManager         *nginx.Manager
	audit                *service.AuditService
	dockerLogCollector   *service.DockerLogCollector
	geoipScheduler       *service.GeoIPScheduler
	cloudProviderService *service.CloudProviderService
}

func NewSystemSettingsHandler(
	repo *repository.SystemSettingsRepository,
	historyRepo *repository.GeoIPHistoryRepository,
	nginxManager *nginx.Manager,
	audit *service.AuditService,
	dockerLogCollector *service.DockerLogCollector,
	geoipScheduler *service.GeoIPScheduler,
	cloudProviderService *service.CloudProviderService,
) *SystemSettingsHandler {
	h := &SystemSettingsHandler{
		repo:                 repo,
		historyRepo:          historyRepo,
		nginxManager:         nginxManager,
		audit:                audit,
		dockerLogCollector:   dockerLogCollector,
		geoipScheduler:       geoipScheduler,
		cloudProviderService: cloudProviderService,
	}

	// Initialize raw log settings on startup
	go h.initRawLogSettings()

	return h
}

// initRawLogSettings applies raw log settings if enabled
// This ensures settings are applied even after container restart
func (h *SystemSettingsHandler) initRawLogSettings() {
	ctx := context.Background()
	settings, err := h.repo.Get(ctx)
	if err != nil {
		log.Printf("[RawLog] Warning: failed to get settings on init: %v", err)
		return
	}

	if settings.RawLogEnabled {
		log.Printf("[RawLog] Raw logging is enabled, applying settings on startup...")
		if err := h.applyRawLogSettings(settings); err != nil {
			log.Printf("[RawLog] Warning: failed to apply raw log settings on init: %v", err)
		}
	}
}

// GetSystemSettings returns the current system settings
func (h *SystemSettingsHandler) GetSystemSettings(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, settings.ToResponse())
}

// GetPublicUISettings returns public UI settings (font, etc.) without authentication
// This is used by welcome page, 403 page, and other public pages
func (h *SystemSettingsHandler) GetPublicUISettings(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		// Return default on error
		return c.JSON(http.StatusOK, map[string]string{
			"font_family": "system",
		})
	}

	fontFamily := settings.UIFontFamily
	if fontFamily == "" {
		fontFamily = "system"
	}

	return c.JSON(http.StatusOK, map[string]string{
		"font_family": fontFamily,
	})
}

// UpdateSystemSettings updates system settings
func (h *SystemSettingsHandler) UpdateSystemSettings(c echo.Context) error {
	var req model.UpdateSystemSettingsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	settings, err := h.repo.Update(c.Request().Context(), &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Generate raw log configuration if raw log settings changed
	if req.RawLogEnabled != nil || req.RawLogRetentionDays != nil ||
		req.RawLogMaxSizeMB != nil || req.RawLogRotateCount != nil ||
		req.RawLogCompressRotated != nil {
		if err := h.generateRawLogConfig(settings); err != nil {
			log.Printf("[SystemSettings] Warning: failed to generate raw log config: %v", err)
		}
	}

	// Generate default server config if direct IP access action changed
	if req.DirectIPAccessAction != nil {
		if err := h.nginxManager.GenerateDefaultServerConfig(c.Request().Context(), settings.DirectIPAccessAction); err != nil {
			log.Printf("[SystemSettings] Warning: failed to generate default server config: %v", err)
		} else {
			// Reload nginx to apply new default server config
			if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
				log.Printf("[SystemSettings] Warning: failed to reload nginx after default server config change: %v", err)
			}
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "시스템 설정", map[string]interface{}{
		"action": "update",
	})

	return c.JSON(http.StatusOK, settings.ToResponse())
}

// generateRawLogConfig creates/updates the raw log configuration file
// that nginx entrypoint uses to configure log files
func (h *SystemSettingsHandler) generateRawLogConfig(settings *model.SystemSettings) error {
	config := fmt.Sprintf(`# Raw Log Configuration
# Auto-generated by API - do not edit manually
# Last updated: %s

ENABLED=%t
MAX_SIZE_MB=%d
ROTATE_COUNT=%d
RETENTION_DAYS=%d
COMPRESS=%t
`,
		time.Now().Format(time.RFC3339),
		settings.RawLogEnabled,
		settings.RawLogMaxSizeMB,
		settings.RawLogRotateCount,
		settings.RawLogRetentionDays,
		settings.RawLogCompressRotated,
	)

	// Write configuration file
	if err := os.WriteFile(rawLogConfigFile, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write raw log config: %w", err)
	}

	// Apply raw log settings immediately (don't wait for container restart)
	if err := h.applyRawLogSettings(settings); err != nil {
		return fmt.Errorf("failed to apply raw log settings: %w", err)
	}

	return nil
}

// applyRawLogSettings creates/removes raw log files and nginx config immediately
func (h *SystemSettingsHandler) applyRawLogSettings(settings *model.SystemSettings) error {
	rawLoggingConf := "/etc/nginx/conf.d/00-raw-logging.conf"
	nginxContainer := os.Getenv("NGINX_CONTAINER")
	if nginxContainer == "" {
		nginxContainer = "npg-proxy"
	}

	if settings.RawLogEnabled {
		// Create nginx config for dual logging (on shared volume)
		nginxConfig := `# Raw log file storage (in addition to stdout/stderr)
# Auto-generated by API - do not edit manually
# Logs stored in /etc/nginx/logs for API access via consolidated volume

# Additional access log to file (main format)
access_log /etc/nginx/logs/access_raw.log main;

# Note: error_log can only have one destination in nginx main context
# For error logs, we log to both via Dockerfile symlink trick is not possible
# Error logs are captured from stderr which goes to error.log -> /dev/stderr
`
		if err := os.WriteFile(rawLoggingConf, []byte(nginxConfig), 0644); err != nil {
			return fmt.Errorf("failed to write raw logging nginx config: %w", err)
		}

		// Generate logrotate configuration in shared volume
		if err := h.generateLogrotateConfig(settings); err != nil {
			log.Printf("[RawLog] Warning: failed to generate logrotate config: %v", err)
			// Continue - logrotate is not critical for basic operation
		}

		log.Printf("[RawLog] Raw logging enabled - config and files created")
	} else {
		// Remove raw logging config
		os.Remove(rawLoggingConf)
		// Note: We don't delete the raw log files - user may want to keep historical data
		log.Printf("[RawLog] Raw logging disabled - nginx config removed")
	}

	// Reload nginx to apply changes
	if h.nginxManager != nil {
		ctx := context.Background()
		if err := h.nginxManager.ReloadNginx(ctx); err != nil {
			return fmt.Errorf("failed to reload nginx: %w", err)
		}
		log.Printf("[RawLog] Nginx reloaded successfully")
	}

	return nil
}

// generateLogrotateConfig creates/updates logrotate configuration
func (h *SystemSettingsHandler) generateLogrotateConfig(settings *model.SystemSettings) error {
	compress := ""
	if settings.RawLogCompressRotated {
		compress = "compress\n    delaycompress"
	}

	// Use access_raw.log and error_raw.log (not access.log/error.log which are symlinks to stdout/stderr)
	// dateext adds date to rotated filenames (e.g., access_raw.log-20251204.gz)
	config := fmt.Sprintf(`# Logrotate configuration for nginx-guard raw logs
# Auto-generated by API

%s/access_raw.log %s/error_raw.log {
    daily
    size %dM
    rotate %d
    missingok
    notifempty
    create 0644 nginx nginx
    sharedscripts
    dateext
    dateformat -%%Y%%m%%d
    %s
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid) 2>/dev/null || true
    endscript
}
`,
		nginxLogsPath, nginxLogsPath,
		settings.RawLogMaxSizeMB,
		settings.RawLogRotateCount,
		compress,
	)

	// Write to shared volume location (conf.d is shared between api and nginx containers)
	logrotateFile := "/etc/nginx/conf.d/.logrotate.conf"
	if err := os.WriteFile(logrotateFile, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write logrotate config: %w", err)
	}

	// Also install to nginx container's /etc/logrotate.d/ via docker exec
	nginxContainer := os.Getenv("NGINX_CONTAINER")
	if nginxContainer == "" {
		nginxContainer = "npg-proxy"
	}

	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "docker", "exec", nginxContainer,
		"sh", "-c", "cp /etc/nginx/conf.d/.logrotate.conf /etc/logrotate.d/nginx-guard 2>/dev/null || true")
	cmd.Run() // Ignore errors - logrotate may not be installed

	return nil
}

// GetGeoIPStatus returns the current GeoIP status
func (h *SystemSettingsHandler) GetGeoIPStatus(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	status := &model.GeoIPStatus{
		Enabled:         settings.GeoIPEnabled,
		LastUpdated:     settings.GeoIPLastUpdated,
		DatabaseVersion: settings.GeoIPDatabaseVersion,
	}

	// Check if GeoIP databases exist
	geoipPath := "/etc/nginx/geoip"
	countryDB := filepath.Join(geoipPath, "GeoLite2-Country.mmdb")
	asnDB := filepath.Join(geoipPath, "GeoLite2-ASN.mmdb")

	if info, err := os.Stat(countryDB); err == nil && info.Size() > config.MinGeoIPDatabaseSize {
		status.CountryDB = true
	}
	if info, err := os.Stat(asnDB); err == nil && info.Size() > config.MinGeoIPDatabaseSize {
		status.ASNDB = true
	}

	// Check .no-geoip flag
	noGeoipFlag := filepath.Join(geoipPath, ".no-geoip")
	if _, err := os.Stat(noGeoipFlag); err == nil {
		status.Status = config.StatusDisabled
	} else if status.CountryDB && status.ASNDB {
		status.Status = config.StatusOK
	} else if settings.GeoIPEnabled && settings.MaxmindLicenseKey != "" {
		status.Status = config.StatusError
		status.ErrorMessage = "GeoIP databases not found"
	} else {
		status.Status = config.StatusDisabled
	}

	// Calculate next update time
	if settings.GeoIPAutoUpdate && settings.GeoIPLastUpdated != nil {
		interval := parseInterval(settings.GeoIPUpdateInterval)
		nextUpdate := settings.GeoIPLastUpdated.Add(interval)
		status.NextUpdate = &nextUpdate
	}

	return c.JSON(http.StatusOK, status)
}

// UpdateGeoIPDatabases triggers a GeoIP database update
func (h *SystemSettingsHandler) UpdateGeoIPDatabases(c echo.Context) error {
	var req model.GeoIPUpdateRequest
	c.Bind(&req) // Ignore bind errors, force is optional

	ctx := c.Request().Context()

	// Get credentials from settings
	licenseKey, accountID, err := h.repo.GetGeoIPCredentials(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if licenseKey == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "MaxMind license key not configured. Please set it in System Settings.",
		})
	}

	// Run GeoIP update in background using scheduler
	// Cloud provider seeding is now handled by the scheduler's RunUpdate
	go func() {
		bgCtx := context.Background()

		if h.geoipScheduler != nil {
			h.geoipScheduler.RunUpdate(bgCtx, model.GeoIPTriggerManual, licenseKey, accountID)
		} else {
			// Fallback to direct update if scheduler not available
			if err := h.runGeoIPUpdate(bgCtx, licenseKey, accountID); err != nil {
				log.Printf("[GeoIP] Update failed: %v", err)
			} else {
				h.repo.UpdateGeoIPStatus(bgCtx, time.Now(), "GeoLite2")
				if h.nginxManager != nil {
					h.nginxManager.ReloadNginx(bgCtx)
				}
			}

			// Seed cloud providers in fallback path
			if h.cloudProviderService != nil {
				if err := h.cloudProviderService.SeedDefaultProviders(bgCtx); err != nil {
					log.Printf("[GeoIP] Failed to seed cloud providers: %v", err)
				}
			}
		}
	}()

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "GeoIP 데이터베이스", map[string]interface{}{
		"action": "update_triggered",
	})

	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"status":  "updating",
		"message": "GeoIP database update has been triggered. This may take a few minutes.",
	})
}

// GetGeoIPHistory returns the GeoIP update history
func (h *SystemSettingsHandler) GetGeoIPHistory(c echo.Context) error {
	if h.historyRepo == nil {
		return c.JSON(http.StatusOK, model.GeoIPUpdateHistoryResponse{
			Data:       []model.GeoIPUpdateHistory{},
			Total:      0,
			Page:       1,
			PerPage:    20,
			TotalPages: 1,
		})
	}

	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	history, err := h.historyRepo.List(c.Request().Context(), page, perPage)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, history)
}

// runGeoIPUpdate runs the geoipupdate command
func (h *SystemSettingsHandler) runGeoIPUpdate(ctx context.Context, licenseKey, accountID string) error {
	geoipPath := "/etc/nginx/geoip"
	confPath := filepath.Join(geoipPath, "GeoIP.conf")

	// Create GeoIP.conf
	conf := fmt.Sprintf(`# GeoIP.conf for Nginx Proxy Guard
# Auto-generated by API

AccountID %s
LicenseKey %s
EditionIDs GeoLite2-Country GeoLite2-ASN
DatabaseDirectory %s
`, accountID, licenseKey, geoipPath)

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("failed to write GeoIP.conf: %w", err)
	}

	// Run geoipupdate
	cmd := exec.CommandContext(ctx, "geoipupdate", "-f", confPath, "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("geoipupdate failed: %s - %w", string(output), err)
	}

	// Update the symlink to use the enabled config
	enabledConf := filepath.Join(geoipPath, "geoip-enabled.conf")
	activeConf := filepath.Join(geoipPath, "geoip-active.conf")

	// Remove .no-geoip flag if exists
	os.Remove(filepath.Join(geoipPath, ".no-geoip"))

	// Update symlink
	os.Remove(activeConf)
	if err := os.Symlink(enabledConf, activeConf); err != nil {
		return fmt.Errorf("failed to update geoip symlink: %w", err)
	}

	return nil
}

// parseInterval parses interval string like "1d", "7d", "30d" to duration
func parseInterval(interval string) time.Duration {
	interval = strings.ToLower(strings.TrimSpace(interval))

	if strings.HasSuffix(interval, "d") {
		days := 7 // default
		fmt.Sscanf(interval, "%dd", &days)
		return time.Duration(days) * 24 * time.Hour
	}
	if strings.HasSuffix(interval, "h") {
		hours := 168 // default 7 days
		fmt.Sscanf(interval, "%dh", &hours)
		return time.Duration(hours) * time.Hour
	}

	// Default to 7 days
	return 7 * 24 * time.Hour
}

// TestACME tests the ACME configuration
func (h *SystemSettingsHandler) TestACME(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	result := map[string]interface{}{
		"acme_enabled": settings.ACMEEnabled,
		"acme_email":   settings.ACMEEmail,
		"acme_staging": settings.ACMEStaging,
		"status":       config.StatusOK,
		"message":      "ACME configuration is valid",
	}

	if !settings.ACMEEnabled {
		result["status"] = config.StatusDisabled
		result["message"] = "ACME is disabled"
	} else if settings.ACMEEmail == "" {
		result["status"] = config.StatusPending
		result["message"] = "ACME email is not configured. Some certificate authorities require an email."
	}

	return c.JSON(http.StatusOK, result)
}

// LogFileInfo represents information about a log file
type LogFileInfo struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	ModifiedAt   time.Time `json:"modified_at"`
	IsCompressed bool      `json:"is_compressed"`
	LogType      string    `json:"log_type"` // access, error
}

// LogFilesResponse represents the response for log files listing
type LogFilesResponse struct {
	Files      []LogFileInfo `json:"files"`
	TotalSize  int64         `json:"total_size"`
	TotalCount int           `json:"total_count"`
	RawLogEnabled bool       `json:"raw_log_enabled"`
}

// ListLogFiles returns a list of nginx log files
func (h *SystemSettingsHandler) ListLogFiles(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	response := LogFilesResponse{
		Files:         []LogFileInfo{},
		RawLogEnabled: settings.RawLogEnabled,
	}

	// Read log files from directory
	entries, err := os.ReadDir(nginxLogsPath)
	if err != nil {
		// If directory doesn't exist or is not readable, return empty
		return c.JSON(http.StatusOK, response)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip symlinks (stdout/stderr)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check if it's a symlink
		fullPath := filepath.Join(nginxLogsPath, name)
		if linkInfo, err := os.Lstat(fullPath); err == nil {
			if linkInfo.Mode()&os.ModeSymlink != 0 {
				// Skip symlinks to /dev/stdout or /dev/stderr
				continue
			}
		}

		// Determine log type
		logType := "unknown"
		if strings.HasPrefix(name, "access") {
			logType = "access"
		} else if strings.HasPrefix(name, "error") {
			logType = "error"
		}

		// Check if compressed
		isCompressed := strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".bz2")

		fileInfo := LogFileInfo{
			Name:         name,
			Size:         info.Size(),
			ModifiedAt:   info.ModTime(),
			IsCompressed: isCompressed,
			LogType:      logType,
		}

		response.Files = append(response.Files, fileInfo)
		response.TotalSize += info.Size()
	}

	// Sort by modification time (newest first)
	sort.Slice(response.Files, func(i, j int) bool {
		return response.Files[i].ModifiedAt.After(response.Files[j].ModifiedAt)
	})

	response.TotalCount = len(response.Files)

	return c.JSON(http.StatusOK, response)
}

// DownloadLogFile downloads a specific log file
func (h *SystemSettingsHandler) DownloadLogFile(c echo.Context) error {
	filename := c.Param("filename")

	// Validate filename (prevent path traversal)
	if strings.Contains(filename, "/") || strings.Contains(filename, "..") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid filename"})
	}

	filePath := filepath.Join(nginxLogsPath, filename)

	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "file not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Don't allow downloading symlinks
	if linkInfo, err := os.Lstat(filePath); err == nil {
		if linkInfo.Mode()&os.ModeSymlink != 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot download symlink"})
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "로그 파일", map[string]interface{}{
		"action":   "download",
		"filename": filename,
	})

	c.Response().Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	return c.Attachment(filePath, filename)
}

// DeleteLogFile deletes a specific log file
func (h *SystemSettingsHandler) DeleteLogFile(c echo.Context) error {
	filename := c.Param("filename")

	// Validate filename (prevent path traversal)
	if strings.Contains(filename, "/") || strings.Contains(filename, "..") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid filename"})
	}

	// Don't allow deleting main log files (access.log, error.log)
	if filename == "access.log" || filename == "error.log" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete active log file"})
	}

	filePath := filepath.Join(nginxLogsPath, filename)

	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "file not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Don't allow deleting symlinks
	if linkInfo, err := os.Lstat(filePath); err == nil {
		if linkInfo.Mode()&os.ModeSymlink != 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete symlink"})
		}
	}

	// Delete the file
	if err := os.Remove(filePath); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "로그 파일", map[string]interface{}{
		"action":   "delete",
		"filename": filename,
	})

	return c.NoContent(http.StatusNoContent)
}

// ViewLogFile returns the last N lines of a log file (for preview)
func (h *SystemSettingsHandler) ViewLogFile(c echo.Context) error {
	filename := c.Param("filename")

	// Validate filename
	if strings.Contains(filename, "/") || strings.Contains(filename, "..") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid filename"})
	}

	// Get line count parameter
	lines := 100
	if linesParam := c.QueryParam("lines"); linesParam != "" {
		if n, err := strconv.Atoi(linesParam); err == nil && n > 0 && n <= 1000 {
			lines = n
		}
	}

	filePath := filepath.Join(nginxLogsPath, filename)

	// Check if file is compressed
	if strings.HasSuffix(filename, ".gz") {
		// For compressed files, use zcat
		cmd := exec.Command("zcat", filePath)
		tailCmd := exec.Command("tail", "-n", strconv.Itoa(lines))

		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		tailCmd.Stdin = pipe

		cmd.Start()
		output, err := tailCmd.Output()
		cmd.Wait()

		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to read compressed file"})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"filename": filename,
			"lines":    lines,
			"content":  string(output),
		})
	}

	// For regular files, read directly
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "file not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer file.Close()

	// Read last N lines using tail command
	cmd := exec.Command("tail", "-n", strconv.Itoa(lines), filePath)
	output, err := cmd.Output()
	if err != nil {
		// Fallback: read the whole file if tail fails
		content, err := io.ReadAll(file)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		output = content
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"filename": filename,
		"lines":    lines,
		"content":  string(output),
	})
}

// TriggerLogRotation manually triggers log rotation
func (h *SystemSettingsHandler) TriggerLogRotation(c echo.Context) error {
	// Get settings
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if !settings.RawLogEnabled {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "raw log files are not enabled",
		})
	}

	// Generate logrotate config first
	if err := h.generateLogrotateConfig(settings); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Try to run logrotate
	logrotateConfig := "/etc/logrotate.d/nginx-guard"
	if _, err := os.Stat(logrotateConfig); os.IsNotExist(err) {
		logrotateConfig = "/etc/nginx/conf.d/.logrotate.conf"
	}

	cmd := exec.CommandContext(c.Request().Context(), "logrotate", "-f", logrotateConfig)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"error":   "logrotate failed",
			"details": string(output),
		})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "로그 파일", map[string]interface{}{
		"action": "rotate",
	})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "completed",
		"message": "Log rotation completed successfully",
	})
}

// GetSystemLogConfig returns the current system log configuration
func (h *SystemSettingsHandler) GetSystemLogConfig(c echo.Context) error {
	if h.dockerLogCollector == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Docker log collector is not enabled"})
	}

	config := h.dockerLogCollector.GetConfig()
	return c.JSON(http.StatusOK, config)
}

// UpdateSystemLogConfig updates system log configuration
func (h *SystemSettingsHandler) UpdateSystemLogConfig(c echo.Context) error {
	if h.dockerLogCollector == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Docker log collector is not enabled"})
	}

	var config service.SystemLogConfig
	if err := c.Bind(&config); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if err := h.dockerLogCollector.UpdateConfig(config); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update config: " + err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "시스템 로그 설정", map[string]interface{}{
		"action": "update",
	})

	return c.JSON(http.StatusOK, config)
}
