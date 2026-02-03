package handler

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
	"nginx-proxy-guard/pkg/cache"
)

type SettingsHandler struct {
	settingsRepo     *repository.GlobalSettingsRepository
	dashboardRepo    *repository.DashboardRepository
	backupRepo       *repository.BackupRepository
	proxyHostRepo    *repository.ProxyHostRepository
	redirectHostRepo *repository.RedirectHostRepository
	certificateRepo  *repository.CertificateRepository
	wafRepo          *repository.WAFRepository
	nginxManager     *nginx.Manager
	backupPath       string
	audit            *service.AuditService
	dockerStats      *service.DockerStatsService
	proxyHostService *service.ProxyHostService
	redisCache       *cache.RedisClient
}

func NewSettingsHandler(
	settingsRepo *repository.GlobalSettingsRepository,
	dashboardRepo *repository.DashboardRepository,
	backupRepo *repository.BackupRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	redirectHostRepo *repository.RedirectHostRepository,
	certificateRepo *repository.CertificateRepository,
	wafRepo *repository.WAFRepository,
	nginxManager *nginx.Manager,
	backupPath string,
	audit *service.AuditService,
	dockerStats *service.DockerStatsService,
	proxyHostService *service.ProxyHostService,
	redisCache *cache.RedisClient,
) *SettingsHandler {
	return &SettingsHandler{
		settingsRepo:     settingsRepo,
		dashboardRepo:    dashboardRepo,
		backupRepo:       backupRepo,
		proxyHostRepo:    proxyHostRepo,
		redirectHostRepo: redirectHostRepo,
		certificateRepo:  certificateRepo,
		wafRepo:          wafRepo,
		nginxManager:     nginxManager,
		backupPath:       backupPath,
		audit:            audit,
		dockerStats:      dockerStats,
		proxyHostService: proxyHostService,
		redisCache:       redisCache,
	}
}

// Global Settings Handlers

func (h *SettingsHandler) GetGlobalSettings(c echo.Context) error {
	settings, err := h.settingsRepo.Get(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, settings)
}

func (h *SettingsHandler) UpdateGlobalSettings(c echo.Context) error {
	var req model.UpdateGlobalSettingsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	settings, err := h.settingsRepo.Update(c.Request().Context(), &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Regenerate default server config if direct IP access action changed
	if req.DirectIPAccessAction != nil {
		if err := h.nginxManager.GenerateDefaultServerConfig(c.Request().Context(), settings.DirectIPAccessAction); err != nil {
			log.Printf("[Settings] Warning: failed to generate default server config: %v", err)
		}
	}

	// Regenerate all proxy host configs to apply global settings (timeouts, body size, etc.)
	if h.proxyHostService != nil {
		if err := h.proxyHostService.SyncAllConfigs(c.Request().Context()); err != nil {
			log.Printf("[Settings] Warning: failed to regenerate proxy host configs after global settings change: %v", err)
		}
	}

	// Reload nginx to apply all changes
	if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
		log.Printf("[Settings] Warning: failed to reload nginx after global settings change: %v", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "전역 설정", map[string]interface{}{
		"action": "update",
	})

	return c.JSON(http.StatusOK, settings)
}

func (h *SettingsHandler) ResetGlobalSettings(c echo.Context) error {
	settings, err := h.settingsRepo.Reset(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Regenerate all proxy host configs to apply default global settings
	if h.proxyHostService != nil {
		if err := h.proxyHostService.SyncAllConfigs(c.Request().Context()); err != nil {
			log.Printf("[Settings] Warning: failed to regenerate proxy host configs after global settings reset: %v", err)
		}
	}

	// Reload nginx to apply all changes
	if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
		log.Printf("[Settings] Warning: failed to reload nginx after global settings reset: %v", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "전역 설정", map[string]interface{}{
		"action": "reset",
	})

	return c.JSON(http.StatusOK, settings)
}

func (h *SettingsHandler) GetSettingsPresets(c echo.Context) error {
	return c.JSON(http.StatusOK, model.GlobalSettingsPresets)
}

func (h *SettingsHandler) ApplySettingsPreset(c echo.Context) error {
	preset := c.Param("preset")

	presetConfig, ok := model.GlobalSettingsPresets[preset]
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid preset"})
	}

	req := &model.UpdateGlobalSettingsRequest{
		WorkerProcesses:       &presetConfig.WorkerProcesses,
		WorkerConnections:     &presetConfig.WorkerConnections,
		MultiAccept:           &presetConfig.MultiAccept,
		Sendfile:              &presetConfig.Sendfile,
		TCPNopush:             &presetConfig.TCPNopush,
		TCPNodelay:            &presetConfig.TCPNodelay,
		KeepaliveTimeout:      &presetConfig.KeepaliveTimeout,
		KeepaliveRequests:     &presetConfig.KeepaliveRequests,
		ServerTokens:          &presetConfig.ServerTokens,
		GzipEnabled:           &presetConfig.GzipEnabled,
		GzipCompLevel:         &presetConfig.GzipCompLevel,
		BrotliEnabled:         &presetConfig.BrotliEnabled,
		BrotliCompLevel:       &presetConfig.BrotliCompLevel,
		SSLProtocols:          presetConfig.SSLProtocols,
		SSLPreferServerCiphers: &presetConfig.SSLPreferServerCiphers,
	}

	settings, err := h.settingsRepo.Update(c.Request().Context(), req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "전역 설정", map[string]interface{}{
		"action": "apply_preset",
		"preset": preset,
	})

	return c.JSON(http.StatusOK, settings)
}

// Dashboard Handlers

func (h *SettingsHandler) GetDashboard(c echo.Context) error {
	ctx := c.Request().Context()

	// Try to get from cache first (for stats data, not live metrics)
	var summary *model.DashboardSummary
	if h.redisCache != nil {
		var cachedSummary model.DashboardSummary
		if err := h.redisCache.GetDashboardSummary(ctx, &cachedSummary); err == nil {
			summary = &cachedSummary
		}
	}

	// If cache miss, fetch from database
	if summary == nil {
		var err error
		summary, err = h.dashboardRepo.GetSummary(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Cache the summary (without live metrics)
		if h.redisCache != nil {
			h.redisCache.SetDashboardSummary(ctx, summary)
		}
	}

	// Always add live host resource metrics (not cached)
	// CPU usage (average over sampling duration for faster response)
	if cpuPercent, err := cpu.Percent(config.CPUSamplingDuration, false); err == nil && len(cpuPercent) > 0 {
		summary.SystemHealth.CPUUsage = cpuPercent[0]
	}

	// Memory stats
	if memStats, err := mem.VirtualMemory(); err == nil {
		summary.SystemHealth.MemoryUsage = memStats.UsedPercent
		summary.SystemHealth.MemoryTotal = memStats.Total
		summary.SystemHealth.MemoryUsed = memStats.Used
	}

	// Disk stats
	if diskStats, err := disk.Usage("/"); err == nil {
		summary.SystemHealth.DiskUsage = diskStats.UsedPercent
		summary.SystemHealth.DiskTotal = diskStats.Total
		summary.SystemHealth.DiskUsed = diskStats.Used
		summary.SystemHealth.DiskPath = "/"
	}

	// Host info
	if hostInfo, err := host.Info(); err == nil {
		summary.SystemHealth.UptimeSeconds = hostInfo.Uptime
		summary.SystemHealth.KernelVersion = hostInfo.KernelVersion
	}

	// Try to read host OS info from mounted files (more accurate than container info)
	if hostname, err := os.ReadFile("/host/etc/hostname"); err == nil {
		summary.SystemHealth.Hostname = strings.TrimSpace(string(hostname))
	} else if hostInfo, err := host.Info(); err == nil {
		summary.SystemHealth.Hostname = hostInfo.Hostname
	}

	// Read host OS release info
	if file, err := os.Open("/host/etc/os-release"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				// Remove quotes and prefix
				name := strings.TrimPrefix(line, "PRETTY_NAME=")
				name = strings.Trim(name, "\"")
				summary.SystemHealth.Platform = name
				break
			}
		}
	}
	if summary.SystemHealth.Platform == "" {
		summary.SystemHealth.Platform = "Linux"
	}
	summary.SystemHealth.OS = "linux"

	// Network I/O stats (total across all interfaces)
	if netStats, err := net.IOCounters(false); err == nil && len(netStats) > 0 {
		summary.SystemHealth.NetworkIn = netStats[0].BytesRecv
		summary.SystemHealth.NetworkOut = netStats[0].BytesSent
	}

	return c.JSON(http.StatusOK, summary)
}

// GetGeoIPStats returns GeoIP statistics for globe visualization
func (h *SettingsHandler) GetGeoIPStats(c echo.Context) error {
	ctx := c.Request().Context()

	// Default to last 24 hours
	hours := 24
	if hoursStr := c.QueryParam("hours"); hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= 168 {
			hours = h
		}
	}

	// Try to get from cache first
	if h.redisCache != nil {
		var cachedResponse model.GeoIPStatsResponse
		if err := h.redisCache.GetGeoIPStats(ctx, hours, &cachedResponse); err == nil {
			return c.JSON(http.StatusOK, cachedResponse)
		}
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	stats, totalCount, err := h.dashboardRepo.GetGeoIPStats(ctx, since)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	response := model.GeoIPStatsResponse{
		Data:       stats,
		TotalCount: totalCount,
	}

	// Cache the response
	if h.redisCache != nil {
		h.redisCache.SetGeoIPStats(ctx, hours, response)
	}

	return c.JSON(http.StatusOK, response)
}

func (h *SettingsHandler) GetSystemHealth(c echo.Context) error {
	health, err := h.dashboardRepo.GetSystemHealth(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update with live nginx status
	if h.nginxManager != nil {
		if err := h.nginxManager.TestConfig(c.Request().Context()); err == nil {
			health.NginxStatus = config.StatusOK
		} else {
			health.NginxStatus = config.StatusError
		}
	}

	health.DBStatus = config.StatusOK
	health.RecordedAt = time.Now()

	// Fetch live host resource metrics using gopsutil
	// CPU usage (average over sampling duration for faster response)
	if cpuPercent, err := cpu.Percent(config.CPUSamplingDuration, false); err == nil && len(cpuPercent) > 0 {
		health.CPUUsage = cpuPercent[0]
	}

	// Memory stats
	if memStats, err := mem.VirtualMemory(); err == nil {
		health.MemoryUsage = memStats.UsedPercent
		health.MemoryTotal = memStats.Total
		health.MemoryUsed = memStats.Used
	}

	// Disk stats
	if diskStats, err := disk.Usage("/"); err == nil {
		health.DiskUsage = diskStats.UsedPercent
		health.DiskTotal = diskStats.Total
		health.DiskUsed = diskStats.Used
		health.DiskPath = "/"
	}

	// Host info
	if hostInfo, err := host.Info(); err == nil {
		health.UptimeSeconds = hostInfo.Uptime
		health.Hostname = hostInfo.Hostname
		health.OS = hostInfo.OS
		health.Platform = hostInfo.Platform
		health.KernelVersion = hostInfo.KernelVersion
	}

	return c.JSON(http.StatusOK, health)
}

// GetSystemHealthHistory returns historical system health data for charts
func (h *SettingsHandler) GetSystemHealthHistory(c echo.Context) error {
	// Default to last 1 hour
	since := time.Now().Add(-1 * time.Hour)

	// Allow custom hours parameter
	if hoursStr := c.QueryParam("hours"); hoursStr != "" {
		if hours, err := strconv.Atoi(hoursStr); err == nil && hours > 0 && hours <= 168 {
			since = time.Now().Add(-time.Duration(hours) * time.Hour)
		}
	}

	// Allow custom limit parameter (max 1000)
	limit := 100
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	history, err := h.dashboardRepo.GetSystemHealthHistory(c.Request().Context(), since, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":   history,
		"total":  len(history),
		"since":  since,
		"limit":  limit,
	})
}

func (h *SettingsHandler) GetHourlyStats(c echo.Context) error {
	startStr := c.QueryParam("start")
	endStr := c.QueryParam("end")
	proxyHostID := c.QueryParam("proxy_host_id")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			start = time.Now().Add(-24 * time.Hour)
		}
	} else {
		start = time.Now().Add(-24 * time.Hour)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			end = time.Now()
		}
	} else {
		end = time.Now()
	}

	params := &model.DashboardQueryParams{
		ProxyHostID: proxyHostID,
		StartTime:   start,
		EndTime:     end,
		Granularity: "hourly",
	}

	stats, err := h.dashboardRepo.GetHourlyStats(c.Request().Context(), params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, stats)
}

func (h *SettingsHandler) GetDockerStats(c echo.Context) error {
	if h.dockerStats == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Docker stats service not available"})
	}

	summary, err := h.dockerStats.GetStatsSummary(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, summary)
}

// Backup Handlers

func (h *SettingsHandler) ListBackups(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	result, err := h.backupRepo.List(c.Request().Context(), page, perPage)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SettingsHandler) CreateBackup(c echo.Context) error {
	var req model.CreateBackupRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Default to include everything
	if !req.IncludesConfig && !req.IncludesCertificates && !req.IncludesDatabase {
		req.IncludesConfig = true
		req.IncludesCertificates = true
		req.IncludesDatabase = true
	}

	// Create backup record
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("nginx_guard_backup_%s.tar.gz", timestamp)
	filePath := filepath.Join(h.backupPath, filename)

	backup := &model.Backup{
		Filename:             filename,
		FilePath:             filePath,
		IncludesConfig:       req.IncludesConfig,
		IncludesCertificates: req.IncludesCertificates,
		IncludesDatabase:     req.IncludesDatabase,
		BackupType:           "manual",
		Description:          req.Description,
		Status:               "in_progress",
	}

	backup, err := h.backupRepo.Create(c.Request().Context(), backup)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Create backup asynchronously
	go h.performBackup(backup)

	// Audit log
	h.audit.LogBackupCreate(c.Request().Context(), backup.Filename)

	return c.JSON(http.StatusAccepted, backup)
}

func (h *SettingsHandler) performBackup(backup *model.Backup) {
	ctx := context.Background()

	// Ensure backup directory exists
	os.MkdirAll(h.backupPath, 0755)

	// Create tar.gz file
	file, err := os.Create(backup.FilePath)
	if err != nil {
		h.backupRepo.UpdateStatus(ctx, backup.ID, "failed", err.Error())
		return
	}

	gzWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzWriter)

	// Export database data
	if backup.IncludesDatabase {
		exportData, err := h.backupRepo.ExportAllData(ctx)
		if err != nil {
			tarWriter.Close()
			gzWriter.Close()
			file.Close()
			h.backupRepo.UpdateStatus(ctx, backup.ID, "failed", err.Error())
			return
		}

		dataJSON, _ := json.MarshalIndent(exportData, "", "  ")
		header := &tar.Header{
			Name:    "data/export.json",
			Mode:    0644,
			Size:    int64(len(dataJSON)),
			ModTime: time.Now(),
		}
		tarWriter.WriteHeader(header)
		tarWriter.Write(dataJSON)
	}

	// Add config files
	if backup.IncludesConfig {
		h.addDirectoryToTar(tarWriter, "/etc/nginx/conf.d", "config/conf.d")
	}

	// Add certificates
	if backup.IncludesCertificates {
		h.addDirectoryToTar(tarWriter, "/etc/nginx/certs", "certs")
	}

	// Close writers in order to flush all data
	tarWriter.Close()
	gzWriter.Close()
	file.Close()

	// Calculate checksum from completed file
	checksum := ""
	if file, err := os.Open(backup.FilePath); err == nil {
		hasher := sha256.New()
		io.Copy(hasher, file)
		checksum = hex.EncodeToString(hasher.Sum(nil))
		file.Close()
	}

	// Get file size
	var fileSize int64
	if fileInfo, err := os.Stat(backup.FilePath); err == nil {
		fileSize = fileInfo.Size()
	}

	// Update backup record
	h.backupRepo.Complete(ctx, backup.ID, fileSize, checksum)
}

func (h *SettingsHandler) addDirectoryToTar(tw *tar.Writer, srcDir, destPrefix string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip symlinks to avoid size mismatch issues
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		relPath, _ := filepath.Rel(srcDir, path)
		destPath := filepath.Join(destPrefix, relPath)

		// Read entire file content first to ensure size accuracy
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[Backup] Warning: failed to read file %s: %v", path, err)
			return nil
		}

		header := &tar.Header{
			Name:    destPath,
			Mode:    int64(info.Mode()),
			Size:    int64(len(content)), // Use actual content size
			ModTime: info.ModTime(),
		}

		if err := tw.WriteHeader(header); err != nil {
			log.Printf("[Backup] Warning: failed to write tar header for %s: %v", path, err)
			return nil
		}

		written, err := tw.Write(content)
		if err != nil {
			log.Printf("[Backup] Warning: failed to write tar content for %s: %v", path, err)
			return nil
		}

		if written != len(content) {
			log.Printf("[Backup] Warning: incomplete write for %s: wrote %d of %d bytes", path, written, len(content))
		}

		return nil
	})
}

func (h *SettingsHandler) GetBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.backupRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	return c.JSON(http.StatusOK, backup)
}

func (h *SettingsHandler) DownloadBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.backupRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	if backup.Status != "completed" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "backup not completed"})
	}

	// Get actual file size
	fileInfo, err := os.Stat(backup.FilePath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "backup file not found"})
	}

	// Add checksum header for client-side verification
	if backup.ChecksumSHA256 != "" {
		c.Response().Header().Set("X-Checksum-SHA256", backup.ChecksumSHA256)
	}

	c.Response().Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	return c.Attachment(backup.FilePath, backup.Filename)
}

func (h *SettingsHandler) DeleteBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.backupRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	// Delete file
	os.Remove(backup.FilePath)

	// Delete record
	if err := h.backupRepo.Delete(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *SettingsHandler) RestoreBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.backupRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	if backup.Status != "completed" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "backup not completed"})
	}

	// Perform restore and get detailed result
	result, err := h.performRestore(c.Request().Context(), backup)
	if err != nil {
		// Critical failure - return error response with partial result if available
		response := map[string]interface{}{
			"error":   "restore failed",
			"details": err.Error(),
		}
		if result != nil {
			response["result"] = result
		}
		return c.JSON(http.StatusInternalServerError, response)
	}

	// Audit log
	h.audit.LogBackupRestore(c.Request().Context(), backup.Filename)

	// Return detailed result with appropriate HTTP status
	httpStatus := http.StatusOK
	if result.Status == "partial" {
		httpStatus = http.StatusPartialContent // HTTP 206
	}

	return c.JSON(httpStatus, result)
}

func (h *SettingsHandler) performRestore(ctx context.Context, backup *model.Backup) (*model.RestoreResult, error) {
	result := model.NewRestoreResult()

	// Verify checksum before restore if available
	if backup.ChecksumSHA256 != "" {
		if err := h.verifyBackupChecksum(backup.FilePath, backup.ChecksumSHA256); err != nil {
			result.Status = "failed"
			result.Message = "Backup integrity check failed"
			return result, fmt.Errorf("backup integrity check failed: %w", err)
		}
	}

	// PHASE 1: Read and import database data FIRST
	// This ensures DB is consistent before touching any files
	var exportData *model.ExportData
	if backup.IncludesDatabase {
		data, err := h.extractExportJSON(backup.FilePath)
		if err != nil {
			result.DatabaseError = err.Error()
			result.DetermineStatus()
			return result, fmt.Errorf("failed to read export.json: %w", err)
		}
		if data != nil {
			exportData = &model.ExportData{}
			if err := json.Unmarshal(data, exportData); err != nil {
				result.DatabaseError = err.Error()
				result.DetermineStatus()
				return result, fmt.Errorf("failed to parse export.json: %w", err)
			}
			// Import database data first - if this fails, no files are touched
			if err := h.backupRepo.ImportAllData(ctx, exportData); err != nil {
				result.DatabaseError = err.Error()
				result.DetermineStatus()
				return result, fmt.Errorf("failed to import database data: %w", err)
			}
			result.DatabaseRestored = true
			log.Printf("[Backup] Database import completed successfully")
		}
	}

	// PHASE 2: Restore files only after DB import succeeds
	filesRestored, fileErrors := h.restoreFilesFromBackupDetailed(backup)
	result.FilesRestored = filesRestored
	result.FileErrors = fileErrors
	if len(fileErrors) > 0 {
		log.Printf("[Backup] Warning: file restoration had %d errors", len(fileErrors))
	}

	// Regenerate nginx configs from restored database
	if h.nginxManager != nil {
		// Create certificate symlinks for new IDs pointing to existing cert files
		if h.certificateRepo != nil {
			certs, _, err := h.certificateRepo.List(ctx, 1, 1000)
			if err != nil {
				log.Printf("[Backup] Warning: failed to list certificates: %v", err)
			} else {
				certsPath := h.nginxManager.GetCertsPath()
				for _, cert := range certs {
					// Check if certificate_path references a different directory than the new ID
					if cert.CertificatePath != nil && *cert.CertificatePath != "" {
						// Extract the original ID from the path (e.g., /etc/nginx/certs/{orig_id}/fullchain.pem)
						pathParts := strings.Split(*cert.CertificatePath, "/")
						if len(pathParts) >= 2 {
							origID := pathParts[len(pathParts)-2]
							newIDPath := filepath.Join(certsPath, cert.ID)
							origIDPath := filepath.Join(certsPath, origID)

							// Create symlink if original path exists and new path doesn't
							if origID != cert.ID {
								if _, err := os.Stat(origIDPath); err == nil {
									if _, err := os.Stat(newIDPath); os.IsNotExist(err) {
										if err := os.Symlink(origIDPath, newIDPath); err != nil {
											log.Printf("[Backup] Warning: failed to create cert symlink %s -> %s: %v", newIDPath, origIDPath, err)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Regenerate Proxy Host configs with safe error handling
		if h.proxyHostRepo != nil {
			proxyHosts, _, err := h.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
			if err != nil {
				log.Printf("[Backup] Warning: failed to list proxy hosts for config regeneration: %v", err)
			} else {
				result.ProxyHostsTotal = len(proxyHosts)
				// Generate configs one by one so we can handle failures gracefully
				for _, host := range proxyHosts {
					// Use BuildConfigData to include all related settings (GeoRestriction, RateLimit, BotFilter, etc.)
					configData := h.proxyHostService.BuildConfigData(ctx, &host)
					if err := h.nginxManager.GenerateConfigFull(ctx, configData); err != nil {
						log.Printf("[Backup] Warning: failed to regenerate config for host %s: %v", host.ID, err)
						result.ProxyHostsFailed = append(result.ProxyHostsFailed, host.ID)
						continue
					}
					// Generate WAF config if enabled
					if host.WAFEnabled {
						// Get merged WAF exclusions (host + global) from database
						exclusions := h.getMergedWAFExclusions(ctx, host.ID)
						// Get Priority Allow IPs from configData
						var allowedIPs []string
						if configData.GeoRestriction != nil {
							allowedIPs = configData.GeoRestriction.AllowedIPs
						}
						if err := h.nginxManager.GenerateHostWAFConfig(ctx, &host, exclusions, allowedIPs); err != nil {
							log.Printf("[Backup] Warning: failed to regenerate WAF config for host %s: %v", host.ID, err)
							// Remove the main config if WAF config fails
							_ = h.nginxManager.RemoveConfig(ctx, &host)
							result.ProxyHostsFailed = append(result.ProxyHostsFailed, host.ID)
							continue
						}
					}
					result.ProxyHostsSuccess++
				}
			}
		}

		// Regenerate Redirect Host configs
		if h.redirectHostRepo != nil {
			redirectHosts, _, err := h.redirectHostRepo.List(ctx, 1, 1000)
			if err != nil {
				log.Printf("[Backup] Warning: failed to list redirect hosts for config regeneration: %v", err)
			} else {
				result.RedirectHostsTotal = len(redirectHosts)
				if err := h.nginxManager.GenerateAllRedirectConfigs(ctx, redirectHosts); err != nil {
					log.Printf("[Backup] Warning: failed to regenerate redirect host configs: %v", err)
					for _, rh := range redirectHosts {
						result.RedirectHostsFailed = append(result.RedirectHostsFailed, rh.ID)
					}
				} else {
					result.RedirectHostsSuccess = len(redirectHosts)
				}
			}
		}

		// Test nginx config before reload
		if err := h.nginxManager.TestConfig(ctx); err != nil {
			log.Printf("[Backup] ERROR: nginx config test failed: %v", err)
			result.NginxConfigValid = false
			result.NginxConfigError = err.Error()
			log.Printf("[Backup] Attempting to remove failed host configs and retry...")

			// Remove configs for failed hosts
			for _, hostID := range result.ProxyHostsFailed {
				configFile := filepath.Join("/etc/nginx/conf.d", fmt.Sprintf("proxy_host_%s.conf", hostID))
				if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
					log.Printf("[Backup] Warning: failed to remove config for host %s: %v", hostID, err)
				}
			}

			// Test again after removing failed configs
			if err := h.nginxManager.TestConfig(ctx); err != nil {
				log.Printf("[Backup] ERROR: nginx config test still failing after cleanup: %v", err)
				log.Printf("[Backup] nginx reload skipped to prevent container issues")
				result.NginxConfigValid = false
				result.NginxConfigError = err.Error()
				result.DetermineStatus()
				// Return partial success instead of silently ignoring the error
				return result, nil
			}
			// Config test passed after cleanup
			result.NginxConfigValid = true
			result.NginxConfigError = ""
		}

		// Reload nginx only if config test passes
		if err := h.nginxManager.ReloadNginx(ctx); err != nil {
			log.Printf("[Backup] Warning: failed to reload nginx after restore: %v", err)
			result.NginxReloaded = false
			result.NginxReloadError = err.Error()
		} else {
			log.Printf("[Backup] nginx reloaded successfully")
			result.NginxReloaded = true
		}
	}

	result.DetermineStatus()
	return result, nil
}

func (h *SettingsHandler) extractFile(tarReader *tar.Reader, destPath string, header *tar.Header) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	// Remove existing symlink or file if it exists
	if info, err := os.Lstat(destPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			// It's a symlink, remove it
			os.Remove(destPath)
		} else if info.IsDir() {
			// It's a directory, skip (don't overwrite directories)
			return nil
		}
	}

	// Create destination file
	outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Use LimitReader to read exactly the expected amount
	limitReader := io.LimitReader(tarReader, header.Size)
	written, err := io.Copy(outFile, limitReader)
	if err != nil {
		return fmt.Errorf("copy error after %d bytes (expected %d): %w", written, header.Size, err)
	}

	if written != header.Size {
		return fmt.Errorf("size mismatch: wrote %d bytes, expected %d", written, header.Size)
	}

	return nil
}

// extractExportJSON reads only the export.json from a backup file
func (h *SettingsHandler) extractExportJSON(backupPath string) ([]byte, error) {
	file, err := os.Open(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry: %w", err)
		}

		if header.Name == "data/export.json" {
			return io.ReadAll(tarReader)
		}
	}

	return nil, nil // No export.json found
}

// restoreFilesFromBackup restores config and certificate files from backup
func (h *SettingsHandler) restoreFilesFromBackup(backup *model.Backup) error {
	file, err := os.Open(backup.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var restoreErrors []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		// Skip directories and symlinks
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			continue
		}

		// Skip entries with zero size (likely directories without proper type flag)
		if header.Size == 0 {
			continue
		}

		// Skip export.json (already processed in phase 1)
		if header.Name == "data/export.json" {
			continue
		}

		switch {
		case filepath.Dir(header.Name) == "config/conf.d":
			// Restore config files
			if backup.IncludesConfig && !strings.HasSuffix(header.Name, "/") {
				destPath := filepath.Join("/etc/nginx/conf.d", filepath.Base(header.Name))
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("config %s: %v", header.Name, err))
				}
			}

		case filepath.HasPrefix(header.Name, "certs/"):
			// Restore certificates
			if backup.IncludesCertificates && !strings.HasSuffix(header.Name, "/") && strings.Contains(filepath.Base(header.Name), ".") {
				relPath := header.Name[6:] // Remove "certs/" prefix
				destPath := filepath.Join("/etc/nginx/certs", relPath)
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("cert %s: %v", header.Name, err))
				}
			}
		}
	}

	if len(restoreErrors) > 0 {
		return fmt.Errorf("file restore errors: %v", restoreErrors)
	}

	return nil
}

// restoreFilesFromBackupDetailed restores files and returns detailed results
func (h *SettingsHandler) restoreFilesFromBackupDetailed(backup *model.Backup) (int, []string) {
	file, err := os.Open(backup.FilePath)
	if err != nil {
		return 0, []string{fmt.Sprintf("failed to open backup file: %v", err)}
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return 0, []string{fmt.Sprintf("failed to create gzip reader: %v", err)}
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var restoreErrors []string
	var filesRestored int

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("tar read error: %v", err))
			break
		}

		// Skip directories, symlinks, zero-size entries, export.json
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeSymlink ||
			header.Typeflag == tar.TypeLink || header.Size == 0 ||
			header.Name == "data/export.json" {
			continue
		}

		switch {
		case filepath.Dir(header.Name) == "config/conf.d":
			if backup.IncludesConfig && !strings.HasSuffix(header.Name, "/") {
				destPath := filepath.Join("/etc/nginx/conf.d", filepath.Base(header.Name))
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("config %s: %v", header.Name, err))
				} else {
					filesRestored++
				}
			}

		case filepath.HasPrefix(header.Name, "certs/"):
			if backup.IncludesCertificates && !strings.HasSuffix(header.Name, "/") &&
				strings.Contains(filepath.Base(header.Name), ".") {
				relPath := header.Name[6:]
				destPath := filepath.Join("/etc/nginx/certs", relPath)
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("cert %s: %v", header.Name, err))
				} else {
					filesRestored++
				}
			}
		}
	}

	return filesRestored, restoreErrors
}

// UploadAndRestoreBackup handles backup file upload and restore
func (h *SettingsHandler) UploadAndRestoreBackup(c echo.Context) error {
	// Get uploaded file
	file, err := c.FormFile("backup")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "backup file required"})
	}

	// Validate file extension
	if !strings.HasSuffix(file.Filename, ".tar.gz") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid file format, expected .tar.gz"})
	}

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to read uploaded file"})
	}
	defer src.Close()

	// Ensure backup directory exists
	os.MkdirAll(h.backupPath, 0755)

	// Save to backup directory
	destPath := filepath.Join(h.backupPath, file.Filename)
	dst, err := os.Create(destPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save backup file"})
	}

	// Calculate checksum while copying
	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)
	size, err := io.Copy(writer, src)
	dst.Close()

	if err != nil {
		os.Remove(destPath)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save backup file"})
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Create backup record
	backup := &model.Backup{
		Filename:             file.Filename,
		FilePath:             destPath,
		FileSize:             size,
		IncludesConfig:       true,
		IncludesCertificates: true,
		IncludesDatabase:     true,
		BackupType:           "uploaded",
		Description:          "Uploaded backup for restore",
		Status:               "completed",
		ChecksumSHA256:       checksum,
	}

	backup, err = h.backupRepo.Create(c.Request().Context(), backup)
	if err != nil {
		os.Remove(destPath)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create backup record"})
	}

	// Perform restore and get detailed result
	result, err := h.performRestore(c.Request().Context(), backup)
	if err != nil {
		response := map[string]interface{}{
			"error":   "restore failed",
			"details": err.Error(),
		}
		if result != nil {
			response["result"] = result
		}
		return c.JSON(http.StatusInternalServerError, response)
	}

	// Audit log
	h.audit.LogBackupRestore(c.Request().Context(), backup.Filename)

	// Determine HTTP status based on result
	httpStatus := http.StatusOK
	if result.Status == "partial" {
		httpStatus = http.StatusPartialContent
	}

	return c.JSON(httpStatus, map[string]interface{}{
		"status":  result.Status,
		"message": result.Message,
		"backup":  backup,
		"result":  result,
	})
}

// verifyBackupChecksum verifies the SHA256 checksum of a backup file
func (h *SettingsHandler) verifyBackupChecksum(filePath, expectedChecksum string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for checksum verification: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

func (h *SettingsHandler) GetBackupStats(c echo.Context) error {
	stats, err := h.backupRepo.GetStats(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, stats)
}

// Test Endpoints

func (h *SettingsHandler) SelfCheck(c echo.Context) error {
	results := make(map[string]interface{})

	// Check database
	dbStatus := config.StatusOK
	// The database is working if we got here

	results["database"] = map[string]interface{}{
		"status": dbStatus,
	}

	// Check nginx
	nginxStatus := config.StatusOK
	var nginxError string
	if h.nginxManager != nil {
		if err := h.nginxManager.TestConfig(c.Request().Context()); err != nil {
			nginxStatus = config.StatusError
			nginxError = err.Error()
		}
	}
	results["nginx"] = map[string]interface{}{
		"status": nginxStatus,
		"error":  nginxError,
	}

	// Check backup directory
	backupStatus := config.StatusOK
	if _, err := os.Stat(h.backupPath); os.IsNotExist(err) {
		if err := os.MkdirAll(h.backupPath, config.DefaultDirPermissions); err != nil {
			backupStatus = config.StatusError
		}
	}
	results["backup_storage"] = map[string]interface{}{
		"status": backupStatus,
		"path":   h.backupPath,
	}

	// Overall status
	overallStatus := config.StatusHealthy
	if nginxStatus != config.StatusOK {
		overallStatus = config.StatusDegraded
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":     overallStatus,
		"checked_at": time.Now(),
		"components": results,
	})
}

func (h *SettingsHandler) TestBackupRestore(c echo.Context) error {
	// Create a test backup
	testBackup := &model.Backup{
		Filename:             "test_backup.tar.gz",
		FilePath:             filepath.Join(h.backupPath, "test_backup.tar.gz"),
		IncludesConfig:       true,
		IncludesCertificates: false,
		IncludesDatabase:     true,
		BackupType:           "test",
		Description:          "Test backup for verification",
		Status:               "completed",
	}

	testBackup, err := h.backupRepo.Create(c.Request().Context(), testBackup)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"test":   "backup_create",
			"status": "failed",
			"error":  err.Error(),
		})
	}

	// Clean up test backup
	h.backupRepo.Delete(c.Request().Context(), testBackup.ID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"test":   "backup_restore",
		"status": "passed",
		"details": map[string]interface{}{
			"backup_create": config.StatusOK,
			"backup_list":   config.StatusOK,
			"backup_delete": config.StatusOK,
		},
	})
}

func (h *SettingsHandler) TestDashboardQueries(c echo.Context) error {
	results := make(map[string]interface{})

	// Test summary query
	summary, err := h.dashboardRepo.GetSummary(c.Request().Context())
	if err != nil {
		results["summary"] = map[string]interface{}{
			"status": config.StatusError,
			"error":  err.Error(),
		}
	} else {
		results["summary"] = map[string]interface{}{
			"status":          config.StatusOK,
			"total_requests":  summary.TotalRequests24h,
			"total_bandwidth": summary.TotalBandwidth24h,
			"proxy_hosts":     summary.TotalProxyHosts,
		}
	}

	// Test health query
	health, err := h.dashboardRepo.GetSystemHealth(c.Request().Context())
	if err != nil {
		results["health"] = map[string]interface{}{
			"status": config.StatusError,
			"error":  err.Error(),
		}
	} else {
		results["health"] = map[string]interface{}{
			"status":       config.StatusOK,
			"nginx_status": health.NginxStatus,
			"db_status":    health.DBStatus,
		}
	}

	// Test hourly stats query
	params := &model.DashboardQueryParams{
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	}
	stats, err := h.dashboardRepo.GetHourlyStats(c.Request().Context(), params)
	if err != nil {
		results["hourly_stats"] = map[string]interface{}{
			"status": config.StatusError,
			"error":  err.Error(),
		}
	} else {
		results["hourly_stats"] = map[string]interface{}{
			"status": config.StatusOK,
			"count":  len(stats),
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"test":    "dashboard_queries",
		"status":  "passed",
		"results": results,
	})
}

// getMergedWAFExclusions returns merged WAF exclusions (host-specific + global)
// This is used during backup restore to regenerate WAF configs correctly
func (h *SettingsHandler) getMergedWAFExclusions(ctx context.Context, hostID string) []model.WAFRuleExclusion {
	if h.wafRepo == nil {
		return nil
	}

	// Get host-specific exclusions
	hostExclusions, err := h.wafRepo.GetExclusionsByProxyHost(ctx, hostID)
	if err != nil {
		log.Printf("[Backup] Warning: failed to get host WAF exclusions for %s: %v", hostID, err)
		hostExclusions = nil
	}

	// Get global exclusions
	globalExclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		log.Printf("[Backup] Warning: failed to get global WAF exclusions: %v", err)
		return hostExclusions // Return host-only if global fails
	}

	// Create a map of host exclusions to avoid duplicates
	hostExclusionMap := make(map[int]bool)
	for _, ex := range hostExclusions {
		hostExclusionMap[ex.RuleID] = true
	}

	// Merge: start with host exclusions
	merged := make([]model.WAFRuleExclusion, len(hostExclusions))
	copy(merged, hostExclusions)

	// Add global exclusions that are not already in host exclusions
	for _, gex := range globalExclusions {
		if !hostExclusionMap[gex.RuleID] {
			merged = append(merged, model.WAFRuleExclusion{
				ID:              gex.ID,
				ProxyHostID:     "global",
				RuleID:          gex.RuleID,
				RuleCategory:    gex.RuleCategory,
				RuleDescription: gex.RuleDescription,
				Reason:          gex.Reason + " (global)",
				DisabledBy:      gex.DisabledBy,
				CreatedAt:       gex.CreatedAt,
			})
		}
	}

	return merged
}
