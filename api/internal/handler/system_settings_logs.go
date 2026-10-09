package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
)

// LogFileInfo is one raw log file in GET /system-settings/log-files.
type LogFileInfo = service.RawLogFile

// LogFilesResponse is GET /system-settings/log-files. Files is one page of
// the location's files (all of them without a limit); TotalSize and
// TotalCount cover every file there, not just the page.
type LogFilesResponse struct {
	Files         []LogFileInfo        `json:"files"`
	TotalSize     int64                `json:"total_size"`
	TotalCount    int                  `json:"total_count"`
	RawLogEnabled bool                 `json:"raw_log_enabled"`
	Location      string               `json:"location"`
	Limit         int                  `json:"limit,omitempty"`
	Offset        int                  `json:"offset"`
	Usage         *service.RawLogUsage `json:"usage,omitempty"`
}

// logFilesViewTimeout bounds a preview. Decompressing a large legacy .gz to
// reach its last lines can take tens of seconds.
const logFilesViewTimeout = 60 * time.Second

// ListLogFiles returns the raw log files, newest first, with the disk usage
// estimate the raw log page shows.
func (h *SystemSettingsHandler) ListLogFiles(c echo.Context) error {
	page, err := parseLogFilesPage(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}
	ctx := c.Request().Context()
	settings, err := h.repo.Get(ctx)
	if err != nil {
		return directInternalError(c, err)
	}

	response := LogFilesResponse{
		Files:         []LogFileInfo{},
		RawLogEnabled: settings.RawLogEnabled,
		Location:      service.RawLogLocationLocal,
		Limit:         page.limit,
		Offset:        page.offset,
	}

	// An unreadable directory still answers 200 with an empty list.
	local, err := service.ScanRawLogDir(nginxLogsPath)
	if err != nil {
		log.Printf("[RawLog] cannot list %s: %v", nginxLogsPath, err)
	}
	service.SortRawLogFiles(local)

	rot, _ := settings.EffectiveRawLogRotation()
	usage := service.EstimateRawLogUsage(local, nil, time.Now(), rot, false, 0)
	if fsType, total, avail, err := service.RawLogFilesystem(ctx, nginxLogsPath); err == nil {
		usage.LocalFSType, usage.LocalTotalBytes, usage.LocalFreeBytes = fsType, total, avail
	}
	response.Usage = &usage

	for _, f := range local {
		response.TotalSize += f.Size
	}
	response.TotalCount = len(local)
	response.Files = page.apply(local)
	return c.JSON(http.StatusOK, response)
}

// DownloadLogFile downloads a raw log file.
func (h *SystemSettingsHandler) DownloadLogFile(c echo.Context) error {
	filename := c.Param("filename")
	path, info, err := localLogFilePath(nginxLogsPath, filename)
	if err != nil {
		return logFileError(c, err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "로그 파일", map[string]interface{}{
		"action":   "download",
		"filename": filename,
	})

	c.Response().Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	return c.Attachment(path, filename)
}

// DeleteLogFile deletes a rotated raw log file. The live access_raw.log and
// error_raw.log are refused here, not only hidden in the UI: nginx keeps
// writing to an unlinked file, and those lines would be lost.
func (h *SystemSettingsHandler) DeleteLogFile(c echo.Context) error {
	filename := c.Param("filename")
	if service.IsActiveRawLog(filename) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete active log file"})
	}
	path, _, err := localLogFilePath(nginxLogsPath, filename)
	if err != nil {
		return logFileError(c, err)
	}
	if err := os.Remove(path); err != nil {
		return logFileError(c, err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "로그 파일", map[string]interface{}{
		"action":   "delete",
		"filename": filename,
	})

	return c.NoContent(http.StatusNoContent)
}

// ViewLogFile returns the last N lines of a raw log file (for preview).
// Compressed files are decompressed on the fly.
func (h *SystemSettingsHandler) ViewLogFile(c echo.Context) error {
	filename := c.Param("filename")

	lines := 100
	if linesParam := c.QueryParam("lines"); linesParam != "" {
		if n, err := strconv.Atoi(linesParam); err == nil && n > 0 && n <= 1000 {
			lines = n
		}
	}

	path, info, err := localLogFilePath(nginxLogsPath, filename)
	if err != nil {
		return logFileError(c, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return logFileError(c, err)
	}
	defer f.Close()

	ctx, cancel := context.WithTimeout(c.Request().Context(), logFilesViewTimeout)
	defer cancel()
	content, err := readLogTail(ctx, f, filename, info.Size(), lines)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return c.JSON(http.StatusGatewayTimeout, map[string]string{"error": "reading the file took too long"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to read file"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"filename": filename,
		"lines":    lines,
		"content":  content,
	})
}

// TriggerLogRotation manually triggers log rotation
func (h *SystemSettingsHandler) TriggerLogRotation(c echo.Context) error {
	// Get settings
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return directInternalError(c, err)
	}

	if !settings.RawLogEnabled {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "raw log files are not enabled",
		})
	}

	// Generate logrotate config first
	if err := h.generateLogrotateConfig(settings); err != nil {
		return directInternalError(c, err)
	}

	// Rotate through the nginx manager: logrotate lives in the nginx container,
	// not here (#301). The scheduler uses the same call so the two cannot drift.
	if h.nginxManager == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "nginx manager is not available",
		})
	}

	if err := h.nginxManager.RotateLogs(c.Request().Context()); err != nil {
		// Three refusals are not failures: nothing to cut, a cut that already
		// happened this second, or a rotation running right now. In each case
		// the current log is as fresh as a rotation could make it, so the
		// answer is 200 with the reason rather than a 500 — but the reason is
		// stated, because "completed" when nothing moved would be a lie.
		if code, reason, skipped := logRotationSkipReason(err); skipped {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"status": "skipped",
				// A stable code beside the sentence. The sentence is English
				// and always will be; the panel is Korean by default, so it
				// needs something to translate on. Clients that only read
				// `message` keep working.
				"reason":  code,
				"message": reason,
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"error":   "logrotate failed",
			"details": SafeErrorDetail(err),
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

// Stable reason codes for a skipped rotation. These are part of the response
// contract — the panel selects its wording from them — so they must not be
// renamed to match a sentence someone rephrased.
const (
	LogRotationSkipEmpty          = "empty"
	LogRotationSkipAlreadyRotated = "already_rotated"
	LogRotationSkipBusy           = "busy"
)

// logRotationSkipReason turns the manager's non-failure outcomes into a code
// and the sentence a client without translations can fall back on. Anything
// else is a real logrotate fault.
func logRotationSkipReason(err error) (code, reason string, skipped bool) {
	switch {
	case errors.Is(err, nginx.ErrLogrotateNothingToRotate):
		return LogRotationSkipEmpty, "Nothing to rotate: the current log files are empty", true
	case errors.Is(err, nginx.ErrLogrotateAlreadyRotated):
		return LogRotationSkipAlreadyRotated, "Log files were rotated a moment ago; the current log is already fresh", true
	case errors.Is(err, nginx.ErrLogrotateBusy):
		return LogRotationSkipBusy, "A log rotation is already in progress", true
	}
	return "", "", false
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
		return badRequestError(c, err.Error())
	}

	if err := h.dockerLogCollector.UpdateConfig(config); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update config: " + SafeErrorMessage(err)})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "시스템 로그 설정", map[string]interface{}{
		"action": "update",
	})

	return c.JSON(http.StatusOK, config)
}
