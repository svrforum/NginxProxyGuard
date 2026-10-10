package handler

import (
	"context"
	"errors"
	"fmt"
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
	Files         []LogFileInfo                `json:"files"`
	TotalSize     int64                        `json:"total_size"`
	TotalCount    int                          `json:"total_count"`
	RawLogEnabled bool                         `json:"raw_log_enabled"`
	Location      string                       `json:"location"`
	Limit         int                          `json:"limit,omitempty"`
	Offset        int                          `json:"offset"`
	Usage         *service.RawLogUsage         `json:"usage,omitempty"`
	Archive       *service.RawLogArchiveStatus `json:"archive,omitempty"`
}

// logFilesViewTimeout bounds a preview. Decompressing a large legacy .gz to
// reach its last lines can take tens of seconds.
const logFilesViewTimeout = 60 * time.Second

// logFileLocation reads ?location=local|archive (default local).
func logFileLocation(c echo.Context) (string, error) {
	switch loc := c.QueryParam("location"); loc {
	case "", service.RawLogLocationLocal:
		return service.RawLogLocationLocal, nil
	case service.RawLogLocationArchive:
		return loc, nil
	}
	return "", errors.New("location must be local or archive")
}

// ListLogFiles returns the raw log files of one location, newest first, with
// the disk usage estimate and the archive status the raw log page shows.
func (h *SystemSettingsHandler) ListLogFiles(c echo.Context) error {
	page, err := parseLogFilesPage(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}
	location, err := logFileLocation(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}
	if location == service.RawLogLocationArchive && h.archiver == nil {
		return h.errArchiveUnavailable(c)
	}
	ctx := c.Request().Context()
	settings, err := h.repo.Get(ctx)
	if err != nil {
		return directInternalError(c, err)
	}

	response := LogFilesResponse{
		Files:         []LogFileInfo{},
		RawLogEnabled: settings.RawLogEnabled,
		Location:      location,
		Limit:         page.limit,
		Offset:        page.offset,
	}

	// An unreadable directory still answers 200 with an empty list.
	local, err := service.ScanRawLogDir(nginxLogsPath)
	if err != nil {
		log.Printf("[RawLog] cannot list %s: %v", nginxLogsPath, err)
	}
	service.SortRawLogFiles(local)

	// The archive: its status always, its files when it answers. For the
	// local tab an archive that does not answer only drops out of the
	// estimate, and a slow listing is not waited for past the call timeout
	// (it goes on and is cached for the next view); for the archive tab it is
	// the answer.
	var archived []service.RawLogFile
	if h.archiver != nil {
		st := h.archiver.Status(ctx)
		response.Archive = &st
		if st.Mounted {
			list := h.archiver.ListArchive
			if location == service.RawLogLocationLocal {
				list = h.archiver.ListArchiveQuick
			}
			archived, err = list(ctx)
			if err != nil {
				if location == service.RawLogLocationArchive {
					return h.archiveError(c, err)
				}
				archived = nil
			}
		} else if location == service.RawLogLocationArchive {
			return c.JSON(http.StatusConflict, map[string]interface{}{"error": st.Detail, "archive": st})
		}
		service.SortRawLogFiles(archived)
	}

	rot, _ := settings.EffectiveRawLogRotation()
	archiveRetention := settings.RawLogArchiveRetentionDays
	usage := service.EstimateRawLogUsage(local, archived, time.Now(), rot, settings.RawLogArchiveEnabled, archiveRetention)
	if fsType, total, avail, err := service.RawLogFilesystem(ctx, nginxLogsPath); err == nil {
		usage.LocalFSType, usage.LocalTotalBytes, usage.LocalFreeBytes = fsType, total, avail
	}
	if response.Archive != nil {
		usage.ArchiveTotalBytes, usage.ArchiveFreeBytes = response.Archive.TotalBytes, response.Archive.FreeBytes
	}
	response.Usage = &usage

	files := local
	if location == service.RawLogLocationArchive {
		files = archived
	}
	for _, f := range files {
		response.TotalSize += f.Size
	}
	response.TotalCount = len(files)
	response.Files = page.apply(files)
	return c.JSON(http.StatusOK, response)
}

// openLogFile opens a raw log file of either location for reading. Archive
// files open through the archiver, so a hung share cannot hold the request.
func (h *SystemSettingsHandler) openLogFile(c echo.Context, location, name string) (*os.File, os.FileInfo, error) {
	if location == service.RawLogLocationArchive {
		if h.archiver == nil {
			return nil, nil, service.ErrArchiveNotReady
		}
		return h.archiver.OpenArchiveFile(c.Request().Context(), name)
	}
	path, info, err := localLogFilePath(nginxLogsPath, name)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, info, nil
}

// DownloadLogFile downloads a raw log file (?location=archive for the archive).
func (h *SystemSettingsHandler) DownloadLogFile(c echo.Context) error {
	filename := c.Param("filename")
	location, err := logFileLocation(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}
	f, info, err := h.openLogFile(c, location, filename)
	if err != nil {
		return h.archiveError(c, err)
	}
	defer f.Close()

	h.auditLogFile(c, map[string]interface{}{
		"action":   "download",
		"filename": filename,
		"location": location,
	})

	c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeContent(c.Response(), c.Request(), filename, info.ModTime(), f)
	return nil
}

// DeleteLogFile deletes a rotated raw log file (?location=archive for the
// archive, which needs this install's marker). The live access_raw.log and
// error_raw.log are refused here, not only hidden in the UI: nginx keeps
// writing to an unlinked file, and those lines would be lost.
func (h *SystemSettingsHandler) DeleteLogFile(c echo.Context) error {
	filename := c.Param("filename")
	location, err := logFileLocation(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}
	if location == service.RawLogLocationArchive {
		if h.archiver == nil {
			return h.errArchiveUnavailable(c)
		}
		if err := h.archiver.DeleteArchiveFile(c.Request().Context(), filename); err != nil {
			return h.archiveError(c, err)
		}
	} else {
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
	}

	h.auditLogFile(c, map[string]interface{}{
		"action":   "delete",
		"filename": filename,
		"location": location,
	})

	return c.NoContent(http.StatusNoContent)
}

// ViewLogFile returns the last N lines of a raw log file (for preview).
// Compressed files are decompressed on the fly.
func (h *SystemSettingsHandler) ViewLogFile(c echo.Context) error {
	filename := c.Param("filename")
	location, err := logFileLocation(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}

	lines := 100
	if linesParam := c.QueryParam("lines"); linesParam != "" {
		if n, err := strconv.Atoi(linesParam); err == nil && n > 0 && n <= 1000 {
			lines = n
		}
	}

	f, info, err := h.openLogFile(c, location, filename)
	if err != nil {
		return h.archiveError(c, err)
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

	// A cut may have finished files for the archive.
	h.archiver.Wake()

	h.auditLogFile(c, map[string]interface{}{"action": "rotate"})

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
