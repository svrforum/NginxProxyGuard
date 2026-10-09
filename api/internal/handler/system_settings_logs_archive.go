package handler

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/service"
)

// Raw log archive: the directory rotated raw logs move to (another disk or a
// NAS share bound into the API container). The mover and its safety rules
// live in service.RawLogArchiver.

// SetRawLogArchiver wires the archive mover. Without it the archive
// endpoints answer 409 and only local files are listed.
func (h *SystemSettingsHandler) SetRawLogArchiver(a *service.RawLogArchiver) {
	h.archiver = a
}

// auditLogFile records a raw log file action ("로그 파일" in the audit log).
func (h *SystemSettingsHandler) auditLogFile(c echo.Context, details map[string]interface{}) {
	if h.audit == nil {
		return
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "로그 파일", details)
}

// errArchiveUnavailable answers when no archiver is wired.
func (h *SystemSettingsHandler) errArchiveUnavailable(c echo.Context) error {
	return c.JSON(http.StatusConflict, map[string]string{"error": "the raw log archive is not available"})
}

// archiveError answers an archive failure with its status: 503 while the
// share does not answer, 409 when it is not mounted or not ours, 400 for a
// bad name, 404 for a missing file.
func (h *SystemSettingsHandler) archiveError(c echo.Context, err error) error {
	var stalled *service.ArchiveStalledError
	switch {
	case errors.As(err, &stalled):
		return c.JSON(http.StatusServiceUnavailable, map[string]interface{}{
			"error":   stalled.Error(),
			"archive": h.archiver.Status(c.Request().Context()),
		})
	case errors.Is(err, service.ErrArchiveNotReady):
		return c.JSON(http.StatusConflict, map[string]interface{}{
			"error":   err.Error(),
			"archive": h.archiver.Status(c.Request().Context()),
		})
	case errors.Is(err, service.ErrArchiveFileName):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": errLogFileName.Error()})
	}
	return logFileError(c, err)
}

// CheckRawLogArchive probes the archive directory with a write test (one
// temporary file, removed again). It writes no marker.
func (h *SystemSettingsHandler) CheckRawLogArchive(c echo.Context) error {
	if h.archiver == nil {
		return h.errArchiveUnavailable(c)
	}
	return c.JSON(http.StatusOK, h.archiver.Check(c.Request().Context()))
}

// InitRawLogArchive claims the archive directory for this install: write
// test, then the marker. It never creates the directory.
func (h *SystemSettingsHandler) InitRawLogArchive(c echo.Context) error {
	if h.archiver == nil {
		return h.errArchiveUnavailable(c)
	}
	st, err := h.archiver.Initialise(c.Request().Context())
	if err != nil {
		code := http.StatusBadRequest
		if st.Status == service.ArchiveStatusStalled {
			code = http.StatusServiceUnavailable
		}
		return c.JSON(code, map[string]interface{}{"error": err.Error(), "archive": st})
	}
	h.auditLogFile(c, map[string]interface{}{
		"action":  "archive_init",
		"dir":     st.Dir,
		"fs_type": st.FSType,
	})
	return c.JSON(http.StatusOK, st)
}

// RunRawLogArchive asks for an archive pass now and answers at once.
func (h *SystemSettingsHandler) RunRawLogArchive(c echo.Context) error {
	if h.archiver == nil {
		return h.errArchiveUnavailable(c)
	}
	h.archiver.Wake()
	return c.JSON(http.StatusAccepted, h.archiver.Status(c.Request().Context()))
}
