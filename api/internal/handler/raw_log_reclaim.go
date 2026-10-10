package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// rawLogReclaimJob is what the handler needs from service.RawLogReclaimService.
type rawLogReclaimJob interface {
	Status(ctx context.Context, refreshEstimate bool) (*model.LogRawReclaimStatus, error)
	Start(ctx context.Context, user string, maxChunks *int) (*model.LogRawReclaimStatus, error)
	Stop(ctx context.Context) (*model.LogRawReclaimStatus, error)
}

// RawLogReclaimHandler serves /system-settings/log-storage/raw-reclaim: the
// opt-in removal of the raw_log copies kept in old compressed log history.
type RawLogReclaimHandler struct {
	job   rawLogReclaimJob
	audit *service.AuditService
}

func NewRawLogReclaimHandler(job *service.RawLogReclaimService, audit *service.AuditService) *RawLogReclaimHandler {
	return &RawLogReclaimHandler{job: job, audit: audit}
}

// GetStatus: ?estimate=1 also measures what is left to reclaim, at most every
// 10 minutes; the card polls without it while the job runs.
func (h *RawLogReclaimHandler) GetStatus(c echo.Context) error {
	refresh := c.QueryParam("estimate") == "1" || c.QueryParam("estimate") == "true"
	st, err := h.job.Status(c.Request().Context(), refresh)
	if err != nil {
		return databaseError(c, "raw log reclaim status", err)
	}
	return c.JSON(http.StatusOK, st)
}

// Start answers 202 once the runner has started (or found nothing to do), 409
// when one is already running, 412 when this database cannot run it or the
// free space is unknown or short.
func (h *RawLogReclaimHandler) Start(c echo.Context) error {
	var req model.StartRawLogReclaimRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if req.MaxChunks != nil && (*req.MaxChunks < 1 || *req.MaxChunks > service.RawReclaimMaxChunks) {
		return badRequestError(c, service.ErrRawReclaimInvalid.Error())
	}
	user := ExtractUserInfo(c).Email
	st, err := h.job.Start(c.Request().Context(), user, req.MaxChunks)
	var pre *service.RawReclaimPreconditionError
	switch {
	case errors.Is(err, service.ErrRawReclaimRunning):
		return c.JSON(http.StatusConflict, map[string]string{"error": err.Error(), "code": "already_running"})
	case errors.Is(err, service.ErrRawReclaimInvalid):
		return badRequestError(c, err.Error())
	case errors.As(err, &pre):
		body := map[string]interface{}{"error": pre.Error(), "code": pre.Code}
		if pre.Code == "unsupported" {
			body["reason"] = pre.Reason
		}
		if pre.Code == "insufficient_space" {
			body["free_bytes"] = pre.FreeBytes
			body["required_free_bytes"] = pre.RequiredBytes
		}
		return c.JSON(http.StatusPreconditionFailed, body)
	case err != nil:
		return databaseError(c, "start raw log reclaim", err)
	}
	if h.audit != nil {
		details := map[string]interface{}{"action": "start"}
		if req.MaxChunks != nil {
			details["max_chunks"] = *req.MaxChunks
		}
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(c.Request().Context(), c), "raw_log_reclaim", details)
	}
	return c.JSON(http.StatusAccepted, st)
}

// Stop records 'paused' and cancels the statement in flight; stopping a job
// that is not running is a no-op that still answers 200.
func (h *RawLogReclaimHandler) Stop(c echo.Context) error {
	st, err := h.job.Stop(c.Request().Context())
	if err != nil {
		return databaseError(c, "stop raw log reclaim", err)
	}
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(c.Request().Context(), c), "raw_log_reclaim",
			map[string]interface{}{"action": "stop"})
	}
	return c.JSON(http.StatusOK, st)
}
