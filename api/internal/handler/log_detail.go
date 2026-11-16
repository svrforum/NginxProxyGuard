package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// GetDetail returns the columns the log list leaves out, for the row the log
// detail shows (#389). created_at comes from the list row; it lets the lookup
// skip every chunk but one.
func (h *LogHandler) GetDetail(c echo.Context) error {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil || len(id) != 36 {
		return badRequestError(c, "invalid log id: must be a UUID")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, c.QueryParam("created_at"))
	if err != nil {
		return badRequestError(c, "invalid created_at: must be the RFC 3339 created_at of the log row")
	}

	detail, err := h.logRepo.GetDetail(c.Request().Context(), id, createdAt)
	if err != nil {
		return databaseError(c, "get log detail", err)
	}
	if detail == nil {
		return notFoundError(c, "Log")
	}
	return c.JSON(http.StatusOK, detail)
}
