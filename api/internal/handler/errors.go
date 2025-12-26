package handler

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Common error messages for clients (no internal details)
const (
	ErrMsgInternalError    = "An internal error occurred"
	ErrMsgDatabaseError    = "A database error occurred"
	ErrMsgNotFound         = "Resource not found"
	ErrMsgUnauthorized     = "Authentication required"
	ErrMsgForbidden        = "Access denied"
	ErrMsgBadRequest       = "Invalid request"
	ErrMsgConflict         = "Resource conflict"
	ErrMsgValidationFailed = "Validation failed"
)

// ErrorResponse is the standard error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// internalError logs the actual error and returns a generic message to the client
func internalError(c echo.Context, operation string, err error) error {
	log.Printf("[ERROR] %s: %v", operation, err)
	return c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   ErrMsgInternalError,
		Details: err.Error(),
	})
}

// databaseError logs the database error and returns a generic message
func databaseError(c echo.Context, operation string, err error) error {
	log.Printf("[DB ERROR] %s: %v", operation, err)
	return c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   ErrMsgDatabaseError,
		Details: err.Error(),
	})
}

// notFoundError returns a not found error
func notFoundError(c echo.Context, resource string) error {
	return c.JSON(http.StatusNotFound, map[string]string{
		"error": resource + " not found",
	})
}

// badRequestError returns a bad request error with a safe message
func badRequestError(c echo.Context, message string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": message,
	})
}

// unauthorizedError returns an unauthorized error
func unauthorizedError(c echo.Context) error {
	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error": ErrMsgUnauthorized,
	})
}

// forbiddenError returns a forbidden error
func forbiddenError(c echo.Context) error {
	return c.JSON(http.StatusForbidden, map[string]string{
		"error": ErrMsgForbidden,
	})
}

// httpInternalError is for standard http.ResponseWriter handlers
func httpInternalError(w http.ResponseWriter, operation string, err error) {
	log.Printf("[ERROR] %s: %v", operation, err)
	http.Error(w, ErrMsgInternalError, http.StatusInternalServerError)
}

// httpDatabaseError is for standard http.ResponseWriter handlers
func httpDatabaseError(w http.ResponseWriter, operation string, err error) {
	log.Printf("[DB ERROR] %s: %v", operation, err)
	http.Error(w, ErrMsgDatabaseError, http.StatusInternalServerError)
}

// validationError returns a validation error with field details
func validationError(c echo.Context, field, message string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": field + " " + message,
		"field": field,
	})
}

// conflictError returns a conflict error
func conflictError(c echo.Context, message string) error {
	return c.JSON(http.StatusConflict, map[string]string{
		"error": message,
	})
}

// successMessage returns a success response with a message
func successMessage(c echo.Context, message string) error {
	return c.JSON(http.StatusOK, map[string]string{
		"message": message,
	})
}

// createdResponse returns a 201 Created response with the created resource
func createdResponse(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusCreated, data)
}

// noContentResponse returns a 204 No Content response
func noContentResponse(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}
