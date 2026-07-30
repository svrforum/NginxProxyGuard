package handler

import (
	"net/http"
	"time"

	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"

	"github.com/labstack/echo/v4"
)

type APITokenHandler struct {
	tokenRepo *repository.APITokenRepository
	auditRepo *repository.AuditLogRepository
}

func NewAPITokenHandler(tokenRepo *repository.APITokenRepository, auditRepo *repository.AuditLogRepository) *APITokenHandler {
	return &APITokenHandler{
		tokenRepo: tokenRepo,
		auditRepo: auditRepo,
	}
}

// getContextString safely extracts a string from echo context
func getContextString(c echo.Context, key string) (string, bool) {
	val := c.Get(key)
	if val == nil {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// CreateToken creates a new API token
func (h *APITokenHandler) CreateToken(c echo.Context) error {
	userIDRaw := c.Get("user_id")
	usernameRaw := c.Get("username")

	if userIDRaw == nil || usernameRaw == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	userID, ok := userIDRaw.(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid user context"})
	}
	username, ok := usernameRaw.(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid user context"})
	}

	var req model.CreateAPITokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	if len(req.Permissions) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "at least one permission is required"})
	}

	// Validate permissions
	for _, perm := range req.Permissions {
		if !isValidPermission(perm) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission: " + perm})
		}
	}
	if over, ok := assertPermissionsWithinRole(c, req.Permissions); !ok {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "cannot grant a token more than your own role allows: " + over,
		})
	}

	// Generate token
	token, hash, prefix, err := model.GenerateToken()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
	}

	// Calculate expiry
	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn != "never" {
		exp, err := parseExpiry(*req.ExpiresIn)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid expires_in format"})
		}
		expiresAt = exp
	}

	// Create token
	apiToken := &model.APIToken{
		UserID:      userID,
		Name:        req.Name,
		TokenHash:   hash,
		TokenPrefix: prefix,
		Permissions: req.Permissions,
		AllowedIPs:  req.AllowedIPs,
		RateLimit:   req.RateLimit,
		ExpiresAt:   expiresAt,
		IsActive:    true,
	}

	if err := h.tokenRepo.Create(c.Request().Context(), apiToken); err != nil {
		return databaseError(c, "create API token", err)
	}

	// Audit log
	h.auditRepo.Log(c.Request().Context(), &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     "api_token_created",
		Resource:   "api_token",
		ResourceID: apiToken.ID,
		Details: map[string]interface{}{
			"token_name":   req.Name,
			"token_prefix": prefix,
			"permissions":  req.Permissions,
		},
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	})

	// Return token with secret (only time it's shown)
	resp := model.APITokenWithSecret{
		APITokenResponse: apiToken.ToResponse(),
		Token:            token,
	}

	return c.JSON(http.StatusCreated, resp)
}

// ListTokens lists all tokens for the current user
func (h *APITokenHandler) ListTokens(c echo.Context) error {
	userID, ok := getContextString(c, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	role, _ := getContextString(c, "role")

	var tokens []*model.APIToken
	var err error

	// Admins can see all tokens
	if role == "admin" && c.QueryParam("all") == "true" {
		tokens, err = h.tokenRepo.ListAll(c.Request().Context())
	} else {
		tokens, err = h.tokenRepo.ListByUser(c.Request().Context(), userID)
	}

	if err != nil {
		return databaseError(c, "list API tokens", err)
	}

	// Convert to response format
	resp := make([]model.APITokenResponse, len(tokens))
	for i, t := range tokens {
		resp[i] = t.ToResponse()
	}

	return c.JSON(http.StatusOK, resp)
}

// GetToken gets a specific token
func (h *APITokenHandler) GetToken(c echo.Context) error {
	tokenID := c.Param("id")

	userID, ok := getContextString(c, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	role, _ := getContextString(c, "role")

	token, err := h.tokenRepo.GetByID(c.Request().Context(), tokenID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get token"})
	}
	if token == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}

	// Check ownership (admins can view all)
	if role != "admin" && token.UserID != userID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	return c.JSON(http.StatusOK, token.ToResponse())
}

// UpdateToken updates a token
func (h *APITokenHandler) UpdateToken(c echo.Context) error {
	tokenID := c.Param("id")

	userID, ok := getContextString(c, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}
	username, ok := getContextString(c, "username")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	role, _ := getContextString(c, "role")

	token, err := h.tokenRepo.GetByID(c.Request().Context(), tokenID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get token"})
	}
	if token == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}

	// Check ownership
	if role != "admin" && token.UserID != userID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	var req model.UpdateAPITokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	// Validate permissions if provided
	if req.Permissions != nil {
		for _, perm := range req.Permissions {
			if !isValidPermission(perm) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission: " + perm})
			}
		}
		if over, ok := assertPermissionsWithinRole(c, req.Permissions); !ok {
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "cannot grant a token more than your own role allows: " + over,
			})
		}
	}

	if err := h.tokenRepo.Update(c.Request().Context(), tokenID, &req); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update token"})
	}

	// Audit log
	h.auditRepo.Log(c.Request().Context(), &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     "api_token_updated",
		Resource:   "api_token",
		ResourceID: tokenID,
		Details: map[string]interface{}{
			"token_name":   token.Name,
			"token_prefix": token.TokenPrefix,
		},
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	})

	// Return updated token
	updated, _ := h.tokenRepo.GetByID(c.Request().Context(), tokenID)
	return c.JSON(http.StatusOK, updated.ToResponse())
}

// RevokeToken revokes a token
func (h *APITokenHandler) RevokeToken(c echo.Context) error {
	tokenID := c.Param("id")

	userID, ok := getContextString(c, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}
	username, ok := getContextString(c, "username")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	role, _ := getContextString(c, "role")

	token, err := h.tokenRepo.GetByID(c.Request().Context(), tokenID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get token"})
	}
	if token == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}

	// Check ownership
	if role != "admin" && token.UserID != userID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	var req model.RevokeAPITokenRequest
	if err := c.Bind(&req); err != nil {
		// Binding errors are non-fatal for this endpoint
		req = model.RevokeAPITokenRequest{}
	}

	reason := req.Reason
	if reason == "" {
		reason = "manually revoked"
	}

	if err := h.tokenRepo.Revoke(c.Request().Context(), tokenID, reason); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to revoke token"})
	}

	// Audit log
	h.auditRepo.Log(c.Request().Context(), &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     "api_token_revoked",
		Resource:   "api_token",
		ResourceID: tokenID,
		Details: map[string]interface{}{
			"token_name":   token.Name,
			"token_prefix": token.TokenPrefix,
			"reason":       reason,
		},
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "token revoked"})
}

// DeleteToken permanently deletes a token
func (h *APITokenHandler) DeleteToken(c echo.Context) error {
	tokenID := c.Param("id")

	userID, ok := getContextString(c, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}
	username, ok := getContextString(c, "username")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	role, _ := getContextString(c, "role")

	token, err := h.tokenRepo.GetByID(c.Request().Context(), tokenID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get token"})
	}
	if token == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}

	// Check ownership
	if role != "admin" && token.UserID != userID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	if err := h.tokenRepo.Delete(c.Request().Context(), tokenID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete token"})
	}

	// Audit log
	h.auditRepo.Log(c.Request().Context(), &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     "api_token_deleted",
		Resource:   "api_token",
		ResourceID: tokenID,
		Details: map[string]interface{}{
			"token_name":   token.Name,
			"token_prefix": token.TokenPrefix,
		},
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	})

	return c.NoContent(http.StatusNoContent)
}

// GetTokenUsage gets usage statistics for a token
func (h *APITokenHandler) GetTokenUsage(c echo.Context) error {
	tokenID := c.Param("id")

	userID, ok := getContextString(c, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	role, _ := getContextString(c, "role")

	token, err := h.tokenRepo.GetByID(c.Request().Context(), tokenID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get token"})
	}
	if token == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}

	// Check ownership
	if role != "admin" && token.UserID != userID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	// Get usage from last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	usages, err := h.tokenRepo.GetUsageStats(c.Request().Context(), tokenID, since)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get usage stats"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":  token.ToResponse(),
		"usages": usages,
	})
}

// GetPermissions returns available permissions
func (h *APITokenHandler) GetPermissions(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"permissions": model.AllPermissions,
		"groups":      model.PermissionGroups,
	})
}

// Helper functions

// assertPermissionsWithinRole refuses a token that would exceed the issuer's own
// role (#222 D5/D3, issuance side).
//
// The runtime intersection in AuthzService.CanToken already caps what a token can
// do, so this is not the security boundary — it is the difference between a token
// that quietly does less than its stated scopes and a request that is refused with
// a reason. Failing at creation is what makes the scope list honest.
//
// Session users are checked too, not only API tokens: the point is the issuer's
// role, whoever they are.
func assertPermissionsWithinRole(c echo.Context, perms []string) (string, bool) {
	for _, perm := range perms {
		// "*" is only within reach of a principal that already holds everything.
		probe := perm
		if perm == model.PermissionAll {
			probe = "role:write"
		}
		if !authMiddleware.HasPermissionFromContext(c, probe) {
			return perm, false
		}
	}
	return "", true
}

func isValidPermission(perm string) bool {
	if perm == model.PermissionAll {
		return true
	}
	for _, valid := range model.AllPermissions {
		if perm == valid {
			return true
		}
	}
	return false
}

func parseExpiry(s string) (*time.Time, error) {
	var duration time.Duration
	var multiplier int

	if len(s) < 2 {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid expiry format")
	}

	unit := s[len(s)-1]
	value := s[:len(s)-1]

	// Simple int parse
	for _, c := range value {
		if c < '0' || c > '9' {
			return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid expiry format")
		}
		multiplier = multiplier*10 + int(c-'0')
	}

	if multiplier <= 0 {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid expiry value")
	}

	switch unit {
	case 'h':
		duration = time.Duration(multiplier) * time.Hour
	case 'd':
		duration = time.Duration(multiplier) * 24 * time.Hour
	case 'w':
		duration = time.Duration(multiplier) * 7 * 24 * time.Hour
	case 'm': // months (approximate)
		duration = time.Duration(multiplier) * 30 * 24 * time.Hour
	case 'y':
		duration = time.Duration(multiplier) * 365 * 24 * time.Hour
	default:
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid expiry unit (use h, d, w, m, y)")
	}

	t := time.Now().Add(duration)
	return &t, nil
}
