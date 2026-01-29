package handler

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/util"
)

type AuditLogHandler struct {
	repo      *repository.AuditLogRepository
	tokenRepo *repository.APITokenRepository
}

func NewAuditLogHandler(repo *repository.AuditLogRepository, tokenRepo *repository.APITokenRepository) *AuditLogHandler {
	return &AuditLogHandler{repo: repo, tokenRepo: tokenRepo}
}

// ListAuditLogs returns audit logs with optional filters
// GET /api/v1/audit-logs
func (h *AuditLogHandler) ListAuditLogs(c echo.Context) error {
	filter := repository.AuditLogFilter{
		UserID:       c.QueryParam("user_id"),
		Action:       c.QueryParam("action"),
		ResourceType: c.QueryParam("resource_type"),
		Search:       c.QueryParam("search"),
	}

	// Parse limit and offset using utility functions
	filter.Limit = util.ParseLimitParam(c, config.DefaultAuditLogLimit)
	filter.Offset = util.ParseOffsetParam(c)

	// Parse time range
	filter.StartTime, filter.EndTime = util.ParseTimeRange(c)

	logs, total, err := h.repo.List(c.Request().Context(), filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Format logs for display
	formattedLogs := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		formattedLogs[i] = map[string]interface{}{
			"id":            log.ID,
			"username":      log.Username,
			"action":        log.Action,
			"action_label":  formatActionLabel(log.Action),
			"resource_type": log.ResourceType,
			"resource_id":   log.ResourceID,
			"resource_name": log.ResourceName,
			"details":       log.Details,
			"ip_address":    log.IPAddress,
			"user_agent":    log.UserAgent,
			"created_at":    log.CreatedAt,
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"logs":   formattedLogs,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// GetActions returns available action types
// GET /api/v1/audit-logs/actions
func (h *AuditLogHandler) GetActions(c echo.Context) error {
	actions, err := h.repo.GetActions(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Format actions with labels
	formattedActions := make([]map[string]string, len(actions))
	for i, action := range actions {
		formattedActions[i] = map[string]string{
			"value": action,
			"label": formatActionLabel(action),
		}
	}

	return c.JSON(http.StatusOK, formattedActions)
}

// GetResourceTypes returns available resource types
// GET /api/v1/audit-logs/resource-types
func (h *AuditLogHandler) GetResourceTypes(c echo.Context) error {
	types, err := h.repo.GetResourceTypes(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Format types with labels
	formattedTypes := make([]map[string]string, len(types))
	for i, t := range types {
		formattedTypes[i] = map[string]string{
			"value": t,
			"label": formatResourceTypeLabel(t),
		}
	}

	return c.JSON(http.StatusOK, formattedTypes)
}

// ListAPITokenUsage returns API token usage logs
// GET /api/v1/audit-logs/api-tokens
func (h *AuditLogHandler) ListAPITokenUsage(c echo.Context) error {
	// Parse limit and offset using utility functions
	limit := util.ParseLimitParam(c, config.DefaultAuditLogLimit)
	offset := util.ParseOffsetParam(c)

	// Get all tokens first to map them
	tokens, err := h.tokenRepo.ListAll(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch tokens",
		})
	}

	tokenMap := make(map[string]*struct {
		Name     string
		Prefix   string
		Username string
	})
	for _, t := range tokens {
		tokenMap[t.ID] = &struct {
			Name     string
			Prefix   string
			Username string
		}{t.Name, t.TokenPrefix, t.Username}
	}

	// Get usage logs for all tokens
	since := time.Now().Add(-7 * 24 * time.Hour) // Last 7 days
	var allUsages []map[string]interface{}

	for _, t := range tokens {
		usages, err := h.tokenRepo.GetUsageStats(c.Request().Context(), t.ID, since)
		if err != nil {
			continue
		}

		for _, u := range usages {
			allUsages = append(allUsages, map[string]interface{}{
				"id":            u.ID,
				"token_id":      u.TokenID,
				"token_name":    t.Name,
				"token_prefix":  t.TokenPrefix,
				"username":      t.Username,
				"endpoint":      u.Endpoint,
				"method":        u.Method,
				"status_code":   u.StatusCode,
				"client_ip":     u.ClientIP,
				"user_agent":    u.UserAgent,
				"response_time": u.ResponseTimeMs,
				"created_at":    u.CreatedAt,
			})
		}
	}

	// Sort by created_at descending
	for i := 0; i < len(allUsages)-1; i++ {
		for j := i + 1; j < len(allUsages); j++ {
			ti := allUsages[i]["created_at"].(time.Time)
			tj := allUsages[j]["created_at"].(time.Time)
			if ti.Before(tj) {
				allUsages[i], allUsages[j] = allUsages[j], allUsages[i]
			}
		}
	}

	// Apply pagination
	total := len(allUsages)
	start := offset
	end := offset + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	pagedUsages := allUsages[start:end]

	return c.JSON(http.StatusOK, map[string]interface{}{
		"logs":   pagedUsages,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// Helper functions for formatting labels
func formatActionLabel(action string) string {
	labels := map[string]string{
		"proxy_host_created":       "프록시 호스트 생성",
		"proxy_host_updated":       "프록시 호스트 수정",
		"proxy_host_deleted":       "프록시 호스트 삭제",
		"certificate_created":      "인증서 생성",
		"certificate_updated":      "인증서 수정",
		"certificate_deleted":      "인증서 삭제",
		"certificate_renewed":      "인증서 갱신",
		"certificate_downloaded":   "인증서 다운로드",
		"waf_enabled":              "WAF 활성화",
		"waf_disabled":             "WAF 비활성화",
		"waf_rules_updated":        "WAF 규칙 수정",
		"settings_updated":         "설정 변경",
		"user_login":               "로그인",
		"user_logout":              "로그아웃",
		"user_created":             "사용자 생성",
		"user_updated":             "사용자 수정",
		"user_deleted":             "사용자 삭제",
		"password_changed":         "비밀번호 변경",
		"username_changed":         "사용자명 변경",
		"totp_enabled":             "2FA 활성화",
		"totp_disabled":            "2FA 비활성화",
		"backup_created":           "백업 생성",
		"backup_restored":          "백업 복원",
		"backup_deleted":           "백업 삭제",
		"api_token_created":        "API 토큰 생성",
		"api_token_updated":        "API 토큰 수정",
		"api_token_revoked":        "API 토큰 폐기",
		"api_token_deleted":        "API 토큰 삭제",
		"api_token_ip_denied":      "API 토큰 IP 거부",
		"api_call":                 "API 호출",
		"api_call_error":           "API 호출 오류",
		"access_list_created":      "접근 목록 생성",
		"access_list_updated":      "접근 목록 수정",
		"access_list_deleted":      "접근 목록 삭제",
		"redirect_host_created":    "리다이렉트 호스트 생성",
		"redirect_host_updated":    "리다이렉트 호스트 수정",
		"redirect_host_deleted":    "리다이렉트 호스트 삭제",
		"rate_limit_enabled":       "속도 제한 활성화",
		"rate_limit_disabled":      "속도 제한 비활성화",
		"bot_filter_enabled":       "봇 필터 활성화",
		"bot_filter_disabled":      "봇 필터 비활성화",
		"security_headers_enabled": "보안 헤더 활성화",
		"security_headers_disabled": "보안 헤더 비활성화",
		"uri_block_enabled":        "URI 차단 활성화",
		"uri_block_disabled":       "URI 차단 비활성화",
		"fail2ban_enabled":         "Fail2ban 활성화",
		"fail2ban_disabled":        "Fail2ban 비활성화",
		"global_uri_block_enabled": "전역 URI 차단 활성화",
		"global_uri_block_disabled": "전역 URI 차단 비활성화",
		"geo_restriction_updated":  "지역 제한 수정",
		"upstream_updated":         "업스트림 수정",
		"ip_banned":                "IP 차단",
		"ip_unbanned":              "IP 차단 해제",
	}

	if label, ok := labels[action]; ok {
		return label
	}
	return action
}

func formatResourceTypeLabel(resourceType string) string {
	labels := map[string]string{
		"proxy_host":    "프록시 호스트",
		"certificate":   "인증서",
		"waf":           "WAF",
		"settings":      "설정",
		"user":          "사용자",
		"backup":        "백업",
		"api_token":     "API 토큰",
		"access_list":   "접근 목록",
		"redirect_host": "리다이렉트 호스트",
	}

	if label, ok := labels[resourceType]; ok {
		return label
	}
	return resourceType
}
