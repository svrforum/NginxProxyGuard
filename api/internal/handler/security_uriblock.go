package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// URI Block handlers

func (h *SecurityHandler) GetURIBlock(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	uriBlock, err := h.securityService.GetURIBlock(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get URI block", err)
	}

	return c.JSON(http.StatusOK, h.uriBlockView(c, uriBlock))
}

func (h *SecurityHandler) UpsertURIBlock(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	skipReload := c.QueryParam("skip_reload") == "true"

	var req model.CreateURIBlockRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if err := checkURIBlockExceptions(req.ExceptionIPs, req.ExceptionHostnames); err != nil {
		return uriBlockRefused(c, err, "upsert URI block")
	}
	var stored []model.URIBlockRule
	var storedNames []string
	if cur, err := h.securityService.GetURIBlock(c.Request().Context(), proxyHostID); err == nil && cur != nil {
		stored = cur.Rules
		storedNames = cur.ExceptionHostnames
	}
	if err := validateChangedURIBlockRules(req.Rules, stored); err != nil {
		return badRequestError(c, err.Error())
	}
	if err := normalizeRuleExceptionIPs(req.Rules); err != nil {
		return badRequestError(c, err.Error())
	}

	uriBlock, err := h.securityService.UpsertURIBlock(c.Request().Context(), proxyHostID, &req, skipReload)
	if err != nil {
		return uriBlockRefused(c, err, "upsert URI block")
	}

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, uriBlock.Enabled, nil)
	if req.ExceptionHostnames != nil {
		auditDNSNames(auditCtx, h.audit, exceptionHostScope(model.DNSScopeKindURIBlock, uriBlock.ProxyHostID), storedNames, uriBlock.ExceptionHostnames)
	}

	return c.JSON(http.StatusOK, uriBlock)
}

func (h *SecurityHandler) DeleteURIBlock(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)
	storedNames := h.storedURIBlockNames(c.Request().Context(), proxyHostID)

	if err := h.securityService.DeleteURIBlock(c.Request().Context(), proxyHostID); err != nil {
		return internalError(c, "delete URI block", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, false, nil)
	auditDNSNames(auditCtx, h.audit, exceptionHostScope(model.DNSScopeKindURIBlock, proxyHostID), storedNames, nil)

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) AddURIBlockRule(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.AddURIBlockRuleRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Pattern == "" {
		return badRequestError(c, "pattern is required")
	}
	if req.MatchType == "" {
		req.MatchType = model.URIMatchPrefix
	}
	rule := model.URIBlockRule{Pattern: req.Pattern, MatchType: req.MatchType, Description: req.Description}
	if err := validateURIBlockRule(&rule); err != nil {
		return badRequestError(c, err.Error())
	}
	req.Pattern = rule.Pattern

	uriBlock, err := h.securityService.AddURIBlockRule(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return internalError(c, "add URI block rule", err)
	}

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, true, map[string]interface{}{
		"action":     "add_rule",
		"pattern":    req.Pattern,
		"match_type": req.MatchType,
	})

	return c.JSON(http.StatusCreated, uriBlock)
}

func (h *SecurityHandler) RemoveURIBlockRule(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	ruleID := c.Param("ruleId")

	if ruleID == "" {
		return badRequestError(c, "rule ID is required")
	}

	if err := h.securityService.RemoveURIBlockRule(c.Request().Context(), proxyHostID, ruleID); err != nil {
		return internalError(c, "remove URI block rule", err)
	}

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", hostName, true, map[string]interface{}{
		"action":  "remove_rule",
		"rule_id": ruleID,
	})

	return c.NoContent(http.StatusNoContent)
}

// BulkAddURIBlockRule adds a rule to multiple or all hosts
func (h *SecurityHandler) BulkAddURIBlockRule(c echo.Context) error {
	var req struct {
		Pattern     string   `json:"pattern"`
		MatchType   string   `json:"match_type"`
		Description string   `json:"description"`
		HostIDs     []string `json:"host_ids"` // If empty, applies to all enabled hosts
	}
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Pattern == "" {
		return badRequestError(c, "pattern is required")
	}
	if req.MatchType == "" {
		req.MatchType = string(model.URIMatchExact)
	}
	rule := model.URIBlockRule{Pattern: req.Pattern, MatchType: model.URIMatchType(req.MatchType), Description: req.Description}
	if err := validateURIBlockRule(&rule); err != nil {
		return badRequestError(c, err.Error())
	}
	req.Pattern = rule.Pattern

	ctx := c.Request().Context()

	result, err := h.securityService.BulkAddURIBlockRule(ctx, req.Pattern, req.MatchType, req.Description, req.HostIDs)
	if err != nil {
		if err.Error() == "no target hosts found" {
			return badRequestError(c, "No target hosts found")
		}
		return databaseError(c, "bulk add URI block rule", err)
	}

	// Audit log for each added host
	auditCtx := service.ContextWithAudit(ctx, c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "uri_block", "bulk", true, map[string]interface{}{
		"action":      "bulk_add_rule",
		"pattern":     req.Pattern,
		"match_type":  req.MatchType,
		"added_count": result.AddedCount,
		"total_hosts": result.TotalHosts,
	})

	response := map[string]interface{}{
		"added_count": result.AddedCount,
		"total_hosts": result.TotalHosts,
		"pattern":     result.Pattern,
		"match_type":  result.MatchType,
	}
	if len(result.Errors) > 0 {
		response["errors"] = result.Errors
	}

	return c.JSON(http.StatusOK, response)
}

// ListAllURIBlocks returns all URI blocks across all hosts
func (h *SecurityHandler) ListAllURIBlocks(c echo.Context) error {
	blocks, err := h.securityService.ListAllURIBlocks(c.Request().Context())
	if err != nil {
		return databaseError(c, "list all URI blocks", err)
	}
	return c.JSON(http.StatusOK, h.uriBlockListView(c, blocks))
}

// ============================================================================
// Global URI Block Handlers
// ============================================================================

// GetGlobalURIBlock returns the global URI block settings
func (h *SecurityHandler) GetGlobalURIBlock(c echo.Context) error {
	block, err := h.securityService.GetGlobalURIBlock(c.Request().Context())
	if err != nil {
		return databaseError(c, "get global URI block", err)
	}

	return c.JSON(http.StatusOK, h.globalURIBlockView(c, block))
}

// UpdateGlobalURIBlock updates the global URI block settings
func (h *SecurityHandler) UpdateGlobalURIBlock(c echo.Context) error {
	var req model.CreateGlobalURIBlockRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if err := checkURIBlockExceptions(req.ExceptionIPs, req.ExceptionHostnames); err != nil {
		return uriBlockRefused(c, err, "update global URI block")
	}
	var stored []model.URIBlockRule
	var storedNames []string
	if cur, err := h.securityService.GetGlobalURIBlock(c.Request().Context()); err == nil && cur != nil {
		stored = cur.Rules
		storedNames = cur.ExceptionHostnames
	}
	if err := validateChangedURIBlockRules(req.Rules, stored); err != nil {
		return badRequestError(c, err.Error())
	}
	if err := normalizeRuleExceptionIPs(req.Rules); err != nil {
		return badRequestError(c, err.Error())
	}

	block, err := h.securityService.UpdateGlobalURIBlock(c.Request().Context(), &req)
	if err != nil {
		if body, ok := exceptionListRefusal(err, "exception_hostnames"); ok {
			return c.JSON(http.StatusBadRequest, body)
		}
		if reloadRefused(err) && block != nil {
			auditCtx := service.ContextWithAudit(c.Request().Context(), c)
			h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", block.Enabled, map[string]interface{}{
				"rules_count": len(block.Rules),
			})
			if req.ExceptionHostnames != nil {
				auditDNSNames(auditCtx, h.audit, globalURIBlockScope, storedNames, block.ExceptionHostnames)
			}
			return internalError(c, "update global URI block", err)
		}
		return databaseError(c, "update global URI block", err)
	}

	// Log audit
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", block.Enabled, map[string]interface{}{
		"rules_count": len(block.Rules),
	})
	if req.ExceptionHostnames != nil {
		auditDNSNames(auditCtx, h.audit, globalURIBlockScope, storedNames, block.ExceptionHostnames)
	}

	return c.JSON(http.StatusOK, block)
}

// AddGlobalURIBlockRule adds a single rule to the global URI block
func (h *SecurityHandler) AddGlobalURIBlockRule(c echo.Context) error {
	var req model.AddURIBlockRuleRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Pattern == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Pattern is required"})
	}

	if req.MatchType == "" {
		req.MatchType = model.URIMatchPrefix
	}
	rule := model.URIBlockRule{Pattern: req.Pattern, MatchType: req.MatchType, Description: req.Description}
	if err := validateURIBlockRule(&rule); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	req.Pattern = rule.Pattern

	block, err := h.securityService.AddGlobalURIBlockRule(c.Request().Context(), &req)
	if err != nil {
		return databaseError(c, "add global URI block rule", err)
	}

	// Log audit
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", true, map[string]interface{}{
		"action":     "add_rule",
		"pattern":    req.Pattern,
		"match_type": req.MatchType,
	})

	return c.JSON(http.StatusOK, block)
}

// RemoveGlobalURIBlockRule removes a single rule from the global URI block
func (h *SecurityHandler) RemoveGlobalURIBlockRule(c echo.Context) error {
	ruleID := c.Param("ruleId")
	if ruleID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Rule ID is required"})
	}

	removedPattern, err := h.securityService.RemoveGlobalURIBlockRule(c.Request().Context(), ruleID)
	if err != nil {
		return databaseError(c, "remove global URI block rule", err)
	}

	// Log audit
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "global_uri_block", "global", true, map[string]interface{}{
		"action":  "remove_rule",
		"rule_id": ruleID,
		"pattern": removedPattern,
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// validateURIBlockRule checks a rule that a request adds or changes: the
// model's check (model.ValidateURIBlockRule, which trims the pattern), and a
// regex must compile within the regex limits. Each rule becomes a location
// block in the config of every host it applies to. The regex compiled is the
// one nginx reads from the pattern (model.URIBlockPatternValue), without the
// quotes a pattern with spaces or braces is written in.
func validateURIBlockRule(rule *model.URIBlockRule) error {
	if err := model.ValidateURIBlockRule(rule); err != nil {
		return errors.New(trimInvalidInputPrefix(err))
	}
	if rule.MatchType == model.URIMatchRegex {
		if err := ValidateRegexPattern(model.URIBlockPatternValue(rule.Pattern)); err != nil {
			return fmt.Errorf("Invalid regex pattern: %v", err)
		}
	}
	return nil
}

// validateChangedURIBlockRules checks the rules of a save that replaces the
// whole list, which the UI sends with every change. A rule identical to a
// stored one (pattern, match type and description) is not checked again: an
// older version may have saved what is now refused, and one such rule must not
// make the rest of the list impossible to edit. The config generator leaves a
// stored rule out if it cannot be written (see uriBlockRules in the nginx
// package). An empty match type is a prefix rule, as the template renders it.
func validateChangedURIBlockRules(rules, stored []model.URIBlockRule) error {
	type ruleKey struct{ pattern, matchType, description string }
	unchanged := make(map[ruleKey]bool, len(stored))
	for _, r := range stored {
		unchanged[ruleKey{r.Pattern, string(r.MatchType), r.Description}] = true
	}
	for i := range rules {
		rule := &rules[i]
		if unchanged[ruleKey{rule.Pattern, string(rule.MatchType), rule.Description}] {
			continue
		}
		if rule.MatchType == "" {
			rule.MatchType = model.URIMatchPrefix
		}
		if err := validateURIBlockRule(rule); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

// normalizeRuleExceptionIPs checks the rules' own exception IPs (#343) and
// writes them normalized (model.NormalizeURIBlockRuleExceptionIPs). Unlike
// the rest of a rule it checks every rule, stored ones too: no older version
// saved such an address, so none can be refused now that was accepted before.
func normalizeRuleExceptionIPs(rules []model.URIBlockRule) error {
	for i := range rules {
		if err := model.NormalizeURIBlockRuleExceptionIPs(&rules[i]); err != nil {
			return fmt.Errorf("rules[%d]: %s", i, trimInvalidInputPrefix(err))
		}
	}
	return nil
}
