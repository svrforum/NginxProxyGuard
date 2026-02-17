package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// getUsernameFromContext extracts username from request context.
// When using echo.WrapHandler, username may be stored in context by auth middleware.
func getUsernameFromContext(ctx context.Context) string {
	if username, ok := ctx.Value("username").(string); ok && username != "" {
		return username
	}
	return "admin" // Fallback for system actions
}

// GetGlobalRules returns all WAF rules with global exclusion status
func (h *WAFHandler) GetGlobalRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get global exclusions
	globalExclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		httpDatabaseError(w, "get global WAF exclusions", err)
		return
	}

	// Create maps for exclusion lookup
	globalExcludedRules := make(map[int]bool)
	globalExclusionMap := make(map[int]*model.GlobalWAFRuleExclusion)
	for i := range globalExclusions {
		ex := &globalExclusions[i]
		globalExcludedRules[ex.RuleID] = true
		globalExclusionMap[ex.RuleID] = ex
	}

	// Parse CRS rules with global exclusion info
	categories, err := h.parseAllRules(RuleParseOptions{
		GlobalExcludedRules: globalExcludedRules,
		GlobalExclusionMap:  globalExclusionMap,
	})
	if err != nil {
		httpInternalError(w, "parse WAF rules", err)
		return
	}

	totalRules := 0
	for _, cat := range categories {
		totalRules += cat.RuleCount
	}

	response := model.GlobalWAFRulesResponse{
		Categories:       categories,
		TotalRules:       totalRules,
		GlobalExclusions: globalExclusions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DisableGlobalRule disables a WAF rule globally (applies to all hosts)
func (h *WAFHandler) DisableGlobalRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /api/v1/waf/global/rules/{ruleId}/disable
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/v1/waf/global/rules/")
	path = strings.TrimPrefix(path, "/api/waf/global/rules/")
	ruleIDStr := strings.TrimSuffix(path, "/disable")

	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	// Parse request body for additional info
	var req model.CreateGlobalWAFRuleExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = model.CreateGlobalWAFRuleExclusionRequest{}
	}
	req.RuleID = ruleID

	// Check if already globally excluded
	existing, err := h.wafRepo.GetGlobalExclusionByRuleID(ctx, ruleID)
	if err != nil {
		httpDatabaseError(w, "check global WAF exclusion", err)
		return
	}
	if existing != nil {
		http.Error(w, "Rule already disabled globally", http.StatusConflict)
		return
	}

	// Get username from context
	username := getUsernameFromContext(ctx)

	// Create the global exclusion
	exclusion, err := h.wafRepo.CreateGlobalExclusion(ctx, &req, username)
	if err != nil {
		httpDatabaseError(w, "create global WAF exclusion", err)
		return
	}

	// Record global policy history
	history := &model.GlobalWAFPolicyHistory{
		RuleID:          ruleID,
		RuleCategory:    req.RuleCategory,
		RuleDescription: req.RuleDescription,
		Action:          "disabled",
		Reason:          req.Reason,
		ChangedBy:       username,
	}
	h.wafRepo.CreateGlobalPolicyHistory(ctx, history)

	// Regenerate nginx config for ALL WAF-enabled hosts
	go h.regenerateAllHostConfigs(context.Background())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(exclusion)
}

// EnableGlobalRule enables a WAF rule globally (removes global exclusion)
func (h *WAFHandler) EnableGlobalRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /api/v1/waf/global/rules/{ruleId}/disable
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/v1/waf/global/rules/")
	path = strings.TrimPrefix(path, "/api/waf/global/rules/")
	ruleIDStr := strings.TrimSuffix(path, "/disable")

	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	// Get exclusion info before deleting (for history)
	exclusion, _ := h.wafRepo.GetGlobalExclusionByRuleID(ctx, ruleID)

	// Delete the global exclusion
	err = h.wafRepo.DeleteGlobalExclusion(ctx, ruleID)
	if err != nil {
		httpDatabaseError(w, "delete global WAF exclusion", err)
		return
	}

	// Record global policy history
	history := &model.GlobalWAFPolicyHistory{
		RuleID:    ruleID,
		Action:    "enabled",
		ChangedBy: "admin",
	}
	if exclusion != nil {
		history.RuleCategory = exclusion.RuleCategory
		history.RuleDescription = exclusion.RuleDescription
	}
	h.wafRepo.CreateGlobalPolicyHistory(ctx, history)

	// Regenerate nginx config for ALL WAF-enabled hosts
	go h.regenerateAllHostConfigs(context.Background())

	w.WriteHeader(http.StatusNoContent)
}

// GetGlobalPolicyHistory returns the global policy change history
func (h *WAFHandler) GetGlobalPolicyHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get limit from query params (default 100)
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Get history
	history, err := h.wafRepo.GetGlobalPolicyHistory(ctx, limit)
	if err != nil {
		httpDatabaseError(w, "get global WAF policy history", err)
		return
	}

	// Get total count
	total, err := h.wafRepo.CountGlobalPolicyHistory(ctx)
	if err != nil {
		httpDatabaseError(w, "count global WAF policy history", err)
		return
	}

	response := model.GlobalWAFPolicyHistoryResponse{
		History: history,
		Total:   total,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetGlobalExclusions returns all global WAF rule exclusions
func (h *WAFHandler) GetGlobalExclusions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	exclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		httpDatabaseError(w, "get global WAF exclusions", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exclusions": exclusions,
		"total":      len(exclusions),
	})
}

// regenerateAllHostConfigs regenerates WAF configs for all WAF-enabled hosts
func (h *WAFHandler) regenerateAllHostConfigs(ctx context.Context) error {
	// Get all proxy hosts
	hosts, _, err := h.proxyHostRepo.List(ctx, 1, 10000, "", "", "")
	if err != nil {
		return err
	}

	// Get global exclusions once
	globalExclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		return err
	}

	// Regenerate config for each WAF-enabled host
	for _, host := range hosts {
		if !host.WAFEnabled {
			continue
		}

		// Get host-specific exclusions
		hostExclusions, err := h.wafRepo.GetExclusionsByProxyHost(ctx, host.ID)
		if err != nil {
			continue
		}

		// Merge global + host exclusions for config generation
		mergedExclusions := h.mergeExclusions(globalExclusions, hostExclusions)

		// Get Priority Allow IPs for WAF bypass
		var allowedIPs []string
		if h.geoRepo != nil {
			geo, err := h.geoRepo.GetByProxyHostID(ctx, host.ID)
			if err == nil && geo != nil {
				allowedIPs = geo.AllowedIPs
			}
		}

		// Generate WAF config
		if err := h.nginxManager.GenerateHostWAFConfig(ctx, &host, mergedExclusions, allowedIPs); err != nil {
			continue
		}
	}

	// Test and reload nginx once after all configs are updated
	if err := h.nginxManager.TestConfig(ctx); err != nil {
		return err
	}

	return h.nginxManager.ReloadNginx(ctx)
}

// mergeExclusions merges global and host-specific exclusions.
// Global exclusions are converted to WAFRuleExclusion format.
func (h *WAFHandler) mergeExclusions(globalExclusions []model.GlobalWAFRuleExclusion, hostExclusions []model.WAFRuleExclusion) []model.WAFRuleExclusion {
	// Create a map of host exclusions to avoid duplicates
	hostExclusionMap := make(map[int]bool)
	for _, ex := range hostExclusions {
		hostExclusionMap[ex.RuleID] = true
	}

	// Start with host exclusions
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
