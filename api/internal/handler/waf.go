package handler

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

type WAFHandler struct {
	wafRepo       *repository.WAFRepository
	proxyHostRepo *repository.ProxyHostRepository
	geoRepo       *repository.GeoRepository
	nginxManager  *nginx.Manager
	crsPath       string
}

func NewWAFHandler(wafRepo *repository.WAFRepository, proxyHostRepo *repository.ProxyHostRepository, geoRepo *repository.GeoRepository, nginxManager *nginx.Manager) *WAFHandler {
	crsPath := os.Getenv("CRS_PATH")
	if crsPath == "" {
		crsPath = "/etc/nginx/owasp-crs"
	}
	return &WAFHandler{
		wafRepo:       wafRepo,
		proxyHostRepo: proxyHostRepo,
		geoRepo:       geoRepo,
		nginxManager:  nginxManager,
		crsPath:       crsPath,
	}
}

// GetRules returns all available OWASP CRS rules
func (h *WAFHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get global exclusions first
	globalExclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		httpDatabaseError(w, "get global WAF exclusions", err)
		return
	}

	// Create maps for global exclusions
	globalExcludedRules := make(map[int]bool)
	globalExclusionMap := make(map[int]*model.GlobalWAFRuleExclusion)
	for i := range globalExclusions {
		ex := &globalExclusions[i]
		globalExcludedRules[ex.RuleID] = true
		globalExclusionMap[ex.RuleID] = ex
	}

	// Get optional proxy_host_id to check which rules are excluded
	proxyHostID := r.URL.Query().Get("proxy_host_id")
	var exclusions []model.WAFRuleExclusion
	if proxyHostID != "" {
		exclusions, err = h.wafRepo.GetExclusionsByProxyHost(ctx, proxyHostID)
		if err != nil {
			httpDatabaseError(w, "get WAF exclusions", err)
			return
		}
	}

	// Create maps of host-specific excluded rule IDs
	excludedRules := make(map[int]bool)
	exclusionMap := make(map[int]*model.WAFRuleExclusion)
	for i := range exclusions {
		ex := &exclusions[i]
		excludedRules[ex.RuleID] = true
		exclusionMap[ex.RuleID] = ex
	}

	// Parse CRS rules with both global and host-specific exclusion info
	categories, err := h.parseAllRules(RuleParseOptions{
		HostExcludedRules:   excludedRules,
		HostExclusionMap:    exclusionMap,
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

	response := model.WAFRulesResponse{
		Categories: categories,
		TotalRules: totalRules,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetHostConfigs returns WAF configuration for all proxy hosts
func (h *WAFHandler) GetHostConfigs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get all proxy hosts
	hosts, _, err := h.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
	if err != nil {
		httpDatabaseError(w, "list proxy hosts for WAF", err)
		return
	}

	// Get exclusion counts for all hosts
	exclusionCounts, err := h.wafRepo.CountExclusionsByProxyHost(ctx)
	if err != nil {
		httpDatabaseError(w, "count WAF exclusions", err)
		return
	}

	var configs []model.WAFHostConfig
	for _, host := range hosts {
		hostName := ""
		if len(host.DomainNames) > 0 {
			hostName = host.DomainNames[0]
		}

		config := model.WAFHostConfig{
			ProxyHostID:    host.ID,
			ProxyHostName:  hostName,
			WAFEnabled:     host.WAFEnabled,
			WAFMode:        host.WAFMode,
			ExclusionCount: exclusionCounts[host.ID],
		}
		configs = append(configs, config)
	}

	response := model.WAFHostConfigListResponse{
		Hosts: configs,
		Total: len(configs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetHostConfig returns detailed WAF configuration for a specific proxy host
func (h *WAFHandler) GetHostConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract proxy host ID from URL path (handles both /api/waf/hosts/ and /api/v1/waf/hosts/)
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/v1/waf/hosts/")
	path = strings.TrimPrefix(path, "/api/waf/hosts/")
	proxyHostID := strings.TrimSuffix(path, "/config")

	// Get the proxy host
	host, err := h.proxyHostRepo.GetByID(ctx, proxyHostID)
	if err != nil {
		httpDatabaseError(w, "get proxy host for WAF config", err)
		return
	}
	if host == nil {
		http.Error(w, "Proxy host not found", http.StatusNotFound)
		return
	}

	// Get exclusions for this host
	exclusions, err := h.wafRepo.GetExclusionsByProxyHost(ctx, proxyHostID)
	if err != nil {
		httpDatabaseError(w, "get WAF exclusions", err)
		return
	}

	hostName := ""
	if len(host.DomainNames) > 0 {
		hostName = host.DomainNames[0]
	}

	config := model.WAFHostConfig{
		ProxyHostID:    host.ID,
		ProxyHostName:  hostName,
		WAFEnabled:     host.WAFEnabled,
		WAFMode:        host.WAFMode,
		Exclusions:     exclusions,
		ExclusionCount: len(exclusions),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// DisableRule disables a WAF rule for a specific proxy host
func (h *WAFHandler) DisableRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /api/v1/waf/hosts/{hostId}/rules/{ruleId}/disable
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/v1/waf/hosts/")
	path = strings.TrimPrefix(path, "/api/waf/hosts/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	proxyHostID := parts[0]
	ruleIDStr := parts[2]

	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	// Parse request body for additional info
	var req model.CreateWAFRuleExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body, just use the rule ID from path
		req = model.CreateWAFRuleExclusionRequest{}
	}
	req.RuleID = ruleID

	// Check if already excluded
	existing, err := h.wafRepo.GetExclusionByRuleID(ctx, proxyHostID, ruleID)
	if err != nil {
		httpDatabaseError(w, "check WAF exclusion", err)
		return
	}
	if existing != nil {
		http.Error(w, "Rule already disabled", http.StatusConflict)
		return
	}

	// Create the exclusion
	exclusion, err := h.wafRepo.CreateExclusion(ctx, proxyHostID, &req)
	if err != nil {
		httpDatabaseError(w, "create WAF exclusion", err)
		return
	}

	// Record policy history
	history := &model.WAFPolicyHistory{
		ProxyHostID:     proxyHostID,
		RuleID:          ruleID,
		RuleCategory:    req.RuleCategory,
		RuleDescription: req.RuleDescription,
		Action:          "disabled",
		Reason:          req.Reason,
	}
	h.wafRepo.CreatePolicyHistory(ctx, history)

	// Regenerate nginx config for this host
	if err := h.regenerateHostConfig(ctx, proxyHostID); err != nil {
		// Log but don't fail - the exclusion is saved
		log.Printf("[WAF] Failed to regenerate nginx config for host %s: %v", proxyHostID, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(exclusion)
}

// DisableRuleByHost disables a WAF rule for a proxy host identified by domain name
func (h *WAFHandler) DisableRuleByHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req struct {
		Host            string `json:"host"`
		RuleID          int    `json:"rule_id"`
		RuleCategory    string `json:"rule_category,omitempty"`
		RuleDescription string `json:"rule_description,omitempty"`
		Reason          string `json:"reason,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Host == "" {
		http.Error(w, "Host is required", http.StatusBadRequest)
		return
	}
	if req.RuleID == 0 {
		http.Error(w, "Rule ID is required", http.StatusBadRequest)
		return
	}

	// Strip port suffix from host (e.g. "example.com:443" → "example.com")
	hostLookup := req.Host
	if h, _, err := net.SplitHostPort(hostLookup); err == nil {
		hostLookup = h
	}

	// Look up proxy host by domain name
	host, err := h.proxyHostRepo.GetByDomain(ctx, hostLookup)
	if err != nil {
		httpDatabaseError(w, "lookup proxy host by domain", err)
		return
	}
	if host == nil {
		http.Error(w, "Proxy host not found for domain", http.StatusNotFound)
		return
	}

	proxyHostID := host.ID

	// Check if already excluded
	existing, err := h.wafRepo.GetExclusionByRuleID(ctx, proxyHostID, req.RuleID)
	if err != nil {
		httpDatabaseError(w, "check WAF exclusion", err)
		return
	}
	if existing != nil {
		http.Error(w, "Rule already disabled for this host", http.StatusConflict)
		return
	}

	// Create the exclusion request
	exclusionReq := &model.CreateWAFRuleExclusionRequest{
		RuleID:          req.RuleID,
		RuleCategory:    req.RuleCategory,
		RuleDescription: req.RuleDescription,
		Reason:          req.Reason,
	}

	// Create the exclusion
	exclusion, err := h.wafRepo.CreateExclusion(ctx, proxyHostID, exclusionReq)
	if err != nil {
		httpDatabaseError(w, "create WAF exclusion", err)
		return
	}

	// Record policy history
	history := &model.WAFPolicyHistory{
		ProxyHostID:     proxyHostID,
		RuleID:          req.RuleID,
		RuleCategory:    req.RuleCategory,
		RuleDescription: req.RuleDescription,
		Action:          "disabled",
		Reason:          req.Reason,
	}
	h.wafRepo.CreatePolicyHistory(ctx, history)

	// Regenerate nginx config for this host
	if err := h.regenerateHostConfig(ctx, proxyHostID); err != nil {
		// Log but don't fail - the exclusion is saved
		log.Printf("[WAF] Failed to regenerate nginx config for host %s (via DisableRuleByHost): %v", proxyHostID, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(exclusion)
}

// EnableRule enables a WAF rule for a specific proxy host (removes exclusion)
func (h *WAFHandler) EnableRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /api/v1/waf/hosts/{hostId}/rules/{ruleId}/disable
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/v1/waf/hosts/")
	path = strings.TrimPrefix(path, "/api/waf/hosts/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	proxyHostID := parts[0]
	ruleIDStr := parts[2]

	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	// Get exclusion info before deleting (for history)
	exclusion, _ := h.wafRepo.GetExclusionByRuleID(ctx, proxyHostID, ruleID)

	// Delete the exclusion
	err = h.wafRepo.DeleteExclusion(ctx, proxyHostID, ruleID)
	if err != nil {
		httpDatabaseError(w, "delete WAF exclusion", err)
		return
	}

	// Record policy history
	history := &model.WAFPolicyHistory{
		ProxyHostID: proxyHostID,
		RuleID:      ruleID,
		Action:      "enabled",
	}
	if exclusion != nil {
		history.RuleCategory = exclusion.RuleCategory
		history.RuleDescription = exclusion.RuleDescription
	}
	h.wafRepo.CreatePolicyHistory(ctx, history)

	// Regenerate nginx config for this host
	if err := h.regenerateHostConfig(ctx, proxyHostID); err != nil {
		// Log but don't fail
		log.Printf("[WAF] Failed to regenerate nginx config for host %s (via EnableRule): %v", proxyHostID, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetPolicyHistory returns the policy change history for a proxy host
func (h *WAFHandler) GetPolicyHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /api/v1/waf/hosts/{hostId}/history
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/v1/waf/hosts/")
	path = strings.TrimPrefix(path, "/api/waf/hosts/")
	proxyHostID := strings.TrimSuffix(path, "/history")

	// Get limit from query params (default 100)
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Get history
	history, err := h.wafRepo.GetPolicyHistory(ctx, proxyHostID, limit)
	if err != nil {
		httpDatabaseError(w, "get WAF policy history", err)
		return
	}

	// Get total count
	total, err := h.wafRepo.CountPolicyHistory(ctx, proxyHostID)
	if err != nil {
		httpDatabaseError(w, "count WAF policy history", err)
		return
	}

	response := model.WAFPolicyHistoryResponse{
		History: history,
		Total:   total,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// regenerateHostConfig regenerates the WAF config for a proxy host.
// This only updates the WAF exclusion config and reloads nginx (faster than full config regeneration).
func (h *WAFHandler) regenerateHostConfig(ctx context.Context, proxyHostID string) error {
	host, err := h.proxyHostRepo.GetByID(ctx, proxyHostID)
	if err != nil || host == nil {
		return err
	}

	// Get host-specific exclusions
	hostExclusions, err := h.wafRepo.GetExclusionsByProxyHost(ctx, proxyHostID)
	if err != nil {
		return err
	}

	// Get global exclusions and merge
	globalExclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		return err
	}

	// Merge global + host exclusions
	mergedExclusions := h.mergeExclusions(globalExclusions, hostExclusions)

	// Get Priority Allow IPs for WAF bypass
	var allowedIPs []string
	if h.geoRepo != nil {
		geo, err := h.geoRepo.GetByProxyHostID(ctx, proxyHostID)
		if err == nil && geo != nil {
			allowedIPs = geo.AllowedIPs
		}
	}

	// Generate per-host WAF config only (not full proxy config)
	if err := h.nginxManager.GenerateHostWAFConfig(ctx, host, mergedExclusions, allowedIPs); err != nil {
		return err
	}

	// Test and reload nginx
	if err := h.nginxManager.TestConfig(ctx); err != nil {
		return err
	}

	return h.nginxManager.ReloadNginx(ctx)
}
