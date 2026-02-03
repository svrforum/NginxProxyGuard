package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// getUsernameFromContext extracts username from request context
// When using echo.WrapHandler, username may be stored in context by auth middleware
func getUsernameFromContext(ctx context.Context) string {
	if username, ok := ctx.Value("username").(string); ok && username != "" {
		return username
	}
	return "admin" // Fallback for system actions
}

// WAF Rule Categories mapping
var ruleCategories = map[string]struct {
	Name        string
	Description string
}{
	// ModSecurity internal rules (200xxx)
	"200": {Name: "MODSEC-INTERNAL", Description: "ModSecurity Internal Rules"},
	// OWASP CRS rules
	"911": {Name: "METHOD", Description: "HTTP Method Enforcement"},
	"913": {Name: "SCANNER", Description: "Scanner Detection"},
	"920": {Name: "PROTOCOL", Description: "Protocol Enforcement"},
	"921": {Name: "PROTOCOL-ATTACK", Description: "Protocol Attack"},
	"922": {Name: "MULTIPART", Description: "Multipart Attack"},
	"930": {Name: "LFI", Description: "Local File Inclusion"},
	"931": {Name: "RFI", Description: "Remote File Inclusion"},
	"932": {Name: "RCE", Description: "Remote Code Execution"},
	"933": {Name: "PHP", Description: "PHP Injection Attack"},
	"934": {Name: "GENERIC", Description: "Generic Application Attack"},
	"941": {Name: "XSS", Description: "Cross-Site Scripting"},
	"942": {Name: "SQLI", Description: "SQL Injection"},
	"943": {Name: "SESSION", Description: "Session Fixation"},
	"944": {Name: "JAVA", Description: "Java Application Attack"},
	"950": {Name: "DATA-LEAK", Description: "Data Leakage"},
	"951": {Name: "DATA-LEAK-SQL", Description: "SQL Data Leakage"},
	"952": {Name: "DATA-LEAK-JAVA", Description: "Java Data Leakage"},
	"953": {Name: "DATA-LEAK-PHP", Description: "PHP Data Leakage"},
	"954": {Name: "DATA-LEAK-IIS", Description: "IIS Data Leakage"},
	"955": {Name: "WEB-SHELL", Description: "Web Shell Detection"},
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
	categories, err := h.parseRulesFromFilesWithBothExclusions(excludedRules, exclusionMap, globalExcludedRules, globalExclusionMap)
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

	// Look up proxy host by domain name
	host, err := h.proxyHostRepo.GetByDomain(ctx, req.Host)
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

// regenerateHostConfig regenerates the WAF config for a proxy host
// This only updates the WAF exclusion config and reloads nginx (faster than full config regeneration)
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

// parseRulesFromFiles parses OWASP CRS rule files and extracts rule information
func (h *WAFHandler) parseRulesFromFiles(excludedRules map[int]bool, exclusionMap map[int]*model.WAFRuleExclusion) ([]model.WAFRuleCategory, error) {
	rulesDir := filepath.Join(h.crsPath, "rules")

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	// Regex to match rule definition: SecRule ... "id:941100, ..." or "id:200004, ..."
	ruleIDRegex := regexp.MustCompile(`(?i)id[:\s]*['"]?(\d{6})`)
	// Regex to match rule message: msg:'...' or msg:"..."
	// CRS uses format like: msg:'Some Message Here',
	msgRegex := regexp.MustCompile(`msg:'([^']+)'|msg:"([^"]+)"`)

	var categories []model.WAFRuleCategory
	categoryMap := make(map[string]*model.WAFRuleCategory)

	// First, parse ModSecurity internal rules from modsec-base.conf
	modsecBasePath := "/etc/nginx/modsec/modsec-base.conf"
	if internalRules, err := h.parseRulesFromFile(modsecBasePath, ruleIDRegex, msgRegex, excludedRules, exclusionMap); err == nil && len(internalRules) > 0 {
		catInfo := ruleCategories["200"]
		category := model.WAFRuleCategory{
			ID:          "200",
			Name:        catInfo.Name,
			Description: catInfo.Description,
			FileName:    "modsec-base.conf",
			RuleCount:   len(internalRules),
			Rules:       internalRules,
		}
		categoryMap["200"] = &category
	}

	// Parse OWASP CRS rule files
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		// Skip example files
		if strings.Contains(entry.Name(), ".example") {
			continue
		}

		// Parse category from filename (e.g., REQUEST-941-APPLICATION-ATTACK-XSS.conf)
		catMatch := regexp.MustCompile(`(\d{3})-`).FindStringSubmatch(entry.Name())
		if catMatch == nil {
			continue
		}
		catID := catMatch[1]

		catInfo, ok := ruleCategories[catID]
		if !ok {
			continue
		}

		filePath := filepath.Join(rulesDir, entry.Name())
		rules, err := h.parseRulesFromFile(filePath, ruleIDRegex, msgRegex, excludedRules, exclusionMap)
		if err != nil {
			continue
		}

		if len(rules) > 0 {
			category := model.WAFRuleCategory{
				ID:          catID,
				Name:        catInfo.Name,
				Description: catInfo.Description,
				FileName:    entry.Name(),
				RuleCount:   len(rules),
				Rules:       rules,
			}
			categoryMap[catID] = &category
		}
	}

	// Convert map to slice
	for _, cat := range categoryMap {
		categories = append(categories, *cat)
	}

	// Sort categories by ID
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].ID < categories[j].ID
	})

	return categories, nil
}

// parseRulesFromFile parses a single CRS rule file
func (h *WAFHandler) parseRulesFromFile(filePath string, ruleIDRegex, msgRegex *regexp.Regexp, excludedRules map[int]bool, exclusionMap map[int]*model.WAFRuleExclusion) ([]model.WAFRule, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []model.WAFRule
	seenIDs := make(map[int]bool)

	// Split content into rule blocks (SecRule/SecAction sections)
	// CRS rules often span multiple lines with backslash continuation
	fileContent := string(content)

	// Remove line continuation (backslash followed by newline)
	fileContent = strings.ReplaceAll(fileContent, "\\\n", " ")
	fileContent = strings.ReplaceAll(fileContent, "\\\r\n", " ")

	// Split by SecRule/SecAction to get individual rule blocks
	lines := strings.Split(fileContent, "\n")

	for _, line := range lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// Find rule ID
		idMatch := ruleIDRegex.FindStringSubmatch(line)
		if idMatch == nil {
			continue
		}

		ruleID, err := strconv.Atoi(idMatch[1])
		if err != nil {
			continue
		}

		// Skip duplicates
		if seenIDs[ruleID] {
			continue
		}
		seenIDs[ruleID] = true

		// Extract message - now the whole rule is on one line after removing continuations
		description := ""
		msgMatch := msgRegex.FindStringSubmatch(line)
		if msgMatch != nil {
			// Check both capture groups (single quote and double quote)
			if msgMatch[1] != "" {
				description = msgMatch[1]
			} else if msgMatch[2] != "" {
				description = msgMatch[2]
			}
		}

		// Determine category from rule ID (first 3 digits)
		categoryID := strconv.Itoa(ruleID / 1000)
		categoryName := ""
		if catInfo, ok := ruleCategories[categoryID]; ok {
			categoryName = catInfo.Name
		}

		// Generate default description for control rules without msg
		if description == "" {
			description = generateDefaultDescription(ruleID, line, categoryName)
		}

		rule := model.WAFRule{
			ID:          ruleID,
			Category:    categoryName,
			Description: description,
			Enabled:     !excludedRules[ruleID],
		}

		// Add exclusion details if rule is disabled
		if exclusion, ok := exclusionMap[ruleID]; ok {
			rule.Exclusion = exclusion
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// generateDefaultDescription generates a default description for rules without msg field
func generateDefaultDescription(ruleID int, line string, categoryName string) string {
	// Check for common control rule patterns
	if strings.Contains(line, "skipAfter:") {
		return "Paranoia level control rule (skip to end)"
	}
	if strings.Contains(line, "skipAfter") || strings.Contains(line, "SKIP") {
		return "Control rule (skip condition)"
	}
	if strings.Contains(line, "setvar:") && !strings.Contains(line, "anomaly") {
		return "Variable initialization rule"
	}
	if strings.Contains(line, "SecMarker") {
		return "Section marker"
	}
	if strings.Contains(line, "nolog") && strings.Contains(line, "pass") {
		return "Paranoia level gate rule"
	}
	if strings.Contains(line, "chain") {
		return "Chained rule (part of multi-condition check)"
	}

	// Generate based on category
	if categoryName != "" {
		return categoryName + " detection rule"
	}

	return "ModSecurity rule"
}

// ============================================================================
// Global WAF Rule Management
// ============================================================================

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
	categories, err := h.parseRulesWithGlobalExclusions(globalExcludedRules, globalExclusionMap)
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

// mergeExclusions merges global and host-specific exclusions
// Global exclusions are converted to WAFRuleExclusion format
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

// parseRulesWithGlobalExclusions parses rules with global exclusion info
func (h *WAFHandler) parseRulesWithGlobalExclusions(globalExcludedRules map[int]bool, globalExclusionMap map[int]*model.GlobalWAFRuleExclusion) ([]model.WAFRuleCategory, error) {
	rulesDir := filepath.Join(h.crsPath, "rules")

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	ruleIDRegex := regexp.MustCompile(`(?i)id[:\s]*['"]?(\d{6})`)
	msgRegex := regexp.MustCompile(`msg:'([^']+)'|msg:"([^"]+)"`)

	var categories []model.WAFRuleCategory
	categoryMap := make(map[string]*model.WAFRuleCategory)

	// Parse ModSecurity internal rules
	modsecBasePath := "/etc/nginx/modsec/modsec-base.conf"
	if internalRules, err := h.parseRulesFromFileWithGlobal(modsecBasePath, ruleIDRegex, msgRegex, globalExcludedRules, globalExclusionMap); err == nil && len(internalRules) > 0 {
		catInfo := ruleCategories["200"]
		category := model.WAFRuleCategory{
			ID:          "200",
			Name:        catInfo.Name,
			Description: catInfo.Description,
			FileName:    "modsec-base.conf",
			RuleCount:   len(internalRules),
			Rules:       internalRules,
		}
		categoryMap["200"] = &category
	}

	// Parse OWASP CRS rule files
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		if strings.Contains(entry.Name(), ".example") {
			continue
		}

		catMatch := regexp.MustCompile(`(\d{3})-`).FindStringSubmatch(entry.Name())
		if catMatch == nil {
			continue
		}
		catID := catMatch[1]

		catInfo, ok := ruleCategories[catID]
		if !ok {
			continue
		}

		filePath := filepath.Join(rulesDir, entry.Name())
		rules, err := h.parseRulesFromFileWithGlobal(filePath, ruleIDRegex, msgRegex, globalExcludedRules, globalExclusionMap)
		if err != nil {
			continue
		}

		if len(rules) > 0 {
			category := model.WAFRuleCategory{
				ID:          catID,
				Name:        catInfo.Name,
				Description: catInfo.Description,
				FileName:    entry.Name(),
				RuleCount:   len(rules),
				Rules:       rules,
			}
			categoryMap[catID] = &category
		}
	}

	for _, cat := range categoryMap {
		categories = append(categories, *cat)
	}

	sort.Slice(categories, func(i, j int) bool {
		return categories[i].ID < categories[j].ID
	})

	return categories, nil
}

// parseRulesFromFilesWithBothExclusions parses rules with both host-specific and global exclusion info
func (h *WAFHandler) parseRulesFromFilesWithBothExclusions(excludedRules map[int]bool, exclusionMap map[int]*model.WAFRuleExclusion, globalExcludedRules map[int]bool, globalExclusionMap map[int]*model.GlobalWAFRuleExclusion) ([]model.WAFRuleCategory, error) {
	rulesDir := filepath.Join(h.crsPath, "rules")

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	ruleIDRegex := regexp.MustCompile(`(?i)id[:\s]*['"]?(\d{6})`)
	msgRegex := regexp.MustCompile(`msg:'([^']+)'|msg:"([^"]+)"`)

	var categories []model.WAFRuleCategory
	categoryMap := make(map[string]*model.WAFRuleCategory)

	// Parse ModSecurity internal rules
	modsecBasePath := "/etc/nginx/modsec/modsec-base.conf"
	if internalRules, err := h.parseRulesFromFileWithBoth(modsecBasePath, ruleIDRegex, msgRegex, excludedRules, exclusionMap, globalExcludedRules, globalExclusionMap); err == nil && len(internalRules) > 0 {
		catInfo := ruleCategories["200"]
		category := model.WAFRuleCategory{
			ID:          "200",
			Name:        catInfo.Name,
			Description: catInfo.Description,
			FileName:    "modsec-base.conf",
			RuleCount:   len(internalRules),
			Rules:       internalRules,
		}
		categoryMap["200"] = &category
	}

	// Parse OWASP CRS rule files
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		if strings.Contains(entry.Name(), ".example") {
			continue
		}

		catMatch := regexp.MustCompile(`(\d{3})-`).FindStringSubmatch(entry.Name())
		if catMatch == nil {
			continue
		}
		catID := catMatch[1]

		catInfo, ok := ruleCategories[catID]
		if !ok {
			continue
		}

		filePath := filepath.Join(rulesDir, entry.Name())
		rules, err := h.parseRulesFromFileWithBoth(filePath, ruleIDRegex, msgRegex, excludedRules, exclusionMap, globalExcludedRules, globalExclusionMap)
		if err != nil {
			continue
		}

		if len(rules) > 0 {
			category := model.WAFRuleCategory{
				ID:          catID,
				Name:        catInfo.Name,
				Description: catInfo.Description,
				FileName:    entry.Name(),
				RuleCount:   len(rules),
				Rules:       rules,
			}
			categoryMap[catID] = &category
		}
	}

	for _, cat := range categoryMap {
		categories = append(categories, *cat)
	}

	sort.Slice(categories, func(i, j int) bool {
		return categories[i].ID < categories[j].ID
	})

	return categories, nil
}

// parseRulesFromFileWithBoth parses a rule file with both host-specific and global exclusion info
func (h *WAFHandler) parseRulesFromFileWithBoth(filePath string, ruleIDRegex, msgRegex *regexp.Regexp, excludedRules map[int]bool, exclusionMap map[int]*model.WAFRuleExclusion, globalExcludedRules map[int]bool, globalExclusionMap map[int]*model.GlobalWAFRuleExclusion) ([]model.WAFRule, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []model.WAFRule
	seenIDs := make(map[int]bool)

	fileContent := string(content)
	fileContent = strings.ReplaceAll(fileContent, "\\\n", " ")
	fileContent = strings.ReplaceAll(fileContent, "\\\r\n", " ")

	lines := strings.Split(fileContent, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		idMatch := ruleIDRegex.FindStringSubmatch(line)
		if idMatch == nil {
			continue
		}

		ruleID, err := strconv.Atoi(idMatch[1])
		if err != nil {
			continue
		}

		if seenIDs[ruleID] {
			continue
		}
		seenIDs[ruleID] = true

		description := ""
		msgMatch := msgRegex.FindStringSubmatch(line)
		if msgMatch != nil {
			if msgMatch[1] != "" {
				description = msgMatch[1]
			} else if msgMatch[2] != "" {
				description = msgMatch[2]
			}
		}

		categoryID := strconv.Itoa(ruleID / 1000)
		categoryName := ""
		if catInfo, ok := ruleCategories[categoryID]; ok {
			categoryName = catInfo.Name
		}

		if description == "" {
			description = generateDefaultDescription(ruleID, line, categoryName)
		}

		// Rule is disabled if either globally disabled or host-specifically disabled
		isDisabled := excludedRules[ruleID] || globalExcludedRules[ruleID]

		rule := model.WAFRule{
			ID:               ruleID,
			Category:         categoryName,
			Description:      description,
			Enabled:          !isDisabled,
			GloballyDisabled: globalExcludedRules[ruleID],
		}

		// Add host-specific exclusion details
		if ex, ok := exclusionMap[ruleID]; ok {
			rule.Exclusion = ex
		}

		// Add global exclusion details
		if gex, ok := globalExclusionMap[ruleID]; ok {
			rule.GlobalExclusion = gex
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRulesFromFileWithGlobal parses a rule file with global exclusion info
func (h *WAFHandler) parseRulesFromFileWithGlobal(filePath string, ruleIDRegex, msgRegex *regexp.Regexp, globalExcludedRules map[int]bool, globalExclusionMap map[int]*model.GlobalWAFRuleExclusion) ([]model.WAFRule, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []model.WAFRule
	seenIDs := make(map[int]bool)

	fileContent := string(content)
	fileContent = strings.ReplaceAll(fileContent, "\\\n", " ")
	fileContent = strings.ReplaceAll(fileContent, "\\\r\n", " ")

	lines := strings.Split(fileContent, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		idMatch := ruleIDRegex.FindStringSubmatch(line)
		if idMatch == nil {
			continue
		}

		ruleID, err := strconv.Atoi(idMatch[1])
		if err != nil {
			continue
		}

		if seenIDs[ruleID] {
			continue
		}
		seenIDs[ruleID] = true

		description := ""
		msgMatch := msgRegex.FindStringSubmatch(line)
		if msgMatch != nil {
			if msgMatch[1] != "" {
				description = msgMatch[1]
			} else if msgMatch[2] != "" {
				description = msgMatch[2]
			}
		}

		categoryID := strconv.Itoa(ruleID / 1000)
		categoryName := ""
		if catInfo, ok := ruleCategories[categoryID]; ok {
			categoryName = catInfo.Name
		}

		if description == "" {
			description = generateDefaultDescription(ruleID, line, categoryName)
		}

		rule := model.WAFRule{
			ID:               ruleID,
			Category:         categoryName,
			Description:      description,
			Enabled:          !globalExcludedRules[ruleID],
			GloballyDisabled: globalExcludedRules[ruleID],
		}

		// Add global exclusion details if rule is globally disabled
		if gex, ok := globalExclusionMap[ruleID]; ok {
			rule.GlobalExclusion = gex
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
