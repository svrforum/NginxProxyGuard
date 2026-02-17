package handler

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"nginx-proxy-guard/internal/model"
)

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

// RuleParseOptions configures which exclusion data to use when parsing rules.
// Nil maps are safe — Go returns zero values on nil map reads.
type RuleParseOptions struct {
	HostExcludedRules   map[int]bool
	HostExclusionMap    map[int]*model.WAFRuleExclusion
	GlobalExcludedRules map[int]bool
	GlobalExclusionMap  map[int]*model.GlobalWAFRuleExclusion
}

// parseAllRules parses OWASP CRS rule files with the given exclusion options
func (h *WAFHandler) parseAllRules(opts RuleParseOptions) ([]model.WAFRuleCategory, error) {
	rulesDir := filepath.Join(h.crsPath, "rules")

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	ruleIDRegex := regexp.MustCompile(`(?i)id[:\s]*['"]?(\d{6})`)
	msgRegex := regexp.MustCompile(`msg:'([^']+)'|msg:"([^"]+)"`)
	catIDRegex := regexp.MustCompile(`(\d{3})-`)

	var categories []model.WAFRuleCategory
	categoryMap := make(map[string]*model.WAFRuleCategory)

	// Parse ModSecurity internal rules from modsec-base.conf
	modsecBasePath := "/etc/nginx/modsec/modsec-base.conf"
	if internalRules, err := parseRulesFromFile(modsecBasePath, ruleIDRegex, msgRegex, opts); err == nil && len(internalRules) > 0 {
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

		catMatch := catIDRegex.FindStringSubmatch(entry.Name())
		if catMatch == nil {
			continue
		}
		catID := catMatch[1]

		catInfo, ok := ruleCategories[catID]
		if !ok {
			continue
		}

		filePath := filepath.Join(rulesDir, entry.Name())
		rules, err := parseRulesFromFile(filePath, ruleIDRegex, msgRegex, opts)
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

// parseRulesFromFile parses a single CRS rule file with the given exclusion options
func parseRulesFromFile(filePath string, ruleIDRegex, msgRegex *regexp.Regexp, opts RuleParseOptions) ([]model.WAFRule, error) {
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

		// Rule is disabled if either globally or host-specifically disabled
		isDisabled := opts.HostExcludedRules[ruleID] || opts.GlobalExcludedRules[ruleID]

		rule := model.WAFRule{
			ID:               ruleID,
			Category:         categoryName,
			Description:      description,
			Enabled:          !isDisabled,
			GloballyDisabled: opts.GlobalExcludedRules[ruleID],
		}

		// Add host-specific exclusion details
		if ex, ok := opts.HostExclusionMap[ruleID]; ok {
			rule.Exclusion = ex
		}

		// Add global exclusion details
		if gex, ok := opts.GlobalExclusionMap[ruleID]; ok {
			rule.GlobalExclusion = gex
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// generateDefaultDescription generates a default description for rules without msg field
func generateDefaultDescription(ruleID int, line string, categoryName string) string {
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

	if categoryName != "" {
		return categoryName + " detection rule"
	}

	return "ModSecurity rule"
}
