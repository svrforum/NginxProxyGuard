package nginx

import (
	"fmt"
	"strings"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// GetTemplateFuncMap returns the common template function map used across all config generators
func GetTemplateFuncMap(apiHost string) template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
		"now": func() string {
			return "auto-generated"
		},
		"escapeNginxPattern": func(s string) string {
			// Normalize: first remove any existing escapes to handle already-escaped patterns
			s = strings.ReplaceAll(s, `\"`, `"`)
			// Then escape all double quotes for nginx double-quoted strings
			return strings.ReplaceAll(s, `"`, `\"`)
		},
		"certPath": func(h *model.ProxyHost) string {
			// Use certificate ID if available, otherwise fall back to proxy host ID
			if h.CertificateID != nil && *h.CertificateID != "" {
				return *h.CertificateID
			}
			return h.ID
		},
		"wafConfig": func(h *model.ProxyHost) string {
			// Return per-host WAF config file
			return fmt.Sprintf("host_%s.conf", h.ID)
		},
		"sanitizeID": func(id string) string {
			// Replace hyphens with underscores for nginx zone names
			return strings.ReplaceAll(id, "-", "_")
		},
		"toRegexPattern": func(s string) string {
			// Convert newline-separated patterns to pipe-separated regex pattern
			lines := strings.Split(s, "\n")
			var patterns []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if len(line) > 500 {
					line = line[:500]
				}
				// Escape special regex characters
				line = strings.ReplaceAll(line, "\\", "\\\\")
				line = strings.ReplaceAll(line, ".", "\\.")
				line = strings.ReplaceAll(line, "+", "\\+")
				line = strings.ReplaceAll(line, "?", "\\?")
				line = strings.ReplaceAll(line, "(", "\\(")
				line = strings.ReplaceAll(line, ")", "\\)")
				line = strings.ReplaceAll(line, "[", "\\[")
				line = strings.ReplaceAll(line, "]", "\\]")
				line = strings.ReplaceAll(line, "{", "\\{")
				line = strings.ReplaceAll(line, "}", "\\}")
				line = strings.ReplaceAll(line, "^", "\\^")
				line = strings.ReplaceAll(line, "$", "\\$")
				line = strings.ReplaceAll(line, "|", "\\|")
				line = strings.ReplaceAll(line, "*", ".*")
				line = strings.ReplaceAll(line, " ", "\\s")
				patterns = append(patterns, line)
			}
			if len(patterns) > 100 {
				patterns = patterns[:100]
			}
			return strings.Join(patterns, "|")
		},
		"apiHost": func() string {
			return apiHost
		},
		"len": func(s []string) int {
			return len(s)
		},
		"uriLocationDirective": func(matchType model.URIMatchType, pattern string) string {
			switch matchType {
			case model.URIMatchExact:
				return fmt.Sprintf("location = %s", pattern)
			case model.URIMatchPrefix:
				return fmt.Sprintf("location ^~ %s", pattern)
			case model.URIMatchRegex:
				return fmt.Sprintf("location ~* %s", pattern)
			default:
				return fmt.Sprintf("location ^~ %s", pattern)
			}
		},
		"hasURIBlockExceptionIPs": func(ub *model.URIBlock) bool {
			return ub != nil && (len(ub.ExceptionIPs) > 0 || ub.AllowPrivateIPs)
		},
		"escapeRegex": func(s string) string {
			s = strings.TrimSpace(s)
			if s == "" {
				return s
			}
			if strings.Contains(s, "/") {
				parts := strings.Split(s, "/")
				if len(parts) == 2 {
					ip := strings.ReplaceAll(parts[0], ".", "\\.")
					return ip + "/" + parts[1]
				}
			}
			return strings.ReplaceAll(s, ".", "\\.")
		},
		"isCIDR":             isCIDR,
		"cidrToNginxPattern": cidrToNginxPattern,
		"splitExceptions": func(s string) []string {
			if s == "" {
				return nil
			}
			lines := strings.Split(s, "\n")
			var patterns []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				patterns = append(patterns, line)
			}
			return patterns
		},
		"hasExceptions": func(s string) bool {
			if s == "" {
				return false
			}
			lines := strings.Split(s, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					return true
				}
			}
			return false
		},
		"mergeExceptions": func(global, host string) string {
			var patterns []string
			seen := make(map[string]bool)

			if global != "" {
				for _, line := range strings.Split(global, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
						patterns = append(patterns, line)
						seen[line] = true
					}
				}
			}

			if host != "" {
				for _, line := range strings.Split(host, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
						patterns = append(patterns, line)
						seen[line] = true
					}
				}
			}

			return strings.Join(patterns, "\n")
		},
		"hasMergedExceptions": func(global, host string) bool {
			if global != "" {
				for _, line := range strings.Split(global, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return true
					}
				}
			}
			if host != "" {
				for _, line := range strings.Split(host, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return true
					}
				}
			}
			return false
		},
		"filterRulesByPatternType": func(rules []model.ExploitBlockRule, patternType string) []model.ExploitBlockRule {
			var filtered []model.ExploitBlockRule
			for _, rule := range rules {
				if rule.PatternType == patternType {
					filtered = append(filtered, rule)
				}
			}
			return filtered
		},
		"hasExploitRules": func(rules []model.ExploitBlockRule) bool {
			return len(rules) > 0
		},
		"hasRulesOfType": func(rules []model.ExploitBlockRule, patternType string) bool {
			for _, rule := range rules {
				if rule.PatternType == patternType {
					return true
				}
			}
			return false
		},
	}
}

// GetRedirectTemplateFuncMap returns template functions for redirect host config
func GetRedirectTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
		"now": func() string {
			return "auto-generated"
		},
		"certPath": func(h *model.RedirectHost) string {
			if h.CertificateID != nil && *h.CertificateID != "" {
				return *h.CertificateID
			}
			return h.ID
		},
		"redirectReturn": func(h *model.RedirectHost) string {
			scheme := h.ForwardScheme
			if scheme == "auto" || scheme == "" {
				scheme = "$scheme"
			}
			target := fmt.Sprintf("%s://%s", scheme, h.ForwardDomainName)
			if h.ForwardPath != "" {
				target += h.ForwardPath
			}
			if h.PreservePath {
				target += "$request_uri"
			}
			return fmt.Sprintf("return %d %s;", h.RedirectCode, target)
		},
	}
}

// GetSimpleTemplateFuncMap returns a minimal template function map for simple templates
func GetSimpleTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"now": func() string {
			return "auto-generated"
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			case string:
				return len(val)
			case map[string]interface{}:
				return len(val)
			case []model.WAFRuleExclusion:
				return len(val)
			case []model.ExploitBlockRule:
				return len(val)
			default:
				return 0
			}
		},
		"joinComma": func(s []string) string {
			return strings.Join(s, ",")
		},
	}
}
