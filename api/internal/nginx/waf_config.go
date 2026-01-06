package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"nginx-proxy-guard/internal/model"
)

// Per-host WAF config template
const hostWAFTemplate = `# nginx-guard per-host WAF configuration
# Host ID: {{.Host.ID}}
# Mode: {{.Mode}}
# Paranoia Level: {{.ParanoiaLevel}}
# Anomaly Threshold: {{.AnomalyThreshold}}
# Exclusions: {{len .Exclusions}}
# Generated at: {{now}}

# Include base ModSecurity configuration
Include /etc/nginx/modsec/modsec-base.conf

# Include OWASP CRS setup
Include /etc/nginx/owasp-crs/crs-setup.conf

# =============================================================================
# Per-host CRS tuning (must be set BEFORE CRS rules are loaded)
# =============================================================================

# Set Paranoia Level (1-4)
# PL1: Minimal false positives (recommended)
# PL2: Medium, for security-sensitive sites
# PL3: High, for financial/healthcare
# PL4: Extreme, experts only
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level={{.ParanoiaLevel}}"

# Set Anomaly Score Threshold
# Lower = stricter (more blocking), Higher = looser (more permissive)
# Default: 5, Permissive: 10+, Strict: 3
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold={{.AnomalyThreshold}},setvar:tx.outbound_anomaly_score_threshold={{.AnomalyThreshold}}"

# Include OWASP CRS rules
Include /etc/nginx/owasp-crs/rules/*.conf

# Custom nginx-guard rules (without ruleEngine overrides)
Include /etc/nginx/modsec/custom-rules.conf

{{if .Exclusions}}
# Per-host rule exclusions
# SecRuleRemoveById completely disables the rule (no matching, no scoring, no logging)
# Note: Excluded rules won't appear in WAF logs since they're completely disabled
{{range .Exclusions}}
# Rule {{.RuleID}}: {{.RuleDescription}} ({{.RuleCategory}})
# Reason: {{.Reason}}
SecRuleRemoveById {{.RuleID}}
{{end}}
{{end}}

# Set WAF mode LAST to ensure it takes precedence
SecRuleEngine {{.Mode}}
`

// hostWAFConfigData holds data for the WAF config template
type hostWAFConfigData struct {
	Host             *model.ProxyHost
	Mode             string
	ParanoiaLevel    int
	AnomalyThreshold int
	Exclusions       []model.WAFRuleExclusion
}

// GenerateHostWAFConfig generates a per-host ModSecurity configuration file
// that includes the appropriate rule engine mode and any rule exclusions
func (m *Manager) GenerateHostWAFConfig(ctx context.Context, host *model.ProxyHost, exclusions []model.WAFRuleExclusion) error {
	// Determine WAF mode
	mode := "On" // blocking mode (default)
	if host.WAFMode == "detection" {
		mode = "DetectionOnly"
	}

	// Get paranoia level with default
	paranoiaLevel := host.WAFParanoiaLevel
	if paranoiaLevel < 1 || paranoiaLevel > 4 {
		paranoiaLevel = 1 // Default to PL1
	}

	// Get anomaly threshold with default
	anomalyThreshold := host.WAFAnomalyThreshold
	if anomalyThreshold < 1 {
		anomalyThreshold = 5 // Default threshold
	}

	// Prepare template data
	data := hostWAFConfigData{
		Host:             host,
		Mode:             mode,
		ParanoiaLevel:    paranoiaLevel,
		AnomalyThreshold: anomalyThreshold,
		Exclusions:       exclusions,
	}

	funcMap := GetSimpleTemplateFuncMap()

	tmpl, err := template.New("host_waf").Funcs(funcMap).Parse(hostWAFTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse WAF template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute WAF template: %w", err)
	}

	// Write config file atomically
	configFile := filepath.Join(m.modsecPath, fmt.Sprintf("host_%s.conf", host.ID))
	if err := m.writeFileAtomic(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write WAF config file: %w", err)
	}

	return nil
}

// RemoveHostWAFConfig removes the per-host WAF configuration file
func (m *Manager) RemoveHostWAFConfig(ctx context.Context, hostID string) error {
	configFile := filepath.Join(m.modsecPath, fmt.Sprintf("host_%s.conf", hostID))

	// Check if file exists before removing
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to remove
	}

	if err := os.Remove(configFile); err != nil {
		return fmt.Errorf("failed to remove WAF config file: %w", err)
	}

	return nil
}
