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
// CRS rules are loaded globally in crs-global.conf (http block).
// This per-host config only contains tuning overrides that merge with the global rules.
const hostWAFTemplate = `# nginx-guard per-host WAF configuration (tuning only)
# Host ID: {{.Host.ID}}
# Mode: {{.Mode}}
# Paranoia Level: {{.ParanoiaLevel}}
# Anomaly Threshold: {{.AnomalyThreshold}}
# Exclusions: {{len .Exclusions}}
# Priority Allow IPs: {{len .AllowedIPs}}
# Generated at: {{now}}
#
# NOTE: CRS rules are loaded globally in /etc/nginx/modsec/crs-global.conf
# This file contains only per-host tuning that merges with the global rules.

# =============================================================================
# Per-host CRS tuning overrides
# =============================================================================

# Set Paranoia Level (1-4)
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level={{.ParanoiaLevel}}"

# Set Anomaly Score Threshold
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold={{.AnomalyThreshold}},setvar:tx.outbound_anomaly_score_threshold={{.AnomalyThreshold}}"

{{if .AllowedIPs}}
# Priority Allow IPs - Bypass WAF completely for these IPs
SecRule REMOTE_ADDR "@ipMatch {{joinComma .AllowedIPs}}" "id:900900,phase:1,pass,nolog,ctl:ruleEngine=Off"
{{end}}

{{if .Exclusions}}
# Per-host rule exclusions
{{range $i, $e := .Exclusions}}
# Rule {{$e.RuleID}}: {{$e.RuleDescription}} ({{$e.RuleCategory}})
# Reason: {{$e.Reason}}
{{- if eq $e.ScopeType "uri"}}
# Scoped to {{$e.ScopeValue}} — the rule keeps protecting every other path.
SecRule REQUEST_URI "@beginsWith {{$e.ScopeValue}}" "id:{{scopedRuleID $i}},phase:1,pass,nolog,ctl:ruleRemoveById={{$e.RuleID}}"
{{- else if eq $e.ScopeType "param"}}
# Scoped to the {{$e.ScopeValue}} argument — the rule still inspects everything else.
SecRuleUpdateTargetById {{$e.RuleID}} "!ARGS:{{$e.ScopeValue}}"
{{- else}}
SecRuleRemoveById {{$e.RuleID}}
{{- end}}
{{end}}
{{end}}

# Set WAF mode (overrides global SecRuleEngine Off)
SecRuleEngine {{.Mode}}
`

// hostWAFConfigData holds data for the WAF config template
type hostWAFConfigData struct {
	Host             *model.ProxyHost
	Mode             string
	ParanoiaLevel    int
	AnomalyThreshold int
	Exclusions       []model.WAFRuleExclusion
	AllowedIPs       []string // Priority Allow IPs that bypass WAF
}

// GenerateHostWAFConfig generates a per-host ModSecurity configuration file
// that includes the appropriate rule engine mode and any rule exclusions
// allowedIPs are Priority Allow IPs from GeoRestriction that bypass WAF completely
func (m *Manager) GenerateHostWAFConfig(ctx context.Context, host *model.ProxyHost, exclusions []model.WAFRuleExclusion, allowedIPs []string) error {
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
		AllowedIPs:       allowedIPs,
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
