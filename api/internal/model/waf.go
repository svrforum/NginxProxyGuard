package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// WAFRuleExclusion represents a disabled WAF rule for a specific proxy host
type WAFRuleExclusion struct {
	ID              string    `json:"id"`
	ProxyHostID     string    `json:"proxy_host_id"`
	RuleID          int       `json:"rule_id"`
	RuleCategory    string    `json:"rule_category,omitempty"`
	RuleDescription string    `json:"rule_description,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	DisabledBy      string    `json:"disabled_by,omitempty"`
	// ScopeType narrows what the exclusion switches off. Turning a rule off for
	// a whole host is a blunt instrument — it opens the attack the rule exists
	// to stop on every other path — so an operator can instead name the path or
	// the argument that is producing the false positive. (#231)
	ScopeType       string    `json:"scope_type"`
	ScopeValue      string    `json:"scope_value,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// Exclusion scopes.
const (
	// WAFScopeHost switches the rule off everywhere on this host.
	WAFScopeHost = "host"
	// WAFScopeURI switches it off only for requests whose path starts with
	// ScopeValue. The rule keeps protecting every other path.
	WAFScopeURI = "uri"
	// WAFScopeParam keeps the rule but stops it inspecting one argument.
	WAFScopeParam = "param"
)

// maxScopeValue bounds a value that ends up inside a generated ModSecurity
// directive. Long enough for any real path or parameter name.
const maxScopeValue = 255

// ValidateScope checks an exclusion's scope before it can reach a config file.
//
// Every one of these values is interpolated into a ModSecurity directive, which
// makes it an injection vector in exactly the way a templated nginx field is:
// a quote or a newline would let an operator append their own directives, and
// "SecRuleEngine Off" is one line away. Rejected here rather than escaped,
// because no real path or parameter name needs any of these characters. (#231)
func (e *WAFRuleExclusion) ValidateScope() error {
	switch e.ScopeType {
	case "", WAFScopeHost:
		e.ScopeType = WAFScopeHost
		e.ScopeValue = ""
		return nil
	case WAFScopeURI, WAFScopeParam:
	default:
		return fmt.Errorf("invalid scope_type: must be host, uri or param")
	}

	v := strings.TrimSpace(e.ScopeValue)
	if v == "" {
		return fmt.Errorf("invalid scope_value: required when scope_type is %s", e.ScopeType)
	}
	if len(v) > maxScopeValue {
		return fmt.Errorf("invalid scope_value: must be %d characters or fewer", maxScopeValue)
	}
	for _, r := range v {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("invalid scope_value: only printable ASCII without spaces is allowed")
		}
	}
	if strings.ContainsAny(v, `"'\`+"`"+`;{}$|&<>`) {
		return fmt.Errorf("invalid scope_value: contains a character that is not allowed in a rule scope")
	}

	if e.ScopeType == WAFScopeURI {
		if !strings.HasPrefix(v, "/") {
			return fmt.Errorf("invalid scope_value: a uri scope must start with /")
		}
		// "/" prefixes every request, so a uri scope of "/" is a host-wide
		// disable wearing a scope — it would render as the widest possible
		// exemption while still reporting the rule as enabled. Normalise it to
		// what it actually is. Rejecting it instead would break the values
		// v2.37.0-v2.53.0 already stored, and the log viewer prefills exactly
		// this for a request blocked on the site root. (#286)
		if v == "/" {
			e.ScopeType, e.ScopeValue = WAFScopeHost, ""
			return nil
		}
	} else if !paramNamePattern.MatchString(v) {
		return fmt.Errorf("invalid scope_value: a param scope must be an argument name")
	}
	e.ScopeValue = v
	return nil
}

// paramNamePattern is what a request argument may be named. Deliberately
// narrower than what HTTP permits: anything outside this set in a real form
// field is rare enough that refusing it costs less than reasoning about how
// ModSecurity would parse it.
var paramNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]+$`)

// WAFRule represents an OWASP CRS rule
type WAFRule struct {
	ID               int                     `json:"id"`
	Category         string                  `json:"category"`
	Description      string                  `json:"description,omitempty"`
	Severity         string                  `json:"severity,omitempty"`
	Tags             []string                `json:"tags,omitempty"`
	Enabled          bool                    `json:"enabled"`                     // Whether this rule still applies to the host (a uri/param scope leaves it enabled)
	GloballyDisabled bool                    `json:"globally_disabled"`           // Whether this rule is disabled globally
	Exclusion        *WAFRuleExclusion       `json:"exclusion,omitempty"`         // The host-wide exclusion, if the rule is switched off for the whole host
	GlobalExclusion  *GlobalWAFRuleExclusion `json:"global_exclusion,omitempty"`  // Global exclusion details if rule is globally disabled
	// Exclusions carries every host exclusion on this rule, including the
	// narrow ones. A rule can be exempted on several paths at once, and
	// reporting only one of them hid the rest from the operator. (#286)
	Exclusions []WAFRuleExclusion `json:"exclusions,omitempty"`
}

// WAFRuleCategory represents a group of related WAF rules
type WAFRuleCategory struct {
	ID          string    `json:"id"`          // e.g., "941" for XSS
	Name        string    `json:"name"`        // e.g., "XSS"
	Description string    `json:"description"` // e.g., "Cross-Site Scripting Attack Detection"
	FileName    string    `json:"file_name"`   // e.g., "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
	RuleCount   int       `json:"rule_count"`
	Rules       []WAFRule `json:"rules,omitempty"`
}

// WAFHostConfig represents the WAF configuration for a specific host
type WAFHostConfig struct {
	ProxyHostID   string             `json:"proxy_host_id"`
	ProxyHostName string             `json:"proxy_host_name"` // First domain name
	WAFEnabled    bool               `json:"waf_enabled"`
	WAFMode       string             `json:"waf_mode"` // "blocking" or "detection"
	Exclusions    []WAFRuleExclusion `json:"exclusions"`
	ExclusionCount int               `json:"exclusion_count"`
}

// CreateWAFRuleExclusionRequest is the request to disable a rule for a host
type CreateWAFRuleExclusionRequest struct {
	RuleID          int    `json:"rule_id" validate:"required,min=100000,max=999999"`
	RuleCategory    string `json:"rule_category,omitempty"`
	RuleDescription string `json:"rule_description,omitempty"`
	Reason          string `json:"reason,omitempty"`
	// ScopeType/ScopeValue narrow the exclusion. Omitted means host — the
	// behaviour every existing client already gets. (#231)
	ScopeType  string `json:"scope_type,omitempty"`
	ScopeValue string `json:"scope_value,omitempty"`
}

// ValidateScope normalises and checks the scope on a create request, using the
// same rules as a stored exclusion, and bounds the rule id.
//
// The `validate:"min=100000,max=999999"` tag on RuleID is decorative — this repo
// has no struct validator — and RuleID is interpolated into the same generated
// directive the scope is. An out-of-range id renders a rule ModSecurity cannot
// load, which fails `nginx -t` and blocks every later reload. (#286)
func (r *CreateWAFRuleExclusionRequest) ValidateScope() error {
	if r.RuleID < minCRSRuleID || r.RuleID > maxCRSRuleID {
		return fmt.Errorf("invalid rule_id: must be between %d and %d", minCRSRuleID, maxCRSRuleID)
	}
	e := WAFRuleExclusion{ScopeType: r.ScopeType, ScopeValue: r.ScopeValue}
	if err := e.ValidateScope(); err != nil {
		return err
	}
	r.ScopeType, r.ScopeValue = e.ScopeType, e.ScopeValue
	return nil
}

// CRS rule ids are six digits. The generated per-host exclusions live at
// 1,000,000+ (see scopedRuleID), clear of this range.
const (
	minCRSRuleID = 100000
	maxCRSRuleID = 999999
)

// WAFRulesResponse is the response for listing WAF rules
type WAFRulesResponse struct {
	Categories []WAFRuleCategory `json:"categories"`
	TotalRules int               `json:"total_rules"`
}

// WAFHostConfigListResponse is the response for listing all hosts' WAF configs
type WAFHostConfigListResponse struct {
	Hosts []WAFHostConfig `json:"hosts"`
	Total int             `json:"total"`
}

// WAFPolicyHistory represents a WAF policy change record
type WAFPolicyHistory struct {
	ID              string    `json:"id"`
	ProxyHostID     string    `json:"proxy_host_id"`
	RuleID          int       `json:"rule_id"`
	RuleCategory    string    `json:"rule_category,omitempty"`
	RuleDescription string    `json:"rule_description,omitempty"`
	Action          string    `json:"action"` // "disabled" or "enabled"
	Reason          string    `json:"reason,omitempty"`
	ChangedBy       string    `json:"changed_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// WAFPolicyHistoryResponse is the response for listing policy history
type WAFPolicyHistoryResponse struct {
	History []WAFPolicyHistory `json:"history"`
	Total   int                `json:"total"`
}

// GlobalWAFRuleExclusion represents a globally disabled WAF rule (applies to all hosts)
type GlobalWAFRuleExclusion struct {
	ID              string    `json:"id"`
	RuleID          int       `json:"rule_id"`
	RuleCategory    string    `json:"rule_category,omitempty"`
	RuleDescription string    `json:"rule_description,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	DisabledBy      string    `json:"disabled_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// GlobalWAFPolicyHistory represents a global WAF policy change record
type GlobalWAFPolicyHistory struct {
	ID              string    `json:"id"`
	RuleID          int       `json:"rule_id"`
	RuleCategory    string    `json:"rule_category,omitempty"`
	RuleDescription string    `json:"rule_description,omitempty"`
	Action          string    `json:"action"` // "disabled" or "enabled"
	Reason          string    `json:"reason,omitempty"`
	ChangedBy       string    `json:"changed_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// CreateGlobalWAFRuleExclusionRequest is the request to disable a rule globally
type CreateGlobalWAFRuleExclusionRequest struct {
	RuleID          int    `json:"rule_id" validate:"required,min=100000,max=999999"`
	RuleCategory    string `json:"rule_category,omitempty"`
	RuleDescription string `json:"rule_description,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// GlobalWAFRulesResponse is the response for listing global WAF rules status
type GlobalWAFRulesResponse struct {
	Categories       []WAFRuleCategory        `json:"categories"`
	TotalRules       int                      `json:"total_rules"`
	GlobalExclusions []GlobalWAFRuleExclusion `json:"global_exclusions"`
}

// GlobalWAFPolicyHistoryResponse is the response for listing global policy history
type GlobalWAFPolicyHistoryResponse struct {
	History []GlobalWAFPolicyHistory `json:"history"`
	Total   int                      `json:"total"`
}

// WAFRuleSnapshot represents a complete snapshot of WAF configuration state
type WAFRuleSnapshot struct {
	ID                string                    `json:"id"`
	ProxyHostID       *string                   `json:"proxy_host_id,omitempty"` // NULL for global snapshots
	VersionNumber     int                       `json:"version_number"`
	SnapshotName      string                    `json:"snapshot_name,omitempty"`
	RuleEngine        string                    `json:"rule_engine,omitempty"`
	ParanoiaLevel     int                       `json:"paranoia_level,omitempty"`
	AnomalyThreshold  int                       `json:"anomaly_threshold,omitempty"`
	TotalRules        int                       `json:"total_rules"`
	DisabledRules     int                       `json:"disabled_rules"`
	ChangeDescription string                    `json:"change_description,omitempty"`
	CreatedBy         string                    `json:"created_by,omitempty"`
	CreatedAt         time.Time                 `json:"created_at"`
	Details           []WAFRuleSnapshotDetail   `json:"details,omitempty"`
}

// WAFRuleSnapshotDetail represents a single rule's state within a snapshot
type WAFRuleSnapshotDetail struct {
	ID              string `json:"id"`
	SnapshotID      string `json:"snapshot_id"`
	RuleID          string `json:"rule_id"`
	RuleCategory    string `json:"rule_category,omitempty"`
	RuleDescription string `json:"rule_description,omitempty"`
	IsDisabled      bool   `json:"is_disabled"`
	Reason          string `json:"reason,omitempty"`
}

// WAFRuleChangeEvent represents an individual rule enable/disable event
type WAFRuleChangeEvent struct {
	ID              string    `json:"id"`
	ProxyHostID     *string   `json:"proxy_host_id,omitempty"`
	RuleID          string    `json:"rule_id"`
	Action          string    `json:"action"` // "enabled" or "disabled"
	RuleCategory    string    `json:"rule_category,omitempty"`
	RuleDescription string    `json:"rule_description,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	ChangedBy       string    `json:"changed_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// CreateWAFSnapshotRequest is the request to create a new WAF snapshot
type CreateWAFSnapshotRequest struct {
	SnapshotName      string `json:"snapshot_name,omitempty"`
	ChangeDescription string `json:"change_description,omitempty"`
}

// WAFSnapshotListResponse is the response for listing WAF snapshots
type WAFSnapshotListResponse struct {
	Snapshots []WAFRuleSnapshot `json:"snapshots"`
	Total     int               `json:"total"`
}

// WAFRuleChangeEventListResponse is the response for listing rule change events
type WAFRuleChangeEventListResponse struct {
	Events []WAFRuleChangeEvent `json:"events"`
	Total  int                  `json:"total"`
}

// ResolveWAF collapses the global WAF default and a host's own WAF columns into
// the effective host used for config generation (#198 slice 6).
//
//	waf_use_global=false → the host's own columns (override, or disable)
//	waf_use_global=true  → the global enabled/mode/paranoia/threshold
//
// It returns a COPY; the stored row is never mutated. Every path that writes a
// per-host modsec file must call this first — writing the raw row silently
// pins an inheriting host to whatever its stale column says, which is how a
// host displayed as "blocking" ended up running DetectionOnly (#272, same
// class as #202).
func ResolveWAF(global *GlobalWAF, host *ProxyHost) *ProxyHost {
	if host == nil || !host.WAFUseGlobal || global == nil {
		return host
	}
	c := *host
	c.WAFEnabled = global.Enabled
	c.WAFMode = global.Mode
	c.WAFParanoiaLevel = global.ParanoiaLevel
	c.WAFAnomalyThreshold = global.AnomalyThreshold
	return &c
}
