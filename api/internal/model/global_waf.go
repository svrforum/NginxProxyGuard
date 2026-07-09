package model

import "time"

// GlobalWAF is the singleton global WAF default (#198 slice 6). Hosts with
// waf_use_global=true inherit its enabled/mode/paranoia/threshold instead of
// their own proxy_hosts WAF columns. WAF/ModSecurity changes only take effect
// after a proxy container restart (reload does not reparse ModSec rules).
type GlobalWAF struct {
	ID               string    `json:"id"`
	Enabled          bool      `json:"enabled"`
	Mode             string    `json:"mode"` // detection | blocking
	ParanoiaLevel    int       `json:"paranoia_level"`
	AnomalyThreshold int       `json:"anomaly_threshold"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// UpdateGlobalWAFRequest is the partial-update request for the singleton.
type UpdateGlobalWAFRequest struct {
	Enabled          *bool  `json:"enabled,omitempty"`
	Mode             string `json:"mode,omitempty"`
	ParanoiaLevel    int    `json:"paranoia_level,omitempty"`
	AnomalyThreshold int    `json:"anomaly_threshold,omitempty"`
}
