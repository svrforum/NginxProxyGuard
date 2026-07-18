package model

import (
	"encoding/json"
	"time"
)

// LogFilterPreset is a saved, named set of log-viewer filters (#210). Presets
// are global (shared across admins). The filter payload is stored as opaque
// JSON that mirrors the query the log viewer applies (exclude_ips, exclude_uris,
// hosts, date range, etc.), so adding new filter fields never requires a schema
// change here.
type LogFilterPreset struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	LogType   string          `json:"log_type"`
	Filter    json.RawMessage `json:"filter"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// CreateLogFilterPresetRequest is the payload to save a new preset.
type CreateLogFilterPresetRequest struct {
	Name    string          `json:"name"`
	LogType string          `json:"log_type"`
	Filter  json.RawMessage `json:"filter"`
}

// UpdateLogFilterPresetRequest is a partial update (rename and/or replace the
// stored filter). Nil fields are left unchanged.
type UpdateLogFilterPresetRequest struct {
	Name   *string          `json:"name,omitempty"`
	Filter *json.RawMessage `json:"filter,omitempty"`
}
