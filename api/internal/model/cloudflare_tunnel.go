package model

import "time"

// CloudflareTunnel is the singleton Cloudflare Tunnel connector setting
// (Phase 1: token mode — the user pastes a connector token created in the
// Cloudflare Zero Trust dashboard; ingress/DNS are managed there).
// mode is reserved for Phase 2 ('managed').
type CloudflareTunnel struct {
	ID        string    `json:"id"`
	Enabled   bool      `json:"enabled"`
	Token     string    `json:"-"` // never serialized — see CloudflareTunnelResponse
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateCloudflareTunnelRequest is the partial-update request for the singleton.
// Token semantics: nil = keep existing token; non-nil = replace (may be "" only
// when disabling).
type UpdateCloudflareTunnelRequest struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Token   *string `json:"token,omitempty"`
}

// CloudflareTunnelResponse is the API view: token masked, presence flagged.
type CloudflareTunnelResponse struct {
	ID          string    `json:"id"`
	Enabled     bool      `json:"enabled"`
	Mode        string    `json:"mode"`
	HasToken    bool      `json:"has_token"`
	TokenMasked string    `json:"token_masked"` // "eyJh****" (first 4 chars) or ""
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TunnelStatus is the connector runtime state.
type TunnelStatus struct {
	State       string `json:"state"` // disabled | starting | connected | error
	Connections int    `json:"connections"`
}
