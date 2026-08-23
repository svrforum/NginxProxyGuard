package model

import "time"

// CloudflareTunnel is the singleton Cloudflare Tunnel connector setting.
// mode 'token' (Phase 1): the user pastes a connector token created in the
// Cloudflare Zero Trust dashboard; ingress/DNS are managed there.
// mode 'managed' (Phase 2, #267): NPG additionally maintains the tunnel's
// trailing catch-all ingress rule via the Cloudflare API, so hostnames that
// are not registered as Public Hostnames still reach NPG and route by Host
// header. DNS records and per-hostname ingress stay out of scope.
type CloudflareTunnel struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Token   string `json:"-"` // never serialized — see CloudflareTunnelResponse
	Mode    string `json:"mode"`
	// APIToken is the separate Cloudflare API token managed mode uses to edit
	// the tunnel's catch-all ingress rule (#267). Account/Cloudflare Tunnel/Edit
	// is the only permission it needs. Never serialized, same as Token.
	APIToken string `json:"-"`
	// CatchallEnabled is the operator's intent; whether the rule is actually in
	// place on the Cloudflare side is reported separately via TunnelStatus.
	CatchallEnabled bool `json:"catchall_enabled"`
	// CatchallAppliedService is the exact service URL NPG last wrote into the
	// tunnel's catch-all rule. It is what lets NPG recognize its own rule for
	// safe restore/update even after NGINX_HTTPS_PORT changes — the remote
	// config has no metadata field to mark ownership.
	CatchallAppliedService string    `json:"-"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// UpdateCloudflareTunnelRequest is the partial-update request for the singleton.
// Token semantics: nil = keep existing token; non-nil = replace (may be "" only
// when disabling).
type UpdateCloudflareTunnelRequest struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Token   *string `json:"token,omitempty"`
	// Mode switches between 'token' (Phase 1, dashboard-managed ingress) and
	// 'managed' (NPG maintains the catch-all rule via the Cloudflare API).
	Mode *string `json:"mode,omitempty"`
	// APIToken: nil = keep stored; non-nil = replace ("" clears — allowed only
	// when leaving managed mode or before it is enabled).
	APIToken        *string `json:"api_token,omitempty"`
	CatchallEnabled *bool   `json:"catchall_enabled,omitempty"`
}

// CloudflareTunnelResponse is the API view: token masked, presence flagged.
// OriginServiceURL is the origin service URL to enter in the Cloudflare
// dashboard's Public Hostname — reflects the actual NGINX_HTTPS_PORT.
// OriginServiceURLHTTP is the http:// variant (NGINX_HTTP_PORT) for hosts that
// serve over plain HTTP (SSL disabled).
type CloudflareTunnelResponse struct {
	ID                   string    `json:"id"`
	Enabled              bool      `json:"enabled"`
	Mode                 string    `json:"mode"`
	HasToken             bool      `json:"has_token"`
	TokenMasked          string    `json:"token_masked"` // "eyJh****" (first 4 chars) or ""
	HasAPIToken          bool      `json:"has_api_token"`
	APITokenMasked       string    `json:"api_token_masked"`
	CatchallEnabled      bool      `json:"catchall_enabled"`
	OriginServiceURL     string    `json:"origin_service_url"`
	OriginServiceURLHTTP string    `json:"origin_service_url_http"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// TunnelStatus is the connector runtime state. The Catchall fields are only
// populated in managed mode; CatchallState mirrors the remote decision table:
//
//	applied        — the tunnel's last rule is NPG's catch-all
//	not_applied    — last rule is the default http_status:404 (toggle off, or on but not yet applied)
//	conflict       — someone else's catch-all occupies the last rule; NPG will not touch it
//	invalid_remote — remote config violates CF's own contract (last rule has a hostname)
//	unreachable    — the Cloudflare API could not be queried (detail carries why)
type TunnelStatus struct {
	State          string `json:"state"` // disabled | starting | connected | error
	Connections    int    `json:"connections"`
	CatchallState  string `json:"catchall_state,omitempty"`
	CatchallDetail string `json:"catchall_detail,omitempty"`
}
