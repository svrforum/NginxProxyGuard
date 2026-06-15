package model

import "time"

// AuthProvider is a reusable external ForwardAuth verifier (Authelia / Authentik
// / custom) that proxy hosts can reference to gate traffic via nginx auth_request.
type AuthProvider struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Type        string             `json:"type"`         // "authelia" | "authentik" | "custom"
	ProviderURL string             `json:"provider_url"` // base URL, e.g. http://127.0.0.1:9091
	Config      AuthProviderConfig `json:"config"`       // custom-only knobs; empty for presets
	TimeoutMs   int                `json:"timeout_ms"`
	Enabled     bool               `json:"enabled"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// AuthProviderConfig holds custom-provider knobs (ignored for authelia/authentik,
// whose directives are generated from verified presets). Stored as jsonb.
type AuthProviderConfig struct {
	VerifyPath        string               `json:"verify_path,omitempty"`        // appended to ProviderURL for auth_request, e.g. /oauth2/auth
	RequestHeaders    []AuthHeader         `json:"request_headers,omitempty"`    // proxy_set_header lines in the verify location
	ResponseHeaders   []AuthResponseHeader `json:"response_headers,omitempty"`   // copied from verifier to backend
	SigninMode        string               `json:"signin_mode,omitempty"`        // "location_header" | "redirect_template"
	SigninRedirect    string               `json:"signin_redirect,omitempty"`    // template for redirect_template mode
	PublicPaths       []string             `json:"public_paths,omitempty"`       // non-gated callback paths proxied to the verifier
	CookiePassthrough bool                 `json:"cookie_passthrough,omitempty"` // re-emit Set-Cookie from verifier
	LargeBuffers      bool                 `json:"large_buffers,omitempty"`      // big proxy buffers for large auth headers
}

// AuthHeader is a request header sent to the verifier (proxy_set_header Name Value;).
type AuthHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AuthResponseHeader copies a verifier response header into a var then forwards it
// to the backend: auth_request_set $<Var> $upstream_http_<Upstream>; proxy_set_header <Forward> $<Var>;
type AuthResponseHeader struct {
	Var      string `json:"var"`      // nginx var name without $, e.g. "user"
	Upstream string `json:"upstream"` // upstream header lowercased w/ underscores, e.g. "x_auth_request_user"
	Forward  string `json:"forward"`  // header sent to backend, e.g. "X-User"
}

// CreateAuthProviderRequest is the create payload.
type CreateAuthProviderRequest struct {
	Name        string              `json:"name" validate:"required,min=1,max=255"`
	Type        string              `json:"type" validate:"required,oneof=authelia authentik custom"`
	ProviderURL string              `json:"provider_url" validate:"required,url"`
	Config      *AuthProviderConfig `json:"config,omitempty"`
	TimeoutMs   *int                `json:"timeout_ms,omitempty"`
	Enabled     *bool               `json:"enabled,omitempty"`
}

// UpdateAuthProviderRequest is a partial update payload.
type UpdateAuthProviderRequest struct {
	Name        *string             `json:"name,omitempty"`
	Type        *string             `json:"type,omitempty"`
	ProviderURL *string             `json:"provider_url,omitempty"`
	Config      *AuthProviderConfig `json:"config,omitempty"`
	TimeoutMs   *int                `json:"timeout_ms,omitempty"`
	Enabled     *bool               `json:"enabled,omitempty"`
}

// AuthProviderListResponse is the paginated list response.
type AuthProviderListResponse struct {
	Data       []AuthProvider `json:"data"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PerPage    int            `json:"per_page"`
	TotalPages int            `json:"total_pages"`
}
