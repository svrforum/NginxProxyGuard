package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Validation for ForwardAuth fields that get interpolated into nginx directives.
// Defense-in-depth (nginx -t also gates before reload): reject anything that could
// break out of the intended directive and inject config. (#179 security review)
var (
	// chars that terminate / open an nginx directive or comment
	nginxUnsafeChars = regexp.MustCompile(`[;{}#\n\r]`)
	// a location/URL path: starts with /, no whitespace or nginx-breaking chars
	nginxPathRe = regexp.MustCompile(`^/[^\s;{}#]*$`)
	// HTTP header name
	httpHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	// nginx variable / upstream-header token
	nginxVarRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

// ValidateProviderURL rejects provider URLs that aren't plain http(s) targets or
// that contain characters which would break the generated proxy_pass directive.
func ValidateProviderURL(u string) error {
	u = strings.TrimSpace(u)
	if u == "" {
		return fmt.Errorf("invalid: provider_url is required")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("invalid: provider_url must start with http:// or https://")
	}
	if strings.ContainsAny(u, " \t") || nginxUnsafeChars.MatchString(u) {
		return fmt.Errorf("invalid: provider_url contains unsafe characters")
	}
	return nil
}

// Validate checks custom-provider config fields that are templated into nginx.
// Presets (authelia/authentik) ignore these fields (directives are hardcoded), so
// only the custom type needs field validation.
func (c *AuthProviderConfig) Validate(providerType string) error {
	if providerType != "custom" {
		return nil
	}
	if c.VerifyPath != "" && !nginxPathRe.MatchString(c.VerifyPath) {
		return fmt.Errorf("invalid: verify_path must be a URL path (e.g. /oauth2/auth)")
	}
	for _, p := range c.PublicPaths {
		if !nginxPathRe.MatchString(p) {
			return fmt.Errorf("invalid: public path %q must be a URL path", p)
		}
	}
	for _, h := range c.RequestHeaders {
		if !httpHeaderNameRe.MatchString(h.Name) {
			return fmt.Errorf("invalid: request header name %q", h.Name)
		}
		if nginxUnsafeChars.MatchString(h.Value) {
			return fmt.Errorf("invalid: request header value for %q contains unsafe characters", h.Name)
		}
	}
	for _, h := range c.ResponseHeaders {
		if !nginxVarRe.MatchString(h.Var) || !nginxVarRe.MatchString(h.Upstream) {
			return fmt.Errorf("invalid: response header var/upstream must be alphanumeric/underscore")
		}
		if !httpHeaderNameRe.MatchString(h.Forward) {
			return fmt.Errorf("invalid: response forward header %q", h.Forward)
		}
	}
	if c.SigninRedirect != "" && nginxUnsafeChars.MatchString(c.SigninRedirect) {
		return fmt.Errorf("invalid: signin_redirect contains unsafe characters")
	}
	return nil
}

// ValidateAuthBypassPath checks a per-host bypass path that is templated into a
// `location <path> { ... }` block.
func ValidateAuthBypassPath(p string) error {
	if !nginxPathRe.MatchString(p) {
		return fmt.Errorf("invalid: auth bypass path %q must be a URL path (e.g. /api)", p)
	}
	return nil
}

// AuthProvider is a reusable external ForwardAuth verifier (Authelia / Authentik
// / custom) that proxy hosts can reference to gate traffic via nginx auth_request.
type AuthProvider struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Type        string             `json:"type"`         // "authelia" | "authentik" | "custom"
	ProviderURL string             `json:"provider_url"` // base URL, e.g. http://127.0.0.1:9091 (resolved value when container-backed)
	Config      AuthProviderConfig `json:"config"`       // custom-only knobs; empty for presets
	TimeoutMs   int                `json:"timeout_ms"`
	Enabled     bool               `json:"enabled"`
	// Optional Docker-container target for the verify endpoint (#181). When set,
	// ProviderURL is derived as ContainerScheme://<resolved IP>:ContainerPort and
	// re-resolved on container IP change (mirrors proxy_hosts #150/#151). Nil = manual URL.
	ContainerName    *string   `json:"container_name,omitempty"`
	ContainerNetwork *string   `json:"container_network,omitempty"`
	ContainerPort    *int      `json:"container_port,omitempty"`
	ContainerScheme  *string   `json:"container_scheme,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
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

// CreateAuthProviderRequest is the create payload. ProviderURL may be omitted when
// a container target is supplied (the service resolves it); validation is enforced
// after resolution in the service layer.
type CreateAuthProviderRequest struct {
	Name        string              `json:"name" validate:"required,min=1,max=255"`
	Type        string              `json:"type" validate:"required,oneof=authelia authentik custom"`
	ProviderURL string              `json:"provider_url"`
	Config      *AuthProviderConfig `json:"config,omitempty"`
	TimeoutMs   *int                `json:"timeout_ms,omitempty"`
	Enabled     *bool               `json:"enabled,omitempty"`
	// Docker-container target (#181); when ContainerName is set the service resolves
	// ProviderURL from the container's IP.
	ContainerName    *string `json:"container_name,omitempty"`
	ContainerNetwork *string `json:"container_network,omitempty"`
	ContainerPort    *int    `json:"container_port,omitempty"`
	ContainerScheme  *string `json:"container_scheme,omitempty"`
}

// UpdateAuthProviderRequest is a partial update payload.
type UpdateAuthProviderRequest struct {
	Name        *string             `json:"name,omitempty"`
	Type        *string             `json:"type,omitempty"`
	ProviderURL *string             `json:"provider_url,omitempty"`
	Config      *AuthProviderConfig `json:"config,omitempty"`
	TimeoutMs   *int                `json:"timeout_ms,omitempty"`
	Enabled     *bool               `json:"enabled,omitempty"`
	// Docker-container target (#181). A nil pointer leaves the field unchanged; an
	// explicit empty ContainerName clears the container binding (back to manual URL).
	ContainerName    *string `json:"container_name,omitempty"`
	ContainerNetwork *string `json:"container_network,omitempty"`
	ContainerPort    *int    `json:"container_port,omitempty"`
	ContainerScheme  *string `json:"container_scheme,omitempty"`
}

// AuthProviderListResponse is the paginated list response.
type AuthProviderListResponse struct {
	Data       []AuthProvider `json:"data"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PerPage    int            `json:"per_page"`
	TotalPages int            `json:"total_pages"`
}
