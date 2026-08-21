package model

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// RedirectHost represents a redirect-only virtual host
type RedirectHost struct {
	ID                string          `json:"id"`
	DomainNames       []string        `json:"domain_names"`
	ForwardScheme     string          `json:"forward_scheme"`      // auto, http, https
	ForwardDomainName string          `json:"forward_domain_name"` // Target domain
	ForwardPath       string          `json:"forward_path"`        // Optional path to append
	PreservePath      bool            `json:"preserve_path"`       // Keep original path
	RedirectCode      int             `json:"redirect_code"`       // 301, 302, 307, 308
	SSLEnabled        bool            `json:"ssl_enabled"`
	CertificateID     *string         `json:"certificate_id,omitempty"`
	SSLForceHTTPS     bool            `json:"ssl_force_https"`
	Enabled           bool            `json:"enabled"`
	BlockExploits     bool            `json:"block_exploits"`
	Meta              json.RawMessage `json:"meta,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// CreateRedirectHostRequest is the request to create a redirect host
type CreateRedirectHostRequest struct {
	DomainNames       []string        `json:"domain_names" validate:"required,min=1"`
	ForwardScheme     string          `json:"forward_scheme,omitempty"` // default: auto
	ForwardDomainName string          `json:"forward_domain_name" validate:"required"`
	ForwardPath       string          `json:"forward_path,omitempty"`
	PreservePath      *bool           `json:"preserve_path,omitempty"`
	RedirectCode      int             `json:"redirect_code,omitempty"` // default: 301
	SSLEnabled        bool            `json:"ssl_enabled,omitempty"`
	CertificateID     *string         `json:"certificate_id,omitempty"`
	SSLForceHTTPS     *bool           `json:"ssl_force_https,omitempty"`
	Enabled           *bool           `json:"enabled,omitempty"`
	BlockExploits     bool            `json:"block_exploits,omitempty"`
	Meta              json.RawMessage `json:"meta,omitempty"`
}

// UpdateRedirectHostRequest is the request to update a redirect host
type UpdateRedirectHostRequest struct {
	DomainNames       []string        `json:"domain_names,omitempty"`
	ForwardScheme     *string         `json:"forward_scheme,omitempty"`
	ForwardDomainName *string         `json:"forward_domain_name,omitempty"`
	ForwardPath       *string         `json:"forward_path,omitempty"`
	PreservePath      *bool           `json:"preserve_path,omitempty"`
	RedirectCode      *int            `json:"redirect_code,omitempty"`
	SSLEnabled        *bool           `json:"ssl_enabled,omitempty"`
	CertificateID     *string         `json:"certificate_id,omitempty"`
	SSLForceHTTPS     *bool           `json:"ssl_force_https,omitempty"`
	Enabled           *bool           `json:"enabled,omitempty"`
	BlockExploits     *bool           `json:"block_exploits,omitempty"`
	Meta              json.RawMessage `json:"meta,omitempty"`
}

// ValidateRedirectHost rejects values that could break out of the generated
// nginx server_name or return directives. nginx -t only validates syntax, so a
// syntactically valid injected directive must be rejected before rendering.
func ValidateRedirectHost(host *RedirectHost) error {
	if host == nil {
		return fmt.Errorf("redirect host is required")
	}
	if err := validateRedirectDomains(host.DomainNames); err != nil {
		return err
	}
	if err := validateRedirectScheme(host.ForwardScheme); err != nil {
		return err
	}
	if err := validateRedirectTarget(host.ForwardDomainName); err != nil {
		return err
	}
	if err := validateRedirectPath(host.ForwardPath); err != nil {
		return err
	}
	if !validRedirectCode(host.RedirectCode) {
		return fmt.Errorf("redirect_code must be one of 301, 302, 307 or 308")
	}
	return nil
}

// ValidateRedirectHostUpdate validates the merged update while allowing one
// narrow recovery action for unsafe legacy rows: an enabled row may be changed
// to disabled when Enabled is the only effective change. Requests may repeat
// existing values (as the UI's full edit form does), but every actual edit or
// re-enable must pass the normal full-host validation.
func ValidateRedirectHostUpdate(existing, updated *RedirectHost, req *UpdateRedirectHostRequest) error {
	err := ValidateRedirectHost(updated)
	if err == nil {
		return nil
	}
	if isDisableOnlyRedirectHostUpdate(existing, updated, req) {
		return nil
	}
	return err
}

func isDisableOnlyRedirectHostUpdate(existing, updated *RedirectHost, req *UpdateRedirectHostRequest) bool {
	if existing == nil || updated == nil || req == nil ||
		!existing.Enabled || updated.Enabled || req.Enabled == nil || *req.Enabled {
		return false
	}
	existingWithUpdatedEnabled := *existing
	existingWithUpdatedEnabled.Enabled = updated.Enabled
	return reflect.DeepEqual(&existingWithUpdatedEnabled, updated)
}

// Validate applies defaults and validates a complete create request.
func (r *CreateRedirectHostRequest) Validate() error {
	scheme := r.ForwardScheme
	if scheme == "" {
		scheme = "auto"
	}
	code := r.RedirectCode
	if code == 0 {
		code = 301
	}
	return ValidateRedirectHost(&RedirectHost{
		DomainNames:       r.DomainNames,
		ForwardScheme:     scheme,
		ForwardDomainName: r.ForwardDomainName,
		ForwardPath:       r.ForwardPath,
		RedirectCode:      code,
	})
}

// Validate checks only fields present in a partial update. The repository also
// validates the merged RedirectHost before writing it, which protects non-HTTP
// callers and combinations with existing values.
func (r *UpdateRedirectHostRequest) Validate() error {
	if len(r.DomainNames) > 0 {
		if err := validateRedirectDomains(r.DomainNames); err != nil {
			return err
		}
	}
	if r.ForwardScheme != nil {
		if err := validateRedirectScheme(*r.ForwardScheme); err != nil {
			return err
		}
	}
	if r.ForwardDomainName != nil {
		if err := validateRedirectTarget(*r.ForwardDomainName); err != nil {
			return err
		}
	}
	if r.ForwardPath != nil {
		if err := validateRedirectPath(*r.ForwardPath); err != nil {
			return err
		}
	}
	if r.RedirectCode != nil && !validRedirectCode(*r.RedirectCode) {
		return fmt.Errorf("redirect_code must be one of 301, 302, 307 or 308")
	}
	return nil
}

func validateRedirectDomains(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("at least one domain name is required")
	}
	for _, domain := range domains {
		if domain != strings.TrimSpace(domain) || !ValidateDomainName(domain) {
			return fmt.Errorf("invalid domain name %q", domain)
		}
	}
	return nil
}

func validateRedirectScheme(scheme string) error {
	switch scheme {
	case "auto", "http", "https":
		return nil
	default:
		return fmt.Errorf("forward_scheme must be one of auto, http or https")
	}
}

func validateRedirectTarget(target string) error {
	if target != strings.TrimSpace(target) || strings.Contains(target, "*") {
		return fmt.Errorf("forward_domain_name must be a valid hostname or IP address")
	}

	host, port, ok := splitRedirectTarget(target)
	if !ok {
		return fmt.Errorf("forward_domain_name must be a valid hostname or IP address with an optional port")
	}
	// A trailing dot is the canonical absolute-FQDN form. Validate the DNS name
	// without that root label while preserving the user's value for rendering.
	hostForValidation := strings.TrimSuffix(host, ".")
	if !ValidateHostnameOrIP(hostForValidation) {
		return fmt.Errorf("forward_domain_name must contain a valid hostname or IP address")
	}
	if port != "" {
		if strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return fmt.Errorf("forward_domain_name port must contain only decimal digits")
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || !ValidatePort(portNumber) {
			return fmt.Errorf("forward_domain_name port must be between 1 and 65535")
		}
	}
	return nil
}

// splitRedirectTarget accepts URL-authority host forms without accepting a
// scheme, credentials or path. IPv6 must be bracketed so the rendered redirect
// remains a valid URL; hostnames and IPv4 addresses may carry an optional port.
func splitRedirectTarget(target string) (host, port string, ok bool) {
	if strings.HasPrefix(target, "[") {
		end := strings.IndexByte(target, ']')
		if end <= 1 {
			return "", "", false
		}
		host = target[1:end]
		rest := target[end+1:]
		switch {
		case rest == "":
			return host, "", net.ParseIP(host) != nil
		case strings.HasPrefix(rest, ":") && len(rest) > 1 && !strings.Contains(rest[1:], ":"):
			return host, rest[1:], net.ParseIP(host) != nil
		default:
			return "", "", false
		}
	}

	switch strings.Count(target, ":") {
	case 0:
		return target, "", true
	case 1:
		host, port, err := net.SplitHostPort(target)
		return host, port, err == nil && host != "" && port != ""
	default:
		// A bare IPv6 literal is not a valid URL authority. Require brackets.
		return "", "", false
	}
}

func validateRedirectPath(path string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("forward_path must start with /")
	}
	if strings.ContainsAny(path, "\r\n;{}\\\"'$") || strings.IndexFunc(path, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return fmt.Errorf("forward_path contains characters that are unsafe in nginx configuration")
	}
	return nil
}

func validRedirectCode(code int) bool {
	return code == 301 || code == 302 || code == 307 || code == 308
}

// RedirectHostListResponse is the response for listing redirect hosts
type RedirectHostListResponse struct {
	Data       []RedirectHost `json:"data"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PerPage    int            `json:"per_page"`
	TotalPages int            `json:"total_pages"`
}
