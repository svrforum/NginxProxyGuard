package model

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"
)

// OIDC SSO for the admin panel (#227).
//
// This is not ForwardAuth. auth_providers protects a PROXIED HOST; an
// SSOProvider lets someone sign in to THIS panel. The two never share a record.

// SecretPlaceholder is what the API returns in place of a stored client secret.
// A write carrying it back means "leave the secret alone".
const SecretPlaceholder = "********"

// SSOLoginStateTTL bounds how long a login may sit half-finished at the IdP.
const SSOLoginStateTTL = 10 * time.Minute

// GroupRoleMapping assigns an NPG role to everyone carrying a given group claim.
type GroupRoleMapping struct {
	Group  string `json:"group"`
	RoleID string `json:"role_id"`
}

type SSOProvider struct {
	ID                  string             `json:"id"`
	Slug                string             `json:"slug"`
	Name                string             `json:"name"`
	IssuerURL           string             `json:"issuer_url"`
	ClientID            string             `json:"client_id"`
	ClientSecret        string             `json:"client_secret,omitempty"`
	Scopes              string             `json:"scopes"`
	CallbackBaseURL     string             `json:"callback_base_url"`
	Enabled             bool               `json:"enabled"`
	AllowJIT            bool               `json:"allow_jit"`
	AllowedEmailDomains pq.StringArray     `json:"allowed_email_domains"`
	AllowedEmails       pq.StringArray     `json:"allowed_emails"`
	GroupClaim          string             `json:"group_claim"`
	RequiredGroup       string             `json:"required_group"`
	DefaultRoleID       *string            `json:"default_role_id"`
	GroupRoleMappings   []GroupRoleMapping `json:"group_role_mappings"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
	// CallbackURL is derived, not stored — the UI shows it so the operator can
	// register the exact value at the IdP.
	CallbackURL string `json:"callback_url,omitempty"`
	// LinkedUsers reports how many accounts are attached to this provider, so a
	// delete can say what it would detach.
	LinkedUsers int `json:"linked_users"`
}

// PublicSSOProvider is what an unauthenticated login screen may learn. Issuer,
// client id and every allowlist detail stay server-side.
type PublicSSOProvider struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type CreateSSOProviderRequest struct {
	Slug                string             `json:"slug"`
	Name                string             `json:"name"`
	IssuerURL           string             `json:"issuer_url"`
	ClientID            string             `json:"client_id"`
	ClientSecret        string             `json:"client_secret"`
	Scopes              string             `json:"scopes"`
	CallbackBaseURL     string             `json:"callback_base_url"`
	Enabled             *bool              `json:"enabled"`
	AllowJIT            bool               `json:"allow_jit"`
	AllowedEmailDomains []string           `json:"allowed_email_domains"`
	AllowedEmails       []string           `json:"allowed_emails"`
	GroupClaim          string             `json:"group_claim"`
	RequiredGroup       string             `json:"required_group"`
	DefaultRoleID       *string            `json:"default_role_id"`
	GroupRoleMappings   []GroupRoleMapping `json:"group_role_mappings"`
}

type UpdateSSOProviderRequest = CreateSSOProviderRequest

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Validate rejects a provider the flow could not use. It runs before anything
// touches the database so a half-configured provider never reaches the login
// screen, where a failure is only visible as a broken redirect.
func (r *CreateSSOProviderRequest) Validate(isCreate bool) error {
	r.Slug = strings.ToLower(strings.TrimSpace(r.Slug))
	r.Name = strings.TrimSpace(r.Name)
	r.IssuerURL = strings.TrimSpace(r.IssuerURL)
	r.ClientID = strings.TrimSpace(r.ClientID)
	r.CallbackBaseURL = strings.TrimSpace(r.CallbackBaseURL)
	r.GroupClaim = strings.TrimSpace(r.GroupClaim)
	r.RequiredGroup = strings.TrimSpace(r.RequiredGroup)

	if !slugPattern.MatchString(r.Slug) {
		return fmt.Errorf("invalid slug: use 1-32 characters of a-z, 0-9 and '-', starting with a letter or digit")
	}
	if r.Name == "" || len(r.Name) > 64 {
		return fmt.Errorf("invalid name: 1-64 characters required")
	}
	if err := validateHTTPSURL(r.IssuerURL, "issuer_url"); err != nil {
		return err
	}
	if r.CallbackBaseURL != "" {
		if err := validateHTTPSURL(r.CallbackBaseURL, "callback_base_url"); err != nil {
			return err
		}
	}
	if r.ClientID == "" {
		return fmt.Errorf("invalid client_id: required")
	}
	if isCreate && r.ClientSecret == "" {
		return fmt.Errorf("invalid client_secret: required")
	}
	if r.Scopes = strings.TrimSpace(r.Scopes); r.Scopes == "" {
		r.Scopes = "openid profile email"
	}
	if !containsField(r.Scopes, "openid") {
		return fmt.Errorf("invalid scopes: openid is required")
	}
	if r.GroupClaim == "" {
		r.GroupClaim = "groups"
	}

	r.AllowedEmails = normaliseList(r.AllowedEmails, strings.ToLower)
	r.AllowedEmailDomains = normaliseList(r.AllowedEmailDomains, func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "@"))
	})
	for _, e := range r.AllowedEmails {
		if !strings.Contains(e, "@") {
			return fmt.Errorf("invalid allowed_emails entry %q: not an email address", e)
		}
	}
	for _, d := range r.AllowedEmailDomains {
		if strings.Contains(d, "@") || !strings.Contains(d, ".") {
			return fmt.Errorf("invalid allowed_email_domains entry %q: use a bare domain such as example.com", d)
		}
	}

	// Fail closed. An IdP like Google authenticates every account on earth, so
	// provisioning without a single restriction would publish the panel.
	if r.AllowJIT && len(r.AllowedEmails) == 0 && len(r.AllowedEmailDomains) == 0 && r.RequiredGroup == "" {
		return fmt.Errorf("invalid allowlist: automatic account creation needs at least one allowed email, allowed domain or required group")
	}
	if r.AllowJIT && (r.DefaultRoleID == nil || *r.DefaultRoleID == "") {
		return fmt.Errorf("invalid default_role_id: automatic account creation needs a role to assign")
	}
	for i, m := range r.GroupRoleMappings {
		if strings.TrimSpace(m.Group) == "" || strings.TrimSpace(m.RoleID) == "" {
			return fmt.Errorf("invalid group_role_mappings[%d]: both group and role_id are required", i)
		}
	}
	return nil
}

func validateHTTPSURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid %s: not a URL", field)
	}
	if u.Scheme == "https" {
		return nil
	}
	// Plain http is allowed only where the traffic cannot leave the operator's
	// own network. On a home server the identity provider is usually a sibling
	// container reached by its compose service name, or a box on the LAN;
	// demanding TLS there would rule out the most common deployment while
	// protecting nothing. Anything publicly routable must be TLS, because the
	// authorization code and the client secret would otherwise cross the
	// internet in the clear.
	if u.Scheme == "http" && isPrivateHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("invalid %s: must use https (http is allowed only for localhost, a private address, or a container/LAN hostname)", field)
}

// isPrivateHost reports whether a host can only be reached from the operator's
// own network: loopback, an RFC1918/CGNAT/link-local address, a .local name, or
// a single-label hostname — which cannot exist in public DNS and is what a
// docker-compose service name looks like.
func isPrivateHost(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || isCGNAT(ip)
	}
	return !strings.Contains(h, ".")
}

// isCGNAT covers 100.64.0.0/10, which is where Tailscale and similar overlay
// networks put hosts.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

func containsField(s, want string) bool {
	for _, f := range strings.Fields(s) {
		if f == want {
			return true
		}
	}
	return false
}

func normaliseList(in []string, transform func(string) string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = transform(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// SSOClaims is the subset of an ID token the flow acts on.
type SSOClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Username      string
	Groups        []string
}

// AllowedByList reports whether the identity passes the provider's allowlist.
// The rule is (email OR domain) AND required group, with an empty allowlist
// meaning "nobody" rather than "everybody".
func (p *SSOProvider) AllowedByList(c *SSOClaims) bool {
	email := strings.ToLower(strings.TrimSpace(c.Email))
	listed := false
	for _, e := range p.AllowedEmails {
		if e == email {
			listed = true
			break
		}
	}
	if !listed {
		if at := strings.LastIndex(email, "@"); at >= 0 {
			domain := email[at+1:]
			for _, d := range p.AllowedEmailDomains {
				if d == domain {
					listed = true
					break
				}
			}
		}
	}
	// With no email allowlist at all, a required group is the only gate and is
	// sufficient on its own.
	if len(p.AllowedEmails) == 0 && len(p.AllowedEmailDomains) == 0 {
		listed = p.RequiredGroup != ""
	}
	if !listed {
		return false
	}
	if p.RequiredGroup == "" {
		return true
	}
	return hasGroup(c.Groups, p.RequiredGroup)
}

// RoleForClaims resolves which role an identity should hold: the first matching
// group mapping in the admin's order, else the provider default. The second
// return reports whether a group mapping decided it, which is what makes the
// role authoritative on every later login.
func (p *SSOProvider) RoleForClaims(c *SSOClaims) (string, bool) {
	for _, m := range p.GroupRoleMappings {
		if hasGroup(c.Groups, m.Group) {
			return m.RoleID, true
		}
	}
	if p.DefaultRoleID != nil {
		return *p.DefaultRoleID, false
	}
	return "", false
}

func hasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g), want) {
			return true
		}
	}
	return false
}
