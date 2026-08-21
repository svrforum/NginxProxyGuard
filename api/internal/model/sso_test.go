package model

import "testing"

func provider(mut func(*SSOProvider)) *SSOProvider {
	p := &SSOProvider{GroupClaim: "groups"}
	if mut != nil {
		mut(p)
	}
	return p
}

// The allowlist is the only thing standing between a public IdP and the panel,
// so "no restriction configured" must mean nobody, never everybody.
func TestAllowedByList(t *testing.T) {
	tests := []struct {
		name   string
		p      *SSOProvider
		claims *SSOClaims
		want   bool
	}{
		{
			name:   "nothing configured refuses everyone",
			p:      provider(nil),
			claims: &SSOClaims{Email: "someone@example.com"},
			want:   false,
		},
		{
			name:   "listed email passes",
			p:      provider(func(p *SSOProvider) { p.AllowedEmails = []string{"admin@example.com"} }),
			claims: &SSOClaims{Email: "Admin@Example.com"},
			want:   true,
		},
		{
			name:   "unlisted email is refused",
			p:      provider(func(p *SSOProvider) { p.AllowedEmails = []string{"admin@example.com"} }),
			claims: &SSOClaims{Email: "stranger@example.com"},
			want:   false,
		},
		{
			name:   "listed domain passes",
			p:      provider(func(p *SSOProvider) { p.AllowedEmailDomains = []string{"example.com"} }),
			claims: &SSOClaims{Email: "anyone@example.com"},
			want:   true,
		},
		{
			name:   "lookalike domain is refused",
			p:      provider(func(p *SSOProvider) { p.AllowedEmailDomains = []string{"example.com"} }),
			claims: &SSOClaims{Email: "anyone@notexample.com"},
			want:   false,
		},
		{
			name:   "required group alone is sufficient",
			p:      provider(func(p *SSOProvider) { p.RequiredGroup = "npg-admins" }),
			claims: &SSOClaims{Email: "someone@anywhere.example", Groups: []string{"npg-admins"}},
			want:   true,
		},
		{
			name:   "required group alone refuses a non-member",
			p:      provider(func(p *SSOProvider) { p.RequiredGroup = "npg-admins" }),
			claims: &SSOClaims{Email: "someone@anywhere.example", Groups: []string{"users"}},
			want:   false,
		},
		{
			name: "domain and required group are ANDed",
			p: provider(func(p *SSOProvider) {
				p.AllowedEmailDomains = []string{"example.com"}
				p.RequiredGroup = "npg-admins"
			}),
			claims: &SSOClaims{Email: "anyone@example.com", Groups: []string{"users"}},
			want:   false,
		},
		{
			name: "domain and required group both satisfied",
			p: provider(func(p *SSOProvider) {
				p.AllowedEmailDomains = []string{"example.com"}
				p.RequiredGroup = "npg-admins"
			}),
			claims: &SSOClaims{Email: "anyone@example.com", Groups: []string{"npg-admins"}},
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AllowedByList(tt.claims); got != tt.want {
				t.Fatalf("AllowedByList = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMeetsRequiredGroup(t *testing.T) {
	p := &SSOProvider{RequiredGroup: "npg-admins"}
	if !p.MeetsRequiredGroup(&SSOClaims{Groups: []string{"users", "NPG-ADMINS"}}) {
		t.Fatal("expected case-insensitive required group match")
	}
	if p.MeetsRequiredGroup(&SSOClaims{Groups: []string{"users"}}) {
		t.Fatal("expected missing required group to be rejected")
	}
	p.RequiredGroup = ""
	if !p.MeetsRequiredGroup(&SSOClaims{}) {
		t.Fatal("provider without a required group should allow the identity")
	}
}

func TestRoleForClaims(t *testing.T) {
	def := "role-default"
	p := &SSOProvider{
		DefaultRoleID: &def,
		GroupRoleMappings: []GroupRoleMapping{
			{Group: "npg-admins", RoleID: "role-admin"},
			{Group: "npg-viewers", RoleID: "role-viewer"},
		},
	}

	t.Run("first matching mapping wins in the admin's order", func(t *testing.T) {
		role, fromGroup := p.RoleForClaims(&SSOClaims{Groups: []string{"npg-viewers", "npg-admins"}})
		if role != "role-admin" || !fromGroup {
			t.Fatalf("got (%q, %v), want (role-admin, true)", role, fromGroup)
		}
	})

	t.Run("no matching group falls back to the default", func(t *testing.T) {
		role, fromGroup := p.RoleForClaims(&SSOClaims{Groups: []string{"unrelated"}})
		if role != "role-default" || fromGroup {
			t.Fatalf("got (%q, %v), want (role-default, false)", role, fromGroup)
		}
	})

	t.Run("no default and no match yields nothing", func(t *testing.T) {
		bare := &SSOProvider{}
		if role, fromGroup := bare.RoleForClaims(&SSOClaims{}); role != "" || fromGroup {
			t.Fatalf("got (%q, %v), want empty", role, fromGroup)
		}
	})
}

func TestValidateRefusesJITWithoutAllowlist(t *testing.T) {
	role := "role-default"
	base := func() *CreateSSOProviderRequest {
		return &CreateSSOProviderRequest{
			Slug: "google", Name: "Google",
			IssuerURL: "https://accounts.google.example", ClientID: "cid", ClientSecret: "secret",
			DefaultRoleID: &role,
		}
	}

	t.Run("JIT with an empty allowlist is refused", func(t *testing.T) {
		r := base()
		r.AllowJIT = true
		if err := r.Validate(true); err == nil {
			t.Fatal("expected the empty allowlist to be refused")
		}
	})

	t.Run("JIT with a domain is accepted", func(t *testing.T) {
		r := base()
		r.AllowJIT = true
		r.AllowedEmailDomains = []string{"@Example.com "}
		if err := r.Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.AllowedEmailDomains) != 1 || r.AllowedEmailDomains[0] != "example.com" {
			t.Fatalf("domain not normalised: %v", r.AllowedEmailDomains)
		}
	})

	t.Run("JIT cannot reach role sync without a default role", func(t *testing.T) {
		r := base()
		r.AllowJIT = true
		r.AllowedEmailDomains = []string{"example.com"}
		r.DefaultRoleID = nil
		r.GroupRoleMappings = []GroupRoleMapping{{Group: "npg-admins", RoleID: "role-admin"}}
		if err := r.Validate(true); err == nil {
			t.Fatal("expected JIT provider without a default role to be refused before login")
		}
	})

	t.Run("no JIT needs no allowlist", func(t *testing.T) {
		if err := base().Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestValidateURLScheme(t *testing.T) {
	role := "r"
	for _, tt := range []struct {
		issuer string
		ok     bool
	}{
		{"https://id.example.com", true},
		{"http://localhost:5556/dex", true},
		{"http://127.0.0.1:5556", true},
		{"http://dex:5556/dex", true},        // compose service name: cannot be public DNS
		{"http://192.168.1.50:9000", true},   // LAN box
		{"http://authentik.local", true},
		{"http://id.example.com", false},     // publicly routable, must be TLS
		{"http://8.8.8.8:9000", false},
		{"not-a-url", false},
	} {
		r := &CreateSSOProviderRequest{
			Slug: "p", Name: "P", IssuerURL: tt.issuer,
			ClientID: "cid", ClientSecret: "s", DefaultRoleID: &role,
		}
		err := r.Validate(true)
		if tt.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tt.issuer, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("%s: expected rejection", tt.issuer)
		}
	}
}
