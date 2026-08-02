package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// OIDC single sign-on for the admin panel (#227).
//
// The flow is authorization-code with PKCE, run entirely server-side: the client
// secret never reaches a browser, and what the browser finally receives is an
// ordinary NPG session token. Everything downstream — auth middleware, RBAC,
// audit — is unchanged and unaware that SSO exists.

var (
	ErrSSOUnavailable   = errors.New("sso is not configured")
	ErrSSOProviderGone  = errors.New("unknown or disabled provider")
	ErrSSOStateInvalid  = errors.New("the sign-in request expired or was already used")
	ErrSSONoAccount     = errors.New("no account is linked to this identity")
	ErrSSONotAllowed    = errors.New("this identity is not permitted to sign in")
	ErrSSOEmailMissing  = errors.New("the provider returned no email address")
	ErrSSODiscovery     = errors.New("could not reach the identity provider")
	ErrSSOTokenInvalid  = errors.New("the identity provider's response could not be verified")
	ErrSSOProviderInUse = errors.New("provider not found")
)

// discoveryTTL bounds how long a cached OIDC discovery document is reused. Short
// enough that a rotated JWKS endpoint recovers on its own, long enough that a
// login is not a round-trip to the IdP's well-known endpoint every time.
const discoveryTTL = time.Hour

type cachedDiscovery struct {
	provider *oidc.Provider
	fetched  time.Time
}

type SSOService struct {
	repo  *repository.SSORepository
	users *repository.UserRepository
	roles *repository.RoleRepository
	auth  *AuthService
	audit *AuditService

	mu        sync.Mutex
	discovery map[string]cachedDiscovery
}

func NewSSOService(repo *repository.SSORepository, users *repository.UserRepository,
	roles *repository.RoleRepository, auth *AuthService, audit *AuditService) *SSOService {
	return &SSOService{
		repo: repo, users: users, roles: roles, auth: auth, audit: audit,
		discovery: make(map[string]cachedDiscovery),
	}
}

// Available reports whether the SSO schema exists. Migrations warn-and-continue
// in this codebase, so an install whose upgrade failed must behave as "no
// providers" rather than erroring on the login screen.
func (s *SSOService) Available(ctx context.Context) bool {
	return s.repo.TablesExist(ctx)
}

// ── login flow ────────────────────────────────────────────────────────────

// StartLogin creates the CSRF/PKCE state and returns the IdP URL to redirect to.
func (s *SSOService) StartLogin(ctx context.Context, slug, callbackBase string) (string, error) {
	if !s.Available(ctx) {
		return "", ErrSSOUnavailable
	}
	p, err := s.repo.GetEnabledBySlug(ctx, slug)
	if err != nil {
		return "", err
	}
	if p == nil {
		return "", ErrSSOProviderGone
	}

	cfg, err := s.oauthConfig(ctx, p, callbackBase)
	if err != nil {
		return "", err
	}

	state, err := randomToken(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()

	if err := s.repo.SaveLoginState(ctx, state, p.ID, nonce, verifier, model.SSOLoginStateTTL); err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// CompleteLogin verifies the callback and returns a session token.
func (s *SSOService) CompleteLogin(ctx context.Context, slug, code, state, callbackBase, ip, userAgent string) (string, error) {
	if !s.Available(ctx) {
		return "", ErrSSOUnavailable
	}
	// The state is deleted as it is read, so a replayed callback finds nothing.
	providerID, nonce, verifier, err := s.repo.ConsumeLoginState(ctx, state)
	if err != nil {
		return "", err
	}
	if providerID == "" {
		return "", ErrSSOStateInvalid
	}

	p, err := s.repo.GetEnabledBySlug(ctx, slug)
	if err != nil {
		return "", err
	}
	// The state belongs to one provider; a callback arriving on a different
	// provider's URL is a mix-up attack, not a routing accident.
	if p == nil || p.ID != providerID {
		return "", ErrSSOProviderGone
	}

	cfg, err := s.oauthConfig(ctx, p, callbackBase)
	if err != nil {
		return "", err
	}
	token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		log.Printf("SSO: code exchange failed for provider %q: %v", p.Slug, err)
		return "", ErrSSOTokenInvalid
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", ErrSSOTokenInvalid
	}

	discovered, err := s.discover(ctx, p.IssuerURL)
	if err != nil {
		return "", err
	}
	idToken, err := discovered.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("SSO: id_token verification failed for provider %q: %v", p.Slug, err)
		return "", ErrSSOTokenInvalid
	}
	if idToken.Nonce != nonce {
		log.Printf("SSO: nonce mismatch for provider %q", p.Slug)
		return "", ErrSSOTokenInvalid
	}

	claims, err := extractClaims(idToken, p.GroupClaim)
	if err != nil {
		return "", err
	}
	if claims.Subject == "" {
		return "", ErrSSOTokenInvalid
	}

	userID, username, err := s.resolveUser(ctx, p, claims)
	if err != nil {
		return "", err
	}
	if err := s.repo.LinkIdentity(ctx, p.ID, claims.Subject, userID, claims.Email); err != nil {
		return "", err
	}

	resp, err := s.auth.CreateSessionForUser(ctx, userID, ip, userAgent)
	if err != nil {
		return "", err
	}
	if s.audit != nil {
		// Same string keys the password login path uses, so the audit row names
		// the actor instead of falling back to "system".
		auditCtx := context.WithValue(ctx, "user_id", userID)
		auditCtx = context.WithValue(auditCtx, "username", username)
		auditCtx = context.WithValue(auditCtx, "client_ip", ip)
		auditCtx = context.WithValue(auditCtx, "user_agent", userAgent)
		_ = s.audit.LogUserLogin(auditCtx, username, ip, userAgent)
	}
	return resp.Token, nil
}

// resolveUser maps a verified identity onto an account, provisioning one only
// when the provider's allowlist permits it. Order matters and is deliberate:
// the stable subject first, then a one-time link by verified email, then
// creation, then refusal.
func (s *SSOService) resolveUser(ctx context.Context, p *model.SSOProvider, c *model.SSOClaims) (userID, username string, err error) {
	if id, err := s.repo.FindUserBySubject(ctx, p.ID, c.Subject); err != nil {
		return "", "", err
	} else if id != "" {
		u, err := s.users.GetSummary(ctx, id)
		if err != nil {
			return "", "", err
		}
		if u == nil {
			return "", "", ErrSSONoAccount
		}
		s.syncRole(ctx, p, c, u)
		return id, u.Username, nil
	}

	// Linking an existing account by email is how the operator's own account
	// gains SSO without losing its history. An unverified address must never
	// match: an IdP that lets a user set an arbitrary email would otherwise
	// hand over any existing NPG account.
	if c.Email != "" && c.EmailVerified {
		if id, err := s.repo.FindUserByEmail(ctx, c.Email); err != nil {
			return "", "", err
		} else if id != "" {
			u, err := s.users.GetSummary(ctx, id)
			if err != nil {
				return "", "", err
			}
			if u == nil {
				return "", "", ErrSSONoAccount
			}
			log.Printf("SSO: linking existing account %q to provider %q by verified email", u.Username, p.Slug)
			s.syncRole(ctx, p, c, u)
			return id, u.Username, nil
		}
	}

	if !p.AllowJIT {
		return "", "", ErrSSONoAccount
	}
	if c.Email == "" {
		return "", "", ErrSSOEmailMissing
	}
	if !p.AllowedByList(c) {
		return "", "", ErrSSONotAllowed
	}
	return s.provision(ctx, p, c)
}

// provision creates an account for an identity that passed the allowlist.
func (s *SSOService) provision(ctx context.Context, p *model.SSOProvider, c *model.SSOClaims) (string, string, error) {
	roleID, _ := p.RoleForClaims(c)
	if roleID == "" {
		return "", "", ErrSSONotAllowed
	}
	role, err := s.roles.GetByID(ctx, roleID)
	if err != nil {
		return "", "", err
	}
	if role == nil {
		return "", "", fmt.Errorf("the role this provider assigns no longer exists")
	}

	username, err := s.uniqueUsername(ctx, c)
	if err != nil {
		return "", "", err
	}

	// users.password_hash is NOT NULL and local login must never succeed for a
	// provisioned account, so the hash is of bytes nobody holds.
	secret, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	id, err := s.users.CreateFederated(ctx, username, c.Email, string(hash), roleID, role.IsSuperuser)
	if err != nil {
		return "", "", err
	}
	log.Printf("SSO: provisioned account %q with role %q from provider %q", username, role.Name, p.Slug)
	if s.audit != nil {
		_ = s.audit.LogUserCreate(ctx, username, role.Name)
	}
	return id, username, nil
}

// syncRole re-applies a group mapping on every login, which is what makes
// revoking a group at the IdP take effect. It is a no-op unless the provider
// actually has mappings — otherwise NPG stays the authority on roles.
func (s *SSOService) syncRole(ctx context.Context, p *model.SSOProvider, c *model.SSOClaims, u *model.UserSummary) {
	if len(p.GroupRoleMappings) == 0 {
		return
	}
	roleID, fromGroup := p.RoleForClaims(c)
	if !fromGroup || roleID == "" {
		return
	}
	if u.RoleID != nil && *u.RoleID == roleID {
		return
	}
	role, err := s.roles.GetByID(ctx, roleID)
	if err != nil || role == nil {
		log.Printf("SSO: cannot sync role for %q: mapped role is missing", u.Username)
		return
	}
	// Reuse the #222 invariant: the install must keep at least one superuser, so
	// a group change must not be able to strand it.
	if u.IsSuperuser && !role.IsSuperuser {
		if n, err := s.roles.CountSuperusers(ctx); err == nil && n <= 1 {
			log.Printf("SSO: keeping %q as a superuser — demoting the last one would lock the install out", u.Username)
			return
		}
	}
	if err := s.users.AssignRole(ctx, u.ID, roleID, role.IsSuperuser); err != nil {
		log.Printf("SSO: failed to sync role for %q: %v", u.Username, err)
		return
	}
	log.Printf("SSO: %q moved to role %q by group mapping", u.Username, role.Name)
	if s.audit != nil {
		_ = s.audit.LogUserRoleAssign(ctx, u.Username, role.Name)
	}
}

// uniqueUsername derives a username from the claims and disambiguates it, since
// two identity providers can legitimately carry the same preferred_username.
func (s *SSOService) uniqueUsername(ctx context.Context, c *model.SSOClaims) (string, error) {
	base := strings.TrimSpace(c.Username)
	if base == "" {
		if at := strings.Index(c.Email, "@"); at > 0 {
			base = c.Email[:at]
		}
	}
	base = sanitiseUsername(base)
	if base == "" {
		base = "user"
	}
	candidate := base
	for i := 2; i < 100; i++ {
		taken, err := s.users.UsernameTaken(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !taken {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s%d", base, i)
	}
	return "", fmt.Errorf("could not derive an unused username from the identity")
}

func sanitiseUsername(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	return b.String()
}

// ── OIDC plumbing ─────────────────────────────────────────────────────────

func (s *SSOService) oauthConfig(ctx context.Context, p *model.SSOProvider, callbackBase string) (*oauth2.Config, error) {
	discovered, err := s.discover(ctx, p.IssuerURL)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     discovered.Endpoint(),
		RedirectURL:  CallbackURL(callbackBase, p),
		Scopes:       strings.Fields(p.Scopes),
	}, nil
}

// CallbackURL is the exact redirect_uri the IdP must have registered. The
// provider's own base wins when set, so an install behind a proxy can pin the
// public URL instead of relying on request headers.
func CallbackURL(requestBase string, p *model.SSOProvider) string {
	base := p.CallbackBaseURL
	if base == "" {
		base = requestBase
	}
	return strings.TrimRight(base, "/") + "/api/v1/auth/sso/" + p.Slug + "/callback"
}

func (s *SSOService) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s.mu.Lock()
	if hit, ok := s.discovery[issuer]; ok && time.Since(hit.fetched) < discoveryTTL {
		s.mu.Unlock()
		return hit.provider, nil
	}
	s.mu.Unlock()

	provider, err := oidc.NewProvider(ctx, strings.TrimRight(issuer, "/"))
	if err != nil {
		log.Printf("SSO: discovery failed for %s: %v", issuer, err)
		return nil, ErrSSODiscovery
	}
	s.mu.Lock()
	s.discovery[issuer] = cachedDiscovery{provider: provider, fetched: time.Now()}
	s.mu.Unlock()
	return provider, nil
}

// forgetDiscovery drops a cached document so an edited issuer takes effect at
// once rather than after the TTL.
func (s *SSOService) forgetDiscovery(issuer string) {
	s.mu.Lock()
	delete(s.discovery, issuer)
	s.mu.Unlock()
}

// extractClaims reads the subset of the ID token the flow acts on. The group
// claim is configurable, so claims are decoded generically rather than into a
// fixed struct, and both a list and a single string are accepted — IdPs differ.
func extractClaims(idToken *oidc.IDToken, groupClaim string) (*model.SSOClaims, error) {
	raw := map[string]any{}
	if err := idToken.Claims(&raw); err != nil {
		return nil, ErrSSOTokenInvalid
	}
	c := &model.SSOClaims{Subject: idToken.Subject}
	c.Email, _ = raw["email"].(string)
	switch v := raw["email_verified"].(type) {
	case bool:
		c.EmailVerified = v
	case string:
		c.EmailVerified = v == "true"
	}
	c.Name, _ = raw["name"].(string)
	if u, ok := raw["preferred_username"].(string); ok {
		c.Username = u
	}
	switch v := raw[groupClaim].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok {
				c.Groups = append(c.Groups, s)
			}
		}
	case []string:
		c.Groups = v
	case string:
		c.Groups = []string{v}
	}
	return c, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ── administration ────────────────────────────────────────────────────────

// ListProviders returns every provider with its secret masked.
func (s *SSOService) ListProviders(ctx context.Context) ([]model.SSOProvider, error) {
	if !s.Available(ctx) {
		return []model.SSOProvider{}, nil
	}
	list, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].ClientSecret = model.SecretPlaceholder
	}
	return list, nil
}

func (s *SSOService) CreateProvider(ctx context.Context, req *model.CreateSSOProviderRequest) (*model.SSOProvider, error) {
	if !s.Available(ctx) {
		return nil, ErrSSOUnavailable
	}
	if err := req.Validate(true); err != nil {
		return nil, err
	}
	if err := s.checkRoleRefs(ctx, req); err != nil {
		return nil, err
	}
	id, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return s.getMasked(ctx, id)
}

func (s *SSOService) UpdateProvider(ctx context.Context, id string, req *model.UpdateSSOProviderRequest) (*model.SSOProvider, error) {
	if !s.Available(ctx) {
		return nil, ErrSSOUnavailable
	}
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrSSOProviderInUse
	}
	// The UI round-trips the masked marker; treat it as "leave it alone" so an
	// edit of an unrelated field cannot blank the secret.
	if req.ClientSecret == model.SecretPlaceholder {
		req.ClientSecret = ""
	}
	if err := req.Validate(false); err != nil {
		return nil, err
	}
	if err := s.checkRoleRefs(ctx, req); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, id, req); err != nil {
		return nil, err
	}
	s.forgetDiscovery(existing.IssuerURL)
	s.forgetDiscovery(req.IssuerURL)
	return s.getMasked(ctx, id)
}

func (s *SSOService) DeleteProvider(ctx context.Context, id string) error {
	if !s.Available(ctx) {
		return ErrSSOUnavailable
	}
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrSSOProviderInUse
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.forgetDiscovery(existing.IssuerURL)
	return nil
}

// ListPublic backs the login screen. It is reachable without authentication, so
// it must never leak issuer, client id or allowlist detail.
func (s *SSOService) ListPublic(ctx context.Context) ([]model.PublicSSOProvider, error) {
	if !s.Available(ctx) {
		return []model.PublicSSOProvider{}, nil
	}
	return s.repo.ListEnabledPublic(ctx)
}

func (s *SSOService) getMasked(ctx context.Context, id string) (*model.SSOProvider, error) {
	p, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrSSOProviderInUse
	}
	p.ClientSecret = model.SecretPlaceholder
	return p, nil
}

// checkRoleRefs refuses a provider that points at a role which does not exist,
// so the failure surfaces while editing rather than at someone's first login.
func (s *SSOService) checkRoleRefs(ctx context.Context, req *model.CreateSSOProviderRequest) error {
	ids := []string{}
	if req.DefaultRoleID != nil && *req.DefaultRoleID != "" {
		ids = append(ids, *req.DefaultRoleID)
	}
	for _, m := range req.GroupRoleMappings {
		ids = append(ids, m.RoleID)
	}
	for _, id := range ids {
		role, err := s.roles.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if role == nil {
			return fmt.Errorf("invalid role: %s does not exist", id)
		}
	}
	return nil
}

// CleanupLoginStates drops expired login states; called by the session cleanup
// scheduler so half-finished sign-ins do not accumulate.
func (s *SSOService) CleanupLoginStates(ctx context.Context) (int64, error) {
	if !s.Available(ctx) {
		return 0, nil
	}
	return s.repo.DeleteExpiredLoginStates(ctx)
}
