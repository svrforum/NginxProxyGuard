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

	// notify is optional: nil means notifications are not configured.
	notify *NotificationService
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

// StartLogin creates the CSRF/PKCE state and returns the IdP URL to redirect to,
// along with the state itself so the handler can bind it to this browser.
func (s *SSOService) StartLogin(ctx context.Context, slug, callbackBase string) (authURL, state string, err error) {
	if !s.Available(ctx) {
		return "", "", ErrSSOUnavailable
	}
	p, err := s.repo.GetEnabledBySlug(ctx, slug)
	if err != nil {
		return "", "", err
	}
	if p == nil {
		return "", "", ErrSSOProviderGone
	}

	cfg, err := s.oauthConfig(ctx, p, callbackBase)
	if err != nil {
		return "", "", err
	}

	state, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	verifier := oauth2.GenerateVerifier()

	if err := s.repo.SaveLoginState(ctx, state, p.ID, nonce, verifier, model.SSOLoginStateTTL); err != nil {
		return "", "", err
	}
	return cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), state, nil
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

	claims, idTokenStatedVerified, err := extractClaims(idToken, p.GroupClaim)
	if err != nil {
		return "", err
	}
	if claims.Subject == "" {
		return "", ErrSSOTokenInvalid
	}
	// Whatever the ID token did not carry, ask the provider for. (#238)
	s.mergeUserInfoClaims(ctx, discovered, token, claims, p.GroupClaim, idTokenStatedVerified)

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
		// Say which condition stopped it. "No account is linked" is true but
		// useless on its own: the operator cannot tell whether the provider sent
		// no email, sent one it did not mark verified, or sent one that matches
		// no local account — and those need three different fixes. The address
		// itself is never logged; this runs on a public-facing box.
		log.Printf("SSO: no account for provider %q — email present=%t, verified=%t, jit=off. "+
			"Linking requires a VERIFIED email matching an existing account.",
			p.Slug, c.Email != "", c.EmailVerified)
		// Refused for the commonest reason of all — JIT provisioning is off by
		// default, so this is the branch a first SSO attempt actually takes.
		// Reporting only the allowlist branch below meant the event could not
		// fire on a default install, and an operator watching for "SSO sign-in
		// refused" saw nothing while people were being turned away.
		s.emitRefusal(ctx, p.Slug, "no_local_account")
		return "", "", ErrSSONoAccount
	}
	if c.Email == "" {
		s.emitRefusal(ctx, p.Slug, "no_verified_email")
		return "", "", ErrSSOEmailMissing
	}
	if !p.AllowedByList(c) {
		s.emitRefusal(ctx, p.Slug, "not_on_allowlist")
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

// toggleTrailingSlash returns the issuer in its other shape, or "" when there
// is no second shape worth trying (an empty issuer, or one that is only "/").
func toggleTrailingSlash(issuer string) string {
	if trimmed := strings.TrimRight(issuer, "/"); trimmed == "" {
		return ""
	} else if trimmed != issuer {
		return trimmed
	}
	return issuer + "/"
}

func (s *SSOService) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s.mu.Lock()
	if hit, ok := s.discovery[issuer]; ok && time.Since(hit.fetched) < discoveryTTL {
		s.mu.Unlock()
		return hit.provider, nil
	}
	s.mu.Unlock()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		// The spec makes the issuer an exact string, so a stray trailing slash
		// is a mismatch rather than a typo the library can absorb — and which
		// shape is right depends on the provider: Authentik's document carries
		// the slash, Dex's does not. Rather than pick a side and break the
		// other, try the value as configured, then the other shape.
		if alt := toggleTrailingSlash(issuer); alt != "" {
			if p, altErr := oidc.NewProvider(ctx, alt); altErr == nil {
				log.Printf("SSO: issuer %q matched the provider only as %q — save it in that form to skip this retry", issuer, alt)
				provider, err = p, nil
			}
		}
	}
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
func extractClaims(idToken *oidc.IDToken, groupClaim string) (*model.SSOClaims, bool, error) {
	raw := map[string]any{}
	if err := idToken.Claims(&raw); err != nil {
		return nil, false, ErrSSOTokenInvalid
	}
	c, statedVerified := claimsFromMap(raw, idToken.Subject, groupClaim)
	return c, statedVerified, nil
}

// claimsFromMap turns a decoded claim set into what the flow acts on.
//
// The second return says whether email_verified was STATED, which is not the
// same as it being true. The claim is optional in OIDC, and a provider that
// omits it from the ID token may still assert it at UserInfo — so the caller
// has to tell "said false" from "said nothing" to know whether it may look
// elsewhere. (#248)
func claimsFromMap(raw map[string]any, subject, groupClaim string) (*model.SSOClaims, bool) {
	c := &model.SSOClaims{Subject: subject}
	c.Email, _ = raw["email"].(string)
	verifiedStated := false
	switch v := raw["email_verified"].(type) {
	case bool:
		c.EmailVerified, verifiedStated = v, true
	case string:
		c.EmailVerified, verifiedStated = v == "true", true
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
	return c, verifiedStated
}

// mergeUserInfoClaims fills in what the ID token did not carry, by asking the
// provider's UserInfo endpoint.
//
// Not an optimisation — for some providers it is the only way the claims
// arrive. Authelia's default claims policy puts email, name and groups in the
// UserInfo response and NOT in the ID token, so reading the ID token alone left
// Email empty: account linking could never match, and JIT refused every sign-in
// for a missing email. OIDC expects a client to fetch claims it needs from
// UserInfo when they are absent from the token. (#238)
//
// Failure is not fatal. A provider may not implement UserInfo, or the token may
// not carry the scope for it, and those installs worked before this existed.
func (s *SSOService) mergeUserInfoClaims(ctx context.Context, provider *oidc.Provider, token *oauth2.Token, claims *model.SSOClaims, groupClaim string, idTokenStatedVerified bool) {
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		log.Printf("SSO: userinfo lookup skipped: %v", err)
		return
	}
	// Required by the spec: a UserInfo response whose subject differs is not
	// about this user and must not be applied.
	if info.Subject != claims.Subject {
		log.Printf("SSO: userinfo subject does not match the id_token subject — ignoring the response")
		return
	}

	raw := map[string]any{}
	if err := info.Claims(&raw); err != nil {
		log.Printf("SSO: userinfo claims could not be decoded: %v", err)
		return
	}
	extra, extraStatedVerified := claimsFromMap(raw, claims.Subject, groupClaim)

	// The ID token is signed and wins wherever it said something. UserInfo only
	// fills gaps.
	if claims.Email == "" && extra.Email != "" {
		claims.Email, claims.EmailVerified = extra.Email, extra.EmailVerified
	} else if claims.Email != "" && !idTokenStatedVerified && extraStatedVerified &&
		strings.EqualFold(claims.Email, extra.Email) {
		// The ID token carried the address but said nothing about whether it is
		// verified — email_verified is optional in OIDC, and a provider may put
		// the address in the token and the verification flag only at UserInfo.
		// Treating "unstated" as "false" refused those sign-ins with no way for
		// the operator to tell it from a genuinely unverified address. (#248)
		//
		// Only when the two addresses agree: a UserInfo response must not be
		// able to mark a DIFFERENT address as verified, and an explicit false in
		// the signed token is never overridden.
		claims.EmailVerified = extra.EmailVerified
	}
	if claims.Name == "" {
		claims.Name = extra.Name
	}
	if claims.Username == "" {
		claims.Username = extra.Username
	}
	if len(claims.Groups) == 0 {
		claims.Groups = extra.Groups
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SSODiscoveryResult reports what an issuer advertises, so an operator learns
// about a typo while editing rather than when somebody first tries to sign in.
type SSODiscoveryResult struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
	SupportsPKCE          bool     `json:"supports_pkce"`
	MissingScopes         []string `json:"missing_scopes"`
}

// TestDiscovery fetches an issuer's discovery document and reports what it
// found. The issuer is validated exactly as it is on save, so this cannot be
// used to reach a host a provider could not have been pointed at anyway — and
// the caller already holds user:write, which can trigger the same outbound
// request simply by saving a provider and signing in.
func (s *SSOService) TestDiscovery(ctx context.Context, issuer, scopes string) (*SSODiscoveryResult, error) {
	probe := &model.CreateSSOProviderRequest{
		Slug: "probe", Name: "probe", IssuerURL: issuer,
		ClientID: "probe", ClientSecret: "probe", Scopes: scopes,
	}
	if err := probe.Validate(true); err != nil {
		return nil, err
	}

	// Deliberately bypasses the cache: the point of pressing Test is to find out
	// what the issuer says right now.
	s.forgetDiscovery(probe.IssuerURL)
	provider, err := s.discover(ctx, probe.IssuerURL)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		ScopesSupported       []string `json:"scopes_supported"`
		CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&doc); err != nil {
		return nil, ErrSSODiscovery
	}

	out := &SSODiscoveryResult{
		Issuer:                doc.Issuer,
		AuthorizationEndpoint: doc.AuthorizationEndpoint,
		TokenEndpoint:         doc.TokenEndpoint,
		ScopesSupported:       doc.ScopesSupported,
	}
	for _, m := range doc.CodeChallengeMethods {
		if m == "S256" {
			out.SupportsPKCE = true
		}
	}
	// Only report a scope as missing when the issuer actually publishes a list;
	// plenty of providers omit scopes_supported and still honour the scopes.
	if len(doc.ScopesSupported) > 0 {
		for _, want := range strings.Fields(probe.Scopes) {
			found := false
			for _, have := range doc.ScopesSupported {
				if have == want {
					found = true
					break
				}
			}
			if !found {
				out.MissingScopes = append(out.MissingScopes, want)
			}
		}
	}
	return out, nil
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

// SetNotificationService wires notifications after construction. (#221)
func (s *SSOService) SetNotificationService(n *NotificationService) { s.notify = n }

// emitRefusal reports an SSO sign-in that was turned away.
//
// Batched (#221): a misconfigured allowlist rejects everyone who tries, and a
// scripted attempt would otherwise produce one message per try.
func (s *SSOService) emitRefusal(ctx context.Context, providerSlug, reason string) {
	if s.notify == nil {
		return
	}
	_ = s.notify.EmitBatched(ctx, "sso.login_refused", map[string]string{
		"subject": providerSlug, "reason": reason,
	})
}
