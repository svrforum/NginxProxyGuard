package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// SSORepository owns the OIDC provider registry, the identity links and the
// short-lived login states. (#227)
type SSORepository struct {
	db *database.DB
}

func NewSSORepository(db *database.DB) *SSORepository {
	return &SSORepository{db: db}
}

const ssoProviderColumns = `id, slug, name, issuer_url, client_id, client_secret, scopes,
	COALESCE(callback_base_url, ''), enabled, allow_jit, trust_provider_email, allowed_email_domains, allowed_emails,
	group_claim, COALESCE(required_group, ''), default_role_id, group_role_mappings, created_at, updated_at`

func scanProvider(s interface{ Scan(...any) error }) (*model.SSOProvider, error) {
	var p model.SSOProvider
	var defaultRole sql.NullString
	var mappings []byte
	if err := s.Scan(&p.ID, &p.Slug, &p.Name, &p.IssuerURL, &p.ClientID, &p.ClientSecret, &p.Scopes,
		&p.CallbackBaseURL, &p.Enabled, &p.AllowJIT, &p.TrustProviderEmail, &p.AllowedEmailDomains, &p.AllowedEmails,
		&p.GroupClaim, &p.RequiredGroup, &defaultRole, &mappings, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	if defaultRole.Valid {
		p.DefaultRoleID = &defaultRole.String
	}
	if len(mappings) > 0 {
		if err := json.Unmarshal(mappings, &p.GroupRoleMappings); err != nil {
			return nil, fmt.Errorf("failed to decode group_role_mappings: %w", err)
		}
	}
	return &p, nil
}

// List returns every provider with its linked-account count, for the admin UI.
func (r *SSORepository) List(ctx context.Context) ([]model.SSOProvider, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+ssoProviderColumns+`,
		(SELECT count(*) FROM user_identities i WHERE i.provider_id = p.id)
		FROM sso_providers p ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to list sso providers: %w", err)
	}
	defer rows.Close()

	out := []model.SSOProvider{}
	for rows.Next() {
		var p model.SSOProvider
		var defaultRole sql.NullString
		var mappings []byte
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.IssuerURL, &p.ClientID, &p.ClientSecret, &p.Scopes,
			&p.CallbackBaseURL, &p.Enabled, &p.AllowJIT, &p.TrustProviderEmail, &p.AllowedEmailDomains, &p.AllowedEmails,
			&p.GroupClaim, &p.RequiredGroup, &defaultRole, &mappings, &p.CreatedAt, &p.UpdatedAt,
			&p.LinkedUsers); err != nil {
			return nil, fmt.Errorf("failed to scan sso provider: %w", err)
		}
		if defaultRole.Valid {
			p.DefaultRoleID = &defaultRole.String
		}
		if len(mappings) > 0 {
			if err := json.Unmarshal(mappings, &p.GroupRoleMappings); err != nil {
				return nil, fmt.Errorf("failed to decode group_role_mappings: %w", err)
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListEnabledPublic is what the unauthenticated login screen reads. It returns
// only what a button needs — never the issuer, client id or allowlist.
func (r *SSORepository) ListEnabledPublic(ctx context.Context) ([]model.PublicSSOProvider, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, slug, name FROM sso_providers WHERE enabled ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to list enabled sso providers: %w", err)
	}
	defer rows.Close()

	out := []model.PublicSSOProvider{}
	for rows.Next() {
		var p model.PublicSSOProvider
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name); err != nil {
			return nil, fmt.Errorf("failed to scan sso provider: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *SSORepository) GetByID(ctx context.Context, id string) (*model.SSOProvider, error) {
	p, err := scanProvider(r.db.QueryRowContext(ctx,
		`SELECT `+ssoProviderColumns+` FROM sso_providers WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sso provider: %w", err)
	}
	return p, nil
}

// GetEnabledBySlug is the login path's lookup: a disabled provider must not be
// reachable even by someone who kept the URL.
func (r *SSORepository) GetEnabledBySlug(ctx context.Context, slug string) (*model.SSOProvider, error) {
	p, err := scanProvider(r.db.QueryRowContext(ctx,
		`SELECT `+ssoProviderColumns+` FROM sso_providers WHERE lower(slug) = lower($1) AND enabled`, slug))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sso provider: %w", err)
	}
	return p, nil
}

func (r *SSORepository) Create(ctx context.Context, req *model.CreateSSOProviderRequest) (string, error) {
	mappings, err := json.Marshal(req.GroupRoleMappings)
	if err != nil {
		return "", fmt.Errorf("failed to encode group_role_mappings: %w", err)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var id string
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO sso_providers (slug, name, issuer_url, client_id, client_secret, scopes,
			callback_base_url, enabled, allow_jit, trust_provider_email, allowed_email_domains, allowed_emails,
			group_claim, required_group, default_role_id, group_role_mappings)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12,$13,NULLIF($14,''),$15,$16)
		RETURNING id`,
		req.Slug, req.Name, req.IssuerURL, req.ClientID, req.ClientSecret, req.Scopes,
		req.CallbackBaseURL, enabled, req.AllowJIT, req.TrustProviderEmail, pq.Array(req.AllowedEmailDomains), pq.Array(req.AllowedEmails),
		req.GroupClaim, req.RequiredGroup, req.DefaultRoleID, mappings).Scan(&id)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return "", fmt.Errorf("a provider with this slug already exists")
		}
		return "", fmt.Errorf("failed to create sso provider: %w", err)
	}
	return id, nil
}

// Update rewrites a provider. An empty secret leaves the stored one in place so
// the UI can round-trip a masked value without the operator retyping it.
func (r *SSORepository) Update(ctx context.Context, id string, req *model.UpdateSSOProviderRequest) error {
	mappings, err := json.Marshal(req.GroupRoleMappings)
	if err != nil {
		return fmt.Errorf("failed to encode group_role_mappings: %w", err)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE sso_providers SET
			slug = $2, name = $3, issuer_url = $4, client_id = $5,
			client_secret = COALESCE(NULLIF($6, ''), client_secret),
			scopes = $7, callback_base_url = NULLIF($8,''), enabled = $9, allow_jit = $10,
			trust_provider_email = $11,
			allowed_email_domains = $12, allowed_emails = $13, group_claim = $14,
			required_group = NULLIF($15,''), default_role_id = $16, group_role_mappings = $17,
			updated_at = now()
		WHERE id = $1`,
		id, req.Slug, req.Name, req.IssuerURL, req.ClientID, req.ClientSecret, req.Scopes,
		req.CallbackBaseURL, enabled, req.AllowJIT, req.TrustProviderEmail, pq.Array(req.AllowedEmailDomains), pq.Array(req.AllowedEmails),
		req.GroupClaim, req.RequiredGroup, req.DefaultRoleID, mappings)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("a provider with this slug already exists")
		}
		return fmt.Errorf("failed to update sso provider: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes a provider. user_identities cascade with it, which unlinks the
// accounts but never deletes them — losing SSO must not lose the account.
func (r *SSORepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sso_providers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete sso provider: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ── identities ────────────────────────────────────────────────────────────

// FindUserBySubject resolves the stable (provider, sub) pair to an account.
func (r *SSORepository) FindUserBySubject(ctx context.Context, providerID, subject string) (string, error) {
	var userID string
	err := r.db.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities WHERE provider_id = $1 AND subject = $2`,
		providerID, subject).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to look up identity: %w", err)
	}
	return userID, nil
}

// FindUserByEmail backs the one-time link of an existing account. Callers must
// only reach it with a verified email.
func (r *SSORepository) FindUserByEmail(ctx context.Context, email string) (string, error) {
	// Two rows can only happen on an install that held a case-differing pair
	// before idx_users_email_lower existed, where the index could not be built.
	// Handing back either one would link an identity to an account nobody chose,
	// so refuse and let the operator resolve the duplicate. (#240)
	var userID string
	var matches int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*), coalesce(min(id::text), '')
		FROM users WHERE lower(email) = lower($1)`, email).Scan(&matches, &userID)
	if err != nil {
		return "", fmt.Errorf("failed to look up user by email: %w", err)
	}
	switch matches {
	case 0:
		return "", nil
	case 1:
		return userID, nil
	default:
		return "", fmt.Errorf("refusing to link: %d accounts share this email address (case-insensitively) — remove the duplicate", matches)
	}
}

// LinkIdentity records the (provider, sub) → user link and stamps the sign-in.
func (r *SSORepository) LinkIdentity(ctx context.Context, providerID, subject, userID, email string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_identities (provider_id, subject, user_id, email, last_login_at)
		VALUES ($1,$2,$3,NULLIF($4,''),now())
		ON CONFLICT (provider_id, subject)
		DO UPDATE SET email = EXCLUDED.email, last_login_at = now()`,
		providerID, subject, userID, email)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("this account is already linked to a different identity on that provider")
		}
		return fmt.Errorf("failed to link identity: %w", err)
	}
	return nil
}

// ── login state ───────────────────────────────────────────────────────────

func (r *SSORepository) SaveLoginState(ctx context.Context, state, providerID, nonce, verifier string, ttl time.Duration) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sso_login_states (state, provider_id, nonce, code_verifier, expires_at)
		VALUES ($1,$2,$3,$4, now() + $5::interval)`,
		state, providerID, nonce, verifier, fmt.Sprintf("%d seconds", int(ttl.Seconds())))
	if err != nil {
		return fmt.Errorf("failed to save login state: %w", err)
	}
	return nil
}

// ConsumeLoginState reads a state and deletes it in the same statement, so a
// replayed callback finds nothing.
func (r *SSORepository) ConsumeLoginState(ctx context.Context, state string) (providerID, nonce, verifier string, err error) {
	err = r.db.QueryRowContext(ctx, `
		DELETE FROM sso_login_states
		WHERE state = $1 AND expires_at > now()
		RETURNING provider_id, nonce, code_verifier`, state).Scan(&providerID, &nonce, &verifier)
	if err == sql.ErrNoRows {
		return "", "", "", nil
	}
	if err != nil {
		return "", "", "", fmt.Errorf("failed to consume login state: %w", err)
	}
	return providerID, nonce, verifier, nil
}

// DeleteExpiredLoginStates is called by the session cleanup scheduler.
func (r *SSORepository) DeleteExpiredLoginStates(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sso_login_states WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TablesExist reports whether the SSO schema is present. Migrations are
// warn-and-continue in this codebase, so every SSO entry point checks first and
// behaves as "no providers configured" rather than erroring.
func (r *SSORepository) TablesExist(ctx context.Context) bool {
	var ok bool
	err := r.db.QueryRowContext(ctx,
		`SELECT to_regclass('public.sso_providers') IS NOT NULL
		    AND to_regclass('public.user_identities') IS NOT NULL
		    AND to_regclass('public.sso_login_states') IS NOT NULL`).Scan(&ok)
	return err == nil && ok
}
