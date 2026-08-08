package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"nginx-proxy-guard/internal/database/dialect"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// UserRepository is the administrative user surface (#222). It is deliberately
// separate from AuthRepository: that file owns the self-service session, 2FA and
// login-attempt logic and is already large. Session invalidation is reused from
// there rather than duplicated.
type UserRepository struct {
	db *database.DB
}

func NewUserRepository(db *database.DB) *UserRepository {
	return &UserRepository{db: db}
}

// List returns every account with its role name, for the admin table.
func (r *UserRepository) List(ctx context.Context) ([]model.UserSummary, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id, u.username, COALESCE(u.role, 'user'), u.role_id, COALESCE(r.name, ''),
		       COALESCE(r.is_superuser, false), u.totp_enabled, u.must_change_password,
		       u.last_login_at, u.login_count, u.created_at,
		       (SELECT count(*) FROM api_tokens t WHERE t.user_id = u.id)
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		ORDER BY u.username`)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var out []model.UserSummary
	for rows.Next() {
		var u model.UserSummary
		var roleID sql.NullString
		var lastLogin sql.NullTime
		if err := rows.Scan(&u.ID, &u.Username, &u.LegacyRole, &roleID, &u.RoleName,
			&u.IsSuperuser, &u.TOTPEnabled, &u.MustChangePassword,
			&lastLogin, &u.LoginCount, &u.CreatedAt, &u.APITokenCount); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		if roleID.Valid {
			u.RoleID = &roleID.String
		}
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Create inserts an account.
//
// users.email is NOT NULL UNIQUE in the schema but absent from model.User and
// from every other query, so a value must be supplied here. It is derived from
// the username rather than asked for in the UI: NPG never sends mail, and adding
// an email field would ask operators for data the product does not use. The
// username is already unique, so the derived address is too.
func (r *UserRepository) Create(ctx context.Context, username, passwordHash, roleID string, isSuperuser bool) (string, error) {
	legacyRole := "user"
	if isSuperuser {
		legacyRole = "admin" // keeps `server reset-password` able to find admins
	}
	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO users (email, username, password_hash, role, role_id,
		                   is_initial_setup, must_change_password, language, font_family)
		VALUES ($1, $2, $3, $4, $5, false, true, 'ko', 'system')
		RETURNING id`,
		username+"@localhost", username, passwordHash, legacyRole, roleID).Scan(&id)
	if err != nil {
		if dialect.IsUniqueViolation(err) {
			return "", fmt.Errorf("username already exists")
		}
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	return id, nil
}

// CreateFederated inserts an account provisioned from an identity provider.
//
// It differs from Create in two ways that matter. The real email from the IdP is
// stored rather than the username@localhost placeholder, because that address is
// what later links the same person arriving from a second provider. And
// must_change_password stays false: there is no password to change — the hash
// the caller supplies is of bytes nobody holds, so local login for this account
// cannot succeed until an admin resets it. (#227)
func (r *UserRepository) CreateFederated(ctx context.Context, username, email, passwordHash, roleID string, isSuperuser bool) (string, error) {
	legacyRole := "user"
	if isSuperuser {
		legacyRole = "admin"
	}
	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO users (email, username, password_hash, role, role_id,
		                   is_initial_setup, must_change_password, language, font_family)
		VALUES ($1, $2, $3, $4, $5, false, false, 'ko', 'system')
		RETURNING id`,
		email, username, passwordHash, legacyRole, roleID).Scan(&id)
	if err != nil {
		if dialect.IsUniqueViolation(err) {
			return "", fmt.Errorf("an account with this username or email already exists")
		}
		return "", fmt.Errorf("failed to create federated user: %w", err)
	}
	return id, nil
}

// UsernameTaken backs the disambiguation of a username derived from IdP claims.
func (r *UserRepository) UsernameTaken(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) = lower($1))`, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check username: %w", err)
	}
	return exists, nil
}

// AssignRole moves an account to a role and keeps the legacy role marker in sync
// so the CLI recovery path still recognises administrators.
func (r *UserRepository) AssignRole(ctx context.Context, userID, roleID string, isSuperuser bool) error {
	legacyRole := "user"
	if isSuperuser {
		legacyRole = "admin"
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET role_id = $2, role = $3, updated_at = now() WHERE id = $1`,
		userID, roleID, legacyRole)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetPassword resets a password and forces a change on next login.
func (r *UserRepository) SetPassword(ctx context.Context, userID, passwordHash string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users SET password_hash = $2, must_change_password = true, updated_at = now()
		WHERE id = $1`, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes an account. api_tokens and auth_sessions cascade with it — the
// handler surfaces the token count first so the choice is informed. (#222 D8)
func (r *UserRepository) Delete(ctx context.Context, userID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetSummary returns one account, for the guards that need its current role.
func (r *UserRepository) GetSummary(ctx context.Context, userID string) (*model.UserSummary, error) {
	var u model.UserSummary
	var roleID sql.NullString
	var lastLogin sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, COALESCE(u.role, 'user'), u.role_id, COALESCE(r.name, ''),
		       COALESCE(r.is_superuser, false), u.totp_enabled, u.must_change_password,
		       u.last_login_at, u.login_count, u.created_at,
		       (SELECT count(*) FROM api_tokens t WHERE t.user_id = u.id)
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1`, userID).Scan(&u.ID, &u.Username, &u.LegacyRole, &roleID, &u.RoleName,
		&u.IsSuperuser, &u.TOTPEnabled, &u.MustChangePassword,
		&lastLogin, &u.LoginCount, &u.CreatedAt, &u.APITokenCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if roleID.Valid {
		u.RoleID = &roleID.String
	}
	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}
	return &u, nil
}

// DeleteSessions ends every session of an account. Used when deleting or
// disabling a user; role changes do not need it because permissions are resolved
// per request.
func (r *UserRepository) DeleteSessions(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = $1`, userID)
	return err
}

// GetDetail returns one account with its sign-in history, active session count
// and the API tokens issued under it. (#222)
func (r *UserRepository) GetDetail(ctx context.Context, userID string) (*model.UserDetail, error) {
	summary, err := r.GetSummary(ctx, userID)
	if err != nil || summary == nil {
		return nil, err
	}
	d := &model.UserDetail{UserSummary: *summary}

	var lastIP sql.NullString
	var totpVerified sql.NullTime
	if err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(last_login_ip, ''), totp_verified_at, updated_at,
		       (SELECT count(*) FROM auth_sessions s WHERE s.user_id = u.id AND s.expires_at > now())
		FROM users u WHERE u.id = $1`, userID).Scan(&lastIP, &totpVerified, &d.UpdatedAt, &d.ActiveSessions); err != nil {
		return nil, fmt.Errorf("failed to load user detail: %w", err)
	}
	d.LastLoginIP = lastIP.String
	if totpVerified.Valid {
		d.TOTPVerifiedAt = &totpVerified.Time
	}

	// 이 계정이 로그인할 수 있는 아이덴티티 공급자들(#227). 테이블 존재 확인으로
	// 감싼 이유는 SSO가 나중에 출시됐고 마이그레이션이 경고 후 계속 진행하기
	// 때문이다. 업그레이드가 실패한 설치에서도 사용자 상세는 열려야 한다.
	var ssoPresent bool
	if err := r.db.QueryRowContext(ctx,
		tablesExistSQL("user_identities")).Scan(&ssoPresent); err == nil && ssoPresent {
		idRows, err := r.db.QueryContext(ctx, `
			SELECT p.name, p.slug, COALESCE(i.email, ''), i.last_login_at, i.created_at
			FROM user_identities i
			JOIN sso_providers p ON p.id = i.provider_id
			WHERE i.user_id = $1 ORDER BY p.name`, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to load linked identities: %w", err)
		}
		for idRows.Next() {
			var info model.UserIdentityInfo
			if err := idRows.Scan(&info.ProviderName, &info.ProviderSlug, &info.Email,
				&info.LastLoginAt, &info.LinkedAt); err != nil {
				idRows.Close()
				return nil, fmt.Errorf("failed to scan linked identity: %w", err)
			}
			d.LinkedIdentities = append(d.LinkedIdentities, info)
		}
		idRows.Close()
		if err := idRows.Err(); err != nil {
			return nil, err
		}
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, token_prefix, permissions, allowed_ips, expires_at,
		       last_used_at, last_used_ip, use_count, is_active, revoked_at, created_at
		FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user tokens: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t model.UserTokenInfo
		// api_tokens.permissions is jsonb while allowed_ips is text[] — the same
		// split the existing token repository handles.
		var permBytes []byte
		var ips pq.StringArray
		var lastUsedIP sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &permBytes, &ips, &t.ExpiresAt,
			&t.LastUsedAt, &lastUsedIP, &t.UseCount, &t.IsActive, &t.RevokedAt, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		if len(permBytes) > 0 {
			if err := json.Unmarshal(permBytes, &t.Permissions); err != nil {
				return nil, fmt.Errorf("failed to decode token permissions: %w", err)
			}
		}
		t.AllowedIPs = ips
		if lastUsedIP.Valid {
			t.LastUsedIP = &lastUsedIP.String
		}
		d.Tokens = append(d.Tokens, t)
	}
	return d, rows.Err()
}
