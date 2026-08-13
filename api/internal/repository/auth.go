package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// ErrEmailTaken reports that another account already holds the address. The
// caller answers 409 with it — a 500 would read as "the server is broken" when
// the operator simply picked an address that is in use. (#240)
var ErrEmailTaken = errors.New("email address is already in use")

type AuthRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// User operations

func (r *AuthRepository) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	query := `
		SELECT id, username, password_hash, COALESCE(role, 'user'), COALESCE(language, 'ko'), COALESCE(font_family, 'system'),
		       is_initial_setup, totp_enabled, totp_secret, totp_verified_at, backup_codes,
		       last_login_at, last_login_ip, login_count,
		       created_at, updated_at, role_id, must_change_password
		FROM users
		WHERE username = $1
	`

	var u model.User
	var lastLoginIP, totpSecret, roleID sql.NullString
	var lastLoginAt, totpVerifiedAt sql.NullTime
	var backupCodes []sql.NullString

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Language, &u.FontFamily,
		&u.IsInitialSetup, &u.TOTPEnabled, &totpSecret, &totpVerifiedAt, pq.Array(&backupCodes),
		&lastLoginAt, &lastLoginIP, &u.LoginCount,
		&u.CreatedAt, &u.UpdatedAt, &roleID, &u.MustChangePassword,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	u.LastLoginIP = lastLoginIP.String
	u.TOTPSecret = totpSecret.String
	if roleID.Valid {
		u.RoleID = &roleID.String
	}
	if lastLoginAt.Valid {
		u.LastLoginAt = &lastLoginAt.Time
	}
	if totpVerifiedAt.Valid {
		u.TOTPVerifiedAt = &totpVerifiedAt.Time
	}
	for _, code := range backupCodes {
		if code.Valid {
			u.BackupCodes = append(u.BackupCodes, code.String)
		}
	}

	return &u, nil
}

func (r *AuthRepository) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	query := `
		SELECT id, username, password_hash, COALESCE(role, 'user'), COALESCE(language, 'ko'), COALESCE(font_family, 'system'),
		       is_initial_setup, totp_enabled, totp_secret, totp_verified_at, backup_codes,
		       last_login_at, last_login_ip, login_count,
		       created_at, updated_at, role_id, must_change_password
		FROM users
		WHERE id = $1
	`

	var u model.User
	var lastLoginIP, totpSecret, roleID sql.NullString
	var lastLoginAt, totpVerifiedAt sql.NullTime
	var backupCodes []sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Language, &u.FontFamily,
		&u.IsInitialSetup, &u.TOTPEnabled, &totpSecret, &totpVerifiedAt, pq.Array(&backupCodes),
		&lastLoginAt, &lastLoginIP, &u.LoginCount,
		&u.CreatedAt, &u.UpdatedAt, &roleID, &u.MustChangePassword,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	u.LastLoginIP = lastLoginIP.String
	u.TOTPSecret = totpSecret.String
	if roleID.Valid {
		u.RoleID = &roleID.String
	}
	if lastLoginAt.Valid {
		u.LastLoginAt = &lastLoginAt.Time
	}
	if totpVerifiedAt.Valid {
		u.TOTPVerifiedAt = &totpVerifiedAt.Time
	}
	for _, code := range backupCodes {
		if code.Valid {
			u.BackupCodes = append(u.BackupCodes, code.String)
		}
	}

	return &u, nil
}

func (r *AuthRepository) UpdateUserLogin(ctx context.Context, userID, ip string) error {
	query := `
		UPDATE users
		SET last_login_at = NOW(),
		    last_login_ip = $2,
		    login_count = login_count + 1,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, ip)
	return err
}

func (r *AuthRepository) UpdateUserCredentials(ctx context.Context, userID, username, passwordHash string) error {
	query := `
		UPDATE users
		SET username = $2,
		    password_hash = $3,
		    is_initial_setup = FALSE,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, username, passwordHash)
	return err
}

// UpdateUserEmail sets the address an account is linked by.
//
// The unique violation is translated rather than surfaced raw: it is the one
// outcome the caller must distinguish, because it means another account already
// holds the address and the answer is 409, not 500. Both the case-sensitive
// users_email_key and the case-insensitive idx_users_email_lower can raise it.
func (r *AuthRepository) UpdateUserEmail(ctx context.Context, userID, email string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET email = $2, updated_at = NOW() WHERE id = $1`, userID, email)
	if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
		return ErrEmailTaken
	}
	return err
}

func (r *AuthRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	// Clearing must_change_password here is what ends the forced-change gate: an
	// admin-created account is blocked from everything but this call until it
	// picks its own password. (#222)
	query := `
		UPDATE users
		SET password_hash = $2,
		    must_change_password = false,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, passwordHash)
	return err
}

func (r *AuthRepository) UpdateLanguage(ctx context.Context, userID, language string) error {
	query := `
		UPDATE users
		SET language = $2,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, language)
	return err
}

func (r *AuthRepository) UpdateFontFamily(ctx context.Context, userID, fontFamily string) error {
	query := `
		UPDATE users
		SET font_family = $2,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, fontFamily)
	return err
}

func (r *AuthRepository) UpdateUsername(ctx context.Context, userID, username string) error {
	query := `
		UPDATE users
		SET username = $2,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, username)
	return err
}

func (r *AuthRepository) CheckUsernameExists(ctx context.Context, username, excludeUserID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND id != $2)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, username, excludeUserID).Scan(&exists)
	return exists, err
}

// 2FA operations

func (r *AuthRepository) SetTOTPSecret(ctx context.Context, userID, secret string, backupCodes []string) error {
	query := `
		UPDATE users
		SET totp_secret = $2,
		    backup_codes = $3,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, secret, pq.Array(backupCodes))
	return err
}

func (r *AuthRepository) EnableTOTP(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET totp_enabled = TRUE,
		    totp_verified_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *AuthRepository) DisableTOTP(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET totp_enabled = FALSE,
		    totp_secret = NULL,
		    totp_verified_at = NULL,
		    backup_codes = NULL,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *AuthRepository) UseBackupCode(ctx context.Context, userID string, remainingCodes []string) error {
	query := `
		UPDATE users
		SET backup_codes = $2,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID, pq.Array(remainingCodes))
	return err
}

// Session operations

func (r *AuthRepository) CreateSession(ctx context.Context, session *model.AuthSession) error {
	query := `
		INSERT INTO auth_sessions (user_id, token_hash, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`
	return r.db.QueryRowContext(ctx, query,
		session.UserID, session.TokenHash, session.IPAddress, session.UserAgent, session.ExpiresAt,
	).Scan(&session.ID, &session.CreatedAt)
}

func (r *AuthRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.AuthSession, error) {
	query := `
		SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at
		FROM auth_sessions
		WHERE token_hash = $1 AND expires_at > NOW()
	`

	var s model.AuthSession
	var ipAddress, userAgent sql.NullString

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &ipAddress, &userAgent, &s.ExpiresAt, &s.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.IPAddress = ipAddress.String
	s.UserAgent = userAgent.String

	return &s, nil
}

func (r *AuthRepository) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM auth_sessions WHERE token_hash = $1", tokenHash)
	return err
}

func (r *AuthRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM auth_sessions WHERE user_id = $1", userID)
	return err
}

func (r *AuthRepository) CleanExpiredSessions(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, "DELETE FROM auth_sessions WHERE expires_at < NOW()")
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Login attempts

func (r *AuthRepository) RecordLoginAttempt(ctx context.Context, ip, username string, success bool) error {
	query := `INSERT INTO login_attempts (ip_address, username, success) VALUES ($1, $2, $3)`
	_, err := r.db.ExecContext(ctx, query, ip, username, success)
	return err
}

// CountRecentFailedAttempts counts failures for one ACCOUNT from one IP.
//
// It used to key on the IP alone, which does not survive multiple users: five
// wrong passwords for one account locked out every other account behind the same
// NAT or reverse proxy. Keying on both keeps the brute-force protection per
// account while leaving colleagues on the same address alone. (#222)
func (r *AuthRepository) CountRecentFailedAttempts(ctx context.Context, ip, username string, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM login_attempts
	          WHERE ip_address = $1 AND username = $2 AND success = FALSE AND attempted_at > $3`
	var count int
	err := r.db.QueryRowContext(ctx, query, ip, username, since).Scan(&count)
	return count, err
}

func (r *AuthRepository) CleanOldAttempts(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, "DELETE FROM login_attempts WHERE attempted_at < $1", before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Check if initial setup is required
func (r *AuthRepository) IsInitialSetupRequired(ctx context.Context) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE is_initial_setup = TRUE LIMIT 1)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query).Scan(&exists)
	return exists, err
}
