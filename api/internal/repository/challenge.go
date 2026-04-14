package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"nginx-proxy-guard/internal/model"
)

type ChallengeRepository struct {
	db *sql.DB
}

func NewChallengeRepository(db *sql.DB) *ChallengeRepository {
	return &ChallengeRepository{db: db}
}

// HashToken creates a SHA256 hash of the token
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// === Challenge Config ===

// GetConfig returns challenge config for a proxy host (or global if proxyHostID is nil)
func (r *ChallengeRepository) GetConfig(ctx context.Context, proxyHostID *string) (*model.ChallengeConfig, error) {
	var query string
	var args []interface{}

	if proxyHostID != nil {
		query = `SELECT id, proxy_host_id, enabled, challenge_type, site_key, secret_key,
		                token_validity, min_score, apply_to, page_title, page_message, theme,
		                created_at, updated_at
		         FROM challenge_configs WHERE proxy_host_id = $1`
		args = []interface{}{*proxyHostID}
	} else {
		query = `SELECT id, proxy_host_id, enabled, challenge_type, site_key, secret_key,
		                token_validity, min_score, apply_to, page_title, page_message, theme,
		                created_at, updated_at
		         FROM challenge_configs WHERE proxy_host_id IS NULL`
	}

	var config model.ChallengeConfig
	var hostID sql.NullString
	var siteKey, secretKey sql.NullString

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&config.ID, &hostID, &config.Enabled, &config.ChallengeType,
		&siteKey, &secretKey, &config.TokenValidity, &config.MinScore,
		&config.ApplyTo, &config.PageTitle, &config.PageMessage, &config.Theme,
		&config.CreatedAt, &config.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		// Return default config
		return &model.ChallengeConfig{
			Enabled:       false,
			ChallengeType: "recaptcha_v2",
			TokenValidity: 86400,
			MinScore:      0.5,
			ApplyTo:       "both",
			PageTitle:     "Security Check",
			PageMessage:   "Please complete the security check to continue.",
			Theme:         "light",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge config: %w", err)
	}

	if hostID.Valid {
		config.ProxyHostID = &hostID.String
	}
	config.SiteKey = siteKey.String
	config.SecretKey = secretKey.String

	return &config, nil
}

// GetGlobalConfig returns the global challenge config
func (r *ChallengeRepository) GetGlobalConfig(ctx context.Context) (*model.ChallengeConfig, error) {
	return r.GetConfig(ctx, nil)
}

// UpsertConfig creates or updates challenge config
func (r *ChallengeRepository) UpsertConfig(ctx context.Context, proxyHostID *string, req *model.ChallengeConfigRequest) (*model.ChallengeConfig, error) {
	// Use a serializable transaction to prevent TOCTOU race conditions.
	// PostgreSQL's UNIQUE constraint doesn't consider NULL = NULL as a conflict,
	// so we can't use INSERT ... ON CONFLICT for the global (NULL proxy_host_id) case.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingID string
	var checkQuery string
	var checkArgs []interface{}

	if proxyHostID != nil {
		checkQuery = `SELECT id FROM challenge_configs WHERE proxy_host_id = $1`
		checkArgs = []interface{}{*proxyHostID}
	} else {
		checkQuery = `SELECT id FROM challenge_configs WHERE proxy_host_id IS NULL`
	}

	err = tx.QueryRowContext(ctx, checkQuery, checkArgs...).Scan(&existingID)
	recordExists := err == nil

	var query string
	if recordExists {
		// UPDATE existing record
		query = `
			UPDATE challenge_configs SET
			    enabled = COALESCE($2, enabled),
			    challenge_type = COALESCE($3, challenge_type),
			    site_key = COALESCE($4, site_key),
			    secret_key = COALESCE($5, secret_key),
			    token_validity = COALESCE($6, token_validity),
			    min_score = COALESCE($7, min_score),
			    apply_to = COALESCE($8, apply_to),
			    page_title = COALESCE($9, page_title),
			    page_message = COALESCE($10, page_message),
			    theme = COALESCE($11, theme),
			    updated_at = NOW()
			WHERE id = $1
			RETURNING id, proxy_host_id, enabled, challenge_type, site_key, secret_key,
			          token_validity, min_score, apply_to, page_title, page_message, theme,
			          created_at, updated_at`
	} else {
		// INSERT new record
		query = `
			INSERT INTO challenge_configs (proxy_host_id, enabled, challenge_type, site_key, secret_key,
			                               token_validity, min_score, apply_to, page_title, page_message, theme)
			VALUES ($1, COALESCE($2, true), COALESCE($3, 'recaptcha_v2'), $4, $5,
			        COALESCE($6, 86400), COALESCE($7, 0.5), COALESCE($8, 'both'),
			        COALESCE($9, 'Security Check'), COALESCE($10, 'Please complete the security check to continue.'),
			        COALESCE($11, 'light'))
			RETURNING id, proxy_host_id, enabled, challenge_type, site_key, secret_key,
			          token_validity, min_score, apply_to, page_title, page_message, theme,
			          created_at, updated_at`
	}

	// Prepare parameter values
	var challengeType *string
	// Use interface{} to distinguish nil (*string not provided → SQL NULL → keep existing)
	// from empty string (*string provided as "" → SQL '' → clear the field)
	var siteKeyParam, secretKeyParam interface{}

	if req.ChallengeType != nil {
		challengeType = req.ChallengeType
	}
	if req.SiteKey != nil {
		siteKeyParam = *req.SiteKey
	}
	if req.SecretKey != nil {
		secretKeyParam = *req.SecretKey
	}

	// For UPDATE, first param is existingID; for INSERT, first param is proxyHostID
	var firstParam interface{}
	if recordExists {
		firstParam = existingID
	} else {
		firstParam = proxyHostID
	}

	var config model.ChallengeConfig
	var hostID sql.NullString
	var siteKey, secretKey sql.NullString

	err = tx.QueryRowContext(ctx, query,
		firstParam, req.Enabled, challengeType, siteKeyParam, secretKeyParam,
		req.TokenValidity, req.MinScore, req.ApplyTo, req.PageTitle, req.PageMessage, req.Theme,
	).Scan(
		&config.ID, &hostID, &config.Enabled, &config.ChallengeType,
		&siteKey, &secretKey, &config.TokenValidity, &config.MinScore,
		&config.ApplyTo, &config.PageTitle, &config.PageMessage, &config.Theme,
		&config.CreatedAt, &config.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert challenge config: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	if hostID.Valid {
		config.ProxyHostID = &hostID.String
	}
	config.SiteKey = siteKey.String
	config.SecretKey = secretKey.String

	return &config, nil
}

// DeleteConfig deletes challenge config
func (r *ChallengeRepository) DeleteConfig(ctx context.Context, proxyHostID *string) error {
	var query string
	var args []interface{}

	if proxyHostID != nil {
		query = `DELETE FROM challenge_configs WHERE proxy_host_id = $1`
		args = []interface{}{*proxyHostID}
	} else {
		query = `DELETE FROM challenge_configs WHERE proxy_host_id IS NULL`
	}

	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

// === Challenge Tokens ===

// CreateToken creates a new challenge token
func (r *ChallengeRepository) CreateToken(ctx context.Context, proxyHostID *string, token, clientIP, userAgent, reason string, validitySeconds int) (*model.ChallengeToken, error) {
	tokenHash := HashToken(token)
	expiresAt := time.Now().Add(time.Duration(validitySeconds) * time.Second)

	query := `
		INSERT INTO challenge_tokens (proxy_host_id, token_hash, client_ip, user_agent, challenge_reason, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, proxy_host_id, token_hash, client_ip, user_agent, challenge_reason,
		          issued_at, expires_at, use_count, last_used_at, revoked, revoked_at, revoked_reason`

	var ct model.ChallengeToken
	var hostID sql.NullString
	var lastUsed, revokedAt sql.NullTime
	var revokedReason sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		proxyHostID, tokenHash, clientIP, userAgent, reason, expiresAt,
	).Scan(
		&ct.ID, &hostID, &ct.TokenHash, &ct.ClientIP, &ct.UserAgent, &ct.ChallengeReason,
		&ct.IssuedAt, &ct.ExpiresAt, &ct.UseCount, &lastUsed, &ct.Revoked, &revokedAt, &revokedReason,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge token: %w", err)
	}

	if hostID.Valid {
		ct.ProxyHostID = &hostID.String
	}
	if lastUsed.Valid {
		ct.LastUsedAt = &lastUsed.Time
	}
	if revokedAt.Valid {
		ct.RevokedAt = &revokedAt.Time
	}
	ct.RevokedReason = revokedReason.String

	return &ct, nil
}

// ValidateToken checks if a token is valid
func (r *ChallengeRepository) ValidateToken(ctx context.Context, token, clientIP string, proxyHostID *string) (*model.ChallengeToken, error) {
	tokenHash := HashToken(token)

	var query string
	var args []interface{}

	// Skip client_ip in WHERE clause: on dual-stack networks desktop browsers
	// may use IPv4 for the fetch() verify call but IPv6 for the subsequent
	// page navigation (Happy Eyeballs / RFC 8305), causing a permanent
	// validation mismatch. The 32-byte random token (SHA256-hashed) provides
	// sufficient security without IP binding.
	if proxyHostID != nil {
		query = `
			SELECT id, proxy_host_id, token_hash, client_ip, user_agent, challenge_reason,
			       issued_at, expires_at, use_count, last_used_at, revoked, revoked_at, revoked_reason
			FROM challenge_tokens
			WHERE token_hash = $1 AND (proxy_host_id = $2 OR proxy_host_id IS NULL)
			  AND revoked = FALSE AND expires_at > NOW()`
		args = []interface{}{tokenHash, *proxyHostID}
	} else {
		query = `
			SELECT id, proxy_host_id, token_hash, client_ip, user_agent, challenge_reason,
			       issued_at, expires_at, use_count, last_used_at, revoked, revoked_at, revoked_reason
			FROM challenge_tokens
			WHERE token_hash = $1
			  AND revoked = FALSE AND expires_at > NOW()`
		args = []interface{}{tokenHash}
	}

	var ct model.ChallengeToken
	var hostID sql.NullString
	var lastUsed, revokedAt sql.NullTime
	var revokedReason sql.NullString

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&ct.ID, &hostID, &ct.TokenHash, &ct.ClientIP, &ct.UserAgent, &ct.ChallengeReason,
		&ct.IssuedAt, &ct.ExpiresAt, &ct.UseCount, &lastUsed, &ct.Revoked, &revokedAt, &revokedReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Token not found or invalid
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if hostID.Valid {
		ct.ProxyHostID = &hostID.String
	}
	if lastUsed.Valid {
		ct.LastUsedAt = &lastUsed.Time
	}
	if revokedAt.Valid {
		ct.RevokedAt = &revokedAt.Time
	}
	ct.RevokedReason = revokedReason.String

	// Update use count
	_, _ = r.db.ExecContext(ctx, `
		UPDATE challenge_tokens SET use_count = use_count + 1, last_used_at = NOW()
		WHERE id = $1`, ct.ID)

	return &ct, nil
}

// RevokeToken revokes a token
func (r *ChallengeRepository) RevokeToken(ctx context.Context, tokenID, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE challenge_tokens SET revoked = TRUE, revoked_at = NOW(), revoked_reason = $2
		WHERE id = $1`, tokenID, reason)
	return err
}

// RevokeAllTokensForIP revokes all tokens for an IP
func (r *ChallengeRepository) RevokeAllTokensForIP(ctx context.Context, clientIP, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE challenge_tokens SET revoked = TRUE, revoked_at = NOW(), revoked_reason = $2
		WHERE client_ip = $1 AND revoked = FALSE`, clientIP, reason)
	return err
}

// CleanupExpiredTokens removes expired tokens
func (r *ChallengeRepository) CleanupExpiredTokens(ctx context.Context) (int, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM challenge_tokens WHERE expires_at < NOW() - INTERVAL '1 day'`)
	if err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	return int(count), nil
}

// GetActiveTokenCount returns count of active tokens
func (r *ChallengeRepository) GetActiveTokenCount(ctx context.Context, proxyHostID *string) (int, error) {
	var query string
	var args []interface{}

	if proxyHostID != nil {
		query = `SELECT COUNT(*) FROM challenge_tokens WHERE proxy_host_id = $1 AND revoked = FALSE AND expires_at > NOW()`
		args = []interface{}{*proxyHostID}
	} else {
		query = `SELECT COUNT(*) FROM challenge_tokens WHERE revoked = FALSE AND expires_at > NOW()`
	}

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// === Challenge Logs ===

// LogChallenge logs a challenge event
func (r *ChallengeRepository) LogChallenge(ctx context.Context, proxyHostID *string, clientIP, userAgent, result, reason string, score *float64, solveTime *int) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO challenge_logs (proxy_host_id, client_ip, user_agent, result, trigger_reason, captcha_score, solve_time)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		proxyHostID, clientIP, userAgent, result, reason, score, solveTime)
	return err
}

// GetChallengeStats returns challenge statistics
func (r *ChallengeRepository) GetChallengeStats(ctx context.Context, proxyHostID *string, since time.Time) (*model.ChallengeStats, error) {
	var query string
	var args []interface{}

	if proxyHostID != nil {
		query = `
			SELECT
				COUNT(*) FILTER (WHERE result IN ('presented', 'passed', 'failed')) as total,
				COUNT(*) FILTER (WHERE result = 'passed') as passed,
				COUNT(*) FILTER (WHERE result = 'failed') as failed,
				COALESCE(AVG(captcha_score) FILTER (WHERE captcha_score IS NOT NULL), 0) as avg_score,
				COALESCE(AVG(solve_time) FILTER (WHERE solve_time IS NOT NULL), 0) as avg_solve_time
			FROM challenge_logs
			WHERE proxy_host_id = $1 AND created_at >= $2`
		args = []interface{}{*proxyHostID, since}
	} else {
		query = `
			SELECT
				COUNT(*) FILTER (WHERE result IN ('presented', 'passed', 'failed')) as total,
				COUNT(*) FILTER (WHERE result = 'passed') as passed,
				COUNT(*) FILTER (WHERE result = 'failed') as failed,
				COALESCE(AVG(captcha_score) FILTER (WHERE captcha_score IS NOT NULL), 0) as avg_score,
				COALESCE(AVG(solve_time) FILTER (WHERE solve_time IS NOT NULL), 0) as avg_solve_time
			FROM challenge_logs
			WHERE created_at >= $1`
		args = []interface{}{since}
	}

	var stats model.ChallengeStats
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&stats.TotalChallenges, &stats.PassedChallenges, &stats.FailedChallenges,
		&stats.AverageScore, &stats.AverageSolveTime,
	)
	if err != nil {
		return nil, err
	}

	// Get active token count
	stats.ActiveTokens, _ = r.GetActiveTokenCount(ctx, proxyHostID)

	return &stats, nil
}
