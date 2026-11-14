package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/password"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrTooManyAttempts    = errors.New("too many failed login attempts, try again later")
	ErrPasswordMismatch   = errors.New("passwords do not match")
	ErrUsernameTaken      = errors.New("username already taken")
	ErrWeakPassword       = errors.New("password does not meet security requirements")
	ErrSessionExpired     = errors.New("session expired")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalid2FACode     = errors.New("invalid 2FA code")
	Err2FARequired        = errors.New("2FA verification required")
	Err2FANotEnabled      = errors.New("2FA is not enabled")
	Err2FAAlreadyEnabled  = errors.New("2FA is already enabled")
	ErrInvalidTempToken   = errors.New("invalid or expired temporary token")
	// ErrSetupNotInitiated: enable was called without a pending secret. It was
	// an untyped errors.New, so the handler's switch fell through to the
	// default arm and answered 500 for what is plainly a client sequencing
	// mistake.
	ErrSetupNotInitiated = errors.New("2FA setup not initiated")
)

const (
	// Max failed attempts before lockout
	maxFailedAttempts = 5
	// Lockout window duration
	lockoutWindow = 15 * time.Minute
	// Session token length
	tokenLength = 32
	// Session duration
	sessionDuration = 24 * time.Hour
	// Temp token duration for 2FA
	tempTokenDuration = 5 * time.Minute
	// Number of backup codes
	backupCodeCount = 10
)

// Temporary token store for 2FA verification
type tempTokenData struct {
	userID    string
	ip        string
	userAgent string
	expiresAt time.Time
}

type AuthService struct {
	repo        *repository.AuthRepository
	jwtSecret   string
	tempTokens  map[string]*tempTokenData
	tokenMu     sync.RWMutex
	redisCache  *cache.RedisClient
	stopCleanup chan struct{}
	// notify is optional: nil means notifications are not configured.
	notify *NotificationService
}

func NewAuthService(repo *repository.AuthRepository, jwtSecret string) *AuthService {
	s := &AuthService{
		repo:        repo,
		jwtSecret:   jwtSecret,
		tempTokens:  make(map[string]*tempTokenData),
		stopCleanup: make(chan struct{}),
	}
	go s.cleanupExpiredTokens()
	return s
}

// NewAuthServiceWithCache creates a new AuthService with cache support
func NewAuthServiceWithCache(repo *repository.AuthRepository, jwtSecret string, redisCache *cache.RedisClient) *AuthService {
	s := &AuthService{
		repo:        repo,
		jwtSecret:   jwtSecret,
		tempTokens:  make(map[string]*tempTokenData),
		redisCache:  redisCache,
		stopCleanup: make(chan struct{}),
	}
	go s.cleanupExpiredTokens()
	return s
}

// cleanupExpiredTokens periodically removes expired temporary tokens to prevent memory leaks
func (s *AuthService) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.tokenMu.Lock()
			now := time.Now()
			for token, data := range s.tempTokens {
				if now.After(data.expiresAt) {
					delete(s.tempTokens, token)
				}
			}
			s.tokenMu.Unlock()
		case <-s.stopCleanup:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (s *AuthService) Close() {
	if s.stopCleanup != nil {
		close(s.stopCleanup)
	}
}

// SetCache sets the Redis cache client
func (s *AuthService) SetCache(redisCache *cache.RedisClient) {
	s.redisCache = redisCache
}

// Login authenticates a user and returns a session token or requires 2FA
func (s *AuthService) Login(ctx context.Context, req *model.LoginRequest, ip, userAgent string) (*model.LoginResponse, error) {
	// Check for too many failed attempts (skip in test environment)
	if os.Getenv("ENVIRONMENT") != "test" {
		failedCount, err := s.repo.CountRecentFailedAttempts(ctx, ip, req.Username, time.Now().Add(-lockoutWindow))
		if err != nil {
			return nil, err
		}
		if failedCount >= maxFailedAttempts {
			// Not edge-triggered on a subject that recovers — a lockout is a
			// discrete occurrence — but batched, so a sustained brute-force
			// attempt produces one message with a count rather than one per
			// rejected password. (#221)
			if s.notify != nil {
				_ = s.notify.EmitBatched(ctx, "auth.login_failed", map[string]string{
					"subject": req.Username, "ip": ip, "reason": "locked_out",
				})
			}
			return nil, ErrTooManyAttempts
		}
	}

	// Get user
	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		s.repo.RecordLoginAttempt(ctx, ip, req.Username, false)
		return nil, ErrInvalidCredentials
	}

	// Verify password
	ok, needsRehash := password.Verify(user.PasswordHash, req.Password)
	if !ok {
		s.repo.RecordLoginAttempt(ctx, ip, req.Username, false)
		return nil, ErrInvalidCredentials
	}
	// The password is known to be right, and this is the only point that sees
	// it: Verify2FA gets a temp token, not the password. Re-encoding the stored
	// hash here is safe before the second factor, because it stores the same
	// password in another form and changes nothing about who can sign in.
	if needsRehash {
		s.upgradePasswordHash(ctx, user, req.Password)
	}

	// Check if 2FA is enabled
	if user.TOTPEnabled {
		// If TOTP code provided, verify it
		if req.TOTPCode != "" {
			if !s.verify2FACode(user, req.TOTPCode) {
				s.repo.RecordLoginAttempt(ctx, ip, req.Username, false)
				return nil, ErrInvalid2FACode
			}
		} else {
			// Generate temporary token for 2FA verification
			tempToken, err := generateToken(tokenLength)
			if err != nil {
				return nil, err
			}

			s.tokenMu.Lock()
			s.tempTokens[tempToken] = &tempTokenData{
				userID:    user.ID,
				ip:        ip,
				userAgent: userAgent,
				expiresAt: time.Now().Add(tempTokenDuration),
			}
			s.tokenMu.Unlock()

			return &model.LoginResponse{
				Requires2FA: true,
				TempToken:   tempToken,
			}, nil
		}
	}

	// Create full session
	return s.createSession(ctx, user, ip, userAgent)
}

// Verify2FA completes login with 2FA code
func (s *AuthService) Verify2FA(ctx context.Context, req *model.Verify2FARequest, ip string) (*model.LoginResponse, error) {
	// Get temp token data
	s.tokenMu.RLock()
	data, exists := s.tempTokens[req.TempToken]
	s.tokenMu.RUnlock()

	if !exists || time.Now().After(data.expiresAt) {
		return nil, ErrInvalidTempToken
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, data.userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUnauthorized
	}

	// Verify 2FA code
	if !s.verify2FACode(user, req.TOTPCode) {
		s.repo.RecordLoginAttempt(ctx, ip, user.Username, false)
		return nil, ErrInvalid2FACode
	}

	// Remove temp token
	s.tokenMu.Lock()
	delete(s.tempTokens, req.TempToken)
	s.tokenMu.Unlock()

	// Create full session
	return s.createSession(ctx, user, data.ip, data.userAgent)
}

// verify2FACode checks TOTP code or backup code
func (s *AuthService) verify2FACode(user *model.User, code string) bool {
	// Try TOTP first
	if ValidateTOTPCode(user.TOTPSecret, code) {
		return true
	}

	// Try backup codes
	valid, remaining := ValidateBackupCode(code, user.BackupCodes)
	if valid {
		// Update remaining backup codes
		s.repo.UseBackupCode(context.Background(), user.ID, remaining)
		return true
	}

	return false
}

// createSession creates a full session after authentication
func (s *AuthService) createSession(ctx context.Context, user *model.User, ip, userAgent string) (*model.LoginResponse, error) {
	// Generate session token
	token, err := generateToken(tokenLength)
	if err != nil {
		return nil, err
	}

	// Hash token for storage
	tokenHash := hashToken(token)

	// Create session
	session := &model.AuthSession{
		UserID:    user.ID,
		TokenHash: tokenHash,
		IPAddress: ip,
		UserAgent: userAgent,
		ExpiresAt: time.Now().Add(sessionDuration),
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Record successful login
	s.repo.RecordLoginAttempt(ctx, ip, user.Username, true)
	s.repo.UpdateUserLogin(ctx, user.ID, ip)

	return &model.LoginResponse{
		Token:          token,
		User:           user,
		IsInitialSetup: user.IsInitialSetup,
	}, nil
}

// upgradePasswordHash re-encodes a verified password in the form password.Hash
// writes now: peppered when it was plain bcrypt, or under the current pepper
// when it matched the previous one. Best effort — the sign-in that triggered it
// succeeds either way, and the next one tries again.
func (s *AuthService) upgradePasswordHash(ctx context.Context, user *model.User, plaintext string) {
	newHash, err := password.Hash(plaintext)
	if err != nil {
		log.Printf("[Auth] could not re-encode the password hash of user %s: %v", user.ID, err)
		return
	}
	if err := s.repo.UpgradePasswordHash(ctx, user.ID, user.PasswordHash, newHash); err != nil {
		log.Printf("[Auth] could not store the re-encoded password hash of user %s: %v", user.ID, err)
		return
	}
	user.PasswordHash = newHash
}

// CreateSessionForUser issues an ordinary session for an account whose identity
// has already been proven by other means. It exists for SSO (#227): the OIDC
// callback has verified the ID token, so it needs exactly the session the
// password path produces — same table, same expiry, same downstream middleware —
// without re-checking a password. NPG's own TOTP is deliberately not consulted;
// the identity provider performed the authentication.
func (s *AuthService) CreateSessionForUser(ctx context.Context, userID, ip, userAgent string) (*model.LoginResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUnauthorized
	}
	return s.createSession(ctx, user, ip, userAgent)
}

// Setup2FA initiates 2FA setup and returns secret + QR code URL
func (s *AuthService) Setup2FA(ctx context.Context, userID string) (*model.Setup2FAResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUnauthorized
	}

	if user.TOTPEnabled {
		return nil, Err2FAAlreadyEnabled
	}

	// Generate new secret
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}

	// Store the secret (not enabled yet).
	//
	// EnsureTOTPSecret returns the secret that is ACTUALLY stored, which is the
	// one already there if this account has an enrolment in progress. Re-opening
	// the setup screen therefore shows the same QR rather than quietly
	// invalidating the one the user has already scanned (#305). Everything
	// below must use the returned value, never the freshly generated one.
	//
	// Backup codes are not minted here. They belong to a completed enrolment —
	// see Enable2FA.
	stored, err := s.repo.EnsureTOTPSecret(ctx, userID, secret)
	if err != nil {
		// No row came back: the account turned out to be enrolled already (the
		// WHERE excludes it), which the caller treats as a conflict rather than
		// a server fault.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, Err2FAAlreadyEnabled
		}
		return nil, err
	}

	// Generate QR code URL
	qrURL := GenerateQRCodeURL(stored, user.Username)

	return &model.Setup2FAResponse{
		Secret:    stored,
		QRCodeURL: qrURL,
	}, nil
}

// Enable2FA enables 2FA after verifying a code
func (s *AuthService) Enable2FA(ctx context.Context, userID string, req *model.Enable2FARequest) ([]string, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUnauthorized
	}

	if user.TOTPEnabled {
		return nil, Err2FAAlreadyEnabled
	}

	if user.TOTPSecret == "" {
		return nil, ErrSetupNotInitiated
	}

	// Verify the code
	if !ValidateTOTPCode(user.TOTPSecret, req.TOTPCode) {
		return nil, ErrInvalid2FACode
	}

	// Mint the backup codes here rather than at setup time, and store them in
	// the same statement that flips the flag. The plaintext returned below is
	// therefore the plaintext whose hashes were just written — there is no
	// window in which the screen shows one set and the database holds another.
	//
	// That window existed when setup issued them: the secret survives a second
	// setup call (so an already-scanned QR keeps working) but the codes did
	// not, so the first screen could enrol successfully and then display ten
	// codes that had been overwritten. Backup codes are the only offline way
	// back into an account, so a set that silently does not work is worse than
	// no set at all.
	codes, hashedCodes, err := GenerateBackupCodes(backupCodeCount)
	if err != nil {
		return nil, err
	}

	if err := s.repo.EnableTOTP(ctx, userID, hashedCodes); err != nil {
		return nil, err
	}
	return codes, nil
}

// Disable2FA disables 2FA
func (s *AuthService) Disable2FA(ctx context.Context, userID string, req *model.Disable2FARequest) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUnauthorized
	}

	if !user.TOTPEnabled {
		return Err2FANotEnabled
	}

	// Verify password
	if ok, _ := password.Verify(user.PasswordHash, req.Password); !ok {
		return ErrInvalidCredentials
	}

	// Verify the second factor with the SAME rule the login path uses: a TOTP
	// code or a backup code.
	//
	// This accepted TOTP only, which made backup codes a one-way door — they
	// got you in but not out. A user whose authenticator is lost or wiped could
	// sign in with a backup code and then had no way to turn 2FA off and pair a
	// new device, because turning it off demanded a code from the device they
	// no longer had. Their only exit was the host-level `reset-password
	// --clear-2fa`, which also resets the password and kills every session.
	// Backup codes exist precisely for that situation.
	//
	// The password is still required, so this is the same strength as the login
	// it mirrors: something known plus one of the two second factors.
	if !s.verify2FACode(user, req.TOTPCode) {
		return ErrInvalid2FACode
	}

	// Disable 2FA
	return s.repo.DisableTOTP(ctx, userID)
}

// Logout invalidates a session
func (s *AuthService) Logout(ctx context.Context, token string) error {
	tokenHash := hashToken(token)

	// Get session to find expiry time for blacklist
	session, err := s.repo.GetSessionByTokenHash(ctx, tokenHash)
	if err == nil && session != nil && s.redisCache != nil {
		// Add to blacklist until original expiry
		s.redisCache.BlacklistJWTToken(ctx, tokenHash, session.ExpiresAt)
	}

	return s.repo.DeleteSession(ctx, tokenHash)
}

// ValidateToken checks if a token is valid and returns the user
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*model.User, error) {
	tokenHash := hashToken(token)

	// Check Redis blacklist first (fast path)
	if s.redisCache != nil {
		if blacklisted, err := s.redisCache.IsJWTTokenBlacklisted(ctx, tokenHash); err == nil && blacklisted {
			return nil, ErrSessionExpired
		}
	}

	session, err := s.repo.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSessionExpired
	}

	user, err := s.repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUnauthorized
	}

	return user, nil
}

// ChangeCredentials updates username and password (for initial setup)
func (s *AuthService) ChangeCredentials(ctx context.Context, userID string, req *model.ChangeCredentialsRequest) error {
	// Get current user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUnauthorized
	}

	// Verify current password
	if ok, _ := password.Verify(user.PasswordHash, req.CurrentPassword); !ok {
		return ErrInvalidCredentials
	}

	// Validate new password
	if len(req.NewPassword) < 10 {
		return ErrWeakPassword
	}
	if req.NewPassword != req.NewPasswordConfirm {
		return ErrPasswordMismatch
	}

	// Check if new username is available
	if req.NewUsername != "" && req.NewUsername != user.Username {
		exists, err := s.repo.CheckUsernameExists(ctx, req.NewUsername, userID)
		if err != nil {
			return err
		}
		if exists {
			return ErrUsernameTaken
		}
	}

	// Hash new password
	hashedPassword, err := password.Hash(req.NewPassword)
	if err != nil {
		return err
	}

	newUsername := req.NewUsername
	if newUsername == "" {
		newUsername = user.Username
	}

	// Setting the address here is what lets SSO ever link this account. Do it
	// before the credential write so a rejected address fails the whole call
	// rather than leaving a renamed account behind. (#240)
	var newEmail string
	if strings.TrimSpace(req.NewEmail) != "" {
		normalized, err := model.NormalizeEmail(req.NewEmail)
		if err != nil {
			return err
		}
		newEmail = normalized
	}

	// Update credentials
	if err := s.repo.UpdateUserCredentials(ctx, userID, newUsername, hashedPassword); err != nil {
		return err
	}
	if newEmail != "" {
		if err := s.repo.UpdateUserEmail(ctx, userID, newEmail); err != nil {
			return err
		}
	}

	// Invalidate all existing sessions (force re-login with new credentials)
	return s.repo.DeleteUserSessions(ctx, userID)
}

// ChangePassword updates password only
func (s *AuthService) ChangePassword(ctx context.Context, userID string, req *model.ChangePasswordRequest) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUnauthorized
	}

	// Verify current password
	if ok, _ := password.Verify(user.PasswordHash, req.CurrentPassword); !ok {
		return ErrInvalidCredentials
	}

	// Validate new password
	if len(req.NewPassword) < 10 {
		return ErrWeakPassword
	}
	if req.NewPassword != req.NewPasswordConfirm {
		return ErrPasswordMismatch
	}

	// Hash new password
	hashedPassword, err := password.Hash(req.NewPassword)
	if err != nil {
		return err
	}

	return s.repo.UpdatePassword(ctx, userID, hashedPassword)
}

// GetAuthStatus returns the current auth status
func (s *AuthService) GetAuthStatus(ctx context.Context, token string) (*model.AuthStatus, error) {
	if token == "" {
		// Check if initial setup is required
		isInitialSetup, err := s.repo.IsInitialSetupRequired(ctx)
		if err != nil {
			return nil, err
		}
		return &model.AuthStatus{
			Authenticated:  false,
			IsInitialSetup: isInitialSetup,
		}, nil
	}

	user, err := s.ValidateToken(ctx, token)
	if err != nil {
		isInitialSetup, _ := s.repo.IsInitialSetupRequired(ctx)
		return &model.AuthStatus{
			Authenticated:  false,
			IsInitialSetup: isInitialSetup,
		}, nil
	}

	return &model.AuthStatus{
		Authenticated:  true,
		IsInitialSetup: user.IsInitialSetup,
		User:           user,
	}, nil
}

// GetAccountInfo returns account information
// GetUserByID returns an account, or nil when it no longer exists.
//
// Exists so a caller authenticated by API token can still be identified: that
// path sets only user_id in the request context, never the *model.User the
// session path stores. (#249)
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*model.User, error) {
	return s.repo.GetUserByID(ctx, userID)
}

func (s *AuthService) GetAccountInfo(ctx context.Context, userID string) (*model.AccountInfo, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUnauthorized
	}

	language := user.Language
	if language == "" {
		language = "ko" // Default language
	}

	fontFamily := user.FontFamily
	if fontFamily == "" {
		fontFamily = "system" // Default font
	}

	return &model.AccountInfo{
		ID:          user.ID,
		Username:    user.Username,
		Role:        user.Role,
		Language:    language,
		FontFamily:  fontFamily,
		TOTPEnabled: user.TOTPEnabled,
		LastLoginAt: user.LastLoginAt,
		LastLoginIP: user.LastLoginIP,
		LoginCount:  user.LoginCount,
		CreatedAt:   user.CreatedAt,
	}, nil
}

// SetLanguage updates user's language preference
func (s *AuthService) SetLanguage(ctx context.Context, userID string, language string) error {
	return s.repo.UpdateLanguage(ctx, userID, language)
}

// SetFontFamily updates user's font family preference
func (s *AuthService) SetFontFamily(ctx context.Context, userID string, fontFamily string) error {
	return s.repo.UpdateFontFamily(ctx, userID, fontFamily)
}

// ChangeUsername updates the username after verifying current password
func (s *AuthService) ChangeUsername(ctx context.Context, userID string, req *model.ChangeUsernameRequest) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUnauthorized
	}

	// Verify current password
	if ok, _ := password.Verify(user.PasswordHash, req.CurrentPassword); !ok {
		return ErrInvalidCredentials
	}

	// Validate new username length
	if len(req.NewUsername) < 3 {
		return errors.New("username must be at least 3 characters")
	}

	// Check if new username is same as current
	if req.NewUsername == user.Username {
		return errors.New("new username must be different from current")
	}

	// Check if new username is available
	exists, err := s.repo.CheckUsernameExists(ctx, req.NewUsername, userID)
	if err != nil {
		return err
	}
	if exists {
		return ErrUsernameTaken
	}

	return s.repo.UpdateUsername(ctx, userID, req.NewUsername)
}

// CleanupSessions removes expired sessions and old login attempts
func (s *AuthService) CleanupSessions(ctx context.Context) error {
	if _, err := s.repo.CleanExpiredSessions(ctx); err != nil {
		return err
	}
	_, err := s.repo.CleanOldAttempts(ctx, time.Now().Add(-24*time.Hour))

	// Clean expired temp tokens
	s.tokenMu.Lock()
	now := time.Now()
	for token, data := range s.tempTokens {
		if now.After(data.expiresAt) {
			delete(s.tempTokens, token)
		}
	}
	s.tokenMu.Unlock()

	return err
}

func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// SetNotificationService wires notifications after construction. (#221)
func (s *AuthService) SetNotificationService(n *NotificationService) { s.notify = n }
