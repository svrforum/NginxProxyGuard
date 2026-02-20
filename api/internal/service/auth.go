package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nginx-proxy-guard/internal/model"
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
	// Check for too many failed attempts
	failedCount, err := s.repo.CountRecentFailedAttempts(ctx, ip, time.Now().Add(-lockoutWindow))
	if err != nil {
		return nil, err
	}
	if failedCount >= maxFailedAttempts {
		return nil, ErrTooManyAttempts
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.repo.RecordLoginAttempt(ctx, ip, req.Username, false)
		return nil, ErrInvalidCredentials
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

	// Generate backup codes
	codes, hashedCodes, err := GenerateBackupCodes(backupCodeCount)
	if err != nil {
		return nil, err
	}

	// Store secret and hashed backup codes (not enabled yet)
	if err := s.repo.SetTOTPSecret(ctx, userID, secret, hashedCodes); err != nil {
		return nil, err
	}

	// Generate QR code URL
	qrURL := GenerateQRCodeURL(secret, user.Username)

	return &model.Setup2FAResponse{
		Secret:      secret,
		QRCodeURL:   qrURL,
		BackupCodes: codes,
	}, nil
}

// Enable2FA enables 2FA after verifying a code
func (s *AuthService) Enable2FA(ctx context.Context, userID string, req *model.Enable2FARequest) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUnauthorized
	}

	if user.TOTPEnabled {
		return Err2FAAlreadyEnabled
	}

	if user.TOTPSecret == "" {
		return errors.New("2FA setup not initiated")
	}

	// Verify the code
	if !ValidateTOTPCode(user.TOTPSecret, req.TOTPCode) {
		return ErrInvalid2FACode
	}

	// Enable 2FA
	return s.repo.EnableTOTP(ctx, userID)
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return ErrInvalidCredentials
	}

	// Verify TOTP code
	if !ValidateTOTPCode(user.TOTPSecret, req.TOTPCode) {
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	newUsername := req.NewUsername
	if newUsername == "" {
		newUsername = user.Username
	}

	// Update credentials
	if err := s.repo.UpdateUserCredentials(ctx, userID, newUsername, string(hashedPassword)); err != nil {
		return err
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.repo.UpdatePassword(ctx, userID, string(hashedPassword))
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
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
