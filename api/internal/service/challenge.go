package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

var (
	ErrCaptchaFailed     = errors.New("CAPTCHA verification failed")
	ErrCaptchaLowScore   = errors.New("CAPTCHA score too low")
	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrChallengeDisabled = errors.New("challenge is not enabled")
	ErrMissingConfig     = errors.New("CAPTCHA configuration is missing")
)

type ChallengeService struct {
	repo              *repository.ChallengeRepository
	systemSettingsRepo *repository.SystemSettingsRepository
	httpClient        *http.Client
}

func NewChallengeService(repo *repository.ChallengeRepository) *ChallengeService {
	return &ChallengeService{
		repo: repo,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetSystemSettingsRepo wires the system settings repository used to resolve
// the global error page language default. Optional — if unset, the challenge
// page falls back to browser-only detection.
func (s *ChallengeService) SetSystemSettingsRepo(r *repository.SystemSettingsRepository) {
	s.systemSettingsRepo = r
}

// GetConfig returns challenge config for a proxy host
func (s *ChallengeService) GetConfig(ctx context.Context, proxyHostID *string) (*model.ChallengeConfig, error) {
	return s.repo.GetConfig(ctx, proxyHostID)
}

// GetGlobalConfig returns global challenge config
func (s *ChallengeService) GetGlobalConfig(ctx context.Context) (*model.ChallengeConfig, error) {
	return s.repo.GetGlobalConfig(ctx)
}

// UpdateConfig updates challenge config
func (s *ChallengeService) UpdateConfig(ctx context.Context, proxyHostID *string, req *model.ChallengeConfigRequest) (*model.ChallengeConfig, error) {
	return s.repo.UpsertConfig(ctx, proxyHostID, req)
}

// DeleteConfig deletes challenge config
func (s *ChallengeService) DeleteConfig(ctx context.Context, proxyHostID *string) error {
	return s.repo.DeleteConfig(ctx, proxyHostID)
}

// VerifyCaptcha verifies CAPTCHA response and issues a bypass token
func (s *ChallengeService) VerifyCaptcha(ctx context.Context, req *model.VerifyCaptchaRequest, clientIP, userAgent string) (*model.VerifyCaptchaResponse, error) {
	startTime := time.Now()

	// Get config (try proxy host first, then global)
	var config *model.ChallengeConfig
	var err error

	if req.ProxyHostID != "" {
		config, err = s.repo.GetConfig(ctx, &req.ProxyHostID)
	}
	if config == nil || config.ID == "" || !config.Enabled {
		config, err = s.repo.GetGlobalConfig(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge config: %w", err)
	}

	if !config.Enabled {
		return nil, ErrChallengeDisabled
	}

	if config.SiteKey == "" || config.SecretKey == "" {
		return nil, ErrMissingConfig
	}

	// Verify based on challenge type
	var verified bool
	var score float64

	switch config.ChallengeType {
	case "turnstile":
		verified, err = s.verifyTurnstile(ctx, config, req.Token, clientIP)
		score = 1.0 // Turnstile doesn't return a score
	case "recaptcha_v2", "recaptcha_v3":
		verified, score, err = s.verifyRecaptcha(ctx, config, req.Token, clientIP)
	default:
		verified, score, err = s.verifyRecaptcha(ctx, config, req.Token, clientIP)
	}

	if err != nil {
		// Log failed attempt
		s.repo.LogChallenge(ctx, nilIfEmpty(req.ProxyHostID), clientIP, userAgent, "failed", req.ChallengeReason, nil, nil)
		return &model.VerifyCaptchaResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	if !verified {
		s.repo.LogChallenge(ctx, nilIfEmpty(req.ProxyHostID), clientIP, userAgent, "failed", req.ChallengeReason, &score, nil)
		return &model.VerifyCaptchaResponse{
			Success: false,
			Error:   "CAPTCHA verification failed",
			Score:   score,
		}, nil
	}

	// Check score for reCAPTCHA v3
	if config.ChallengeType == "recaptcha_v3" && score < config.MinScore {
		s.repo.LogChallenge(ctx, nilIfEmpty(req.ProxyHostID), clientIP, userAgent, "failed", req.ChallengeReason, &score, nil)
		return &model.VerifyCaptchaResponse{
			Success: false,
			Error:   fmt.Sprintf("Score too low: %.2f (minimum: %.2f)", score, config.MinScore),
			Score:   score,
		}, nil
	}

	// Generate bypass token
	token, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Store token
	var proxyHostPtr *string
	if req.ProxyHostID != "" {
		proxyHostPtr = &req.ProxyHostID
	}

	tokenRecord, err := s.repo.CreateToken(ctx, proxyHostPtr, token, clientIP, userAgent, req.ChallengeReason, config.TokenValidity)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// Log success
	solveTime := int(time.Since(startTime).Seconds())
	s.repo.LogChallenge(ctx, nilIfEmpty(req.ProxyHostID), clientIP, userAgent, "passed", req.ChallengeReason, &score, &solveTime)

	return &model.VerifyCaptchaResponse{
		Success:   true,
		Token:     token,
		ExpiresAt: tokenRecord.ExpiresAt,
		ExpiresIn: config.TokenValidity,
		Score:     score,
	}, nil
}

// verifyRecaptcha verifies reCAPTCHA token with Google
func (s *ChallengeService) verifyRecaptcha(ctx context.Context, config *model.ChallengeConfig, token, clientIP string) (bool, float64, error) {
	verifyURL := "https://www.google.com/recaptcha/api/siteverify"

	data := url.Values{}
	data.Set("secret", config.SecretKey)
	data.Set("response", token)
	data.Set("remoteip", clientIP)

	resp, err := s.httpClient.PostForm(verifyURL, data)
	if err != nil {
		return false, 0, fmt.Errorf("failed to verify with reCAPTCHA: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read reCAPTCHA response: %w", err)
	}

	var result model.RecaptchaVerifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, 0, fmt.Errorf("failed to parse reCAPTCHA response: %w", err)
	}

	if !result.Success {
		errMsg := "verification failed"
		if len(result.ErrorCodes) > 0 {
			errMsg = result.ErrorCodes[0]
		}
		return false, 0, fmt.Errorf("reCAPTCHA: %s", errMsg)
	}

	return true, result.Score, nil
}

// verifyTurnstile verifies Cloudflare Turnstile token
func (s *ChallengeService) verifyTurnstile(ctx context.Context, config *model.ChallengeConfig, token, clientIP string) (bool, error) {
	verifyURL := "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	data := url.Values{}
	data.Set("secret", config.SecretKey)
	data.Set("response", token)
	data.Set("remoteip", clientIP)

	resp, err := s.httpClient.PostForm(verifyURL, data)
	if err != nil {
		return false, fmt.Errorf("failed to verify with Turnstile: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read Turnstile response: %w", err)
	}

	var result model.TurnstileVerifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse Turnstile response: %w", err)
	}

	if !result.Success {
		errMsg := "verification failed"
		if len(result.ErrorCodes) > 0 {
			errMsg = result.ErrorCodes[0]
		}
		return false, fmt.Errorf("Turnstile: %s", errMsg)
	}

	return true, nil
}

// ValidateToken validates a bypass token
func (s *ChallengeService) ValidateToken(ctx context.Context, token, clientIP string, proxyHostID *string) (*model.ValidateTokenResponse, error) {
	tokenRecord, err := s.repo.ValidateToken(ctx, token, clientIP, proxyHostID)
	if err != nil {
		return nil, err
	}

	if tokenRecord == nil {
		return &model.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	return &model.ValidateTokenResponse{
		Valid:     true,
		ExpiresAt: tokenRecord.ExpiresAt,
		Reason:    tokenRecord.ChallengeReason,
	}, nil
}

// RevokeToken revokes a token
func (s *ChallengeService) RevokeToken(ctx context.Context, tokenID, reason string) error {
	return s.repo.RevokeToken(ctx, tokenID, reason)
}

// GetStats returns challenge statistics
func (s *ChallengeService) GetStats(ctx context.Context, proxyHostID *string, hours int) (*model.ChallengeStats, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	return s.repo.GetChallengeStats(ctx, proxyHostID, since)
}

// CleanupExpiredTokens removes expired tokens
func (s *ChallengeService) CleanupExpiredTokens(ctx context.Context) (int, error) {
	return s.repo.CleanupExpiredTokens(ctx)
}

// GenerateChallengePageData returns data for rendering challenge page
func (s *ChallengeService) GenerateChallengePageData(ctx context.Context, proxyHostID *string, reason string) (map[string]interface{}, error) {
	var config *model.ChallengeConfig
	var err error

	if proxyHostID != nil {
		config, err = s.repo.GetConfig(ctx, proxyHostID)
	}
	if config == nil || config.ID == "" || !config.Enabled {
		config, err = s.repo.GetGlobalConfig(ctx)
	}
	if err != nil {
		return nil, err
	}

	if !config.Enabled {
		return nil, ErrChallengeDisabled
	}

	// Resolve admin-configured default error page language so the challenge
	// page honors the same setting as the 403 page (Issue #105).
	// Default "auto" means "follow visitor's browser language", same as 403.html.
	errorPageLanguage := "auto"
	if s.systemSettingsRepo != nil {
		if sys, sysErr := s.systemSettingsRepo.Get(ctx); sysErr == nil && sys != nil && sys.UIErrorPageLanguage != "" {
			errorPageLanguage = sys.UIErrorPageLanguage
		}
	}

	return map[string]interface{}{
		"site_key":            config.SiteKey,
		"challenge_type":      config.ChallengeType,
		"theme":               config.Theme,
		"page_title":          config.PageTitle,
		"page_message":        config.PageMessage,
		"reason":              reason,
		"proxy_host_id":       proxyHostID,
		"error_page_language": errorPageLanguage,
	}, nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
