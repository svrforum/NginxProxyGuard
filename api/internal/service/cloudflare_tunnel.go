package service

import (
	"context"
	"errors"
	"log"
	"regexp"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// tunnelTokenRe: Cloudflare connector tokens are base64url blobs. Anything
// else (newlines, control chars, shell metachars) is rejected — the token is
// written to a file consumed inside the nginx container, so treat it as an
// injection vector (same rule as ForwardAuth templated fields, #179).
var tunnelTokenRe = regexp.MustCompile(`^[A-Za-z0-9_=\-\.]+$`)

// ValidateTunnelToken rejects anything that is not a plausible connector token.
func ValidateTunnelToken(token string) error {
	if token == "" {
		return errors.New("invalid tunnel token: empty")
	}
	if len(token) > 4096 {
		return errors.New("invalid tunnel token: too long")
	}
	if !tunnelTokenRe.MatchString(token) {
		return errors.New("invalid tunnel token: must contain only base64url characters")
	}
	return nil
}

// TunnelNginxManager is the slice of nginx.Manager this service needs
// (interface dep to avoid import cycles, matching other services).
type TunnelNginxManager interface {
	WriteCloudflaredToken(token string) error
	RemoveCloudflaredToken() error
	CloudflaredReady(ctx context.Context) (int, error)
	GetHTTPSPort() string
	GetHTTPPort() string
}

// CloudflareTunnelService manages the tunnel settings singleton and keeps the
// token file (watched by the in-container supervisor) in sync with the DB.
type CloudflareTunnelService struct {
	repo  *repository.CloudflareTunnelRepository
	nginx TunnelNginxManager

	// updateMu serializes DB upsert + token-file convergence so concurrent
	// Update/SyncTokenFile calls cannot leave the file diverged from the DB.
	// Kept separate from mu — never hold the status mutex across file I/O.
	updateMu sync.Mutex

	mu          sync.Mutex
	enabledAt   time.Time // when the tunnel was last (re)enabled — grace window for 'starting'
	statusCache *model.TunnelStatus
	statusAt    time.Time
}

func NewCloudflareTunnelService(repo *repository.CloudflareTunnelRepository, nginx TunnelNginxManager) *CloudflareTunnelService {
	return &CloudflareTunnelService{repo: repo, nginx: nginx}
}

func toResponse(t *model.CloudflareTunnel) *model.CloudflareTunnelResponse {
	masked := ""
	if t.Token != "" {
		if len(t.Token) > 4 {
			masked = t.Token[:4] + "****"
		} else {
			masked = "****"
		}
	}
	return &model.CloudflareTunnelResponse{
		ID: t.ID, Enabled: t.Enabled, Mode: t.Mode,
		HasToken: t.Token != "", TokenMasked: masked,
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

// withOriginURL fills the origin service URL shown in the setup guide —
// NPG's HTTPS port is configurable (NGINX_HTTPS_PORT), so the dashboard
// entry must point at the actual port, not a hardcoded 443.
func (s *CloudflareTunnelService) withOriginURL(resp *model.CloudflareTunnelResponse) *model.CloudflareTunnelResponse {
	resp.OriginServiceURL = "https://localhost:" + s.nginx.GetHTTPSPort()
	resp.OriginServiceURLHTTP = "http://localhost:" + s.nginx.GetHTTPPort()
	return resp
}

func (s *CloudflareTunnelService) Get(ctx context.Context) (*model.CloudflareTunnelResponse, error) {
	t, err := s.repo.GetSingleton(ctx)
	if err != nil {
		return nil, err
	}
	return s.withOriginURL(toResponse(t)), nil
}

// Update validates, persists, and converges the token file. Token semantics:
// req.Token nil = keep stored token (UI sends masked value back? no — UI omits).
func (s *CloudflareTunnelService) Update(ctx context.Context, req *model.UpdateCloudflareTunnelRequest) (*model.CloudflareTunnelResponse, error) {
	if req.Token != nil && *req.Token != "" {
		if err := ValidateTunnelToken(*req.Token); err != nil {
			return nil, err
		}
	}

	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	// Reject enabling without a token. Compute the effective post-merge state
	// (mirrors Upsert: nil keeps stored, non-nil replaces) — otherwise the DB
	// would say enabled while Status() reads "disabled" forever.
	cur, err := s.repo.GetSingleton(ctx)
	if err != nil {
		return nil, err
	}
	effEnabled := cur.Enabled
	if req.Enabled != nil {
		effEnabled = *req.Enabled
	}
	effToken := cur.Token
	if req.Token != nil {
		effToken = *req.Token
	}
	if effEnabled {
		if effToken == "" {
			return nil, errors.New("invalid tunnel token: cannot enable tunnel without a token")
		}
		// Re-validate the STORED effective token, not just non-emptiness —
		// tokens can enter the DB unvalidated (backup import), and enabling
		// over an invalid one must fail here instead of succeeding and then
		// landing on "error" (syncFile refuses to write invalid tokens).
		if err := ValidateTunnelToken(effToken); err != nil {
			return nil, err
		}
	}

	t, err := s.repo.Upsert(ctx, req)
	if err != nil {
		return nil, err
	}
	syncErr := s.syncFile(t)

	// Invalidate the status cache even when the file sync failed — the DB
	// state already changed, so a cached status would be stale either way.
	s.mu.Lock()
	if t.Enabled && t.Token != "" {
		s.enabledAt = time.Now()
	}
	s.statusCache = nil // invalidate
	s.mu.Unlock()

	if syncErr != nil {
		return nil, syncErr
	}
	return s.withOriginURL(toResponse(t)), nil
}

// syncFile converges the token file to the given settings state. The stored
// token is re-validated before every write: Update guards its own input, but
// tokens can also enter the DB unvalidated (e.g. backup import), and this
// file is consumed by the in-container supervisor — never write a token that
// would fail ValidateTunnelToken.
func (s *CloudflareTunnelService) syncFile(t *model.CloudflareTunnel) error {
	if t.Enabled && t.Token != "" {
		if err := ValidateTunnelToken(t.Token); err != nil {
			// Log the validation error only — it contains no token bytes.
			log.Printf("[CloudflareTunnel] stored token invalid; removing token file: %v", err)
			return s.nginx.RemoveCloudflaredToken()
		}
		return s.nginx.WriteCloudflaredToken(t.Token)
	}
	return s.nginx.RemoveCloudflaredToken()
}

// SyncTokenFile re-converges file state to DB state. Called once at startup
// (covers volume re-creation and backup restore).
func (s *CloudflareTunnelService) SyncTokenFile(ctx context.Context) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	t, err := s.repo.GetSingleton(ctx)
	if err != nil {
		return err
	}
	if err := s.syncFile(t); err != nil {
		return err
	}
	if t.Enabled && t.Token != "" {
		s.mu.Lock()
		s.enabledAt = time.Now()
		s.mu.Unlock()
		log.Printf("[CloudflareTunnel] token file synced (enabled)")
	}
	return nil
}

const tunnelStatusCacheTTL = 15 * time.Second
const tunnelStartingGrace = 60 * time.Second

// Status returns the connector state, cached for 15s (dashboard polls at 15s;
// avoids docker-exec storms).
func (s *CloudflareTunnelService) Status(ctx context.Context) *model.TunnelStatus {
	s.mu.Lock()
	if s.statusCache != nil && time.Since(s.statusAt) < tunnelStatusCacheTTL {
		defer s.mu.Unlock()
		return s.statusCache
	}
	enabledAt := s.enabledAt
	s.mu.Unlock()

	st := s.probe(ctx, enabledAt)

	s.mu.Lock()
	s.statusCache = st
	s.statusAt = time.Now()
	s.mu.Unlock()
	return st
}

func (s *CloudflareTunnelService) probe(ctx context.Context, enabledAt time.Time) *model.TunnelStatus {
	t, err := s.repo.GetSingleton(ctx)
	if err != nil || !t.Enabled || t.Token == "" {
		return &model.TunnelStatus{State: "disabled"}
	}
	conns, err := s.nginx.CloudflaredReady(ctx)
	if err == nil && conns > 0 {
		return &model.TunnelStatus{State: "connected", Connections: conns}
	}
	if time.Since(enabledAt) < tunnelStartingGrace {
		return &model.TunnelStatus{State: "starting"}
	}
	return &model.TunnelStatus{State: "error"}
}
