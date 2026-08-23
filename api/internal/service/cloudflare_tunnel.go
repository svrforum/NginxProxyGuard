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
	cf    *cfTunnelClient

	// updateMu serializes DB upsert + token-file convergence so concurrent
	// Update/SyncTokenFile calls cannot leave the file diverged from the DB.
	// Kept separate from mu — never hold the status mutex across file I/O.
	updateMu sync.Mutex

	mu          sync.Mutex
	enabledAt   time.Time // when the tunnel was last (re)enabled — grace window for 'starting'
	statusCache *model.TunnelStatus
	statusAt    time.Time

	// Managed-mode catch-all state, cached separately from the connector
	// status: it costs a Cloudflare API round trip, so Status() serves the
	// cache and refreshes it in the background when stale.
	catchallState      string
	catchallDetail     string
	catchallAt         time.Time
	catchallRefreshing bool
}

func NewCloudflareTunnelService(repo *repository.CloudflareTunnelRepository, nginx TunnelNginxManager) *CloudflareTunnelService {
	return &CloudflareTunnelService{repo: repo, nginx: nginx, cf: newCFTunnelClient()}
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
	apiMasked := ""
	if t.APIToken != "" {
		if len(t.APIToken) > 4 {
			apiMasked = t.APIToken[:4] + "****"
		} else {
			apiMasked = "****"
		}
	}
	return &model.CloudflareTunnelResponse{
		ID: t.ID, Enabled: t.Enabled, Mode: t.Mode,
		HasToken: t.Token != "", TokenMasked: masked,
		HasAPIToken: t.APIToken != "", APITokenMasked: apiMasked,
		CatchallEnabled: t.CatchallEnabled,
		CreatedAt:       t.CreatedAt, UpdatedAt: t.UpdatedAt,
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
	if req.Mode != nil && *req.Mode != "token" && *req.Mode != "managed" {
		return nil, errors.New("invalid tunnel mode: must be 'token' or 'managed'")
	}
	if req.APIToken != nil && *req.APIToken != "" {
		if err := ValidateCFAPIToken(*req.APIToken); err != nil {
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

	// Managed-mode invariants, on the effective post-merge state (#267).
	effMode := cur.Mode
	if req.Mode != nil {
		effMode = *req.Mode
	}
	effAPIToken := cur.APIToken
	if req.APIToken != nil {
		effAPIToken = *req.APIToken
	}
	effCatchall := cur.CatchallEnabled
	if req.CatchallEnabled != nil {
		effCatchall = *req.CatchallEnabled
	}
	if effCatchall && effMode != "managed" {
		if req.CatchallEnabled != nil && *req.CatchallEnabled {
			// An explicit attempt to switch the catch-all ON outside managed
			// mode is a caller error and stays one.
			return nil, errors.New("invalid tunnel mode: the catch-all rule requires managed mode")
		}
		// Leaving managed mode implies the STORED catch-all intent goes with
		// it. Requiring the caller to also send catchall_enabled=false made the
		// UI a dead-end: the checkbox is hidden the moment the mode radio
		// flips, so the 400 named a control the operator could no longer see.
		// The converge below performs the actual removal in this same save.
		effCatchall = false
		f := false
		req.CatchallEnabled = &f
	}
	if effMode == "managed" {
		if effAPIToken == "" {
			return nil, errors.New("invalid api token: managed mode requires a Cloudflare API token (Account / Cloudflare Tunnel / Edit)")
		}
		// Same backup-import rule as the connector token: re-validate stored.
		if err := ValidateCFAPIToken(effAPIToken); err != nil {
			return nil, err
		}
		if effToken == "" {
			return nil, errors.New("invalid tunnel token: managed mode needs the connector token to identify the tunnel")
		}
		if _, err := decodeConnectorToken(effToken); err != nil {
			return nil, errors.New("invalid tunnel token: " + err.Error())
		}
	}

	// Replacing the connector token re-points converge at a DIFFERENT tunnel,
	// and the apply there would overwrite catchall_applied_service — the only
	// record that NPG wrote a rule into the old one. Clean the old tunnel up
	// first, best-effort: a failure only logs, it must not block the swap.
	if req.Token != nil && *req.Token != cur.Token && cur.CatchallAppliedService != "" &&
		cur.Token != "" && cur.APIToken != "" {
		if oldID, derr := decodeConnectorToken(cur.Token); derr == nil {
			if cfg, gerr := s.cf.getConfig(ctx, oldID, cur.APIToken); gerr == nil {
				if _, changed, rerr := removeCatchall(cfg, cur.CatchallAppliedService, s.catchallWantService()); rerr == nil && changed {
					if perr := s.cf.putConfig(ctx, oldID, cur.APIToken, cfg); perr == nil {
						log.Printf("[CloudflareTunnel] catch-all removed from previous tunnel %s before token swap", oldID.TunnelID)
					} else {
						log.Printf("[CloudflareTunnel] could not remove catch-all from previous tunnel %s: %v", oldID.TunnelID, perr)
					}
				}
			} else {
				log.Printf("[CloudflareTunnel] could not read previous tunnel %s before token swap: %v", oldID.TunnelID, gerr)
			}
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

	// Converge the remote catch-all while still holding updateMu. A conflict is
	// a STATE (surfaced via Status), not an error; only validation refusals and
	// an unreachable Cloudflare API fail the save.
	convErr := s.convergeCatchallLocked(ctx, t)
	// The converge just rewrote the catch-all state; drop any status snapshot a
	// concurrent poll may have cached between the upsert and now.
	s.mu.Lock()
	s.statusCache = nil
	s.mu.Unlock()
	if convErr != nil {
		return nil, convErr
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

	// Managed mode: attach the catch-all state (its own 60s cache + background
	// refresh — never a synchronous Cloudflare call on the poll path).
	if t, err := s.repo.GetSingleton(ctx); err == nil {
		s.attachCatchallStatus(st, t)
	}

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

// ─── managed-mode convergence (#267) ─────────────────────────────────────────

// catchallWantService is the service URL NPG installs today. cloudflared runs
// inside the host-network nginx container, so localhost reaches the listener
// directly; the port tracks NGINX_HTTPS_PORT (the #264 lesson: never hardcode
// 443).
func (s *CloudflareTunnelService) catchallWantService() string {
	return "https://localhost:" + s.nginx.GetHTTPSPort()
}

// setCatchallStatus stores the state served by Status().
func (s *CloudflareTunnelService) setCatchallStatus(state, detail string) {
	s.mu.Lock()
	s.catchallState = state
	s.catchallDetail = detail
	s.catchallAt = time.Now()
	s.mu.Unlock()
}

// convergeCatchallLocked reconciles the remote catch-all rule with the stored
// intent. Caller must hold updateMu. Returns an error only for failures the
// operator must act on immediately (unreachable API, refused token); conflict
// and invalid_remote are recorded as states and do not fail the save.
func (s *CloudflareTunnelService) convergeCatchallLocked(ctx context.Context, t *model.CloudflareTunnel) error {
	wantApply := t.Mode == "managed" && t.CatchallEnabled
	ownService := t.CatchallAppliedService

	// Nothing to apply and nothing of ours to clean up: done.
	if !wantApply && ownService == "" {
		s.setCatchallStatus("", "")
		return nil
	}
	// Removal needs the API too; if the tokens are gone (mode switched off and
	// credentials cleared in one save), record that our rule may linger.
	if t.Token == "" || t.APIToken == "" {
		if wantApply {
			return errors.New("invalid api token: managed mode requires both the connector token and a Cloudflare API token")
		}
		s.setCatchallStatus(CatchallUnreachable, "NPG's catch-all rule may still be set on the tunnel, but the credentials to remove it were cleared. Restore it to http_status:404 in the Cloudflare dashboard if needed.")
		log.Printf("[CloudflareTunnel] catch-all cleanup skipped: credentials cleared while rule %q may remain", ownService)
		return nil
	}

	id, err := decodeConnectorToken(t.Token)
	if err != nil {
		return errors.New("invalid tunnel token: " + err.Error())
	}

	if wantApply {
		// Full preflight only on the write path: verifies token permission,
		// tunnel existence, account match and remote management in one call.
		if _, err := s.cf.preflight(ctx, id, t.APIToken); err != nil {
			s.setCatchallStatus(CatchallUnreachable, err.Error())
			return err
		}
	}

	cfg, err := s.cf.getConfig(ctx, id, t.APIToken)
	if err != nil {
		s.setCatchallStatus(CatchallUnreachable, err.Error())
		if !wantApply {
			// Turning off must not be blocked by an unreachable API — the
			// leftover rule stays recorded and cleanup retries later.
			log.Printf("[CloudflareTunnel] catch-all cleanup deferred: %v", err)
			return nil
		}
		return err
	}

	if wantApply {
		state, changed, resultService, aerr := applyCatchall(cfg, ownService, s.catchallWantService())
		if aerr != nil {
			s.setCatchallStatus(state, aerr.Error())
			return nil // broken remote config is a state, not a save failure
		}
		if changed {
			if perr := s.cf.putConfig(ctx, id, t.APIToken, cfg); perr != nil {
				s.setCatchallStatus(CatchallUnreachable, perr.Error())
				return perr
			}
			log.Printf("[CloudflareTunnel] catch-all rule applied (service %s)", resultService)
		}
		if state == CatchallApplied {
			if rerr := s.repo.SetCatchallAppliedService(ctx, resultService); rerr != nil {
				return rerr
			}
			s.setCatchallStatus(CatchallApplied, "")
		} else {
			detail := "the tunnel's last ingress rule is managed by someone else (" + resultService + "); NPG will not overwrite it. Set it back to http_status:404 in the Cloudflare dashboard to let NPG take over."
			if state == CatchallInvalidRemote {
				detail = "the tunnel's last ingress rule carries a hostname, which violates Cloudflare's own catch-all contract; fix the ingress in the dashboard first."
			}
			s.setCatchallStatus(state, detail)
			log.Printf("[CloudflareTunnel] catch-all not applied: %s", state)
		}
		return nil
	}

	// Removal path: restore http_status:404, but only over our own rule.
	// Failures here never fail the save — the operator asked to turn something
	// OFF, and that intent is already persisted; the leftover rule is retried
	// at startup and by the status refresher for as long as
	// catchall_applied_service remains set.
	state, changed, rerr := removeCatchall(cfg, ownService, s.catchallWantService())
	if rerr != nil {
		s.setCatchallStatus(state, rerr.Error())
		return nil
	}
	if changed {
		if perr := s.cf.putConfig(ctx, id, t.APIToken, cfg); perr != nil {
			s.setCatchallStatus(CatchallUnreachable, "NPG's catch-all rule could not be removed yet: "+perr.Error())
			log.Printf("[CloudflareTunnel] catch-all removal failed (will retry): %v", perr)
			return nil
		}
		log.Printf("[CloudflareTunnel] catch-all rule restored to %s", cfDefaultCatchallService)
	}
	if err := s.repo.SetCatchallAppliedService(ctx, ""); err != nil {
		return err
	}
	s.setCatchallStatus("", "")
	return nil
}

const catchallStatusTTL = 60 * time.Second

// refreshCatchallStatus re-reads the remote last rule for the status badge,
// and SELF-HEALS: when the stored intent and the remote state disagree in a
// direction NPG owns (apply pending, our rule on a stale port, leftover rule
// after disable), it runs a full converge under updateMu. That is what makes a
// conflict resolved in the dashboard, or a save made while Cloudflare was
// down, take effect without a re-save. Bounded by the 60s cache TTL and the
// single-flight catchallRefreshing flag; conflict and invalid_remote remain
// look-don't-touch.
func (s *CloudflareTunnelService) refreshCatchallStatus(parent context.Context) {
	defer func() {
		s.mu.Lock()
		s.catchallRefreshing = false
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()

	t, err := s.repo.GetSingleton(ctx)
	if err != nil {
		return
	}
	relevant := t.Mode == "managed" || t.CatchallAppliedService != ""
	if !relevant {
		s.setCatchallStatus("", "") // plain token mode, nothing of ours anywhere
		return
	}
	if t.Token == "" || t.APIToken == "" {
		return // keep whatever state converge recorded (credentials-cleared detail)
	}
	id, derr := decodeConnectorToken(t.Token)
	if derr != nil {
		s.setCatchallStatus(CatchallUnreachable, derr.Error())
		return
	}
	cfg, gerr := s.cf.getConfig(ctx, id, t.APIToken)
	if gerr != nil {
		s.setCatchallStatus(CatchallUnreachable, gerr.Error())
		return
	}
	state, lastService, cerr := classifyLastRule(cfg.Ingress, t.CatchallAppliedService, s.catchallWantService())

	wantApply := t.Mode == "managed" && t.CatchallEnabled
	needsConverge := cerr == nil &&
		((wantApply && (state == CatchallNotApplied || (state == CatchallApplied && lastService != s.catchallWantService()))) ||
			(!wantApply && t.CatchallAppliedService != "" && state == CatchallApplied))
	if needsConverge {
		s.updateMu.Lock()
		defer s.updateMu.Unlock()
		// Re-read under the lock — a concurrent save may have changed intent.
		if t2, rerr := s.repo.GetSingleton(ctx); rerr == nil {
			if cverr := s.convergeCatchallLocked(ctx, t2); cverr != nil {
				log.Printf("[CloudflareTunnel] background catch-all converge failed: %v", cverr)
			}
		}
		return // converge recorded the fresh state
	}

	detail := ""
	if cerr != nil {
		detail = cerr.Error()
	} else if state == CatchallConflict {
		if !t.CatchallEnabled {
			// The operator is not asking for a catch-all; a foreign last rule
			// is simply the dashboard's business, not a conflict to wave about.
			state, detail = "", ""
		} else {
			detail = "the tunnel's last ingress rule is managed by someone else (" + lastService + ")"
		}
	}
	s.setCatchallStatus(state, detail)
}

// attachCatchallStatus adds the managed-mode fields to a status response and
// schedules a background refresh when the cache has gone stale.
func (s *CloudflareTunnelService) attachCatchallStatus(st *model.TunnelStatus, t *model.CloudflareTunnel) {
	if t == nil {
		return
	}
	s.mu.Lock()
	hasState := s.catchallState != ""
	s.mu.Unlock()
	if t.Mode != "managed" && !hasState && t.CatchallAppliedService == "" {
		return
	}
	s.mu.Lock()
	st.CatchallState = s.catchallState
	st.CatchallDetail = s.catchallDetail
	stale := time.Since(s.catchallAt) > catchallStatusTTL
	kick := stale && !s.catchallRefreshing
	if kick {
		s.catchallRefreshing = true
	}
	s.mu.Unlock()
	if kick {
		// Detached on purpose: a slow Cloudflare API must not block the 15s
		// dashboard poll. Bounded by the client's own 15s timeout.
		go s.refreshCatchallStatus(context.Background())
	}
}

// SyncCatchallAtStartup re-converges the remote rule once at boot (and after a
// backup restore) — this is what follows an NGINX_HTTPS_PORT change (#264
// class) without operator action. Runs detached on its OWN context: the caller
// hands in the startup/request context, which is canceled the moment that
// phase returns, and a converge needs three internet round trips — closing
// over it killed the goroutine mid-flight (found by review, reproduced).
// Also runs when a leftover rule is still recorded (mode already back to
// token) so cleanup is retried, not abandoned.
func (s *CloudflareTunnelService) SyncCatchallAtStartup(_ context.Context) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		s.updateMu.Lock()
		defer s.updateMu.Unlock()
		t, err := s.repo.GetSingleton(ctx)
		if err != nil {
			log.Printf("[CloudflareTunnel] startup catch-all sync: %v", err)
			return
		}
		if t.Mode != "managed" && t.CatchallAppliedService == "" {
			return
		}
		if err := s.convergeCatchallLocked(ctx, t); err != nil {
			log.Printf("[CloudflareTunnel] startup catch-all sync failed: %v", err)
		}
	}()
}
