package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Managed mode (#267): NPG maintains ONLY the tunnel's trailing hostname-less
// catch-all ingress rule via the Cloudflare Configurations API, so requests for
// hostnames that are not registered as Public Hostnames still reach NPG and get
// routed by their Host header (the NPM + app-cloudflared pattern). Everything
// above the last rule belongs to the operator's dashboard and is preserved
// verbatim as raw JSON: the PUT is a full-replace with no optimistic
// concurrency, so all rules except the last travel through this file as
// json.RawMessage. encoding/json compacts and HTML-escapes raw messages on
// output, so the wire form is semantically identical rather than byte-equal —
// every field, number and string survives exactly.

// cfAPITokenRe: Cloudflare API tokens are short base64url-ish identifiers. The
// token only ever travels in an Authorization header, but reject anything that
// could smuggle header/control characters all the same.
var cfAPITokenRe = regexp.MustCompile(`^[A-Za-z0-9_\-\.]{20,256}$`)

// ValidateCFAPIToken rejects anything that is not a plausible Cloudflare API token.
func ValidateCFAPIToken(token string) error {
	if token == "" {
		return errors.New("invalid api token: empty")
	}
	if !cfAPITokenRe.MatchString(token) {
		return errors.New("invalid api token: must be 20-256 characters of A-Z a-z 0-9 _ - .")
	}
	return nil
}

// connectorIdentity is what a cloudflared connector token encodes: enough to
// address the tunnel in the API without asking the user for anything else.
type connectorIdentity struct {
	AccountID string
	TunnelID  string
}

var cfIDRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var cfUUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// decodeConnectorToken extracts the account tag and tunnel ID from the stored
// connector token: base64(JSON{"a": accountTag, "t": tunnelUUID, "s": secret})
// per cloudflared's connection.TunnelToken. Both Std and RawStd padding are
// tried — the encoder has varied across cloudflared versions.
func decodeConnectorToken(token string) (*connectorIdentity, error) {
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		raw, err = enc.DecodeString(token)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("connector token is not valid base64")
	}
	var payload struct {
		AccountTag string `json:"a"`
		TunnelID   string `json:"t"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, errors.New("connector token does not decode to the expected JSON shape")
	}
	if !cfIDRe.MatchString(payload.AccountTag) {
		return nil, errors.New("connector token carries no valid account tag")
	}
	if !cfUUIDRe.MatchString(payload.TunnelID) {
		return nil, errors.New("connector token carries no valid tunnel id")
	}
	return &connectorIdentity{AccountID: payload.AccountTag, TunnelID: payload.TunnelID}, nil
}

// ─── Cloudflare API client ───────────────────────────────────────────────────

// cfTunnelClient speaks to the Configurations API. apiBase is injectable so the
// whole flow is testable against an httptest server (same idiom as the DDNS
// Cloudflare updater).
type cfTunnelClient struct {
	client  *http.Client
	apiBase string
}

func newCFTunnelClient() *cfTunnelClient {
	base := os.Getenv("NPG_CF_API_BASE") // test hook: point at a mock server
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &cfTunnelClient{
		client:  &http.Client{Timeout: 15 * time.Second},
		apiBase: base,
	}
}

// cfEnvelope is the standard Cloudflare v4 response wrapper.
type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// ErrCFUnreachable marks transport-level failures (DNS, timeout, 5xx) so the
// caller can report "could not reach Cloudflare" distinctly from a refusal.
var ErrCFUnreachable = errors.New("could not reach the Cloudflare API")

// ErrCFRefused marks a well-formed Cloudflare envelope with success=false —
// rate limiting, server-side config validation, and the like. The handler maps
// it to 502 with the message intact; without the sentinel these surfaced as an
// anonymous 500 "internal error".
var ErrCFRefused = errors.New("the Cloudflare API refused the request")

func (c *cfTunnelClient) do(ctx context.Context, method, path, apiToken string, body []byte) (*cfEnvelope, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCFUnreachable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%w: %v", ErrCFUnreachable, err)
	}
	var env cfEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%w: unexpected response (HTTP %d)", ErrCFUnreachable, resp.StatusCode)
	}
	return &env, resp.StatusCode, nil
}

// cfError flattens the envelope's errors into one operator-readable line.
func cfError(env *cfEnvelope, status int) error {
	if env == nil {
		return fmt.Errorf("%w (HTTP %d)", ErrCFRefused, status)
	}
	var parts []string
	for _, e := range env.Errors {
		parts = append(parts, fmt.Sprintf("%d: %s", e.Code, e.Message))
	}
	if len(parts) == 0 {
		return fmt.Errorf("%w (HTTP %d)", ErrCFRefused, status)
	}
	return fmt.Errorf("%w (HTTP %d) — %s", ErrCFRefused, status, strings.Join(parts, "; "))
}

// tunnelDetails is the slice of GET cfd_tunnel/{id} this feature reads.
type tunnelDetails struct {
	ID         string `json:"id"`
	AccountTag string `json:"account_tag"`
	ConfigSrc  string `json:"config_src"`
	Status     string `json:"status"`
}

// preflight verifies the API token, the tunnel's existence, and that its
// configuration is remotely managed — one functional call instead of
// /user/tokens/verify, which rejects valid account-owned tokens.
func (c *cfTunnelClient) preflight(ctx context.Context, id *connectorIdentity, apiToken string) (*tunnelDetails, error) {
	env, status, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/accounts/%s/cfd_tunnel/%s", id.AccountID, id.TunnelID), apiToken, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		// "invalid " prefix: the handler maps operator-fixable refusals to 400.
		return nil, fmt.Errorf("invalid api token: refused by Cloudflare — it needs Account / Cloudflare Tunnel / Edit for this account (%v)", cfError(env, status))
	}
	if status == http.StatusNotFound {
		return nil, errors.New("invalid tunnel token: Cloudflare has no such tunnel in this account — the connector token and the API token may belong to different accounts")
	}
	if !env.Success {
		return nil, cfError(env, status)
	}
	var det tunnelDetails
	if err := json.Unmarshal(env.Result, &det); err != nil {
		return nil, fmt.Errorf("unexpected tunnel details shape: %v", err)
	}
	if det.ConfigSrc != "" && det.ConfigSrc != "cloudflare" {
		return nil, errors.New("invalid tunnel configuration: this tunnel is locally managed (config_src=local); the catch-all can only be managed on a remotely-managed tunnel")
	}
	return &det, nil
}

// tunnelConfig carries the remote config with every field NPG does not own kept
// as raw JSON: Extra holds unknown top-level config keys, and each ingress rule
// is a raw blob. Only the LAST rule is ever parsed or replaced.
type tunnelConfig struct {
	Ingress []json.RawMessage
	Extra   map[string]json.RawMessage
	Version int64
}

// getConfig fetches and splits the remote configuration. A tunnel that has
// never been configured returns config null — normalized to empty Ingress.
func (c *cfTunnelClient) getConfig(ctx context.Context, id *connectorIdentity, apiToken string) (*tunnelConfig, error) {
	env, status, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", id.AccountID, id.TunnelID), apiToken, nil)
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, cfError(env, status)
	}
	var outer struct {
		Config  map[string]json.RawMessage `json:"config"`
		Version int64                      `json:"version"`
	}
	if err := json.Unmarshal(env.Result, &outer); err != nil {
		return nil, fmt.Errorf("unexpected configuration shape: %v", err)
	}
	cfg := &tunnelConfig{Extra: map[string]json.RawMessage{}, Version: outer.Version}
	for k, v := range outer.Config {
		switch k {
		case "ingress":
			var rules []json.RawMessage
			if err := json.Unmarshal(v, &rules); err != nil {
				return nil, fmt.Errorf("unexpected ingress shape: %v", err)
			}
			cfg.Ingress = rules
		case "warp-routing":
			// readOnly/deprecated — echoing it back into PUT risks rejection.
		default:
			cfg.Extra[k] = v
		}
	}
	return cfg, nil
}

// putConfig writes the full configuration back: preserved raw rules plus any
// preserved top-level keys. This is the only write this feature performs.
func (c *cfTunnelClient) putConfig(ctx context.Context, id *connectorIdentity, apiToken string, cfg *tunnelConfig) error {
	config := map[string]interface{}{}
	for k, v := range cfg.Extra {
		config[k] = v
	}
	config["ingress"] = cfg.Ingress
	body, err := json.Marshal(map[string]interface{}{"config": config})
	if err != nil {
		return err
	}
	env, status, err := c.do(ctx, http.MethodPut,
		fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", id.AccountID, id.TunnelID), apiToken, body)
	if err != nil {
		return err
	}
	if !env.Success {
		return cfError(env, status)
	}
	return nil
}

// ─── catch-all decision table ────────────────────────────────────────────────

// ingressRuleView is the only shape NPG ever parses out of a rule — just enough
// to classify the last rule. Everything else stays raw.
type ingressRuleView struct {
	Hostname      string `json:"hostname,omitempty"`
	Service       string `json:"service"`
	OriginRequest *struct {
		NoTLSVerify bool `json:"noTLSVerify"`
	} `json:"originRequest,omitempty"`
}

// Catch-all states surfaced to the UI (TunnelStatus.CatchallState).
const (
	CatchallApplied       = "applied"
	CatchallNotApplied    = "not_applied"
	CatchallConflict      = "conflict"
	CatchallInvalidRemote = "invalid_remote"
	CatchallUnreachable   = "unreachable"
)

const cfDefaultCatchallService = "http_status:404"

// npgCatchallRule renders the rule NPG installs: route every unmatched
// hostname into NPG's HTTPS listener, skipping TLS verification because the
// certificate nginx presents for an arbitrary Host is its default one.
func npgCatchallRule(service string) json.RawMessage {
	b, _ := json.Marshal(map[string]interface{}{
		"service":       service,
		"originRequest": map[string]interface{}{"noTLSVerify": true},
	})
	return b
}

// classifyLastRule maps the tunnel's trailing rule onto the decision table.
// ownService is the URL NPG previously wrote ("" if none); wantService is what
// NPG would write today (they differ after a port change).
func classifyLastRule(ingress []json.RawMessage, ownService, wantService string) (state string, lastService string, err error) {
	if len(ingress) == 0 {
		return CatchallNotApplied, "", nil
	}
	var last ingressRuleView
	if uerr := json.Unmarshal(ingress[len(ingress)-1], &last); uerr != nil {
		return CatchallInvalidRemote, "", fmt.Errorf("the tunnel's last ingress rule could not be parsed: %v", uerr)
	}
	if last.Hostname != "" {
		// Cloudflare's own contract requires a hostname-less final rule; a
		// hostname here means the remote config is broken — never touch it.
		return CatchallInvalidRemote, last.Service, nil
	}
	switch {
	case last.Service == cfDefaultCatchallService:
		return CatchallNotApplied, last.Service, nil
	case last.Service == wantService, ownService != "" && last.Service == ownService:
		return CatchallApplied, last.Service, nil
	default:
		return CatchallConflict, last.Service, nil
	}
}

// applyCatchall converges the remote last rule to NPG's catch-all. It returns
// the resulting state, whether a PUT was performed, and the service now in
// place. Conflict and invalid_remote never write.
func applyCatchall(cfg *tunnelConfig, ownService, wantService string) (state string, changed bool, resultService string, err error) {
	st, lastService, cerr := classifyLastRule(cfg.Ingress, ownService, wantService)
	if cerr != nil {
		return st, false, "", cerr
	}
	switch st {
	case CatchallConflict, CatchallInvalidRemote:
		return st, false, lastService, nil
	case CatchallApplied:
		if lastService == wantService {
			return CatchallApplied, false, wantService, nil
		}
		// Ours, but stale (port changed) — rewrite in place.
		cfg.Ingress[len(cfg.Ingress)-1] = npgCatchallRule(wantService)
		return CatchallApplied, true, wantService, nil
	default: // not_applied
		if len(cfg.Ingress) == 0 {
			cfg.Ingress = []json.RawMessage{npgCatchallRule(wantService)}
		} else {
			cfg.Ingress[len(cfg.Ingress)-1] = npgCatchallRule(wantService)
		}
		return CatchallApplied, true, wantService, nil
	}
}

// removeCatchall restores Cloudflare's default 404 rule — but only over a rule
// NPG owns. Anything else is left exactly as found.
func removeCatchall(cfg *tunnelConfig, ownService, wantService string) (state string, changed bool, err error) {
	st, _, cerr := classifyLastRule(cfg.Ingress, ownService, wantService)
	if cerr != nil {
		return st, false, cerr
	}
	if st != CatchallApplied {
		return st, false, nil
	}
	b, _ := json.Marshal(map[string]string{"service": cfDefaultCatchallService})
	cfg.Ingress[len(cfg.Ingress)-1] = b
	return CatchallNotApplied, true, nil
}
