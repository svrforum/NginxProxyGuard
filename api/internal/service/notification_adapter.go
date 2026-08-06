package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Notification delivery (#221).
//
// The retry classifier here is load-bearing rather than housekeeping. Discord
// counts 401, 403 and 429 responses toward a limit of 10,000 invalid requests
// per 10 minutes enforced by a Cloudflare IP ban, and documents that repeatedly
// posting to a deleted webhook "will result in a temporary restriction". So a
// 4xx other than 429 is permanent, full stop — and there is no retry code
// anywhere else in this codebase to copy the wrong habit from.

type Outcome int

const (
	OutcomeSent Outcome = iota
	OutcomeRetry
	OutcomeFailed
)

func (o Outcome) String() string {
	switch o {
	case OutcomeSent:
		return "sent"
	case OutcomeRetry:
		return "retry"
	default:
		return "failed"
	}
}

const (
	// defaultThrottleWait is used when a 429 arrives with no usable Retry-After.
	defaultThrottleWait = 30 * time.Second
	// maxThrottleWait keeps an absurd Retry-After from parking the queue.
	maxThrottleWait = time.Hour
	// maxAttempts bounds delivery. An unreachable receiver plus a short
	// scheduler interval is how a retry loop becomes a self-inflicted flood.
	maxAttempts = 4
)

// classifyResponse decides what a status code means for delivery.
func classifyResponse(status int, retryAfter string) (Outcome, time.Duration) {
	switch {
	case status >= 200 && status < 300:
		return OutcomeSent, 0
	case status == http.StatusTooManyRequests:
		return OutcomeRetry, parseRetryAfter(retryAfter)
	case status >= 500:
		return OutcomeRetry, 0
	default:
		// Everything else — 3xx, 400, 401, 403, 404 — is a configuration
		// problem that retrying cannot fix and that Discord punishes.
		return OutcomeFailed, 0
	}
}

func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return defaultThrottleWait
	}
	d := time.Duration(secs) * time.Second
	if d > maxThrottleWait {
		return maxThrottleWait
	}
	return d
}

// backoffFor returns how long to wait before attempt n+1.
func backoffFor(attempts int) time.Duration {
	switch attempts {
	case 1:
		return time.Minute
	case 2:
		return 5 * time.Minute
	default:
		return 30 * time.Minute
	}
}

func isExhausted(attempts int) bool { return attempts >= maxAttempts }

// channelAdapter turns a rendered message into one HTTP request and a response
// into an outcome. It knows nothing about events or scheduling.
type channelAdapter interface {
	Send(ctx context.Context, ch *model.NotificationChannel, msg model.RenderedMessage) (Outcome, time.Duration, error)
}

// notifyHTTPClient follows the convention used elsewhere in this codebase — an
// explicit per-client timeout rather than http.DefaultClient (see
// service/ddns_duckdns.go).
func notifyHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// A redirect could walk a validated public URL to a private one.
			return http.ErrUseLastResponse
		},
	}
}

// ── generic webhook ───────────────────────────────────────────────────────

type webhookAdapter struct{ client *http.Client }

func newWebhookAdapter() *webhookAdapter {
	return &webhookAdapter{client: notifyHTTPClient()}
}

// webhookEnvelope is the stable JSON shape a receiver can rely on.
//
// Message, Title and Body are aliases of the same human line, not redundancy:
// Gotify reads "message", Apprise reads "body", and both reject a payload
// without their key. Sending one shape that all three accept costs a few bytes
// and removes a configuration step the operator would otherwise have to
// discover from a rejected delivery.
type webhookEnvelope struct {
	Event    string            `json:"event"`
	At       time.Time         `json:"at"`
	Instance string            `json:"instance"`
	Severity string            `json:"severity"`
	Text     string            `json:"text"`
	Message  string            `json:"message"`
	Body     string            `json:"body"`
	Title    string            `json:"title"`
	Fields   map[string]string `json:"fields"`
}

// payloadFormatText posts the human line as a plain-text body.
//
// ntfy cannot be served by any JSON shape when the URL carries the topic:
// it treats the whole body as the message, so an operator pointing NPG at
// https://ntfy.sh/my-topic got a wall of raw JSON on their phone — and because
// ntfy answers 2xx, NPG reported success. This is the format that receiver
// actually wants.
const payloadFormatText = "text"

func (a *webhookAdapter) Send(ctx context.Context, ch *model.NotificationChannel, msg model.RenderedMessage) (Outcome, time.Duration, error) {
	target := ch.Config["url"]
	// Re-checked here and not only at save time: DNS can be re-pointed after
	// the channel was stored, which is the whole trick behind DNS rebinding.
	if err := model.ValidateNotificationTarget(target, ch.AllowPrivateTarget); err != nil {
		return OutcomeFailed, 0, err
	}

	// The envelope is already structured, so a receiver keys off fields rather
	// than parsing prose; text is the human line it can also display.
	text := bodyFor(ch.Language, ch, msg)

	var body []byte
	contentType := "application/json"
	if ch.Config["payload_format"] == payloadFormatText {
		body, contentType = []byte(text), "text/plain; charset=utf-8"
	} else {
		encoded, err := json.Marshal(webhookEnvelope{
			Event: msg.Event, At: msg.At, Instance: "npg",
			Severity: msg.Severity, Text: text,
			Message: text, Body: text, Title: headline(ch.Language, msg),
			Fields: msg.Fields,
		})
		if err != nil {
			return OutcomeFailed, 0, err
		}
		body = encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return OutcomeFailed, 0, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "NginxProxyGuard")
	// Operator-supplied headers, for an Authorization against ntfy or Gotify.
	for k, v := range ch.Config {
		if name, ok := strings.CutPrefix(k, "header_"); ok && name != "" {
			req.Header.Set(name, v)
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		// A transport error is worth retrying: the receiver may simply be down.
		return OutcomeRetry, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	outcome, wait := classifyResponse(resp.StatusCode, resp.Header.Get("Retry-After"))
	if outcome == OutcomeSent {
		return outcome, 0, nil
	}
	return outcome, wait, fmt.Errorf("receiver returned %d", resp.StatusCode)
}
