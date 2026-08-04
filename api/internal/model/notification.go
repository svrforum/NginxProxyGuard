package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Notifications (#221).
//
// The shape of this file is dictated by two measurements. A persistently
// failing certificate is re-checked every six hours, so anything sent on every
// occurrence would speak four times a day about one problem — hence
// edge-triggered events. And the peak measured hour held 1,566 blocked
// requests, so anything request-scoped must be coalesced — hence Batched.

const (
	NotificationTypeWebhook  = "webhook"
	NotificationTypeDiscord  = "discord"
	NotificationTypeTelegram = "telegram"
)

// EventDescriptor is one thing NPG can tell an operator about.
type EventDescriptor struct {
	Key string `json:"key"`
	// Severity lets the UI group events and the adapters colour them. It is not
	// operator-configurable: whether a failed backup is an error is not a
	// matter of taste.
	Severity string `json:"severity"`
	// Batched events are coalesced over a window into a single message with a
	// count. Everything else is edge-triggered on (key, subject): one message
	// when it breaks, one when it recovers, nothing in between.
	Batched bool `json:"batched"`
}

// EventCatalogue is the authority for what an operator may subscribe to. The UI
// builds its checklist from it, and Validate refuses anything not in it, so the
// two can never disagree.
//
// Deliberately absent: per-request WAF, geo and bot blocks. At 1,566 in the peak
// hour they belong in the digest and in ip.banned, which already means "this
// address earned a ban". Also absent: update.available, because nothing checks
// for updates in the background — UpdateChecker.Check is only ever called from
// an HTTP handler; cert.expiring, because the daily digest already lists every
// certificate expiring within 30 days and a separate event would say the same
// thing again; and host.unreachable, because the only per-host prober is
// the on-demand one the UI calls — there is no background health check to hang
// an event on. An event key that can never fire is worse than an absent one:
// the operator ticks it and then waits for a message that will not come.
var EventCatalogue = []EventDescriptor{
	{Key: "cert.renewal_failed", Severity: "error"},
	{Key: "cert.renewed", Severity: "info"},
	{Key: "ddns.sync_failed", Severity: "error"},
	{Key: "ddns.recovered", Severity: "info"},
	{Key: "backup.failed", Severity: "error"},
	{Key: "nginx.reload_failed", Severity: "error"},
	{Key: "auth.login_failed", Severity: "warning"},
	{Key: "ip.banned", Severity: "warning", Batched: true},
	{Key: "sso.login_refused", Severity: "warning", Batched: true},
}

func IsKnownEvent(key string) bool {
	for _, e := range EventCatalogue {
		if e.Key == key {
			return true
		}
	}
	return false
}

func IsBatchedEvent(key string) bool {
	for _, e := range EventCatalogue {
		if e.Key == key {
			return e.Batched
		}
	}
	return false
}

type NotificationChannel struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Enabled      bool              `json:"enabled"`
	Config       map[string]string `json:"config"`
	Events       []string          `json:"events"`
	DigestEvents []string          `json:"digest_events"`
	RichFormat   bool              `json:"rich_format"`
	// Language the messages are written in. The person who configured this
	// channel is the person who reads it, so English is not a safe default.
	Language string `json:"language"`
	// DashboardURL is appended to the daily summary so the numbers lead
	// somewhere. Per channel, not global: an internal channel and an external
	// one legitimately reach the panel at different addresses.
	DashboardURL       string     `json:"dashboard_url"`
	DigestEnabled      bool       `json:"digest_enabled"`
	DigestHour         int        `json:"digest_hour"`
	AllowPrivateTarget bool       `json:"allow_private_target"`
	Template           string     `json:"template"`
	LastSuccessAt      *time.Time `json:"last_success_at"`
	LastErrorAt        *time.Time `json:"last_error_at"`
	LastError          string     `json:"last_error"`
	ConsecutiveFail    int        `json:"consecutive_failures"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type CreateNotificationChannelRequest struct {
	Name               string            `json:"name"`
	Type               string            `json:"type"`
	Enabled            *bool             `json:"enabled"`
	Config             map[string]string `json:"config"`
	Events             []string          `json:"events"`
	DigestEvents       []string          `json:"digest_events"`
	RichFormat         bool              `json:"rich_format"`
	Language           string            `json:"language"`
	DashboardURL       string            `json:"dashboard_url"`
	DigestEnabled      bool              `json:"digest_enabled"`
	DigestHour         int               `json:"digest_hour"`
	AllowPrivateTarget bool              `json:"allow_private_target"`
	Template           string            `json:"template"`
}

type UpdateNotificationChannelRequest = CreateNotificationChannelRequest

// Validate refuses a channel that could not deliver anything, so the failure
// surfaces while the operator is looking at the form rather than as silence.
func (r *CreateNotificationChannelRequest) Validate(isCreate bool) error {
	r.Name = strings.TrimSpace(r.Name)
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))

	if r.Name == "" || len(r.Name) > 64 {
		return fmt.Errorf("invalid name: 1-64 characters required")
	}
	switch r.Type {
	case NotificationTypeWebhook, NotificationTypeDiscord, NotificationTypeTelegram:
	default:
		return fmt.Errorf("invalid type: must be webhook, discord or telegram")
	}
	if r.Config == nil {
		r.Config = map[string]string{}
	}
	for k, v := range r.Config {
		r.Config[k] = strings.TrimSpace(v)
		if k != strings.TrimSpace(k) {
			return fmt.Errorf("invalid config: key %q has surrounding whitespace", k)
		}
	}

	switch r.Type {
	case NotificationTypeWebhook, NotificationTypeDiscord:
		u := r.Config["url"]
		// An update may round-trip the mask to keep the stored URL, which for
		// Discord is itself the credential.
		if !isCreate && u == SecretPlaceholder {
			break
		}
		if err := ValidateNotificationTarget(u, r.AllowPrivateTarget); err != nil {
			return err
		}
	case NotificationTypeTelegram:
		// The endpoint is api.telegram.org, not operator-supplied, so there is
		// nothing to check for a private destination here.
		if r.Config["bot_token"] == "" && isCreate {
			return fmt.Errorf("invalid bot_token: required")
		}
		if r.Config["chat_id"] == "" {
			return fmt.Errorf("invalid chat_id: required — message the bot or add it to your group first, then use Detect")
		}
	}

	seen := map[string]bool{}
	kept := make([]string, 0, len(r.Events))
	for _, e := range r.Events {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		if !IsKnownEvent(e) {
			return fmt.Errorf("invalid event: %q is not a known event", e)
		}
		seen[e] = true
		kept = append(kept, e)
	}
	r.Events = kept

	digestSeen := map[string]bool{}
	keptDigest := make([]string, 0, len(r.DigestEvents))
	for _, e := range r.DigestEvents {
		e = strings.TrimSpace(e)
		if e == "" || digestSeen[e] {
			continue
		}
		if !IsKnownEvent(e) {
			return fmt.Errorf("invalid event: %q is not a known event", e)
		}
		// An event cannot be both immediate and summary-only; the UI offers a
		// three-way choice, so this can only happen through the API.
		if seen[e] {
			return fmt.Errorf("invalid event: %q is set to both immediate and summary", e)
		}
		digestSeen[e] = true
		keptDigest = append(keptDigest, e)
	}
	r.DigestEvents = keptDigest
	// Summary-only events need the summary turned on, or they go nowhere.
	if len(r.DigestEvents) > 0 {
		r.DigestEnabled = true
	}

	if len(r.Events) == 0 && !r.DigestEnabled {
		return fmt.Errorf("invalid events: pick at least one event, or turn on the daily summary")
	}
	// The link is shown to a human, never fetched by NPG, so it needs no SSRF
	// check — but a malformed one in a message is just noise.
	r.DashboardURL = strings.TrimSpace(r.DashboardURL)
	if r.DashboardURL != "" && !strings.HasPrefix(r.DashboardURL, "http://") && !strings.HasPrefix(r.DashboardURL, "https://") {
		return fmt.Errorf("invalid dashboard_url: must start with http:// or https://")
	}

	switch strings.ToLower(strings.TrimSpace(r.Language)) {
	case "", "en":
		r.Language = "en"
	case "ko":
		r.Language = "ko"
	default:
		return fmt.Errorf("invalid language: must be ko or en")
	}
	if r.DigestHour < 0 || r.DigestHour > 23 {
		return fmt.Errorf("invalid digest_hour: must be between 0 and 23")
	}
	return nil
}

// RenderedMessage is what an adapter turns into one HTTP request.
type RenderedMessage struct {
	Event string `json:"event"`
	// Preformatted marks a body the sender composed in full — the daily digest
	// is a multi-section report, not a headline plus fields, and rebuilding it
	// from those parts throws the report away.
	Preformatted bool              `json:"preformatted,omitempty"`
	Severity     string            `json:"severity"`
	Text         string            `json:"text"`
	Fields       map[string]string `json:"fields"`
	At           time.Time         `json:"at"`
}

var placeholderPattern = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

// Render substitutes {{key}} from fields. An unknown placeholder renders empty
// rather than erroring: one template serves every event a channel subscribes
// to, so a template written with ip in mind must not break on a certificate
// event that has no ip.
//
// The fields a caller may supply are deliberately limited — see the notify
// service. Request headers, cookies, raw_log and rule_data never appear,
// because they carry credentials: of 1,106 ModSecurity rows measured over 30
// days, 476 contained an authorization value.
func Render(tpl string, fields map[string]string) string {
	return placeholderPattern.ReplaceAllStringFunc(tpl, func(m string) string {
		key := placeholderPattern.FindStringSubmatch(m)[1]
		return fields[key]
	})
}

// OutboxEntry is one queued delivery.
type OutboxEntry struct {
	ID            int64                `json:"id"`
	ChannelID     string               `json:"channel_id"`
	EventKey      string               `json:"event_key"`
	Payload       RenderedMessage      `json:"payload"`
	Status        string               `json:"status"`
	Attempts      int                  `json:"attempts"`
	NextAttemptAt time.Time            `json:"next_attempt_at"`
	LastError     string               `json:"last_error"`
	CreatedAt     time.Time            `json:"created_at"`
	SentAt        *time.Time           `json:"sent_at"`
	Channel       *NotificationChannel `json:"-"`
}

// NotificationState is one subject's last known health, which is what makes an
// event edge-triggered rather than repeated.
type NotificationState struct {
	EventKey   string    `json:"event_key"`
	Subject    string    `json:"subject"`
	State      string    `json:"state"`
	Since      time.Time `json:"since"`
	LastDetail string    `json:"last_detail"`
}
