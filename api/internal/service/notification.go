package service

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// Notifications (#221) — deciding whether something is worth sending.
//
// This file contains no HTTP. Its whole job is to answer "should the operator
// hear about this", which is the difference between a useful feature and a
// channel nobody can read. Two rules do the work:
//
//   - Edge triggering. A failing certificate is re-checked every six hours and
//     a failing DDNS record every five minutes. Sending on every occurrence
//     would say the same thing four times a day, or 288. So a message is
//     produced only when (event, subject) changes state.
//   - Batching. The peak measured hour held 1,566 blocked requests. Anything
//     request-scoped is coalesced into one message with a count.

// notifyStore is the slice of the repository this service needs. It exists so
// the emission rules can be tested without a database — those rules are the
// part that would flood somebody's phone if they were wrong.
type notifyStore interface {
	TablesExist(ctx context.Context) bool
	GetState(ctx context.Context, eventKey, subject string) (string, error)
	SetState(ctx context.Context, eventKey, subject, state, detail string) error
	ChannelsForEvent(ctx context.Context, eventKey string) ([]model.NotificationChannel, error)
	Enqueue(ctx context.Context, channelID, eventKey string, payload model.RenderedMessage) error
}

// allowedFields is the whole vocabulary a payload may carry.
//
// It is an allowlist rather than a denylist on purpose. A denylist has to
// predict every sensitive field a future caller might pass; this cannot leak a
// field nobody thought about. Request headers, cookies, raw_log, rule_data,
// user-agent and the full request URI are absent deliberately: of 1,106
// ModSecurity rows measured over 30 days, 476 contained an authorization value,
// and a notification is by definition sent off the operator's network.
var allowedFields = map[string]bool{
	"event": true, "time": true, "host": true, "ip": true, "country": true,
	"reason": true, "count": true, "detail": true, "instance": true, "subject": true,
}

const (
	stateOK      = "ok"
	stateFailing = "failing"
	// batchWindow bounds how long a burst is held before it is summarised.
	batchWindow = 5 * time.Minute
	// batchSubjectsShown caps how many examples a coalesced message names.
	batchSubjectsShown = 3
)

type batch struct {
	count    int
	first    time.Time
	subjects []string
	fields   map[string]string
}

type NotificationService struct {
	store notifyStore

	mu      sync.Mutex
	batches map[string]*batch
}

func NewNotificationService(repo *repository.NotificationRepository) *NotificationService {
	return NewNotificationServiceWithStore(repo)
}

func NewNotificationServiceWithStore(store notifyStore) *NotificationService {
	return &NotificationService{store: store, batches: map[string]*batch{}}
}

// EmitTransition reports that a subject is either failing or healthy. A message
// is produced only when that differs from what was last recorded.
//
// The recovery message travels under its own event key — cert.renewal_failed
// becomes cert.renewed — so a channel that only subscribed to failures is not
// told about recoveries it did not ask for.
func (s *NotificationService) EmitTransition(ctx context.Context, eventKey, subject string, failing bool, detail string, fields map[string]string) error {
	if s == nil || s.store == nil || !s.store.TablesExist(ctx) {
		return nil
	}

	want := stateOK
	if failing {
		want = stateFailing
	}
	previous, err := s.store.GetState(ctx, eventKey, subject)
	if err != nil {
		return err
	}
	if previous == want {
		return nil
	}
	// An unseen subject that is already healthy is not news.
	if previous == "" && !failing {
		return s.store.SetState(ctx, eventKey, subject, want, detail)
	}
	if err := s.store.SetState(ctx, eventKey, subject, want, detail); err != nil {
		return err
	}

	key := eventKey
	severity := "error"
	if !failing {
		key = recoveryKeyFor(eventKey)
		severity = "resolved"
	}

	payload := s.buildPayload(key, severity, subject, detail, fields)
	return s.fanOut(ctx, key, payload)
}

// EmitBatched records a high-frequency event. Nothing is sent until FlushBatches
// runs, which the dispatcher does every batchWindow.
func (s *NotificationService) EmitBatched(ctx context.Context, eventKey string, fields map[string]string) error {
	if s == nil || s.store == nil || !s.store.TablesExist(ctx) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	b := s.batches[eventKey]
	if b == nil {
		b = &batch{first: time.Now(), fields: map[string]string{}}
		s.batches[eventKey] = b
	}
	b.count++
	// The first few subjects are worth naming; after that the count carries the
	// information and the message stays readable.
	if subject := firstNonEmpty(fields["ip"], fields["subject"], fields["host"]); subject != "" {
		if len(b.subjects) < batchSubjectsShown && !contains(b.subjects, subject) {
			b.subjects = append(b.subjects, subject)
		}
	}
	for k, v := range fields {
		if allowedFields[k] && b.fields[k] == "" {
			b.fields[k] = v
		}
	}
	return nil
}

// FlushBatches turns every pending burst into one message each.
func (s *NotificationService) FlushBatches(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	s.mu.Lock()
	pending := s.batches
	s.batches = map[string]*batch{}
	s.mu.Unlock()

	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order, which makes the tests honest

	for _, eventKey := range keys {
		b := pending[eventKey]
		if b.count == 0 {
			continue
		}
		fields := map[string]string{}
		for k, v := range b.fields {
			fields[k] = v
		}
		fields["count"] = strconv.Itoa(b.count)
		subject := strings.Join(b.subjects, ", ")
		if b.count > len(b.subjects) {
			subject = fmt.Sprintf("%s and %d more", subject, b.count-len(b.subjects))
		}
		payload := s.buildPayload(eventKey, "warning", subject, "", fields)
		if err := s.fanOut(ctx, eventKey, payload); err != nil {
			log.Printf("[Notify] failed to enqueue %s: %v", eventKey, err)
		}
	}
}

// buildPayload assembles the message. Every field passes through the allowlist,
// so a caller cannot widen what leaves the box by passing an extra key.
func (s *NotificationService) buildPayload(eventKey, severity, subject, detail string, fields map[string]string) model.RenderedMessage {
	now := time.Now()
	out := map[string]string{
		"event": eventKey,
		"time":  now.Format(time.RFC3339),
	}
	for k, v := range fields {
		if allowedFields[k] {
			out[k] = v
		}
	}
	if subject != "" {
		out["subject"] = subject
	}
	if detail != "" {
		out["detail"] = detail
	}

	text := eventKey
	if subject != "" {
		text += " — " + subject
	}
	if detail != "" {
		text += ": " + detail
	}
	return model.RenderedMessage{
		Event:    eventKey,
		Severity: severity,
		Text:     text,
		Fields:   out,
		At:       now,
	}
}

// fanOut writes one outbox row per subscribed channel, applying the channel's
// template when it has one.
func (s *NotificationService) fanOut(ctx context.Context, eventKey string, payload model.RenderedMessage) error {
	channels, err := s.store.ChannelsForEvent(ctx, eventKey)
	if err != nil {
		return err
	}
	for _, ch := range channels {
		msg := payload
		if strings.TrimSpace(ch.Template) != "" {
			msg.Text = model.Render(ch.Template, payload.Fields)
		}
		if err := s.store.Enqueue(ctx, ch.ID, eventKey, msg); err != nil {
			return err
		}
	}
	return nil
}

// recoveryKeyFor maps a failure key to the key its recovery is announced under.
// Events with no distinct recovery key announce recovery under their own key,
// which a channel subscribed to the failure already receives.
func recoveryKeyFor(failureKey string) string {
	switch failureKey {
	case "cert.renewal_failed":
		return "cert.renewed"
	case "ddns.sync_failed":
		return "ddns.recovered"
	default:
		return failureKey
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
