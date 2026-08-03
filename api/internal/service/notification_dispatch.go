package service

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// NotificationDispatcher drains the outbox. It is the only place that performs
// outbound HTTP for notifications, which is what makes the retry budget and the
// per-channel health bookkeeping enforceable in one spot. (#221)
type NotificationDispatcher struct {
	repo     *repository.NotificationRepository
	notify   *NotificationService
	adapters map[string]channelAdapter
	// batchSize bounds one pass so a large backlog cannot hold the tick open.
	batchSize int
}

func NewNotificationDispatcher(repo *repository.NotificationRepository, notify *NotificationService) *NotificationDispatcher {
	return &NotificationDispatcher{
		repo:   repo,
		notify: notify,
		adapters: map[string]channelAdapter{
			model.NotificationTypeWebhook: newWebhookAdapter(),
		},
		batchSize: 25,
	}
}

// DispatchOnce sends everything currently due. Returns the number sent.
func (d *NotificationDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || d.repo == nil || !d.repo.TablesExist(ctx) {
		return 0, nil
	}
	entries, err := d.repo.ClaimDue(ctx, d.batchSize)
	if err != nil {
		return 0, err
	}

	sent := 0
	for _, e := range entries {
		if e.Channel == nil {
			_ = d.repo.MarkFailed(ctx, e.ID, "channel is gone")
			continue
		}
		adapter, ok := d.adapters[e.Channel.Type]
		if !ok {
			// A channel of a type this build does not implement — for example a
			// backup restored from a newer version. Fail it rather than
			// retrying something that can never succeed.
			_ = d.repo.MarkFailed(ctx, e.ID, "unsupported channel type "+e.Channel.Type)
			continue
		}

		outcome, wait, sendErr := adapter.Send(ctx, e.Channel, e.Payload)
		reason := ""
		if sendErr != nil {
			reason = sendErr.Error()
		}

		switch outcome {
		case OutcomeSent:
			if err := d.repo.MarkSent(ctx, e.ID); err != nil {
				log.Printf("[Notify] failed to mark %d sent: %v", e.ID, err)
			}
			_ = d.repo.RecordChannelResult(ctx, e.Channel.ID, "")
			sent++
		case OutcomeRetry:
			if isExhausted(e.Attempts + 1) {
				_ = d.repo.MarkFailed(ctx, e.ID, "gave up after "+reason)
				_ = d.repo.RecordChannelResult(ctx, e.Channel.ID, reason)
				continue
			}
			if wait <= 0 {
				wait = backoffFor(e.Attempts + 1)
			}
			if err := d.repo.MarkRetry(ctx, e.ID, wait, reason); err != nil {
				log.Printf("[Notify] failed to reschedule %d: %v", e.ID, err)
			}
			_ = d.repo.RecordChannelResult(ctx, e.Channel.ID, reason)
		default:
			_ = d.repo.MarkFailed(ctx, e.ID, reason)
			_ = d.repo.RecordChannelResult(ctx, e.Channel.ID, reason)
		}
	}
	return sent, nil
}

// FlushBatches hands the batching window to the notify service.
func (d *NotificationDispatcher) FlushBatches(ctx context.Context) {
	if d == nil || d.notify == nil {
		return
	}
	d.notify.FlushBatches(ctx)
}

// Prune trims the outbox.
func (d *NotificationDispatcher) Prune(ctx context.Context) {
	if d == nil || d.repo == nil || !d.repo.TablesExist(ctx) {
		return
	}
	if n, err := d.repo.Prune(ctx); err != nil {
		log.Printf("[Notify] outbox prune failed: %v", err)
	} else if n > 0 {
		log.Printf("[Notify] pruned %d outbox rows", n)
	}
}

// SendTest delivers a message immediately, bypassing the outbox, so the UI's
// Test button reports a real result rather than "queued".
func (d *NotificationDispatcher) SendTest(ctx context.Context, ch *model.NotificationChannel) error {
	adapter, ok := d.adapters[ch.Type]
	if !ok {
		return &UnsupportedChannelError{Type: ch.Type}
	}
	msg := model.RenderedMessage{
		Event:    "test",
		Severity: "info",
		Text:     "Nginx Proxy Guard test notification",
		Fields:   map[string]string{"event": "test", "instance": "npg"},
	}
	if ch.Template != "" {
		msg.Text = model.Render(ch.Template, msg.Fields)
	}
	outcome, _, err := adapter.Send(ctx, ch, msg)
	if outcome == OutcomeSent {
		_ = d.repo.RecordChannelResult(ctx, ch.ID, "")
		return nil
	}
	if err == nil {
		err = &UnsupportedChannelError{Type: ch.Type}
	}
	_ = d.repo.RecordChannelResult(ctx, ch.ID, err.Error())
	return err
}

// UnsupportedChannelError is returned for a channel type this build cannot send.
type UnsupportedChannelError struct{ Type string }

func (e *UnsupportedChannelError) Error() string {
	return "no adapter for channel type " + e.Type
}
