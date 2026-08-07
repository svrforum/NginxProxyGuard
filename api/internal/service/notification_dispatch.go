package service

import (
	"context"
	"log"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// NotificationDispatcher drains the outbox. It is the only place that performs
// outbound HTTP for notifications, which is what makes the retry budget and the
// per-channel health bookkeeping enforceable in one spot. (#221)
type NotificationDispatcher struct {
	repo   *repository.NotificationRepository
	notify *NotificationService
	// digest is optional and set after construction: the digest service needs
	// the certificate service, which is built later in the graph.
	digest   *NotificationDigestService
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
			model.NotificationTypeDiscord: newDiscordAdapter(),
			// The persister closes over the repository so the adapter can report
			// a migrated chat id without knowing what a repository is.
			model.NotificationTypeTelegram: newTelegramAdapter(func(ctx context.Context, channelID, newChatID string) {
				if err := repo.SetChatID(ctx, channelID, newChatID); err != nil {
					log.Printf("[Notify] failed to persist migrated chat id for %s: %v", channelID, err)
				} else {
					log.Printf("[Notify] telegram chat %s migrated to a supergroup, new id stored", channelID)
				}
			}),
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
			_, _ = d.repo.RecordChannelResult(ctx, e.Channel.ID, "")
			sent++
		case OutcomeRetry:
			if isExhausted(e.Attempts + 1) {
				_ = d.repo.MarkFailed(ctx, e.ID, "gave up after "+reason)
				d.recordTerminalFailure(ctx, e.Channel, reason)
				continue
			}
			if wait <= 0 {
				wait = backoffFor(e.Attempts + 1)
			}
			if err := d.repo.MarkRetry(ctx, e.ID, wait, reason); err != nil {
				log.Printf("[Notify] failed to reschedule %d: %v", e.ID, err)
			}
			// A retry is not evidence about the channel — see
			// RecordTransientFailure. It records the error without spending the
			// disable budget.
			_ = d.repo.RecordTransientFailure(ctx, e.Channel.ID, reason)
		default:
			_ = d.repo.MarkFailed(ctx, e.ID, reason)
			d.recordTerminalFailure(ctx, e.Channel, reason)
		}
	}
	return sent, nil
}

// recordTerminalFailure books a failure we will not retry, and says so in the
// container log.
//
// Until now a channel could count to ten and switch itself off with the only
// trace anywhere being a red box inside one settings sub-tab. A home-server
// operator reads container logs; alerting going dark has to appear there.
func (d *NotificationDispatcher) recordTerminalFailure(ctx context.Context, ch *model.NotificationChannel, reason string) {
	disabled, err := d.repo.RecordChannelResult(ctx, ch.ID, reason)
	if err != nil {
		log.Printf("[Notify] failed to record channel result for %q: %v", ch.Name, err)
		return
	}
	if disabled {
		log.Printf("[Notify] channel %q (%s) DISABLED after 10 consecutive delivery failures — alerts are no longer being sent to it. Last error: %s", ch.Name, ch.Type, reason)
		// Whatever it still had queued is now unreachable: ClaimDue requires an
		// enabled channel, so those rows would sit there until Prune deleted
		// them without ever reaching the delivery log. Close them out with a
		// reason the operator can read.
		if n, err := d.repo.FailQueuedForDisabledChannel(ctx, ch.ID, "channel turned off after 10 consecutive failures"); err != nil {
			log.Printf("[Notify] failed to close out queued messages for %q: %v", ch.Name, err)
		} else if n > 0 {
			log.Printf("[Notify] %d queued message(s) for %q were dropped with the channel", n, ch.Name)
		}
		return
	}
	log.Printf("[Notify] delivery to %q (%s) failed: %s", ch.Name, ch.Type, reason)
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
	// Stale first, then prune. A message that has waited longer than this is no
	// longer news: delivering yesterday's alert as if it just happened sends the
	// operator looking for a problem that is over.
	if n, err := d.repo.ExpireStaleQueued(ctx, staleQueuedAfter, "not sent within 6 hours — too old to still be news"); err != nil {
		log.Printf("[Notify] failed to expire stale queued messages: %v", err)
	} else if n > 0 {
		log.Printf("[Notify] %d queued message(s) expired unsent after %s", n, staleQueuedAfter)
	}
	if n, err := d.repo.Prune(ctx); err != nil {
		log.Printf("[Notify] outbox prune failed: %v", err)
	} else if n > 0 {
		log.Printf("[Notify] pruned %d outbox rows", n)
	}
}

// SendTest delivers a sample message immediately and records the attempt, so
// the button reports a real result AND the delivery log shows it.
//
// The first version skipped the outbox entirely, which meant an operator who
// pressed Test and then opened the log found it empty and had no way to tell
// whether anything had happened. Bypassing the queue is right — a test should
// answer now, not in thirty seconds — but skipping the record was not.
//
// eventKey selects which event to imitate, so an operator can see what each
// alert will actually look like before subscribing to it.
func (d *NotificationDispatcher) SendTest(ctx context.Context, ch *model.NotificationChannel, eventKey string) error {
	adapter, ok := d.adapters[ch.Type]
	if !ok {
		return &UnsupportedChannelError{Type: ch.Type}
	}

	// A digest preview is built from REAL data — a fabricated one would not
	// answer "is my summary useful", which is the only reason to preview it.
	var msg model.RenderedMessage
	if eventKey == "digest.daily" && d.digest != nil {
		built, err := d.digest.BuildPreview(ctx, ch, time.Now())
		if err != nil {
			return err
		}
		msg = built
	} else {
		msg = SampleMessage(ch.Language, eventKey)
	}
	if ch.Template != "" {
		msg.Text = model.Render(ch.Template, msg.Fields)
	}

	outcome, _, sendErr := adapter.Send(ctx, ch, msg)
	reason := ""
	if sendErr != nil {
		reason = sendErr.Error()
	}
	if outcome == OutcomeSent {
		_, _ = d.repo.RecordChannelResult(ctx, ch.ID, "")
		_ = d.repo.RecordAttempt(ctx, ch.ID, msg.Event, msg, "sent", "")
		return nil
	}
	if sendErr == nil {
		sendErr = &UnsupportedChannelError{Type: ch.Type}
		reason = sendErr.Error()
	}
	d.recordTerminalFailure(ctx, ch, reason)
	_ = d.repo.RecordAttempt(ctx, ch.ID, msg.Event, msg, "failed", reason)
	return sendErr
}

// SetDigestService wires the digest after construction. (#221)
func (d *NotificationDispatcher) SetDigestService(s *NotificationDigestService) { d.digest = s }

// UnsupportedChannelError is returned for a channel type this build cannot send.
type UnsupportedChannelError struct{ Type string }

func (e *UnsupportedChannelError) Error() string {
	return "no adapter for channel type " + e.Type
}
