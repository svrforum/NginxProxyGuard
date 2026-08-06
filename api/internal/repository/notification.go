package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// NotificationRepository owns the channel registry, the edge-trigger state and
// the delivery outbox. (#221)
type NotificationRepository struct {
	db *database.DB
}

func NewNotificationRepository(db *database.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

// TablesExist reports whether the notification schema is present. Migrations are
// warn-and-continue in this codebase, so every entry point checks first and
// behaves as "no channels configured" rather than erroring — an install whose
// upgrade failed must still serve its dashboard.
func (r *NotificationRepository) TablesExist(ctx context.Context) bool {
	var ok bool
	err := r.db.QueryRowContext(ctx,
		`SELECT to_regclass('public.notification_channels') IS NOT NULL
		    AND to_regclass('public.notification_state') IS NOT NULL
		    AND to_regclass('public.notification_outbox') IS NOT NULL`).Scan(&ok)
	return err == nil && ok
}

const channelColumns = `id, name, type, enabled, config, events, digest_events, rich_format, language, COALESCE(dashboard_url, ''), digest_enabled, digest_hour,
	allow_private_target, COALESCE(template, ''), last_success_at, last_error_at,
	COALESCE(last_error, ''), consecutive_failures, created_at, updated_at`

// channelColumnsAliased is the same list qualified with the c alias. It exists
// because the unqualified list is ambiguous the moment it appears in a join —
// notification_outbox also has id, created_at and last_error. A single shared
// constant used in both contexts silently produced "column reference id is
// ambiguous" only at runtime, which no unit test would have caught.
const channelColumnsAliased = `c.id, c.name, c.type, c.enabled, c.config, c.events, c.digest_events, c.rich_format, c.language, COALESCE(c.dashboard_url, ''), c.digest_enabled, c.digest_hour,
	c.allow_private_target, COALESCE(c.template, ''), c.last_success_at, c.last_error_at,
	COALESCE(c.last_error, ''), c.consecutive_failures, c.created_at, c.updated_at`

func scanChannel(s interface{ Scan(...any) error }) (*model.NotificationChannel, error) {
	var c model.NotificationChannel
	var config []byte
	var events, digestEvents pq.StringArray
	if err := s.Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &config, &events, &digestEvents,
		&c.RichFormat, &c.Language, &c.DashboardURL, &c.DigestEnabled, &c.DigestHour, &c.AllowPrivateTarget, &c.Template,
		&c.LastSuccessAt, &c.LastErrorAt, &c.LastError, &c.ConsecutiveFail,
		&c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.Config = map[string]string{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &c.Config); err != nil {
			return nil, fmt.Errorf("failed to decode channel config: %w", err)
		}
	}
	c.Events = events
	c.DigestEvents = digestEvents
	return &c, nil
}

func (r *NotificationRepository) List(ctx context.Context) ([]model.NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+channelColumns+` FROM notification_channels ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to list notification channels: %w", err)
	}
	defer rows.Close()

	out := []model.NotificationChannel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (r *NotificationRepository) GetByID(ctx context.Context, id string) (*model.NotificationChannel, error) {
	c, err := scanChannel(r.db.QueryRowContext(ctx,
		`SELECT `+channelColumns+` FROM notification_channels WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get notification channel: %w", err)
	}
	return c, nil
}

// ChannelsForEvent returns the enabled channels subscribed to a key. The array
// containment test happens in the database so a busy event does not pull every
// channel into Go on every emission.
func (r *NotificationRepository) ChannelsForEvent(ctx context.Context, eventKey string) ([]model.NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+channelColumns+` FROM notification_channels
		 WHERE enabled AND events @> ARRAY[$1]::text[] ORDER BY name`, eventKey)
	if err != nil {
		return nil, fmt.Errorf("failed to select channels for %s: %w", eventKey, err)
	}
	defer rows.Close()

	out := []model.NotificationChannel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ChannelsForDigest returns channels whose digest is due this hour and which
// have not already been sent one today. last_digest_on is the idempotency key:
// the scheduler ticks hourly and must not send twice if a tick is retried.
func (r *NotificationRepository) ChannelsForDigest(ctx context.Context, hour int, today time.Time) ([]model.NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+channelColumns+` FROM notification_channels
		 WHERE enabled AND digest_enabled AND digest_hour = $1
		   AND (last_digest_on IS NULL OR last_digest_on < $2::date)
		 ORDER BY name`, hour, today.Format("2006-01-02"))
	if err != nil {
		return nil, fmt.Errorf("failed to select digest channels: %w", err)
	}
	defer rows.Close()

	out := []model.NotificationChannel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// SetChatID rewrites a Telegram channel's chat id in place. Telegram hands out
// a new one when a group is upgraded to a supergroup, and the old id stops
// working, so persisting it is what keeps the channel alive across the upgrade.
func (r *NotificationRepository) SetChatID(ctx context.Context, channelID, chatID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_channels
		 SET config = jsonb_set(config, '{chat_id}', to_jsonb($2::text)), updated_at = now()
		 WHERE id = $1`, channelID, chatID)
	if err != nil {
		return fmt.Errorf("failed to store migrated chat id: %w", err)
	}
	return nil
}

func (r *NotificationRepository) MarkDigestSent(ctx context.Context, channelID string, day time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_channels SET last_digest_on = $2::date WHERE id = $1`,
		channelID, day.Format("2006-01-02"))
	return err
}

func (r *NotificationRepository) Create(ctx context.Context, req *model.CreateNotificationChannelRequest) (string, error) {
	config, err := json.Marshal(req.Config)
	if err != nil {
		return "", fmt.Errorf("failed to encode channel config: %w", err)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var id string
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO notification_channels (name, type, enabled, config, events, digest_events,
			rich_format, language, dashboard_url, digest_enabled, digest_hour, allow_private_target, template)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11,$12,NULLIF($13,''))
		RETURNING id`,
		req.Name, req.Type, enabled, config, pq.Array(req.Events), pq.Array(req.DigestEvents),
		req.RichFormat, req.Language, req.DashboardURL, req.DigestEnabled, req.DigestHour, req.AllowPrivateTarget, req.Template).Scan(&id)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return "", fmt.Errorf("a channel with this name already exists")
		}
		return "", fmt.Errorf("failed to create notification channel: %w", err)
	}
	return id, nil
}

// Update rewrites a channel. Config is merged rather than replaced so a masked
// secret the UI round-tripped keeps its stored value; the service is what
// decides which keys survive.
func (r *NotificationRepository) Update(ctx context.Context, id string, req *model.UpdateNotificationChannelRequest) error {
	config, err := json.Marshal(req.Config)
	if err != nil {
		return fmt.Errorf("failed to encode channel config: %w", err)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE notification_channels SET
			name = $2, type = $3, enabled = $4, config = $5, events = $6, digest_events = $7,
			rich_format = $8, language = $9, dashboard_url = NULLIF($10,''), digest_enabled = $11,
			digest_hour = $12, allow_private_target = $13, template = NULLIF($14,''), updated_at = now()
		WHERE id = $1`,
		id, req.Name, req.Type, enabled, config, pq.Array(req.Events), pq.Array(req.DigestEvents),
		req.RichFormat, req.Language, req.DashboardURL, req.DigestEnabled, req.DigestHour, req.AllowPrivateTarget, req.Template)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("a channel with this name already exists")
		}
		return fmt.Errorf("failed to update notification channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *NotificationRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete notification channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ── edge-trigger state ────────────────────────────────────────────────────

// GetState returns the last known state for a subject, or "" when unseen.
func (r *NotificationRepository) GetState(ctx context.Context, eventKey, subject string) (string, error) {
	var state string
	err := r.db.QueryRowContext(ctx,
		`SELECT state FROM notification_state WHERE event_key = $1 AND subject = $2`,
		eventKey, subject).Scan(&state)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read notification state: %w", err)
	}
	return state, nil
}

func (r *NotificationRepository) SetState(ctx context.Context, eventKey, subject, label, state, detail string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO notification_state (event_key, subject, subject_label, state, since, last_detail)
		VALUES ($1,$2,NULLIF($3,''),$4,now(),NULLIF($5,''))
		ON CONFLICT (event_key, subject)
		DO UPDATE SET subject_label = EXCLUDED.subject_label, state = EXCLUDED.state,
		              since = now(), last_detail = EXCLUDED.last_detail`,
		eventKey, subject, label, state, detail)
	if err != nil {
		return fmt.Errorf("failed to write notification state: %w", err)
	}
	return nil
}

// SetSubjectLabel refreshes the readable name without touching the state or
// its since timestamp.
//
// It exists for the path where nothing changed: a certificate that has been
// failing for a week is re-checked every six hours and takes the early return
// in EmitTransition, so a row written before labels existed — or written when
// the domain was different — would otherwise keep showing a UUID in the digest
// forever. The IS DISTINCT FROM guard means the common case writes nothing.
func (r *NotificationRepository) SetSubjectLabel(ctx context.Context, eventKey, subject, label string) error {
	if label == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE notification_state SET subject_label = $3
		WHERE event_key = $1 AND subject = $2 AND subject_label IS DISTINCT FROM $3`,
		eventKey, subject, label)
	if err != nil {
		return fmt.Errorf("failed to update notification subject label: %w", err)
	}
	return nil
}

// OutstandingFailures backs the digest section that keeps a long-running
// breakage visible after its single edge-triggered alert.
func (r *NotificationRepository) OutstandingFailures(ctx context.Context) ([]model.NotificationState, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT event_key, subject, COALESCE(subject_label, ''), since, COALESCE(last_detail, '')
		FROM notification_state WHERE state = 'failing' ORDER BY since`)
	if err != nil {
		return nil, fmt.Errorf("failed to list outstanding failures: %w", err)
	}
	defer rows.Close()

	out := []model.NotificationState{}
	for rows.Next() {
		var s model.NotificationState
		if err := rows.Scan(&s.EventKey, &s.Subject, &s.Label, &s.Since, &s.LastDetail); err != nil {
			return nil, err
		}
		s.State = "failing"
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── outbox ────────────────────────────────────────────────────────────────

func (r *NotificationRepository) Enqueue(ctx context.Context, channelID, eventKey string, payload model.RenderedMessage) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode notification payload: %w", err)
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO notification_outbox (channel_id, event_key, payload) VALUES ($1,$2,$3)`,
		channelID, eventKey, encoded)
	if err != nil {
		return fmt.Errorf("failed to enqueue notification: %w", err)
	}
	return nil
}

// outboxStatusDigest parks an occurrence for tomorrow's summary instead of
// sending it.
//
// It rides in the outbox rather than a table of its own because everything the
// row needs already exists here: the channel FK with its ON DELETE CASCADE, the
// payload, the timestamp, and Prune's retention. ClaimDue selects status
// 'queued', so a parked row is never dispatched.
const outboxStatusDigest = "digest"

// EnqueueForDigest records an event a channel asked to hear about only in the
// daily summary.
func (r *NotificationRepository) EnqueueForDigest(ctx context.Context, channelID, eventKey string, payload model.RenderedMessage) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode notification payload: %w", err)
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO notification_outbox (channel_id, event_key, payload, status) VALUES ($1,$2,$3,$4)`,
		channelID, eventKey, encoded, outboxStatusDigest)
	if err != nil {
		return fmt.Errorf("failed to park notification for the digest: %w", err)
	}
	return nil
}

// ChannelsForDigestEvent lists channels that want this event in the summary
// only. digest_enabled is required because a channel with the summary switched
// off has nowhere to put it.
func (r *NotificationRepository) ChannelsForDigestEvent(ctx context.Context, eventKey string) ([]model.NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+channelColumns+` FROM notification_channels
		 WHERE enabled AND digest_enabled AND digest_events @> ARRAY[$1]::text[] ORDER BY name`, eventKey)
	if err != nil {
		return nil, fmt.Errorf("failed to select digest channels for %s: %w", eventKey, err)
	}
	defer rows.Close()

	out := []model.NotificationChannel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// DigestPending is one event key parked for a channel, with how many times it
// happened and when it was last seen.
type DigestPending struct {
	EventKey string
	Count    int
	Last     time.Time
	Subject  string
}

// PendingDigestItems groups a channel's parked occurrences for rendering.
func (r *NotificationRepository) PendingDigestItems(ctx context.Context, channelID string, since time.Time) ([]DigestPending, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT event_key, count(*), max(created_at),
		       COALESCE((array_agg(payload->'fields'->>'subject' ORDER BY created_at DESC))[1], '')
		FROM notification_outbox
		WHERE channel_id = $1 AND status = $2 AND created_at >= $3
		GROUP BY event_key
		ORDER BY count(*) DESC, event_key`, channelID, outboxStatusDigest, since)
	if err != nil {
		return nil, fmt.Errorf("failed to read parked digest items: %w", err)
	}
	defer rows.Close()

	out := []DigestPending{}
	for rows.Next() {
		var p DigestPending
		var subject sql.NullString
		if err := rows.Scan(&p.EventKey, &p.Count, &p.Last, &subject); err != nil {
			return nil, err
		}
		p.Subject = subject.String
		out = append(out, p)
	}
	return out, rows.Err()
}

// ConsumeDigestItems marks a channel's parked rows as delivered, so tomorrow's
// summary does not repeat today's. They stay in the log as evidence until Prune
// takes them.
func (r *NotificationRepository) ConsumeDigestItems(ctx context.Context, channelID string, until time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_outbox SET status = 'sent', sent_at = now()
		 WHERE channel_id = $1 AND status = $2 AND created_at <= $3`,
		channelID, outboxStatusDigest, until)
	if err != nil {
		return fmt.Errorf("failed to consume parked digest items: %w", err)
	}
	return nil
}

// ClaimDue returns queued rows whose time has come, each joined to its channel
// so the dispatcher needs no second query. SKIP LOCKED keeps a second process
// (a restart overlapping a shutdown) from sending the same row twice.
func (r *NotificationRepository) ClaimDue(ctx context.Context, limit int) ([]model.OutboxEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT o.id, o.channel_id, o.event_key, o.payload, o.status, o.attempts,
		       o.next_attempt_at, COALESCE(o.last_error,''), o.created_at, o.sent_at,
		       `+channelColumnsAliased+`
		FROM notification_outbox o
		JOIN notification_channels c ON c.id = o.channel_id
		WHERE o.status = 'queued' AND o.next_attempt_at <= now() AND c.enabled
		ORDER BY o.id
		LIMIT $1
		FOR UPDATE OF o SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to claim notifications: %w", err)
	}
	defer rows.Close()

	out := []model.OutboxEntry{}
	for rows.Next() {
		var e model.OutboxEntry
		var payload []byte
		var c model.NotificationChannel
		var config []byte
		var events, digestEvents pq.StringArray
		if err := rows.Scan(&e.ID, &e.ChannelID, &e.EventKey, &payload, &e.Status, &e.Attempts,
			&e.NextAttemptAt, &e.LastError, &e.CreatedAt, &e.SentAt,
			&c.ID, &c.Name, &c.Type, &c.Enabled, &config, &events, &digestEvents, &c.RichFormat, &c.Language, &c.DashboardURL, &c.DigestEnabled, &c.DigestHour,
			&c.AllowPrivateTarget, &c.Template, &c.LastSuccessAt, &c.LastErrorAt, &c.LastError,
			&c.ConsecutiveFail, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan notification: %w", err)
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &e.Payload); err != nil {
				return nil, fmt.Errorf("failed to decode notification payload: %w", err)
			}
		}
		c.Config = map[string]string{}
		if len(config) > 0 {
			if err := json.Unmarshal(config, &c.Config); err != nil {
				return nil, fmt.Errorf("failed to decode channel config: %w", err)
			}
		}
		c.Events = events
		c.DigestEvents = digestEvents
		e.Channel = &c
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *NotificationRepository) MarkSent(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_outbox SET status='sent', sent_at=now(), attempts=attempts+1, last_error=NULL WHERE id=$1`, id)
	return err
}

func (r *NotificationRepository) MarkRetry(ctx context.Context, id int64, in time.Duration, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE notification_outbox
		SET attempts = attempts + 1, next_attempt_at = now() + $2::interval, last_error = $3
		WHERE id = $1`, id, fmt.Sprintf("%d seconds", int(in.Seconds())), reason)
	return err
}

func (r *NotificationRepository) MarkFailed(ctx context.Context, id int64, reason string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_outbox SET status='failed', attempts=attempts+1, last_error=$2 WHERE id=$1`, id, reason)
	return err
}

// RecordChannelResult tracks health so the UI can explain silence, and disables
// a channel that has failed ten times running — a dead webhook should stop
// costing outbound requests.
// It reports whether this result is what turned the channel off, so the caller
// can say so in the container log — the surface a home-server operator actually
// watches. A channel that disables itself in silence is the same failure the
// whole feature exists to prevent.
func (r *NotificationRepository) RecordChannelResult(ctx context.Context, channelID string, failure string) (justDisabled bool, err error) {
	if failure == "" {
		// A success re-enables a channel this counter turned off: the operator
		// fixed the token, pressed Test, and the channel has proved it works.
		_, err := r.db.ExecContext(ctx,
			`UPDATE notification_channels
			 SET last_success_at = now(), consecutive_failures = 0, last_error = NULL,
			     enabled = CASE WHEN consecutive_failures >= 10 THEN true ELSE enabled END
			 WHERE id = $1`, channelID)
		return false, err
	}
	// The previous value comes from a CTE rather than a subquery in RETURNING:
	// both would read the pre-update snapshot, but only one of them says so.
	var wasEnabled, nowEnabled bool
	err = r.db.QueryRowContext(ctx, `
		WITH prev AS (SELECT enabled FROM notification_channels WHERE id = $1)
		UPDATE notification_channels c
		SET last_error_at = now(), last_error = $2,
		    consecutive_failures = c.consecutive_failures + 1,
		    enabled = CASE WHEN c.consecutive_failures + 1 >= 10 THEN false ELSE c.enabled END
		FROM prev
		WHERE c.id = $1
		RETURNING prev.enabled, c.enabled`,
		channelID, failure).Scan(&wasEnabled, &nowEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return wasEnabled && !nowEnabled, err
}

// RecordTransientFailure notes an attempt that is going to be retried.
//
// It records the error so the card can explain the silence, but deliberately
// does NOT touch consecutive_failures. Counting retries toward the disable
// threshold meant a receiver that was merely DOWN — an ntfy container
// restarting, a Telegram 429 — burned the whole budget from a single message:
// four attempts is four failures, so a short outage turned alerting off
// permanently and the operator was never told why. Only results we will not
// retry say anything about the channel's configuration.
func (r *NotificationRepository) RecordTransientFailure(ctx context.Context, channelID, failure string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_channels SET last_error_at = now(), last_error = $2 WHERE id = $1`,
		channelID, failure)
	return err
}

// RecordAttempt writes an already-completed delivery straight to the log. It
// exists for the Test button, which sends immediately rather than queueing but
// must still leave a trace — an operator who presses Test and finds an empty
// log has been told nothing.
func (r *NotificationRepository) RecordAttempt(ctx context.Context, channelID, eventKey string, payload model.RenderedMessage, status, reason string) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sentAt := "now()"
	if status != "sent" {
		sentAt = "NULL"
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO notification_outbox (channel_id, event_key, payload, status, attempts, last_error, sent_at)
		VALUES ($1,$2,$3,$4,1,NULLIF($5,''), `+sentAt+`)`,
		channelID, eventKey, encoded, status, reason)
	return err
}

// RecentDeliveries backs the "why did I not get an alert" view.
func (r *NotificationRepository) RecentDeliveries(ctx context.Context, channelID string, limit int) ([]model.OutboxEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, channel_id, event_key, payload, status, attempts, next_attempt_at,
		       COALESCE(last_error,''), created_at, sent_at
		FROM notification_outbox WHERE channel_id = $1 ORDER BY id DESC LIMIT $2`, channelID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list deliveries: %w", err)
	}
	defer rows.Close()

	out := []model.OutboxEntry{}
	for rows.Next() {
		var e model.OutboxEntry
		var payload []byte
		if err := rows.Scan(&e.ID, &e.ChannelID, &e.EventKey, &payload, &e.Status, &e.Attempts,
			&e.NextAttemptAt, &e.LastError, &e.CreatedAt, &e.SentAt); err != nil {
			return nil, err
		}
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &e.Payload)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Prune keeps the outbox from growing without bound. Sent rows are evidence for
// a week; failures are worth keeping a month because that is the window in which
// somebody asks why they never heard about something.
func (r *NotificationRepository) Prune(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM notification_outbox
		WHERE (status = 'sent'   AND created_at < now() - interval '7 days')
		   OR (status <> 'sent'  AND created_at < now() - interval '30 days')`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
