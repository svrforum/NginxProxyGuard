package repository

import (
	"context"
	"database/sql"
	"encoding/json"
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

const channelColumns = `id, name, type, enabled, config, events, digest_enabled, digest_hour,
	allow_private_target, COALESCE(template, ''), last_success_at, last_error_at,
	COALESCE(last_error, ''), consecutive_failures, created_at, updated_at`

func scanChannel(s interface{ Scan(...any) error }) (*model.NotificationChannel, error) {
	var c model.NotificationChannel
	var config []byte
	var events pq.StringArray
	if err := s.Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &config, &events,
		&c.DigestEnabled, &c.DigestHour, &c.AllowPrivateTarget, &c.Template,
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
		INSERT INTO notification_channels (name, type, enabled, config, events,
			digest_enabled, digest_hour, allow_private_target, template)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''))
		RETURNING id`,
		req.Name, req.Type, enabled, config, pq.Array(req.Events),
		req.DigestEnabled, req.DigestHour, req.AllowPrivateTarget, req.Template).Scan(&id)
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
			name = $2, type = $3, enabled = $4, config = $5, events = $6,
			digest_enabled = $7, digest_hour = $8, allow_private_target = $9,
			template = NULLIF($10,''), updated_at = now()
		WHERE id = $1`,
		id, req.Name, req.Type, enabled, config, pq.Array(req.Events),
		req.DigestEnabled, req.DigestHour, req.AllowPrivateTarget, req.Template)
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

func (r *NotificationRepository) SetState(ctx context.Context, eventKey, subject, state, detail string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO notification_state (event_key, subject, state, since, last_detail)
		VALUES ($1,$2,$3,now(),NULLIF($4,''))
		ON CONFLICT (event_key, subject)
		DO UPDATE SET state = EXCLUDED.state, since = now(), last_detail = EXCLUDED.last_detail`,
		eventKey, subject, state, detail)
	if err != nil {
		return fmt.Errorf("failed to write notification state: %w", err)
	}
	return nil
}

// OutstandingFailures backs the digest section that keeps a long-running
// breakage visible after its single edge-triggered alert.
func (r *NotificationRepository) OutstandingFailures(ctx context.Context) ([]model.NotificationState, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT event_key, subject, since, COALESCE(last_detail, '')
		FROM notification_state WHERE state = 'failing' ORDER BY since`)
	if err != nil {
		return nil, fmt.Errorf("failed to list outstanding failures: %w", err)
	}
	defer rows.Close()

	out := []model.NotificationState{}
	for rows.Next() {
		var s model.NotificationState
		if err := rows.Scan(&s.EventKey, &s.Subject, &s.Since, &s.LastDetail); err != nil {
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

// ClaimDue returns queued rows whose time has come, each joined to its channel
// so the dispatcher needs no second query. SKIP LOCKED keeps a second process
// (a restart overlapping a shutdown) from sending the same row twice.
func (r *NotificationRepository) ClaimDue(ctx context.Context, limit int) ([]model.OutboxEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT o.id, o.channel_id, o.event_key, o.payload, o.status, o.attempts,
		       o.next_attempt_at, COALESCE(o.last_error,''), o.created_at, o.sent_at,
		       `+channelColumns+`
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
		var events pq.StringArray
		if err := rows.Scan(&e.ID, &e.ChannelID, &e.EventKey, &payload, &e.Status, &e.Attempts,
			&e.NextAttemptAt, &e.LastError, &e.CreatedAt, &e.SentAt,
			&c.ID, &c.Name, &c.Type, &c.Enabled, &config, &events, &c.DigestEnabled, &c.DigestHour,
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
func (r *NotificationRepository) RecordChannelResult(ctx context.Context, channelID string, failure string) error {
	if failure == "" {
		_, err := r.db.ExecContext(ctx,
			`UPDATE notification_channels SET last_success_at = now(), consecutive_failures = 0, last_error = NULL WHERE id = $1`,
			channelID)
		return err
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE notification_channels
		SET last_error_at = now(), last_error = $2,
		    consecutive_failures = consecutive_failures + 1,
		    enabled = CASE WHEN consecutive_failures + 1 >= 10 THEN false ELSE enabled END
		WHERE id = $1`, channelID, failure)
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
