package repository

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	"nginx-proxy-guard/internal/model"
)

// FilterSubscriptionRepository handles filter subscription database operations
type FilterSubscriptionRepository struct {
	db *sql.DB
}

// NewFilterSubscriptionRepository creates a new filter subscription repository
func NewFilterSubscriptionRepository(db *sql.DB) *FilterSubscriptionRepository {
	return &FilterSubscriptionRepository{db: db}
}

// List returns a paginated list of filter subscriptions
func (r *FilterSubscriptionRepository) List(ctx context.Context, page, perPage int) (*model.FilterSubscriptionListResponse, error) {
	var total int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM filter_subscriptions`).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("failed to count filter subscriptions: %w", err)
	}

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))
	offset := (page - 1) * perPage

	query := `
		SELECT id, name, COALESCE(description, '') as description, url, format, type,
		       enabled, refresh_type, refresh_value,
		       last_fetched_at, last_success_at, last_error,
		       entry_count, created_at, updated_at
		FROM filter_subscriptions
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.QueryContext(ctx, query, perPage, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list filter subscriptions: %w", err)
	}
	defer rows.Close()

	subs := []model.FilterSubscription{}
	for rows.Next() {
		var sub model.FilterSubscription
		if err := rows.Scan(
			&sub.ID, &sub.Name, &sub.Description, &sub.URL, &sub.Format, &sub.Type,
			&sub.Enabled, &sub.RefreshType, &sub.RefreshValue,
			&sub.LastFetchedAt, &sub.LastSuccessAt, &sub.LastError,
			&sub.EntryCount, &sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan filter subscription: %w", err)
		}
		subs = append(subs, sub)
	}

	return &model.FilterSubscriptionListResponse{
		Data:       subs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, rows.Err()
}

// GetByID returns a single filter subscription by ID
func (r *FilterSubscriptionRepository) GetByID(ctx context.Context, id string) (*model.FilterSubscription, error) {
	query := `
		SELECT id, name, COALESCE(description, '') as description, url, format, type,
		       enabled, refresh_type, refresh_value,
		       last_fetched_at, last_success_at, last_error,
		       entry_count, created_at, updated_at
		FROM filter_subscriptions
		WHERE id = $1`

	var sub model.FilterSubscription
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&sub.ID, &sub.Name, &sub.Description, &sub.URL, &sub.Format, &sub.Type,
		&sub.Enabled, &sub.RefreshType, &sub.RefreshValue,
		&sub.LastFetchedAt, &sub.LastSuccessAt, &sub.LastError,
		&sub.EntryCount, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get filter subscription: %w", err)
	}
	return &sub, nil
}

// GetByURL returns a filter subscription by URL, or nil if not found
func (r *FilterSubscriptionRepository) GetByURL(ctx context.Context, url string) (*model.FilterSubscription, error) {
	query := `
		SELECT id, name, COALESCE(description, '') as description, url, format, type,
		       enabled, refresh_type, refresh_value,
		       last_fetched_at, last_success_at, last_error,
		       entry_count, created_at, updated_at
		FROM filter_subscriptions
		WHERE url = $1`

	var sub model.FilterSubscription
	err := r.db.QueryRowContext(ctx, query, url).Scan(
		&sub.ID, &sub.Name, &sub.Description, &sub.URL, &sub.Format, &sub.Type,
		&sub.Enabled, &sub.RefreshType, &sub.RefreshValue,
		&sub.LastFetchedAt, &sub.LastSuccessAt, &sub.LastError,
		&sub.EntryCount, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get filter subscription by URL: %w", err)
	}
	return &sub, nil
}

// Create creates a new filter subscription
func (r *FilterSubscriptionRepository) Create(ctx context.Context, sub *model.FilterSubscription) (*model.FilterSubscription, error) {
	query := `
		INSERT INTO filter_subscriptions (name, description, url, format, type, enabled, refresh_type, refresh_value, entry_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		sub.Name, sub.Description, sub.URL, sub.Format, sub.Type,
		sub.Enabled, sub.RefreshType, sub.RefreshValue, sub.EntryCount,
	).Scan(&sub.ID, &sub.CreatedAt, &sub.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter subscription: %w", err)
	}
	return sub, nil
}

// Update updates a filter subscription with dynamic fields
func (r *FilterSubscriptionRepository) Update(ctx context.Context, id string, req *model.UpdateFilterSubscriptionRequest) (*model.FilterSubscription, error) {
	setClauses := []string{"updated_at = CURRENT_TIMESTAMP"}
	args := []interface{}{}
	argIndex := 1

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *req.Name)
		argIndex++
	}
	if req.Enabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *req.Enabled)
		argIndex++
	}
	if req.RefreshType != nil {
		setClauses = append(setClauses, fmt.Sprintf("refresh_type = $%d", argIndex))
		args = append(args, *req.RefreshType)
		argIndex++
	}
	if req.RefreshValue != nil {
		setClauses = append(setClauses, fmt.Sprintf("refresh_value = $%d", argIndex))
		args = append(args, *req.RefreshValue)
		argIndex++
	}

	if len(args) == 0 {
		return r.GetByID(ctx, id)
	}

	args = append(args, id)
	query := fmt.Sprintf(`
		UPDATE filter_subscriptions
		SET %s
		WHERE id = $%d
		RETURNING id, name, COALESCE(description, '') as description, url, format, type,
		          enabled, refresh_type, refresh_value,
		          last_fetched_at, last_success_at, last_error,
		          entry_count, created_at, updated_at`,
		joinStrings(setClauses, ", "), argIndex)

	var sub model.FilterSubscription
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&sub.ID, &sub.Name, &sub.Description, &sub.URL, &sub.Format, &sub.Type,
		&sub.Enabled, &sub.RefreshType, &sub.RefreshValue,
		&sub.LastFetchedAt, &sub.LastSuccessAt, &sub.LastError,
		&sub.EntryCount, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update filter subscription: %w", err)
	}
	return &sub, nil
}

// Delete deletes a filter subscription (CASCADE handles entries/exclusions)
func (r *FilterSubscriptionRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM filter_subscriptions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete filter subscription: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("filter subscription not found")
	}
	return nil
}

// UpdateFetchStatus updates the fetch status of a subscription
func (r *FilterSubscriptionRepository) UpdateFetchStatus(ctx context.Context, id string, success bool, entryCount int, lastError string) error {
	var query string
	if success {
		query = `
			UPDATE filter_subscriptions
			SET last_fetched_at = CURRENT_TIMESTAMP,
			    last_success_at = CURRENT_TIMESTAMP,
			    last_error = NULL,
			    entry_count = $2,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = $1`
		_, err := r.db.ExecContext(ctx, query, id, entryCount)
		return err
	}

	query = `
		UPDATE filter_subscriptions
		SET last_fetched_at = CURRENT_TIMESTAMP,
		    last_error = $2,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, lastError)
	return err
}

// ReplaceEntries replaces all entries for a subscription in a transaction
func (r *FilterSubscriptionRepository) ReplaceEntries(ctx context.Context, subscriptionID string, entries []model.FilterSubscriptionEntry) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete old entries
	_, err = tx.ExecContext(ctx, `DELETE FROM filter_subscription_entries WHERE subscription_id = $1`, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to delete old entries: %w", err)
	}

	// Insert new entries in batches of 500
	const batchSize = 500
	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}
		batch := entries[i:end]

		valueStrings := make([]string, 0, len(batch))
		valueArgs := make([]interface{}, 0, len(batch)*3)
		for j, entry := range batch {
			base := j*3 + 1
			valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d)", base, base+1, base+2))
			valueArgs = append(valueArgs, subscriptionID, entry.Value, entry.Reason)
		}

		query := fmt.Sprintf(
			`INSERT INTO filter_subscription_entries (subscription_id, value, reason) VALUES %s ON CONFLICT (subscription_id, value) DO NOTHING`,
			joinStrings(valueStrings, ", "),
		)
		if _, err = tx.ExecContext(ctx, query, valueArgs...); err != nil {
			return fmt.Errorf("failed to insert entries batch: %w", err)
		}
	}

	return tx.Commit()
}

// GetEntries returns all entries for a subscription
func (r *FilterSubscriptionRepository) GetEntries(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionEntry, error) {
	query := `
		SELECT id, subscription_id, value, COALESCE(reason, '') as reason, created_at
		FROM filter_subscription_entries
		WHERE subscription_id = $1
		ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}
	defer rows.Close()

	entries := []model.FilterSubscriptionEntry{}
	for rows.Next() {
		var e model.FilterSubscriptionEntry
		if err := rows.Scan(&e.ID, &e.SubscriptionID, &e.Value, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetTotalEntryCount returns the total count of all filter subscription entries
func (r *FilterSubscriptionRepository) GetTotalEntryCount(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM filter_subscription_entries`).Scan(&count)
	return count, err
}

// GetEntriesForHost returns entries from enabled subscriptions where the host is NOT excluded
func (r *FilterSubscriptionRepository) GetEntriesForHost(ctx context.Context, hostID string, filterType string) ([]model.FilterSubscriptionEntry, error) {
	query := `
		SELECT e.id, e.subscription_id, e.value, COALESCE(e.reason, '') as reason, e.created_at
		FROM filter_subscription_entries e
		INNER JOIN filter_subscriptions s ON e.subscription_id = s.id
		LEFT JOIN filter_subscription_host_exclusions x
			ON s.id = x.subscription_id AND x.proxy_host_id = $1
		WHERE s.enabled = true
		  AND s.type = $2
		  AND x.id IS NULL
		ORDER BY e.created_at`

	rows, err := r.db.QueryContext(ctx, query, hostID, filterType)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries for host: %w", err)
	}
	defer rows.Close()

	entries := []model.FilterSubscriptionEntry{}
	for rows.Next() {
		var e model.FilterSubscriptionEntry
		if err := rows.Scan(&e.ID, &e.SubscriptionID, &e.Value, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ListExclusions returns all host exclusions for a subscription
func (r *FilterSubscriptionRepository) ListExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionHostExclusion, error) {
	query := `
		SELECT id, subscription_id, proxy_host_id, created_at
		FROM filter_subscription_host_exclusions
		WHERE subscription_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list exclusions: %w", err)
	}
	defer rows.Close()

	exclusions := []model.FilterSubscriptionHostExclusion{}
	for rows.Next() {
		var e model.FilterSubscriptionHostExclusion
		if err := rows.Scan(&e.ID, &e.SubscriptionID, &e.ProxyHostID, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan exclusion: %w", err)
		}
		exclusions = append(exclusions, e)
	}
	return exclusions, rows.Err()
}

// AddExclusion adds a host exclusion for a subscription
func (r *FilterSubscriptionRepository) AddExclusion(ctx context.Context, subscriptionID, hostID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO filter_subscription_host_exclusions (subscription_id, proxy_host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		subscriptionID, hostID,
	)
	if err != nil {
		return fmt.Errorf("failed to add exclusion: %w", err)
	}
	return nil
}

// RemoveExclusion removes a host exclusion for a subscription
func (r *FilterSubscriptionRepository) RemoveExclusion(ctx context.Context, subscriptionID, hostID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM filter_subscription_host_exclusions WHERE subscription_id = $1 AND proxy_host_id = $2`,
		subscriptionID, hostID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove exclusion: %w", err)
	}
	return nil
}

// GetEnabledSubscriptions returns all enabled subscriptions
func (r *FilterSubscriptionRepository) GetEnabledSubscriptions(ctx context.Context) ([]model.FilterSubscription, error) {
	query := `
		SELECT id, name, COALESCE(description, '') as description, url, format, type,
		       enabled, refresh_type, refresh_value,
		       last_fetched_at, last_success_at, last_error,
		       entry_count, created_at, updated_at
		FROM filter_subscriptions
		WHERE enabled = true
		ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled subscriptions: %w", err)
	}
	defer rows.Close()

	subs := []model.FilterSubscription{}
	for rows.Next() {
		var sub model.FilterSubscription
		if err := rows.Scan(
			&sub.ID, &sub.Name, &sub.Description, &sub.URL, &sub.Format, &sub.Type,
			&sub.Enabled, &sub.RefreshType, &sub.RefreshValue,
			&sub.LastFetchedAt, &sub.LastSuccessAt, &sub.LastError,
			&sub.EntryCount, &sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan filter subscription: %w", err)
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

// GetSubscribedURLs returns a map of all subscription URLs for catalog display
func (r *FilterSubscriptionRepository) GetSubscribedURLs(ctx context.Context) (map[string]bool, error) {
	query := `SELECT url FROM filter_subscriptions`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscribed URLs: %w", err)
	}
	defer rows.Close()

	urls := make(map[string]bool)
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, fmt.Errorf("failed to scan URL: %w", err)
		}
		urls[url] = true
	}
	return urls, rows.Err()
}

// GetAllEnabledEntriesByType returns all entries from enabled subscriptions of the given type.
// This is used for generating shared filter subscription config files.
func (r *FilterSubscriptionRepository) GetAllEnabledEntriesByType(ctx context.Context, filterType string) ([]string, error) {
	query := `
		SELECT DISTINCT e.value
		FROM filter_subscription_entries e
		INNER JOIN filter_subscriptions s ON e.subscription_id = s.id
		WHERE s.enabled = true AND s.type = $1
		ORDER BY e.value`

	rows, err := r.db.QueryContext(ctx, query, filterType)
	if err != nil {
		return nil, fmt.Errorf("failed to get all enabled entries by type: %w", err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("failed to scan entry value: %w", err)
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// CountExclusionsForHost returns the number of subscriptions that exclude a given host
func (r *FilterSubscriptionRepository) CountExclusionsForHost(ctx context.Context, hostID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM filter_subscription_host_exclusions WHERE proxy_host_id = $1`,
		hostID,
	).Scan(&count)
	return count, err
}

// CountEnabledSubscriptions returns the count of enabled subscriptions
func (r *FilterSubscriptionRepository) CountEnabledSubscriptions(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM filter_subscriptions WHERE enabled = true`,
	).Scan(&count)
	return count, err
}
