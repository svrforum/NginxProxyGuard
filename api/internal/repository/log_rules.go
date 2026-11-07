package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// LogRulesRepository stores the hosts' log rules (#347): a row in
// proxy_host_log_rules for each proxy host whose rules skip something.
type LogRulesRepository struct {
	db *sql.DB
}

func NewLogRulesRepository(db *sql.DB) *LogRulesRepository {
	return &LogRulesRepository{db: db}
}

// logRulesHostSelect reads proxy hosts with their rules, empty for a host
// without a row. A stream host has no access log lines, so it is left out.
const logRulesHostSelect = `
	SELECT h.id, h.domain_names, h.enabled,
		COALESCE(l.skip_all, false), COALESCE(l.skip_statuses, '{}'), COALESCE(l.skip_methods, '{}'),
		COALESCE(l.skip_paths, '{}'), l.updated_at
	FROM proxy_hosts h
	LEFT JOIN proxy_host_log_rules l ON l.proxy_host_id = h.id
	WHERE h.proxy_type IS DISTINCT FROM 'stream'`

func scanLogRulesEntry(s interface{ Scan(dest ...any) error }) (model.HostLogRulesEntry, error) {
	var e model.HostLogRulesEntry
	var domains, statuses, methods, paths pq.StringArray
	var updatedAt sql.NullTime
	if err := s.Scan(&e.ProxyHostID, &domains, &e.Enabled, &e.SkipAll, &statuses, &methods, &paths, &updatedAt); err != nil {
		return e, err
	}
	e.DomainNames = nonNil(domains)
	e.SkipStatuses, e.SkipMethods, e.SkipPaths = nonNil(statuses), nonNil(methods), nonNil(paths)
	if updatedAt.Valid {
		t := updatedAt.Time
		e.UpdatedAt = &t
	}
	return e, nil
}

func nonNil(a pq.StringArray) []string {
	if a == nil {
		return []string{}
	}
	return a
}

// List returns every proxy host other than a stream host, with its rules,
// in the order of the hosts' first domain.
func (r *LogRulesRepository) List(ctx context.Context) ([]model.HostLogRulesEntry, error) {
	rows, err := r.db.QueryContext(ctx, logRulesHostSelect+` ORDER BY h.domain_names[1], h.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []model.HostLogRulesEntry{}
	for rows.Next() {
		e, err := scanLogRulesEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Get returns a proxy host with its rules, nil when there is no such host.
func (r *LogRulesRepository) Get(ctx context.Context, proxyHostID string) (*model.HostLogRulesEntry, error) {
	e, err := scanLogRulesEntry(r.db.QueryRowContext(ctx, logRulesHostSelect+` AND h.id = $1`, proxyHostID))
	var pqErr *pq.Error
	if errors.Is(err, sql.ErrNoRows) || errors.As(err, &pqErr) && pqErr.Code == "22P02" {
		// No such host, or an id that is no uuid.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Set replaces the host's rules, which model.NormalizeHostLogRules has
// checked, and returns the host with them; nil, and nothing written, when
// there is no such host or it is a stream host (Get). Rules that skip nothing
// remove the host's row.
func (r *LogRulesRepository) Set(ctx context.Context, proxyHostID string, rules model.HostLogRules) (*model.HostLogRulesEntry, error) {
	if host, err := r.Get(ctx, proxyHostID); host == nil || err != nil {
		return nil, err
	}
	if rules.IsEmpty() {
		if _, err := r.db.ExecContext(ctx, `DELETE FROM proxy_host_log_rules WHERE proxy_host_id = $1`, proxyHostID); err != nil {
			return nil, err
		}
		return r.Get(ctx, proxyHostID)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO proxy_host_log_rules (proxy_host_id, skip_all, skip_statuses, skip_methods, skip_paths)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			skip_all = EXCLUDED.skip_all,
			skip_statuses = EXCLUDED.skip_statuses,
			skip_methods = EXCLUDED.skip_methods,
			skip_paths = EXCLUDED.skip_paths,
			updated_at = NOW()`,
		proxyHostID, rules.SkipAll, pq.Array(nonNil(rules.SkipStatuses)), pq.Array(nonNil(rules.SkipMethods)), pq.Array(nonNil(rules.SkipPaths)))
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23503" {
		// The host was deleted since Get read it.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, proxyHostID)
}

// ListActive returns the rules of every host that has some, for the log
// collector.
func (r *LogRulesRepository) ListActive(ctx context.Context) ([]model.HostLogRules, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT proxy_host_id, skip_all, skip_statuses, skip_methods, skip_paths, updated_at
		FROM proxy_host_log_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.HostLogRules
	for rows.Next() {
		var rules model.HostLogRules
		var statuses, methods, paths pq.StringArray
		var updatedAt time.Time
		if err := rows.Scan(&rules.ProxyHostID, &rules.SkipAll, &statuses, &methods, &paths, &updatedAt); err != nil {
			return nil, err
		}
		rules.SkipStatuses, rules.SkipMethods, rules.SkipPaths = nonNil(statuses), nonNil(methods), nonNil(paths)
		rules.UpdatedAt = &updatedAt
		out = append(out, rules)
	}
	return out, rows.Err()
}
