package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ModSecEventRaw is what is needed to explain one WAF event after the fact:
// the full audit record, plus enough to find the host it belongs to.
type ModSecEventRaw struct {
	RawLog      string
	Host        string
	ProxyHostID string // empty when the collector had not attributed it yet
}

// modsecEventWindow bounds the lookup around the time the caller already holds.
//
// logs_partitioned is a compressed hypertable. A bare "WHERE id = $1" cannot
// prune a single chunk — it decompresses and scans every one of them, which on
// the 154M-row production install is minutes, not milliseconds. The panel
// always has the row's created_at in hand (it came from the list), so the
// lookup is pinned to a window around it and the planner touches one chunk.
const modsecEventWindow = time.Minute

// GetModSecEventRaw returns the stored audit JSON for one modsec log row. nil
// with no error means "no such row in that window".
func (r *LogRepository) GetModSecEventRaw(ctx context.Context, id string, around time.Time) (*ModSecEventRaw, error) {
	var ev ModSecEventRaw
	var raw, host, hostID sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT raw_log, host, proxy_host_id::text
		FROM logs_partitioned
		WHERE id = $1
		  AND log_type = 'modsec'
		  AND created_at BETWEEN $2 AND $3
		LIMIT 1`,
		id, around.Add(-modsecEventWindow), around.Add(modsecEventWindow),
	).Scan(&raw, &host, &hostID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load modsec event: %w", err)
	}
	ev.RawLog, ev.Host, ev.ProxyHostID = raw.String, host.String, hostID.String
	return &ev, nil
}
