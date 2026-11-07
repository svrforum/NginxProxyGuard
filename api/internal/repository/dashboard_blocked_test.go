package repository

import (
	"context"
	"testing"
	"time"
)

// The dashboard's blocked counts read both kinds of block row: the reason
// nginx wrote on an access row, and the WAF's modsec row, whose request's
// access row says 'none' (#369). A modsec row the WAF only logged is no block.
func TestDashboardBlockedCountsTheWAFFromModsecRows(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TYPE log_type AS ENUM ('access', 'error', 'modsec')`,
		`CREATE TYPE block_reason AS ENUM ('none', 'waf', 'bot_filter', 'rate_limit', 'geo_block')`,
		`CREATE TABLE logs_partitioned (
			log_type log_type NOT NULL, client_ip inet,
			block_reason block_reason DEFAULT 'none', created_at timestamptz NOT NULL)`,
		`INSERT INTO logs_partitioned (log_type, client_ip, block_reason, created_at) VALUES
			('access', '192.0.2.1', 'none',       '2026-10-08 10:00:00+00'),
			('modsec', '192.0.2.1', 'waf',        '2026-10-08 10:00:00+00'),
			('access', '192.0.2.2', 'rate_limit', '2026-10-08 10:01:00+00'),
			('access', '192.0.2.2', 'bot_filter', '2026-10-08 10:02:00+00'),
			('access', '192.0.2.3', 'geo_block',  '2026-10-08 10:03:00+00'),
			('modsec', '192.0.2.4', 'none',       '2026-10-08 10:04:00+00'),
			('error',  '192.0.2.5', 'waf',        '2026-10-08 10:05:00+00'),
			('modsec', '192.0.2.6', 'waf',        '2026-10-07 09:59:59+00')`)

	var blocked, ips, waf, rl, bot int64
	since := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	if err := db.QueryRowContext(context.Background(), dashboardBlocked24hSQL, since).
		Scan(&blocked, &ips, &waf, &rl, &bot); err != nil {
		t.Fatal(err)
	}
	if blocked != 4 || ips != 3 || waf != 1 || rl != 1 || bot != 1 {
		t.Errorf("blocked=%d ips=%d waf=%d rate_limit=%d bot=%d, want 4 blocks from 3 IPs: 1 WAF, 1 rate limit, 1 bot",
			blocked, ips, waf, rl, bot)
	}
}
