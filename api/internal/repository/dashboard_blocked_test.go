package repository

import (
	"context"
	"testing"
	"time"
)

// The dashboard's blocked total counts each request once, from its access
// row, and the WAF count is the modsec rows marked 'waf' (#369). A WAF
// block's access row says 'none' with no upstream, or carries a label nginx
// put on every request of the host (access_denied) or the bot user agent
// fallback's bot_filter; either way the request counts once in the total.
func TestDashboardBlockedCountsEachRequestOnce(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TYPE log_type AS ENUM ('access', 'error', 'modsec')`,
		`CREATE TYPE block_reason AS ENUM ('none', 'waf', 'bot_filter', 'rate_limit', 'geo_block', 'access_denied', 'exploit_block')`,
		`CREATE TABLE logs_partitioned (
			log_type log_type NOT NULL, client_ip inet, status_code integer, upstream_addr text,
			block_reason block_reason DEFAULT 'none', created_at timestamptz NOT NULL)`,
		`INSERT INTO logs_partitioned (log_type, client_ip, status_code, upstream_addr, block_reason, created_at) VALUES
			-- answered by the upstream: not blocked
			('access', '192.0.2.1', 200, '192.0.2.50:8080', 'none', '2026-10-08 10:00:00+00'),
			('access', '192.0.2.1', 403, '192.0.2.50:8080', 'none', '2026-10-08 10:00:01+00'),
			-- a WAF block: an untagged 403 nginx answered itself, and its modsec row
			('access', '192.0.2.2', 403, NULL,              'none', '2026-10-08 10:01:00+00'),
			('modsec', '192.0.2.2', 403, NULL,              'waf',  '2026-10-08 10:01:00+00'),
			-- a WAF block on a host with an access list
			('access', '192.0.2.3', 403, NULL,              'access_denied', '2026-10-08 10:02:00+00'),
			('modsec', '192.0.2.3', 403, NULL,              'waf',  '2026-10-08 10:02:00+00'),
			-- a WAF block of a scanner user agent, labelled by the bot fallback
			('access', '192.0.2.4', 403, NULL,              'bot_filter', '2026-10-08 10:03:00+00'),
			('modsec', '192.0.2.4', 403, NULL,              'waf',  '2026-10-08 10:03:00+00'),
			-- an exploit rule's 403 that CRS rules matched as well
			('access', '192.0.2.5', 403, NULL,              'exploit_block', '2026-10-08 10:04:00+00'),
			('modsec', '192.0.2.5', 403, NULL,              'waf',  '2026-10-08 10:04:00+00'),
			-- a rate limit, and a WAF event that was only logged
			('access', '192.0.2.6', 429, NULL,              'rate_limit', '2026-10-08 10:05:00+00'),
			('modsec', '192.0.2.7', 200, NULL,              'none', '2026-10-08 10:06:00+00'),
			-- before the window
			('access', '192.0.2.8', 403, NULL,              'none', '2026-10-07 09:59:59+00'),
			('modsec', '192.0.2.8', 403, NULL,              'waf',  '2026-10-07 09:59:59+00')`)

	var blocked, ips, waf, rl, bot int64
	since := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	if err := db.QueryRowContext(context.Background(), dashboardBlocked24hSQL, since).
		Scan(&blocked, &ips, &waf, &rl, &bot); err != nil {
		t.Fatal(err)
	}
	if blocked != 5 || ips != 5 || waf != 4 || rl != 1 || bot != 1 {
		t.Errorf("blocked=%d ips=%d waf=%d rate_limit=%d bot=%d, want 5 requests from 5 IPs, 4 WAF, 1 rate limit, 1 bot",
			blocked, ips, waf, rl, bot)
	}
}
