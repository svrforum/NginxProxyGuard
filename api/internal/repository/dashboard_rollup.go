package repository

import (
	"context"
	"fmt"
	"time"
)

// averagedRequestFilter picks the requests an average response time is taken
// over. The hourly average and timed_requests, the count by which the 24h
// figure weights each hour, both use it, so they always cover the same
// requests.
//
// A request that took more than 60 seconds is left out (#324). An event
// stream or a long poll holds its request open for minutes on purpose: its
// time is how long the client stayed connected, not how fast the server
// answered, and one of them outweighs thousands of real answers. A request
// that waited out an upstream timeout of a minute or more is left out with
// them; its 504 still counts as an error. A WebSocket upgrade (101) is left
// out however short it was: its time is the connection's lifetime (#148).
// Leaving a request out of the average changes nothing else: it still counts
// in the request totals, the status classes and the bytes sent. Requests
// stored without a time (instant answers) have nothing to average; avg and
// count skip them on their own.
const averagedRequestFilter = `status_code IS DISTINCT FROM 101 AND request_time <= 60`

// hourlyRollupRecomputeSQL rebuilds the global rows (proxy_host_id IS NULL) of
// dashboard_stats_hourly for every UTC hour in [$1, $2) from logs_partitioned.
//
// Each row is overwritten with the count of what the logs hold, never added
// to, so running it again gives the same rows and it cannot count a request
// twice. An hour inside the window that has a row but no requests left is set
// to zero. It reads the same requests the dashboard always meant to count:
// access rows for a real host, without NPG's own health, status, ACME and
// pipeline-canary requests. Rows whose request_time, body_bytes_sent or
// request_uri is NULL count like any other (instant answers are stored with a
// NULL request_time); the average response time covers only the requests
// averagedRequestFilter picks. timed_requests is how many requests that
// average covers: an average over several hours weights each hour by it, not
// by total_requests, or an hour of instant answers (blocked scanners, say)
// would multiply the time of its few measured requests.
const hourlyRollupRecomputeSQL = `
WITH hours AS (
    SELECT generate_series(date_trunc('hour', $1::timestamptz, 'UTC'),
                           $2::timestamptz - interval '1 hour', interval '1 hour') AS hour_bucket
), agg AS (
    SELECT date_trunc('hour', created_at, 'UTC')                    AS hour_bucket,
           count(*)                                                AS total,
           count(*) FILTER (WHERE status_code BETWEEN 200 AND 299) AS s2,
           count(*) FILTER (WHERE status_code BETWEEN 300 AND 399) AS s3,
           count(*) FILTER (WHERE status_code BETWEEN 400 AND 499) AS s4,
           count(*) FILTER (WHERE status_code >= 500)              AS s5,
           avg(request_time) FILTER (WHERE ` + averagedRequestFilter + `) * 1000 AS avg_ms,
           count(request_time) FILTER (WHERE ` + averagedRequestFilter + `) AS timed,
           COALESCE(sum(body_bytes_sent), 0)                       AS bytes,
           count(*) FILTER (WHERE block_reason = 'waf')            AS waf,
           count(*) FILTER (WHERE block_reason = 'rate_limit')     AS rl,
           count(*) FILTER (WHERE block_reason = 'bot_filter')     AS bot
    FROM logs_partitioned
    WHERE log_type = 'access'
      AND created_at >= date_trunc('hour', $1::timestamptz, 'UTC') AND created_at < $2::timestamptz
      AND host IS NOT NULL
      AND host NOT IN ('localhost', 'nginx', '127.0.0.1', '', '_', '0.0.0.0')
      AND host NOT LIKE 'localhost:%'
      AND (request_uri NOT IN ('/health', '/nginx_status') OR request_uri IS NULL)
      AND (request_uri NOT LIKE '/.well-known/%' OR request_uri IS NULL)
      AND ` + canaryURIExclusion + `
    GROUP BY 1
)
INSERT INTO dashboard_stats_hourly (
    proxy_host_id, hour_bucket, total_requests,
    status_2xx, status_3xx, status_4xx, status_5xx,
    avg_response_time, timed_requests, bytes_sent,
    waf_blocked, rate_limited, bot_blocked
)
SELECT NULL, h.hour_bucket, COALESCE(a.total, 0),
       COALESCE(a.s2, 0), COALESCE(a.s3, 0), COALESCE(a.s4, 0), COALESCE(a.s5, 0),
       COALESCE(a.avg_ms, 0), COALESCE(a.timed, 0), COALESCE(a.bytes, 0),
       COALESCE(a.waf, 0), COALESCE(a.rl, 0), COALESCE(a.bot, 0)
FROM hours h
LEFT JOIN agg a USING (hour_bucket)
WHERE a.total IS NOT NULL
   OR EXISTS (SELECT 1 FROM dashboard_stats_hourly d
              WHERE d.proxy_host_id IS NULL AND d.hour_bucket = h.hour_bucket)
ON CONFLICT (hour_bucket) WHERE proxy_host_id IS NULL DO UPDATE SET
    total_requests    = EXCLUDED.total_requests,
    status_2xx        = EXCLUDED.status_2xx,
    status_3xx        = EXCLUDED.status_3xx,
    status_4xx        = EXCLUDED.status_4xx,
    status_5xx        = EXCLUDED.status_5xx,
    avg_response_time = EXCLUDED.avg_response_time,
    timed_requests    = EXCLUDED.timed_requests,
    bytes_sent        = EXCLUDED.bytes_sent,
    waf_blocked       = EXCLUDED.waf_blocked,
    rate_limited      = EXCLUDED.rate_limited,
    bot_blocked       = EXCLUDED.bot_blocked`

// RecomputeHourlyRollup rewrites the dashboard's global hourly totals for the
// UTC hours from from's hour up to to (exclusive; pass an hour boundary) from
// the logs themselves, and returns how many hourly rows it wrote.
//
// The dashboard used to add up what a 30-second poll had seen in the last 35
// seconds, which counted some requests twice, missed the rest of a busy
// window (the poll read at most 10,000 rows) and every row with a NULL
// request_time or body_bytes_sent (the scan failed on them), and could not
// repair anything after a restart. A recompute is exact for whatever the logs
// hold, whichever path wrote them.
func (r *DashboardRepository) RecomputeHourlyRollup(ctx context.Context, from, to time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, hourlyRollupRecomputeSQL, from, to)
	if err != nil {
		return 0, fmt.Errorf("recompute hourly dashboard stats: %w", err)
	}
	return result.RowsAffected()
}
