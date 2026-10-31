package repository

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Traffic counts completed HTTP access requests and response body bytes only.
// Upload bytes and wire-level bandwidth are not present in the access logs.
type TrafficHost struct {
	ID         string  `json:"id"`
	Domain     string  `json:"domain"`
	Bytes      int64   `json:"bytes"`
	Requests   int64   `json:"requests"`
	Percentage float64 `json:"percentage"`
}

type TrafficSummary struct {
	Start    time.Time     `json:"start"`
	End      time.Time     `json:"end"`
	Bytes    int64         `json:"bytes"`
	Requests int64         `json:"requests"`
	Hosts    []TrafficHost `json:"hosts"`
	Source   string        `json:"source"`
}

type TrafficPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Bytes     int64     `json:"bytes"`
	Requests  int64     `json:"requests"`
}

// The access filter must match the dashboard's global/host rollup filter.
const trafficAccessFilter = `
    log_type = 'access'
    AND host IS NOT NULL
    AND host NOT IN ('localhost', 'nginx', '127.0.0.1', '', '_', '0.0.0.0')
    AND host NOT LIKE 'localhost:%'
    AND (request_uri NOT IN ('/health', '/nginx_status') OR request_uri IS NULL)
    AND (request_uri NOT LIKE '/.well-known/%' OR request_uri IS NULL)
    AND ` + canaryURIExclusion

// Recent windows read the raw logs for exact time boundaries. Historical
// windows read the hourly table to avoid scanning weeks of request logs.
func TrafficUsesRaw(start, end time.Time) bool {
	return end.Sub(start) <= 24*time.Hour
}

// Only complete UTC hours may be read from hourly aggregates. The fractional
// hours at the start and end must come directly from the access logs.
func trafficFullHours(start, end time.Time) (time.Time, time.Time) {
	from := start.Truncate(time.Hour)
	if !from.Equal(start) {
		from = from.Add(time.Hour)
	}
	return from, end.Truncate(time.Hour)
}

func trafficSummarySQL(historical bool) string {
	predicate := "created_at >= $1 AND created_at < $2"
	if historical {
		predicate = "((created_at >= $1 AND created_at < $3) OR (created_at >= $4 AND created_at < $2))"
	}
	// GROUPING distinguishes the grand total from a log with a NULL host.
	raw := `SELECT proxy_host_id, count(*)::bigint AS requests,
	         COALESCE(sum(body_bytes_sent), 0)::bigint AS bytes,
	         GROUPING(proxy_host_id) = 1 AS is_total
	         FROM logs_partitioned WHERE ` + predicate + ` AND ` + trafficAccessFilter + `
	         GROUP BY ROLLUP(proxy_host_id)`
	if historical {
		raw += ` UNION ALL SELECT proxy_host_id, total_requests, bytes_sent, proxy_host_id IS NULL
		         FROM dashboard_stats_hourly WHERE hour_bucket >= $3 AND hour_bucket < $4`
	}
	return `WITH samples AS (` + raw + `)
	        SELECT COALESCE(proxy_host_id::text, ''), is_total,
	               COALESCE(sum(requests), 0)::bigint, COALESCE(sum(bytes), 0)::bigint
	        FROM samples WHERE is_total OR proxy_host_id IS NOT NULL
	        GROUP BY proxy_host_id, is_total`
}

func (r *DashboardRepository) GetTrafficSummary(ctx context.Context, start, end time.Time) (*TrafficSummary, error) {
	historical := !TrafficUsesRaw(start, end)
	summary := &TrafficSummary{Start: start, End: end, Hosts: []TrafficHost{}, Source: "access_logs"}
	if historical {
		summary.Source = "hourly_and_access_logs"
	}
	fullStart, fullEnd := trafficFullHours(start, end)
	args := []any{start, end}
	if historical {
		args = append(args, fullStart, fullEnd)
	}
	rows, err := r.db.QueryContext(ctx, trafficSummarySQL(historical), args...)
	if err != nil {
		return nil, err
	}
	var classifiedBytes, classifiedRequests int64
	byID := make(map[string]*TrafficHost)
	for rows.Next() {
		var id string
		var isTotal bool
		var requests, bytes int64
		if err := rows.Scan(&id, &isTotal, &requests, &bytes); err != nil {
			rows.Close()
			return nil, err
		}
		if isTotal {
			summary.Requests += requests
			summary.Bytes += bytes
			continue
		}
		classifiedRequests += requests
		classifiedBytes += bytes
		byID[id] = &TrafficHost{ID: id, Domain: id, Requests: requests, Bytes: bytes}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// Read all currently configured hosts, including ones with zero traffic.
	hostRows, err := r.db.QueryContext(ctx, `SELECT id::text, COALESCE(domain_names[1], id::text) FROM proxy_hosts`)
	if err != nil {
		return nil, err
	}
	for hostRows.Next() {
		var id, domain string
		if err := hostRows.Scan(&id, &domain); err != nil {
			hostRows.Close()
			return nil, err
		}
		if byID[id] == nil {
			byID[id] = &TrafficHost{ID: id}
		}
		byID[id].Domain = domain
	}
	if err := hostRows.Err(); err != nil {
		hostRows.Close()
		return nil, err
	}
	hostRows.Close()

	// Unclassified = global total - sum of known host totals, including logs
	// without proxy_host_id (and legacy data that cannot be attributed).
	unknownRequests := summary.Requests - classifiedRequests
	unknownBytes := summary.Bytes - classifiedBytes
	if unknownRequests < 0 {
		unknownRequests = 0
	}
	if unknownBytes < 0 {
		unknownBytes = 0
	}
	for _, h := range byID {
		if summary.Bytes > 0 {
			h.Percentage = float64(h.Bytes) / float64(summary.Bytes) * 100
		}
		summary.Hosts = append(summary.Hosts, *h)
	}
	if unknownRequests > 0 || unknownBytes > 0 {
		h := TrafficHost{ID: "unclassified", Domain: "Unclassified", Requests: unknownRequests, Bytes: unknownBytes}
		if summary.Bytes > 0 {
			h.Percentage = float64(h.Bytes) / float64(summary.Bytes) * 100
		}
		summary.Hosts = append(summary.Hosts, h)
	}
	sort.Slice(summary.Hosts, func(i, j int) bool {
		if summary.Hosts[i].Bytes == summary.Hosts[j].Bytes {
			return summary.Hosts[i].Domain < summary.Hosts[j].Domain
		}
		return summary.Hosts[i].Bytes > summary.Hosts[j].Bytes
	})
	return summary, nil
}

func (r *DashboardRepository) GetTrafficSeries(ctx context.Context, start, end time.Time, hostID string, realtime bool) ([]TrafficPoint, error) {
	var query string
	args := []any{start, end, hostID}
	if realtime || TrafficUsesRaw(start, end) {
		bucketSeconds := 300
		if realtime {
			bucketSeconds = 10
		}
		query = fmt.Sprintf(`SELECT to_timestamp(floor(extract(epoch from created_at) / %d) * %d) AS bucket,
		    count(*), COALESCE(sum(body_bytes_sent), 0)
		    FROM logs_partitioned
		    WHERE created_at >= $1 AND created_at < $2 AND %s
		      AND ($3 = '' OR ($3 = 'unclassified' AND proxy_host_id IS NULL) OR proxy_host_id::text = $3)
		    GROUP BY 1 ORDER BY 1 LIMIT 500`, bucketSeconds, bucketSeconds, trafficAccessFilter)
	} else {
		from, to := trafficFullHours(start, end)
		args = append(args, from, to)
		bucket := "bucket"
		if end.Sub(start) > 14*24*time.Hour {
			bucket = "date_trunc('day', bucket, 'UTC')"
		}
		// All partial UTC hours are counted from raw logs. The NULL ID in
		// dashboard_stats_hourly is a global rollup, never a host record.
		query = fmt.Sprintf(`WITH samples AS (
		  SELECT date_trunc('hour', created_at, 'UTC') AS bucket,
		         proxy_host_id::text AS host_id,
		         GROUPING(proxy_host_id) = 1 AS is_total,
		         COUNT(*)::bigint AS requests, COALESCE(SUM(body_bytes_sent), 0)::bigint AS bytes
		  FROM logs_partitioned
		  WHERE ((created_at >= $1 AND created_at < $4) OR (created_at >= $5 AND created_at < $2))
		    AND %s
		  GROUP BY date_trunc('hour', created_at, 'UTC'), ROLLUP(proxy_host_id)
		  UNION ALL
		  SELECT hour_bucket, proxy_host_id::text, proxy_host_id IS NULL,
		         total_requests, bytes_sent
		  FROM dashboard_stats_hourly WHERE hour_bucket >= $4 AND hour_bucket < $5
		)
		SELECT %s AS bucket,
		  GREATEST(COALESCE(SUM(CASE WHEN $3 = 'unclassified' THEN
		    CASE WHEN is_total THEN requests WHEN host_id IS NOT NULL THEN -requests ELSE 0 END
		    WHEN ($3 = '' AND is_total) OR ($3 <> '' AND NOT is_total AND host_id = $3)
		      THEN requests ELSE 0 END), 0), 0)::bigint,
		  GREATEST(COALESCE(SUM(CASE WHEN $3 = 'unclassified' THEN
		    CASE WHEN is_total THEN bytes WHEN host_id IS NOT NULL THEN -bytes ELSE 0 END
		    WHEN ($3 = '' AND is_total) OR ($3 <> '' AND NOT is_total AND host_id = $3)
		      THEN bytes ELSE 0 END), 0), 0)::bigint
		FROM samples GROUP BY 1 ORDER BY 1 LIMIT 800`, trafficAccessFilter, bucket)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := []TrafficPoint{}
	for rows.Next() {
		var point TrafficPoint
		if err := rows.Scan(&point.Timestamp, &point.Requests, &point.Bytes); err != nil {
			return nil, err
		}
		points = append(points, point)
	}
	return points, rows.Err()
}

// GetTrafficRate counts the exact last interval, rather than approximating
// it by summing 10-second buckets which may extend beyond the interval.
func (r *DashboardRepository) GetTrafficRate(ctx context.Context, start, end time.Time, hostID string) (int64, int64, error) {
	var requests, bytes int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)::bigint, COALESCE(SUM(body_bytes_sent), 0)::bigint
	  FROM logs_partitioned
	  WHERE created_at >= $1 AND created_at < $2 AND `+trafficAccessFilter+`
	    AND ($3 = '' OR ($3 = 'unclassified' AND proxy_host_id IS NULL) OR proxy_host_id::text = $3)`, start, end, hostID).Scan(&requests, &bytes)
	return requests, bytes, err
}

const (
	trafficBackfillLookback = 90 * 24 * time.Hour
	trafficBackfillBatch    = 6 * time.Hour
	// The regular collector rebuilds the current and previous 25 UTC hours.
	// Historical backfill stops before that window to avoid overlapping writes.
	trafficBackfillRecent = 25 * time.Hour
)

// BackfillTrafficHourly fills historical per-host rows from the already stored
// access logs. It never changes the global rollup: global rows may predate the
// retained raw logs and must not be erased by a history rebuild. A persisted
// cursor and one transaction per 6-hour batch make it safe to interrupt, retry
// and restart. The checkpoint begins at the earliest available log within the
// UI's 90-day search horizon, so retention gaps are not scanned unnecessarily.
// A completed batch returns its [from, to) and complete=false; once there is
// nothing left to process it returns complete=true.
func (r *DashboardRepository) BackfillTrafficHourly(ctx context.Context, now time.Time) (from, to time.Time, complete bool, err error) {
	hour := now.UTC().Truncate(time.Hour)
	oldest := hour.Add(-trafficBackfillLookback)
	cutoff := hour.Add(-trafficBackfillRecent)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return from, to, false, err
	}
	defer tx.Rollback()

	// MIN is bounded by the configured history window. If there are no old
	// access logs, advance to the cutoff and leave retained hourly totals alone.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO traffic_hourly_backfill (id, next_hour)
		SELECT 1, GREATEST(
		    COALESCE(date_trunc('hour', MIN(created_at), 'UTC'), $2::timestamptz),
		    $1::timestamptz)
		FROM logs_partitioned
		WHERE log_type = 'access' AND created_at >= $1 AND created_at < $2
		ON CONFLICT (id) DO NOTHING`, oldest, cutoff)
	if err != nil {
		return from, to, false, fmt.Errorf("initialize traffic backfill: %w", err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT next_hour FROM traffic_hourly_backfill WHERE id = 1 FOR UPDATE`).Scan(&from); err != nil {
		return from, to, false, fmt.Errorf("read traffic backfill cursor: %w", err)
	}
	if !from.Before(cutoff) {
		return from, from, true, tx.Commit()
	}
	to = from.Add(trafficBackfillBatch)
	if to.After(cutoff) {
		to = cutoff
	}
	if _, err = tx.ExecContext(ctx, hourlyHostRollupSQL, from, to); err != nil {
		return from, to, false, fmt.Errorf("backfill hourly proxy hosts: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE traffic_hourly_backfill SET next_hour = $1, updated_at = now() WHERE id = 1`, to); err != nil {
		return from, to, false, fmt.Errorf("save traffic backfill cursor: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return from, to, false, fmt.Errorf("commit traffic backfill: %w", err)
	}
	return from, to, false, nil
}
