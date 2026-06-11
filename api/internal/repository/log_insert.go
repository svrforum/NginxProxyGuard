package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// nullInt64 mirrors NULLIF(n, 0) for bigint columns: zero becomes NULL.
func nullInt64(n int64) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

// nullFloat64 mirrors NULLIF(f, 0) for double precision columns: zero becomes NULL.
func nullFloat64(f float64) interface{} {
	if f == 0 {
		return nil
	}
	return f
}

// createBatchTx inserts all logs in a single transaction via the COPY protocol
// (pq.CopyIn). Each stmt.ExecContext only appends the row to the local COPY
// buffer, so a full flush costs one network round trip instead of one per row
// (the previous prepared-INSERT loop paid 500 sequential round trips per
// 500-row flush with lib/pq). The NULL normalization the old INSERT did with
// NULLIF()/COALESCE() now happens in Go before binding — column semantics are
// identical to createSingle.
func (r *LogRepository) createBatchTx(ctx context.Context, logs []model.CreateLogRequest) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("logs_partitioned",
		"log_type", "timestamp", "host", "client_ip",
		"geo_country", "geo_country_code", "geo_city", "geo_asn", "geo_org",
		"request_method", "request_uri", "request_protocol", "status_code",
		"body_bytes_sent", "request_time", "upstream_response_time",
		"upstream_addr", "upstream_status",
		"http_referer", "http_user_agent", "http_x_forwarded_for",
		"severity", "error_message",
		"rule_id", "rule_message", "rule_severity", "rule_data", "attack_type", "action_taken",
		"block_reason", "bot_category", "exploit_rule",
		"proxy_host_id", "raw_log",
	))
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, req := range logs {
		timestamp := req.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		// COALESCE(NULLIF(block_reason, '')::block_reason, 'none')
		blockReason := string(req.BlockReason)
		if blockReason == "" {
			blockReason = "none"
		}

		_, err := stmt.ExecContext(ctx,
			string(req.LogType), timestamp, nullString(req.Host), nullString(req.ClientIP),
			nullString(req.GeoCountry), nullString(req.GeoCountryCode), nullString(req.GeoCity), nullString(req.GeoASN), nullString(req.GeoOrg),
			nullString(req.RequestMethod), nullString(req.RequestURI), nullString(req.RequestProtocol), nullInt64(int64(req.StatusCode)),
			nullInt64(req.BodyBytesSent), nullFloat64(req.RequestTime), nullFloat64(req.UpstreamResponseTime),
			nullString(req.UpstreamAddr), nullString(req.UpstreamStatus),
			nullString(req.HTTPReferer), nullString(req.HTTPUserAgent), nullString(req.HTTPXForwardedFor),
			nullString(string(req.Severity)), nullString(req.ErrorMessage),
			nullInt64(req.RuleID), nullString(req.RuleMessage), nullString(req.RuleSeverity), nullString(req.RuleData), nullString(req.AttackType), nullString(req.ActionTaken),
			blockReason, nullString(req.BotCategory), nullString(req.ExploitRule),
			nullString(req.ProxyHostID), nullString(req.RawLog),
		)
		if err != nil {
			return fmt.Errorf("failed to insert log: %w", err)
		}
	}

	// Flush the COPY stream. Row-level errors (bad enum/inet/uuid values)
	// surface here and abort the whole transaction — the caller (CreateBatch)
	// then degrades to mini-batches and single-row inserts to isolate the
	// poison row, exactly as before.
	if _, err := stmt.ExecContext(ctx); err != nil {
		return fmt.Errorf("failed to insert log: %w", err)
	}

	return tx.Commit()
}

// createSingle inserts a single log entry (used as fallback when batch fails)
func (r *LogRepository) createSingle(ctx context.Context, req *model.CreateLogRequest) error {
	timestamp := req.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO logs_partitioned (
			log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
			upstream_addr, upstream_status,
			http_referer, http_user_agent, http_x_forwarded_for,
			severity, error_message,
			rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
			block_reason, bot_category, exploit_rule,
			proxy_host_id, raw_log
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, '')::inet,
			NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, 0),
			NULLIF($14::bigint, 0), NULLIF($15::double precision, 0), NULLIF($16::double precision, 0),
			NULLIF($17, ''), NULLIF($18, ''),
			NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, ''),
			NULLIF($22, '')::log_severity, NULLIF($23, ''),
			NULLIF($24::bigint, 0), NULLIF($25, ''), NULLIF($26, ''), NULLIF($27, ''), NULLIF($28, ''), NULLIF($29, ''),
			COALESCE(NULLIF($30, '')::block_reason, 'none'), NULLIF($31, ''), NULLIF($32, ''),
			NULLIF($33, '')::uuid, NULLIF($34, '')
		)`,
		req.LogType, timestamp, req.Host, req.ClientIP,
		req.GeoCountry, req.GeoCountryCode, req.GeoCity, req.GeoASN, req.GeoOrg,
		req.RequestMethod, req.RequestURI, req.RequestProtocol, req.StatusCode,
		req.BodyBytesSent, req.RequestTime, req.UpstreamResponseTime,
		req.UpstreamAddr, req.UpstreamStatus,
		req.HTTPReferer, req.HTTPUserAgent, req.HTTPXForwardedFor,
		req.Severity, req.ErrorMessage,
		req.RuleID, req.RuleMessage, req.RuleSeverity, req.RuleData, req.AttackType, req.ActionTaken,
		req.BlockReason, req.BotCategory, req.ExploitRule,
		req.ProxyHostID, req.RawLog,
	)
	return err
}
