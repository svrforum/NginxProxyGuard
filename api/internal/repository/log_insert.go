package repository

import (
	"context"
	"fmt"
	"time"

	"nginx-proxy-guard/internal/model"
)

// createBatchTx inserts all logs in a single transaction
func (r *LogRepository) createBatchTx(ctx context.Context, logs []model.CreateLogRequest) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
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
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, req := range logs {
		timestamp := req.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		_, err := stmt.ExecContext(ctx,
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
		if err != nil {
			return fmt.Errorf("failed to insert log: %w", err)
		}
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
