package repository

import (
	"context"
	"fmt"
	"strings"
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
	if r.db.IsMySQLFamily() {
		return r.createBatchMultiRow(ctx, logs)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("logs_partitioned", logColumns...))
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, req := range logs {
		if _, err := stmt.ExecContext(ctx, logInsertValues(req)...); err != nil {
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

// logColumns는 COPY 경로, 다중 행 경로, logInsertValues가 공유하는 컬럼 순서다.
// 바꾸려면 셋을 함께 바꿔야 한다.
var logColumns = []string{
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
}

// logInsertValues는 요청 하나를 logColumns 순서의 바인딩 값으로 정규화한다.
// 빈 문자열과 0을 SQL의 NULLIF()가 아니라 여기서 NULL로 바꾸므로, COPY 경로와
// 다중 행 경로가 createSingle과 정확히 같은 값을 저장한다.
func logInsertValues(req model.CreateLogRequest) []interface{} {
	timestamp := req.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// COALESCE(NULLIF(block_reason, '')::block_reason, 'none')
	blockReason := string(req.BlockReason)
	if blockReason == "" {
		blockReason = "none"
	}

	return []interface{}{
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
	}
}

// maxMultiRowChunk는 INSERT 하나에 들어갈 로그 행 수의 상한이다.
//
// MySQL 프로토콜은 문장당 바인딩 파라미터를 최대 65535개까지 허용하고, 행마다
// len(logColumns)개를 쓴다. 수집기의 플러시 크기인 500행은 그 안에 충분히
// 들어가지만, 컬럼을 추가했을 때 조용히 한도를 넘는 문장이 만들어지지 않도록
// 값을 가정하지 않고 계산한다.
var maxMultiRowChunk = 65535 / len(logColumns)

// createBatchMultiRow는 COPY 경로의 MySQL 계열 대응물이다.
//
// MySQL 계열에는 COPY 프로토콜이 없으므로, 왕복 한 번으로 끝내는 동등한 쓰기는
// 다중 행 INSERT다. 의미는 COPY 경로와 정확히 같다. 트랜잭션 하나, Go에서 이미
// 정규화된 값, 그리고 행 하나가 거부되면 배치 전체가 중단되어 CreateBatch가 더
// 작은 배치로 물러나 문제 행을 격리할 수 있게 하는 것까지.
func (r *LogRepository) createBatchMultiRow(ctx context.Context, logs []model.CreateLogRequest) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	for start := 0; start < len(logs); start += maxMultiRowChunk {
		end := start + maxMultiRowChunk
		if end > len(logs) {
			end = len(logs)
		}
		chunk := logs[start:end]

		placeholderRow := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(logColumns)), ", ") + ")"
		rowsSQL := make([]string, len(chunk))
		args := make([]interface{}, 0, len(chunk)*len(logColumns))
		for i, req := range chunk {
			rowsSQL[i] = placeholderRow
			args = append(args, logInsertValues(req)...)
		}

		// 이미 대상 엔진의 SQL이므로 $N이 아니라 `?`로 쓴다. 번역기는 $N
		// 플레이스홀더가 없는 문장은 건드리지 않는다.
		query := fmt.Sprintf("INSERT INTO logs_partitioned (%s) VALUES %s",
			strings.Join(quoteLogColumns(), ", "), strings.Join(rowsSQL, ", "))

		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to insert log: %w", err)
		}
	}

	return tx.Commit()
}

// quoteLogColumns는 로그 컬럼 중 예약어를 인용한다. 모든 커넥션에 ANSI_QUOTES가
// 켜져 있으므로 큰따옴표가 식별자 구분자다.
func quoteLogColumns() []string {
	out := make([]string, len(logColumns))
	for i, c := range logColumns {
		if c == "timestamp" {
			out[i] = `"timestamp"`
			continue
		}
		out[i] = c
	}
	return out
}
