package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"
)

type LogRepository struct {
	db    *database.DB
	cache *cache.RedisClient
}

func NewLogRepository(db *database.DB) *LogRepository {
	return &LogRepository{db: db}
}

// SetCache sets the cache client for the repository
func (r *LogRepository) SetCache(c *cache.RedisClient) {
	r.cache = c
}

// buildHostFilter converts a host filter pattern to SQL condition and value.
// - "example.com" -> exact match (host = 'example.com')
// - "*.example.com" -> wildcard match (host LIKE '%.example.com')
func buildHostFilter(host string, argIndex int) (condition string, value string, isExact bool) {
	if strings.HasPrefix(host, "*") {
		// Wildcard pattern: *.example.com -> %.example.com
		pattern := "%" + strings.TrimPrefix(host, "*")
		return fmt.Sprintf("host LIKE $%d", argIndex), pattern, false
	}
	// Exact match
	return fmt.Sprintf("host = $%d", argIndex), host, true
}

func (r *LogRepository) Create(ctx context.Context, req *model.CreateLogRequest) (*model.Log, error) {
	query := `
		INSERT INTO logs_partitioned (
			log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
			upstream_addr, upstream_status,
			http_referer, http_user_agent, http_x_forwarded_for,
			severity, error_message,
			rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
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
			NULLIF($30, '')::uuid, NULLIF($31, '')
		)
		RETURNING id, log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
			upstream_addr, upstream_status,
			http_referer, http_user_agent, http_x_forwarded_for,
			severity, error_message,
			rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
			proxy_host_id, raw_log, created_at
	`

	timestamp := req.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	var log model.Log
	var host, clientIP, requestMethod, requestURI, requestProtocol sql.NullString
	var geoCountry, geoCountryCode, geoCity, geoASN, geoOrg sql.NullString
	var statusCode sql.NullInt32
	var ruleID sql.NullInt64
	var bodyBytesSent sql.NullInt64
	var requestTime, upstreamResponseTime sql.NullFloat64
	var upstreamAddr, upstreamStatus sql.NullString
	var httpReferer, httpUserAgent, httpXForwardedFor sql.NullString
	var severity, errorMessage sql.NullString
	var ruleMessage, ruleSeverity, ruleData, attackType, actionTaken sql.NullString
	var proxyHostID, rawLog sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		req.LogType, timestamp, req.Host, req.ClientIP,
		req.GeoCountry, req.GeoCountryCode, req.GeoCity, req.GeoASN, req.GeoOrg,
		req.RequestMethod, req.RequestURI, req.RequestProtocol, req.StatusCode,
		req.BodyBytesSent, req.RequestTime, req.UpstreamResponseTime,
		req.UpstreamAddr, req.UpstreamStatus,
		req.HTTPReferer, req.HTTPUserAgent, req.HTTPXForwardedFor,
		req.Severity, req.ErrorMessage,
		req.RuleID, req.RuleMessage, req.RuleSeverity, req.RuleData, req.AttackType, req.ActionTaken,
		req.ProxyHostID, req.RawLog,
	).Scan(
		&log.ID, &log.LogType, &log.Timestamp, &host, &clientIP,
		&geoCountry, &geoCountryCode, &geoCity, &geoASN, &geoOrg,
		&requestMethod, &requestURI, &requestProtocol, &statusCode,
		&bodyBytesSent, &requestTime, &upstreamResponseTime,
		&upstreamAddr, &upstreamStatus,
		&httpReferer, &httpUserAgent, &httpXForwardedFor,
		&severity, &errorMessage,
		&ruleID, &ruleMessage, &ruleSeverity, &ruleData, &attackType, &actionTaken,
		&proxyHostID, &rawLog, &log.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create log: %w", err)
	}

	// Map nullable fields
	if host.Valid {
		log.Host = &host.String
	}
	if clientIP.Valid {
		ip := net.ParseIP(clientIP.String)
		log.ClientIP = &ip
	}
	if geoCountry.Valid {
		log.GeoCountry = &geoCountry.String
	}
	if geoCountryCode.Valid {
		log.GeoCountryCode = &geoCountryCode.String
	}
	if geoCity.Valid {
		log.GeoCity = &geoCity.String
	}
	if geoASN.Valid {
		log.GeoASN = &geoASN.String
	}
	if geoOrg.Valid {
		log.GeoOrg = &geoOrg.String
	}
	if requestMethod.Valid {
		log.RequestMethod = &requestMethod.String
	}
	if requestURI.Valid {
		log.RequestURI = &requestURI.String
	}
	if requestProtocol.Valid {
		log.RequestProtocol = &requestProtocol.String
	}
	if statusCode.Valid {
		code := int(statusCode.Int32)
		log.StatusCode = &code
	}
	if bodyBytesSent.Valid {
		log.BodyBytesSent = &bodyBytesSent.Int64
	}
	if requestTime.Valid {
		log.RequestTime = &requestTime.Float64
	}
	if upstreamResponseTime.Valid {
		log.UpstreamResponseTime = &upstreamResponseTime.Float64
	}
	if upstreamAddr.Valid {
		log.UpstreamAddr = &upstreamAddr.String
	}
	if upstreamStatus.Valid {
		log.UpstreamStatus = &upstreamStatus.String
	}
	if httpReferer.Valid {
		log.HTTPReferer = &httpReferer.String
	}
	if httpUserAgent.Valid {
		log.HTTPUserAgent = &httpUserAgent.String
	}
	if httpXForwardedFor.Valid {
		log.HTTPXForwardedFor = &httpXForwardedFor.String
	}
	if severity.Valid {
		sev := model.LogSeverity(severity.String)
		log.Severity = &sev
	}
	if errorMessage.Valid {
		log.ErrorMessage = &errorMessage.String
	}
	if ruleID.Valid {
		id := ruleID.Int64
		log.RuleID = &id
	}
	if ruleMessage.Valid {
		log.RuleMessage = &ruleMessage.String
	}
	if ruleSeverity.Valid {
		log.RuleSeverity = &ruleSeverity.String
	}
	if ruleData.Valid {
		log.RuleData = &ruleData.String
	}
	if attackType.Valid {
		log.AttackType = &attackType.String
	}
	if actionTaken.Valid {
		log.ActionTaken = &actionTaken.String
	}
	if proxyHostID.Valid {
		log.ProxyHostID = &proxyHostID.String
	}
	if rawLog.Valid {
		log.RawLog = &rawLog.String
	}

	return &log, nil
}

func (r *LogRepository) CreateBatch(ctx context.Context, logs []model.CreateLogRequest) error {
	if len(logs) == 0 {
		return nil
	}

	// Try batch transaction first
	err := r.createBatchTx(ctx, logs)
	if err == nil {
		return nil
	}

	// Batch failed - fall back to mini-batch inserts (50 at a time) to avoid N round-trips
	log.Printf("[LogRepository] Batch insert failed, falling back to mini-batch inserts: %v", err)
	const miniBatchSize = 50
	var failCount int
	for i := 0; i < len(logs); i += miniBatchSize {
		end := i + miniBatchSize
		if end > len(logs) {
			end = len(logs)
		}
		chunk := logs[i:end]
		if err := r.createBatchTx(ctx, chunk); err != nil {
			// Mini-batch failed, fall back to individual inserts for this chunk
			for j, req := range chunk {
				if err := r.createSingle(ctx, &req); err != nil {
					failCount++
					log.Printf("[LogRepository] Failed to insert log %d/%d: %v", i+j+1, len(logs), err)
				}
			}
		}
	}
	if failCount > 0 {
		log.Printf("[LogRepository] Mini-batch fallback: %d/%d logs failed", failCount, len(logs))
	}
	if failCount == len(logs) {
		return fmt.Errorf("all %d log inserts failed after batch failure", failCount)
	}
	return nil
}

func (r *LogRepository) List(ctx context.Context, filter *model.LogFilter, page, perPage int) ([]model.Log, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	if perPage > 1000 {
		perPage = 1000
	}
	offset := (page - 1) * perPage

	// Build WHERE clause using shared builder
	conditions := []string{}
	args := []interface{}{}
	argIndex := 1

	if filter != nil {
		if filter.LogType != nil {
			conditions = append(conditions, fmt.Sprintf("log_type = $%d", argIndex))
			args = append(args, *filter.LogType)
			argIndex++

			// For access logs, exclude internal requests
			if *filter.LogType == "access" {
				conditions = append(conditions, "(request_uri NOT IN ('/health', '/nginx_status') OR request_uri IS NULL)")
				conditions = append(conditions, "(request_uri NOT LIKE '/.well-known/%' OR request_uri IS NULL)")
				conditions = append(conditions, "(host NOT IN ('localhost', '127.0.0.1', 'nginx', '') OR host IS NULL)")
			}
		}
		if filter.Host != nil && *filter.Host != "" {
			condition, value, _ := buildHostFilter(*filter.Host, argIndex)
			conditions = append(conditions, condition)
			args = append(args, value)
			argIndex++
		}
		if filter.ClientIP != nil && *filter.ClientIP != "" {
			conditions = append(conditions, fmt.Sprintf("client_ip = $%d::inet", argIndex))
			args = append(args, *filter.ClientIP)
			argIndex++
		}
		if filter.StatusCode != nil && *filter.StatusCode > 0 {
			conditions = append(conditions, fmt.Sprintf("status_code = $%d", argIndex))
			args = append(args, *filter.StatusCode)
			argIndex++
		}
		if filter.Severity != nil {
			conditions = append(conditions, fmt.Sprintf("severity = $%d", argIndex))
			args = append(args, *filter.Severity)
			argIndex++
		}
		if filter.RuleID != nil && *filter.RuleID > 0 {
			// Use partial match (prefix) for rule_id filter
			conditions = append(conditions, fmt.Sprintf("rule_id::text LIKE $%d", argIndex))
			args = append(args, fmt.Sprintf("%d%%", *filter.RuleID))
			argIndex++
		}
		if filter.ProxyHostID != nil && *filter.ProxyHostID != "" {
			conditions = append(conditions, fmt.Sprintf("proxy_host_id = $%d::uuid", argIndex))
			args = append(args, *filter.ProxyHostID)
			argIndex++
		}
		if filter.StartTime != nil {
			conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
			args = append(args, *filter.StartTime)
			argIndex++
		}
		if filter.EndTime != nil {
			conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIndex))
			args = append(args, *filter.EndTime)
			argIndex++
		}
		if filter.Search != nil && *filter.Search != "" {
			// Check if search term looks like an IP address
			isIPLike := strings.Contains(*filter.Search, ".") || strings.Contains(*filter.Search, ":")

			// Check if search term contains only digits (for rule_id partial match)
			isNumeric := true
			for _, c := range *filter.Search {
				if c < '0' || c > '9' {
					isNumeric = false
					break
				}
			}

			if isIPLike {
				// Search looks like IP address - search in client_ip field
				conditions = append(conditions, fmt.Sprintf(
					"(host(client_ip) LIKE $%d OR host ILIKE $%d OR http_user_agent ILIKE $%d OR request_uri ILIKE $%d)",
					argIndex, argIndex+1, argIndex+1, argIndex+1,
				))
				args = append(args, *filter.Search+"%", "%"+*filter.Search+"%")
				argIndex += 2
			} else if isNumeric && len(*filter.Search) > 0 {
				// Search is numeric - search by rule_id (partial match using LIKE on text cast)
				conditions = append(conditions, fmt.Sprintf(
					"(rule_id::text LIKE $%d OR request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)",
					argIndex, argIndex+1, argIndex+1, argIndex+1,
				))
				args = append(args, *filter.Search+"%", "%"+*filter.Search+"%")
				argIndex += 2
			} else {
				// Search is text - search by host, user_agent, uri, and error fields
				conditions = append(conditions, fmt.Sprintf(
					"(host ILIKE $%d OR http_user_agent ILIKE $%d OR request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)",
					argIndex, argIndex, argIndex, argIndex, argIndex,
				))
				args = append(args, "%"+*filter.Search+"%")
				argIndex++
			}
		}

		// Block reason filters
		if filter.BlockReason != nil && *filter.BlockReason != "" {
			conditions = append(conditions, fmt.Sprintf("block_reason = $%d", argIndex))
			args = append(args, *filter.BlockReason)
			argIndex++
		}
		if filter.BotCategory != nil && *filter.BotCategory != "" {
			conditions = append(conditions, fmt.Sprintf("bot_category = $%d", argIndex))
			args = append(args, *filter.BotCategory)
			argIndex++
		}
		if filter.ExploitRule != nil && *filter.ExploitRule != "" {
			conditions = append(conditions, fmt.Sprintf("exploit_rule = $%d", argIndex))
			args = append(args, *filter.ExploitRule)
			argIndex++
		}

		// Array filters for multi-select support
		if len(filter.Hosts) > 0 {
			orConditions := make([]string, len(filter.Hosts))
			for i, host := range filter.Hosts {
				condition, value, _ := buildHostFilter(host, argIndex)
				orConditions[i] = condition
				args = append(args, value)
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("(%s)", strings.Join(orConditions, " OR ")))
		}
		if len(filter.ClientIPs) > 0 {
			placeholders := make([]string, len(filter.ClientIPs))
			for i, ip := range filter.ClientIPs {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, ip)
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("host(client_ip) IN (%s)", strings.Join(placeholders, ",")))
		}
		if len(filter.URIs) > 0 {
			orConditions := make([]string, len(filter.URIs))
			for i, uri := range filter.URIs {
				orConditions[i] = fmt.Sprintf("request_uri ILIKE $%d", argIndex)
				args = append(args, "%"+uri+"%")
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("(%s)", strings.Join(orConditions, " OR ")))
		}
		if len(filter.UserAgents) > 0 {
			orConditions := make([]string, len(filter.UserAgents))
			for i, ua := range filter.UserAgents {
				orConditions[i] = fmt.Sprintf("http_user_agent ILIKE $%d", argIndex)
				args = append(args, "%"+ua+"%")
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("(%s)", strings.Join(orConditions, " OR ")))
		}

		// Extended filters (legacy single-value)
		if filter.UserAgent != nil && *filter.UserAgent != "" {
			conditions = append(conditions, fmt.Sprintf("http_user_agent ILIKE $%d", argIndex))
			args = append(args, "%"+*filter.UserAgent+"%")
			argIndex++
		}
		if filter.URI != nil && *filter.URI != "" {
			conditions = append(conditions, fmt.Sprintf("request_uri ILIKE $%d", argIndex))
			args = append(args, "%"+*filter.URI+"%")
			argIndex++
		}
		if filter.Method != nil && *filter.Method != "" {
			conditions = append(conditions, fmt.Sprintf("request_method = $%d", argIndex))
			args = append(args, *filter.Method)
			argIndex++
		}
		if filter.GeoCountryCode != nil && *filter.GeoCountryCode != "" {
			conditions = append(conditions, fmt.Sprintf("geo_country_code = $%d", argIndex))
			args = append(args, *filter.GeoCountryCode)
			argIndex++
		}
		if len(filter.StatusCodes) > 0 {
			placeholders := make([]string, len(filter.StatusCodes))
			for i, code := range filter.StatusCodes {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, code)
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("status_code IN (%s)", strings.Join(placeholders, ",")))
		}
		if filter.MinSize != nil && *filter.MinSize > 0 {
			conditions = append(conditions, fmt.Sprintf("body_bytes_sent >= $%d", argIndex))
			args = append(args, *filter.MinSize)
			argIndex++
		}
		if filter.MaxSize != nil && *filter.MaxSize > 0 {
			conditions = append(conditions, fmt.Sprintf("body_bytes_sent <= $%d", argIndex))
			args = append(args, *filter.MaxSize)
			argIndex++
		}
		if filter.MinRequestTime != nil && *filter.MinRequestTime > 0 {
			conditions = append(conditions, fmt.Sprintf("request_time >= $%d", argIndex))
			args = append(args, *filter.MinRequestTime)
			argIndex++
		}
		// Upstream filters (Issue #109). Substring match since upstream_addr may be a
		// comma-separated list on retries; we want "10.0.0.1" to hit "10.0.0.1:8080" too.
		if filter.UpstreamAddr != nil && *filter.UpstreamAddr != "" {
			conditions = append(conditions, fmt.Sprintf("upstream_addr ILIKE $%d", argIndex))
			args = append(args, "%"+*filter.UpstreamAddr+"%")
			argIndex++
		}
		if filter.UpstreamStatus != nil && *filter.UpstreamStatus != "" {
			conditions = append(conditions, fmt.Sprintf("upstream_status ILIKE $%d", argIndex))
			args = append(args, "%"+*filter.UpstreamStatus+"%")
			argIndex++
		}

		// Exclude filters
		if len(filter.ExcludeIPs) > 0 {
			placeholders := make([]string, len(filter.ExcludeIPs))
			for i, ip := range filter.ExcludeIPs {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, ip)
				argIndex++
			}
			// Use host() function to extract IP without /32 suffix for proper comparison
			conditions = append(conditions, fmt.Sprintf("(client_ip IS NULL OR host(client_ip) NOT IN (%s))", strings.Join(placeholders, ",")))
		}
		if len(filter.ExcludeUserAgents) > 0 {
			for _, ua := range filter.ExcludeUserAgents {
				conditions = append(conditions, fmt.Sprintf("(http_user_agent IS NULL OR http_user_agent NOT ILIKE $%d)", argIndex))
				args = append(args, "%"+ua+"%")
				argIndex++
			}
		}
		if len(filter.ExcludeURIs) > 0 {
			for _, uri := range filter.ExcludeURIs {
				conditions = append(conditions, fmt.Sprintf("(request_uri IS NULL OR request_uri NOT ILIKE $%d)", argIndex))
				args = append(args, "%"+uri+"%")
				argIndex++
			}
		}
		if len(filter.ExcludeHosts) > 0 {
			placeholders := make([]string, len(filter.ExcludeHosts))
			for i, host := range filter.ExcludeHosts {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, host)
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("(host IS NULL OR host NOT IN (%s))", strings.Join(placeholders, ",")))
		}
		if len(filter.ExcludeCountries) > 0 {
			placeholders := make([]string, len(filter.ExcludeCountries))
			for i, country := range filter.ExcludeCountries {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, country)
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("(geo_country_code IS NULL OR geo_country_code NOT IN (%s))", strings.Join(placeholders, ",")))
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Build ORDER BY clause
	orderBy := "timestamp DESC" // default
	if filter != nil && filter.SortBy != nil && *filter.SortBy != "" {
		allowedSortFields := map[string]bool{
			"timestamp":       true,
			"body_bytes_sent": true,
			"request_time":    true,
			"status_code":     true,
			"client_ip":       true,
			"host":            true,
		}
		if allowedSortFields[*filter.SortBy] {
			sortOrder := "DESC"
			if filter.SortOrder != nil && (*filter.SortOrder == "asc" || *filter.SortOrder == "ASC") {
				sortOrder = "ASC"
			}
			orderBy = fmt.Sprintf("%s %s", *filter.SortBy, sortOrder)
		}
	}

	// Fetch perPage+1 rows to determine hasMore without COUNT(*)
	// Select only columns needed for list view to reduce IO (~60% less data)
	fetchLimit := perPage + 1
	query := fmt.Sprintf(`
		SELECT id, log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_org,
			request_method, request_uri, status_code,
			body_bytes_sent, request_time,
			upstream_addr, upstream_status,
			http_user_agent,
			severity, error_message,
			rule_id, rule_message, action_taken,
			block_reason, bot_category, exploit_rule,
			created_at
		FROM logs_partitioned
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, fetchLimit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list logs: %w", err)
	}
	defer rows.Close()

	var logs []model.Log
	for rows.Next() {
		var log model.Log
		var host, clientIP, requestMethod, requestURI sql.NullString
		var geoCountry, geoCountryCode, geoOrg sql.NullString
		var statusCode sql.NullInt32
		var ruleID sql.NullInt64
		var bodyBytesSent sql.NullInt64
		var requestTime sql.NullFloat64
		var upstreamAddr, upstreamStatus sql.NullString
		var httpUserAgent sql.NullString
		var severity, errorMessage sql.NullString
		var ruleMessage, actionTaken sql.NullString
		var blockReason, botCategory, exploitRule sql.NullString

		err := rows.Scan(
			&log.ID, &log.LogType, &log.Timestamp, &host, &clientIP,
			&geoCountry, &geoCountryCode, &geoOrg,
			&requestMethod, &requestURI, &statusCode,
			&bodyBytesSent, &requestTime,
			&upstreamAddr, &upstreamStatus,
			&httpUserAgent,
			&severity, &errorMessage,
			&ruleID, &ruleMessage, &actionTaken,
			&blockReason, &botCategory, &exploitRule,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan log: %w", err)
		}

		if host.Valid {
			log.Host = &host.String
		}
		if clientIP.Valid {
			ip := net.ParseIP(clientIP.String)
			log.ClientIP = &ip
		}
		if geoCountry.Valid {
			log.GeoCountry = &geoCountry.String
		}
		if geoCountryCode.Valid {
			log.GeoCountryCode = &geoCountryCode.String
		}
		if geoOrg.Valid {
			log.GeoOrg = &geoOrg.String
		}
		if requestMethod.Valid {
			log.RequestMethod = &requestMethod.String
		}
		if requestURI.Valid {
			log.RequestURI = &requestURI.String
		}
		if statusCode.Valid {
			code := int(statusCode.Int32)
			log.StatusCode = &code
		}
		if bodyBytesSent.Valid {
			log.BodyBytesSent = &bodyBytesSent.Int64
		}
		if requestTime.Valid {
			log.RequestTime = &requestTime.Float64
		}
		if upstreamAddr.Valid {
			log.UpstreamAddr = &upstreamAddr.String
		}
		if upstreamStatus.Valid {
			log.UpstreamStatus = &upstreamStatus.String
		}
		if httpUserAgent.Valid {
			log.HTTPUserAgent = &httpUserAgent.String
		}
		if severity.Valid {
			sev := model.LogSeverity(severity.String)
			log.Severity = &sev
		}
		if errorMessage.Valid {
			log.ErrorMessage = &errorMessage.String
		}
		if ruleID.Valid {
			id := ruleID.Int64
			log.RuleID = &id
		}
		if ruleMessage.Valid {
			log.RuleMessage = &ruleMessage.String
		}
		if actionTaken.Valid {
			log.ActionTaken = &actionTaken.String
		}
		if blockReason.Valid {
			br := model.BlockReason(blockReason.String)
			log.BlockReason = &br
		}
		if botCategory.Valid {
			log.BotCategory = &botCategory.String
		}
		if exploitRule.Valid && exploitRule.String != "" {
			log.ExploitRule = &exploitRule.String
		}

		logs = append(logs, log)
	}

	// Determine hasMore: if we fetched more than perPage, there are more rows
	hasMore := len(logs) > perPage
	if hasMore {
		logs = logs[:perPage] // trim the extra row
	}

	// Synthetic total avoids expensive COUNT(*).
	// Add +1 when hasMore so the handler can detect it via total > page*perPage.
	// The frontend relies on has_more for navigation, not on total.
	total := offset + len(logs)
	if hasMore {
		total++
	}

	return logs, total, nil
}
