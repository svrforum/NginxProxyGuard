package repository

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type LogRepository struct {
	db *database.DB
}

func NewLogRepository(db *database.DB) *LogRepository {
	return &LogRepository{db: db}
}

func (r *LogRepository) Create(ctx context.Context, req *model.CreateLogRequest) (*model.Log, error) {
	query := `
		INSERT INTO logs (
			log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
			http_referer, http_user_agent, http_x_forwarded_for,
			severity, error_message,
			rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
			proxy_host_id, raw_log
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, '')::inet,
			NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, 0),
			NULLIF($14, 0), NULLIF($15::numeric, 0), NULLIF($16::numeric, 0),
			NULLIF($17, ''), NULLIF($18, ''), NULLIF($19, ''),
			NULLIF($20, '')::log_severity, NULLIF($21, ''),
			NULLIF($22, 0), NULLIF($23, ''), NULLIF($24, ''), NULLIF($25, ''), NULLIF($26, ''), NULLIF($27, ''),
			NULLIF($28, '')::uuid, NULLIF($29, '')
		)
		RETURNING id, log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
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
	var statusCode, ruleID sql.NullInt32
	var bodyBytesSent sql.NullInt64
	var requestTime, upstreamResponseTime sql.NullFloat64
	var httpReferer, httpUserAgent, httpXForwardedFor sql.NullString
	var severity, errorMessage sql.NullString
	var ruleMessage, ruleSeverity, ruleData, attackType, actionTaken sql.NullString
	var proxyHostID, rawLog sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		req.LogType, timestamp, req.Host, req.ClientIP,
		req.GeoCountry, req.GeoCountryCode, req.GeoCity, req.GeoASN, req.GeoOrg,
		req.RequestMethod, req.RequestURI, req.RequestProtocol, req.StatusCode,
		req.BodyBytesSent, req.RequestTime, req.UpstreamResponseTime,
		req.HTTPReferer, req.HTTPUserAgent, req.HTTPXForwardedFor,
		req.Severity, req.ErrorMessage,
		req.RuleID, req.RuleMessage, req.RuleSeverity, req.RuleData, req.AttackType, req.ActionTaken,
		req.ProxyHostID, req.RawLog,
	).Scan(
		&log.ID, &log.LogType, &log.Timestamp, &host, &clientIP,
		&geoCountry, &geoCountryCode, &geoCity, &geoASN, &geoOrg,
		&requestMethod, &requestURI, &requestProtocol, &statusCode,
		&bodyBytesSent, &requestTime, &upstreamResponseTime,
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
		id := int(ruleID.Int32)
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

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO logs (
			log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
			http_referer, http_user_agent, http_x_forwarded_for,
			severity, error_message,
			rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
			block_reason, bot_category, exploit_rule,
			proxy_host_id, raw_log
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, '')::inet,
			NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, 0),
			NULLIF($14, 0), NULLIF($15::numeric, 0), NULLIF($16::numeric, 0),
			NULLIF($17, ''), NULLIF($18, ''), NULLIF($19, ''),
			NULLIF($20, '')::log_severity, NULLIF($21, ''),
			NULLIF($22, 0), NULLIF($23, ''), NULLIF($24, ''), NULLIF($25, ''), NULLIF($26, ''), NULLIF($27, ''),
			COALESCE(NULLIF($28, '')::block_reason, 'none'), NULLIF($29, ''), NULLIF($30, ''),
			NULLIF($31, '')::uuid, NULLIF($32, '')
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

	// Build WHERE clause
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
			conditions = append(conditions, fmt.Sprintf("host ILIKE $%d", argIndex))
			args = append(args, "%"+*filter.Host+"%")
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
			// Check if search term contains only digits (for rule_id partial match)
			isNumeric := true
			for _, c := range *filter.Search {
				if c < '0' || c > '9' {
					isNumeric = false
					break
				}
			}
			if isNumeric && len(*filter.Search) > 0 {
				// Search is numeric - search by rule_id (partial match using LIKE on text cast)
				conditions = append(conditions, fmt.Sprintf(
					"(rule_id::text LIKE $%d OR request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)",
					argIndex, argIndex+1, argIndex+1, argIndex+1,
				))
				args = append(args, *filter.Search+"%", "%"+*filter.Search+"%")
				argIndex += 2
			} else {
				// Search is text - search by text fields only
				conditions = append(conditions, fmt.Sprintf(
					"(request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)",
					argIndex, argIndex, argIndex,
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
				orConditions[i] = fmt.Sprintf("host ILIKE $%d", argIndex)
				args = append(args, "%"+host+"%")
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

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM logs %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count logs: %w", err)
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

	// Get paginated data
	query := fmt.Sprintf(`
		SELECT id, log_type, timestamp, host, client_ip,
			geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			request_method, request_uri, request_protocol, status_code,
			body_bytes_sent, request_time, upstream_response_time,
			http_referer, http_user_agent, http_x_forwarded_for,
			severity, error_message,
			rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
			block_reason, bot_category, exploit_rule,
			proxy_host_id, raw_log, created_at
		FROM logs
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, perPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list logs: %w", err)
	}
	defer rows.Close()

	var logs []model.Log
	for rows.Next() {
		var log model.Log
		var host, clientIP, requestMethod, requestURI, requestProtocol sql.NullString
		var geoCountry, geoCountryCode, geoCity, geoASN, geoOrg sql.NullString
		var statusCode, ruleID sql.NullInt32
		var bodyBytesSent sql.NullInt64
		var requestTime, upstreamResponseTime sql.NullFloat64
		var httpReferer, httpUserAgent, httpXForwardedFor sql.NullString
		var severity, errorMessage sql.NullString
		var ruleMessage, ruleSeverity, ruleData, attackType, actionTaken sql.NullString
		var blockReason, botCategory, exploitRule sql.NullString
		var proxyHostID, rawLog sql.NullString

		err := rows.Scan(
			&log.ID, &log.LogType, &log.Timestamp, &host, &clientIP,
			&geoCountry, &geoCountryCode, &geoCity, &geoASN, &geoOrg,
			&requestMethod, &requestURI, &requestProtocol, &statusCode,
			&bodyBytesSent, &requestTime, &upstreamResponseTime,
			&httpReferer, &httpUserAgent, &httpXForwardedFor,
			&severity, &errorMessage,
			&ruleID, &ruleMessage, &ruleSeverity, &ruleData, &attackType, &actionTaken,
			&blockReason, &botCategory, &exploitRule,
			&proxyHostID, &rawLog, &log.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan log: %w", err)
		}

		// Map nullable fields (same as Create)
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
			id := int(ruleID.Int32)
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
		if blockReason.Valid {
			br := model.BlockReason(blockReason.String)
			log.BlockReason = &br
		}
		if botCategory.Valid {
			log.BotCategory = &botCategory.String
		}
		if exploitRule.Valid {
			log.ExploitRule = &exploitRule.String
		}
		if proxyHostID.Valid {
			log.ProxyHostID = &proxyHostID.String
		}
		if rawLog.Valid {
			log.RawLog = &rawLog.String
		}

		logs = append(logs, log)
	}

	return logs, total, nil
}

func (r *LogRepository) GetStats(ctx context.Context, startTime, endTime *time.Time) (*model.LogStats, error) {
	// Use the new filter-based method with just time filters
	filter := &model.LogFilter{
		StartTime: startTime,
		EndTime:   endTime,
	}
	return r.GetStatsWithFilter(ctx, filter)
}

func (r *LogRepository) GetStatsWithFilter(ctx context.Context, filter *model.LogFilter) (*model.LogStats, error) {
	stats := &model.LogStats{}

	// Build WHERE clause from filter
	whereClause := "1=1"
	args := []interface{}{}
	argIndex := 1

	if filter != nil {
		if filter.LogType != nil {
			whereClause += fmt.Sprintf(" AND log_type = $%d", argIndex)
			args = append(args, *filter.LogType)
			argIndex++
		}
		if filter.Host != nil {
			whereClause += fmt.Sprintf(" AND host ILIKE $%d", argIndex)
			args = append(args, "%"+*filter.Host+"%")
			argIndex++
		}
		if filter.ClientIP != nil {
			whereClause += fmt.Sprintf(" AND client_ip::text ILIKE $%d", argIndex)
			args = append(args, "%"+*filter.ClientIP+"%")
			argIndex++
		}
		if filter.StartTime != nil {
			whereClause += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
			args = append(args, *filter.StartTime)
			argIndex++
		}
		if filter.EndTime != nil {
			whereClause += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
			args = append(args, *filter.EndTime)
			argIndex++
		}
		// Array filters for multi-select support
		if len(filter.Hosts) > 0 {
			orConditions := make([]string, len(filter.Hosts))
			for i, host := range filter.Hosts {
				orConditions[i] = fmt.Sprintf("host ILIKE $%d", argIndex)
				args = append(args, "%"+host+"%")
				argIndex++
			}
			whereClause += fmt.Sprintf(" AND (%s)", strings.Join(orConditions, " OR "))
		}
		if len(filter.ClientIPs) > 0 {
			placeholders := make([]string, len(filter.ClientIPs))
			for i, ip := range filter.ClientIPs {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, ip)
				argIndex++
			}
			whereClause += fmt.Sprintf(" AND host(client_ip) IN (%s)", strings.Join(placeholders, ","))
		}
		if len(filter.URIs) > 0 {
			orConditions := make([]string, len(filter.URIs))
			for i, uri := range filter.URIs {
				orConditions[i] = fmt.Sprintf("request_uri ILIKE $%d", argIndex)
				args = append(args, "%"+uri+"%")
				argIndex++
			}
			whereClause += fmt.Sprintf(" AND (%s)", strings.Join(orConditions, " OR "))
		}
		if len(filter.UserAgents) > 0 {
			orConditions := make([]string, len(filter.UserAgents))
			for i, ua := range filter.UserAgents {
				orConditions[i] = fmt.Sprintf("http_user_agent ILIKE $%d", argIndex)
				args = append(args, "%"+ua+"%")
				argIndex++
			}
			whereClause += fmt.Sprintf(" AND (%s)", strings.Join(orConditions, " OR "))
		}
		// Legacy single-value filters
		if filter.UserAgent != nil {
			whereClause += fmt.Sprintf(" AND http_user_agent ILIKE $%d", argIndex)
			args = append(args, "%"+*filter.UserAgent+"%")
			argIndex++
		}
		if filter.URI != nil {
			whereClause += fmt.Sprintf(" AND request_uri ILIKE $%d", argIndex)
			args = append(args, "%"+*filter.URI+"%")
			argIndex++
		}
		if filter.Method != nil {
			whereClause += fmt.Sprintf(" AND request_method = $%d", argIndex)
			args = append(args, *filter.Method)
			argIndex++
		}
		if filter.GeoCountryCode != nil {
			whereClause += fmt.Sprintf(" AND geo_country_code = $%d", argIndex)
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
			whereClause += fmt.Sprintf(" AND status_code IN (%s)", strings.Join(placeholders, ","))
		}
		if filter.StatusCode != nil {
			whereClause += fmt.Sprintf(" AND status_code = $%d", argIndex)
			args = append(args, *filter.StatusCode)
			argIndex++
		}
		if filter.MinSize != nil {
			whereClause += fmt.Sprintf(" AND body_bytes_sent >= $%d", argIndex)
			args = append(args, *filter.MinSize)
			argIndex++
		}
		if filter.MaxSize != nil {
			whereClause += fmt.Sprintf(" AND body_bytes_sent <= $%d", argIndex)
			args = append(args, *filter.MaxSize)
			argIndex++
		}
		if filter.MinRequestTime != nil {
			whereClause += fmt.Sprintf(" AND request_time >= $%d", argIndex)
			args = append(args, *filter.MinRequestTime)
			argIndex++
		}
		if filter.Search != nil && *filter.Search != "" {
			// Check if search term contains only digits (for rule_id partial match)
			isNumeric := true
			for _, c := range *filter.Search {
				if c < '0' || c > '9' {
					isNumeric = false
					break
				}
			}
			if isNumeric && len(*filter.Search) > 0 {
				// Search is numeric - search by rule_id (partial match using LIKE on text cast)
				whereClause += fmt.Sprintf(" AND (rule_id::text LIKE $%d OR request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)", argIndex, argIndex+1, argIndex+1, argIndex+1)
				args = append(args, *filter.Search+"%", "%"+*filter.Search+"%")
				argIndex += 2
			} else {
				// Search is text - search by text fields only
				whereClause += fmt.Sprintf(" AND (request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)", argIndex, argIndex, argIndex)
				args = append(args, "%"+*filter.Search+"%")
				argIndex++
			}
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
			whereClause += fmt.Sprintf(" AND (client_ip IS NULL OR host(client_ip) NOT IN (%s))", strings.Join(placeholders, ","))
		}
		if len(filter.ExcludeUserAgents) > 0 {
			for _, ua := range filter.ExcludeUserAgents {
				whereClause += fmt.Sprintf(" AND (http_user_agent IS NULL OR http_user_agent NOT ILIKE $%d)", argIndex)
				args = append(args, "%"+ua+"%")
				argIndex++
			}
		}
		if len(filter.ExcludeURIs) > 0 {
			for _, uri := range filter.ExcludeURIs {
				whereClause += fmt.Sprintf(" AND (request_uri IS NULL OR request_uri NOT ILIKE $%d)", argIndex)
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
			whereClause += fmt.Sprintf(" AND (host IS NULL OR host NOT IN (%s))", strings.Join(placeholders, ","))
		}
		if len(filter.ExcludeCountries) > 0 {
			placeholders := make([]string, len(filter.ExcludeCountries))
			for i, country := range filter.ExcludeCountries {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, country)
				argIndex++
			}
			whereClause += fmt.Sprintf(" AND (geo_country_code IS NULL OR geo_country_code NOT IN (%s))", strings.Join(placeholders, ","))
		}
	}

	// Total counts by type
	countQuery := fmt.Sprintf(`
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE log_type = 'access') as access_logs,
			COUNT(*) FILTER (WHERE log_type = 'error') as error_logs,
			COUNT(*) FILTER (WHERE log_type = 'modsec') as modsec_logs
		FROM logs
		WHERE %s
	`, whereClause)

	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(
		&stats.TotalLogs, &stats.AccessLogs, &stats.ErrorLogs, &stats.ModSecLogs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get log counts: %w", err)
	}

	// Top status codes
	statusQuery := fmt.Sprintf(`
		SELECT status_code, COUNT(*) as count
		FROM logs
		WHERE status_code IS NOT NULL AND %s
		GROUP BY status_code
		ORDER BY count DESC
		LIMIT 10
	`, whereClause)

	statusRows, err := r.db.QueryContext(ctx, statusQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get status codes: %w", err)
	}
	defer statusRows.Close()

	for statusRows.Next() {
		var stat model.StatusCodeStat
		if err := statusRows.Scan(&stat.StatusCode, &stat.Count); err != nil {
			return nil, fmt.Errorf("failed to scan status code: %w", err)
		}
		stats.TopStatusCodes = append(stats.TopStatusCodes, stat)
	}

	// Top client IPs
	ipQuery := fmt.Sprintf(`
		SELECT client_ip::text, COUNT(*) as count
		FROM logs
		WHERE client_ip IS NOT NULL AND %s
		GROUP BY client_ip
		ORDER BY count DESC
		LIMIT 10
	`, whereClause)

	ipRows, err := r.db.QueryContext(ctx, ipQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get client IPs: %w", err)
	}
	defer ipRows.Close()

	for ipRows.Next() {
		var stat model.ClientIPStat
		if err := ipRows.Scan(&stat.ClientIP, &stat.Count); err != nil {
			return nil, fmt.Errorf("failed to scan client IP: %w", err)
		}
		stats.TopClientIPs = append(stats.TopClientIPs, stat)
	}

	// Top user agents
	uaQuery := fmt.Sprintf(`
		SELECT http_user_agent, COUNT(*) as count
		FROM logs
		WHERE http_user_agent IS NOT NULL AND http_user_agent != '' AND %s
		GROUP BY http_user_agent
		ORDER BY count DESC
		LIMIT 10
	`, whereClause)

	uaRows, err := r.db.QueryContext(ctx, uaQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user agents: %w", err)
	}
	defer uaRows.Close()

	for uaRows.Next() {
		var stat model.UserAgentStat
		if err := uaRows.Scan(&stat.UserAgent, &stat.Count); err != nil {
			return nil, fmt.Errorf("failed to scan user agent: %w", err)
		}
		stats.TopUserAgents = append(stats.TopUserAgents, stat)
	}

	// Top attacked URIs (from modsec logs or access logs depending on log_type filter)
	uriLogType := "modsec"
	if filter != nil && filter.LogType != nil && *filter.LogType == "access" {
		uriLogType = "access"
	}
	uriQuery := fmt.Sprintf(`
		SELECT request_uri, COUNT(*) as count
		FROM logs
		WHERE log_type = '%s' AND request_uri IS NOT NULL AND %s
		GROUP BY request_uri
		ORDER BY count DESC
		LIMIT 10
	`, uriLogType, whereClause)

	uriRows, err := r.db.QueryContext(ctx, uriQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attacked URIs: %w", err)
	}
	defer uriRows.Close()

	for uriRows.Next() {
		var stat model.URIStat
		if err := uriRows.Scan(&stat.URI, &stat.Count); err != nil {
			return nil, fmt.Errorf("failed to scan URI: %w", err)
		}
		stats.TopAttackedURIs = append(stats.TopAttackedURIs, stat)
	}

	// Top rule IDs
	ruleQuery := fmt.Sprintf(`
		SELECT rule_id, COALESCE(rule_message, 'Unknown'), COUNT(*) as count
		FROM logs
		WHERE log_type = 'modsec' AND rule_id IS NOT NULL AND %s
		GROUP BY rule_id, rule_message
		ORDER BY count DESC
		LIMIT 10
	`, whereClause)

	ruleRows, err := r.db.QueryContext(ctx, ruleQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule IDs: %w", err)
	}
	defer ruleRows.Close()

	for ruleRows.Next() {
		var stat model.RuleIDStat
		if err := ruleRows.Scan(&stat.RuleID, &stat.Message, &stat.Count); err != nil {
			return nil, fmt.Errorf("failed to scan rule ID: %w", err)
		}
		stats.TopRuleIDs = append(stats.TopRuleIDs, stat)
	}

	return stats, nil
}

func (r *LogRepository) DeleteOld(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM logs WHERE created_at < NOW() - ($1 || ' days')::INTERVAL`
	result, err := r.db.ExecContext(ctx, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old logs: %w", err)
	}
	return result.RowsAffected()
}

func (r *LogRepository) GetSettings(ctx context.Context) (*model.LogSettings, error) {
	query := `
		SELECT id, retention_days, max_logs_per_type, auto_cleanup_enabled, created_at, updated_at
		FROM log_settings
		LIMIT 1
	`

	var settings model.LogSettings
	var maxLogsPerType sql.NullInt64

	err := r.db.QueryRowContext(ctx, query).Scan(
		&settings.ID, &settings.RetentionDays, &maxLogsPerType,
		&settings.AutoCleanupEnabled, &settings.CreatedAt, &settings.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		// Auto-create default settings if not exists
		return r.createDefaultSettings(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get log settings: %w", err)
	}

	if maxLogsPerType.Valid {
		settings.MaxLogsPerType = &maxLogsPerType.Int64
	}

	return &settings, nil
}

// createDefaultSettings creates default log settings if none exist
func (r *LogRepository) createDefaultSettings(ctx context.Context) (*model.LogSettings, error) {
	query := `
		INSERT INTO log_settings (retention_days, auto_cleanup_enabled, system_log_retention_days, enable_docker_logs, filter_health_checks)
		VALUES (30, true, 7, true, true)
		RETURNING id, retention_days, max_logs_per_type, auto_cleanup_enabled, created_at, updated_at
	`

	var settings model.LogSettings
	var maxLogsPerType sql.NullInt64

	err := r.db.QueryRowContext(ctx, query).Scan(
		&settings.ID, &settings.RetentionDays, &maxLogsPerType,
		&settings.AutoCleanupEnabled, &settings.CreatedAt, &settings.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create default log settings: %w", err)
	}

	if maxLogsPerType.Valid {
		settings.MaxLogsPerType = &maxLogsPerType.Int64
	}

	return &settings, nil
}

// GetDistinctHosts returns unique hosts from logs for autocomplete
func (r *LogRepository) GetDistinctHosts(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	query := `
		SELECT DISTINCT host
		FROM logs
		WHERE host IS NOT NULL AND host != ''
	`
	args := []interface{}{}
	argIndex := 1

	if search != "" {
		query += fmt.Sprintf(" AND host ILIKE $%d", argIndex)
		args = append(args, "%"+search+"%")
		argIndex++
	}

	query += fmt.Sprintf(" ORDER BY host LIMIT $%d", argIndex)
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct hosts: %w", err)
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

// GetDistinctIPs returns unique client IPs from logs for autocomplete
func (r *LogRepository) GetDistinctIPs(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	// Use host() function to get IP without /32 suffix
	query := `
		SELECT DISTINCT host(client_ip) as ip
		FROM logs
		WHERE client_ip IS NOT NULL
	`
	args := []interface{}{}
	argIndex := 1

	if search != "" {
		query += fmt.Sprintf(" AND host(client_ip) LIKE $%d", argIndex)
		args = append(args, search+"%")
		argIndex++
	}

	query += fmt.Sprintf(" ORDER BY ip LIMIT $%d", argIndex)
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct IPs: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// GetDistinctUserAgents returns unique user agents from logs for autocomplete
func (r *LogRepository) GetDistinctUserAgents(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	query := `
		SELECT DISTINCT http_user_agent
		FROM logs
		WHERE http_user_agent IS NOT NULL AND http_user_agent != ''
	`
	args := []interface{}{}
	argIndex := 1

	if search != "" {
		query += fmt.Sprintf(" AND http_user_agent ILIKE $%d", argIndex)
		args = append(args, "%"+search+"%")
		argIndex++
	}

	query += fmt.Sprintf(" ORDER BY http_user_agent LIMIT $%d", argIndex)
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct user agents: %w", err)
	}
	defer rows.Close()

	var agents []string
	for rows.Next() {
		var agent string
		if err := rows.Scan(&agent); err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

// GetDistinctCountries returns unique country codes with counts from logs
func (r *LogRepository) GetDistinctCountries(ctx context.Context) ([]model.CountryStat, error) {
	query := `
		SELECT geo_country_code, geo_country, COUNT(*) as count
		FROM logs
		WHERE geo_country_code IS NOT NULL AND geo_country_code != ''
		GROUP BY geo_country_code, geo_country
		ORDER BY count DESC
		LIMIT 50
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct countries: %w", err)
	}
	defer rows.Close()

	var countries []model.CountryStat
	for rows.Next() {
		var stat model.CountryStat
		var country sql.NullString
		if err := rows.Scan(&stat.CountryCode, &country, &stat.Count); err != nil {
			return nil, err
		}
		if country.Valid {
			stat.Country = country.String
		}
		countries = append(countries, stat)
	}
	return countries, nil
}

// GetDistinctURIs returns unique URIs from logs for autocomplete
func (r *LogRepository) GetDistinctURIs(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	query := `
		SELECT DISTINCT request_uri
		FROM logs
		WHERE request_uri IS NOT NULL AND request_uri != ''
			AND request_uri NOT IN ('/health', '/nginx_status')
			AND request_uri NOT LIKE '/.well-known/%'
	`
	args := []interface{}{}
	argIndex := 1

	if search != "" {
		query += fmt.Sprintf(" AND request_uri ILIKE $%d", argIndex)
		args = append(args, "%"+search+"%")
		argIndex++
	}

	query += fmt.Sprintf(" ORDER BY request_uri LIMIT $%d", argIndex)
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct URIs: %w", err)
	}
	defer rows.Close()

	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	return uris, nil
}

// GetDistinctMethods returns unique HTTP methods from logs
func (r *LogRepository) GetDistinctMethods(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT request_method
		FROM logs
		WHERE request_method IS NOT NULL AND request_method != ''
		ORDER BY request_method
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct methods: %w", err)
	}
	defer rows.Close()

	var methods []string
	for rows.Next() {
		var method string
		if err := rows.Scan(&method); err != nil {
			return nil, err
		}
		methods = append(methods, method)
	}
	return methods, nil
}

func (r *LogRepository) UpdateSettings(ctx context.Context, req *model.UpdateLogSettingsRequest) (*model.LogSettings, error) {
	settings, err := r.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	if req.RetentionDays != nil {
		settings.RetentionDays = *req.RetentionDays
	}
	if req.MaxLogsPerType != nil {
		settings.MaxLogsPerType = req.MaxLogsPerType
	}
	if req.AutoCleanupEnabled != nil {
		settings.AutoCleanupEnabled = *req.AutoCleanupEnabled
	}

	query := `
		UPDATE log_settings SET
			retention_days = $1,
			max_logs_per_type = $2,
			auto_cleanup_enabled = $3
		WHERE id = $4
		RETURNING updated_at
	`

	err = r.db.QueryRowContext(ctx, query,
		settings.RetentionDays, settings.MaxLogsPerType, settings.AutoCleanupEnabled, settings.ID,
	).Scan(&settings.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to update log settings: %w", err)
	}

	return settings, nil
}
