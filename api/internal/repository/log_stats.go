package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"nginx-proxy-guard/internal/model"
)

const statsCacheTTL = 5 * time.Minute

func (r *LogRepository) GetStats(ctx context.Context, startTime, endTime *time.Time) (*model.LogStats, error) {
	// Use the new filter-based method with just time filters
	filter := &model.LogFilter{
		StartTime: startTime,
		EndTime:   endTime,
	}
	return r.GetStatsWithFilter(ctx, filter)
}

// statsFilterCacheKey generates a short cache key for log stats based on filter content
func statsFilterCacheKey(filter *model.LogFilter) string {
	data, _ := json.Marshal(filter)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("log_stats:%x", hash[:16])
}

func (r *LogRepository) GetStatsWithFilter(ctx context.Context, filter *model.LogFilter) (*model.LogStats, error) {
	// Try cache first
	if r.cache != nil {
		cacheKey := statsFilterCacheKey(filter)
		var cached model.LogStats
		if err := r.cache.Get(ctx, cacheKey, &cached); err == nil {
			return &cached, nil
		}
	}

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
		if filter.Host != nil && *filter.Host != "" {
			condition, value, _ := buildHostFilter(*filter.Host, argIndex)
			whereClause += " AND " + condition
			args = append(args, value)
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
				condition, value, _ := buildHostFilter(host, argIndex)
				orConditions[i] = condition
				args = append(args, value)
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
				whereClause += fmt.Sprintf(" AND (host(client_ip) LIKE $%d OR host ILIKE $%d OR http_user_agent ILIKE $%d OR request_uri ILIKE $%d)", argIndex, argIndex+1, argIndex+1, argIndex+1)
				args = append(args, *filter.Search+"%", "%"+*filter.Search+"%")
				argIndex += 2
			} else if isNumeric && len(*filter.Search) > 0 {
				// Search is numeric - search by rule_id (partial match using LIKE on text cast)
				whereClause += fmt.Sprintf(" AND (rule_id::text LIKE $%d OR request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)", argIndex, argIndex+1, argIndex+1, argIndex+1)
				args = append(args, *filter.Search+"%", "%"+*filter.Search+"%")
				argIndex += 2
			} else {
				// Search is text - search by host, user_agent, uri, and error fields
				whereClause += fmt.Sprintf(" AND (host ILIKE $%d OR http_user_agent ILIKE $%d OR request_uri ILIKE $%d OR error_message ILIKE $%d OR rule_message ILIKE $%d)", argIndex, argIndex, argIndex, argIndex, argIndex)
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
		// Block reason filters
		if filter.BlockReason != nil && *filter.BlockReason != "" {
			whereClause += fmt.Sprintf(" AND block_reason = $%d", argIndex)
			args = append(args, *filter.BlockReason)
			argIndex++
		}
		if filter.BotCategory != nil && *filter.BotCategory != "" {
			whereClause += fmt.Sprintf(" AND bot_category = $%d", argIndex)
			args = append(args, *filter.BotCategory)
			argIndex++
		}
		if filter.ExploitRule != nil && *filter.ExploitRule != "" {
			whereClause += fmt.Sprintf(" AND exploit_rule = $%d", argIndex)
			args = append(args, *filter.ExploitRule)
			argIndex++
		}
	}

	// Run all stats queries in parallel using errgroup
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)

	// 1. Total counts by type
	g.Go(func() error {
		countQuery := fmt.Sprintf(`
			SELECT
				COUNT(*) as total,
				COUNT(*) FILTER (WHERE log_type = 'access') as access_logs,
				COUNT(*) FILTER (WHERE log_type = 'error') as error_logs,
				COUNT(*) FILTER (WHERE log_type = 'modsec') as modsec_logs
			FROM logs_partitioned
			WHERE %s
		`, whereClause)
		return r.db.QueryRowContext(gctx, countQuery, args...).Scan(
			&stats.TotalLogs, &stats.AccessLogs, &stats.ErrorLogs, &stats.ModSecLogs,
		)
	})

	// 2. Top status codes
	g.Go(func() error {
		statusQuery := fmt.Sprintf(`
			SELECT status_code, COUNT(*) as count
			FROM logs_partitioned
			WHERE status_code IS NOT NULL AND %s
			GROUP BY status_code
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)
		rows, err := r.db.QueryContext(gctx, statusQuery, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var results []model.StatusCodeStat
		for rows.Next() {
			var stat model.StatusCodeStat
			if err := rows.Scan(&stat.StatusCode, &stat.Count); err != nil {
				return err
			}
			results = append(results, stat)
		}
		mu.Lock()
		stats.TopStatusCodes = results
		mu.Unlock()
		return nil
	})

	// 3. Top client IPs
	g.Go(func() error {
		ipQuery := fmt.Sprintf(`
			SELECT host(client_ip), COUNT(*) as count
			FROM logs_partitioned
			WHERE client_ip IS NOT NULL AND %s
			GROUP BY client_ip
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)
		rows, err := r.db.QueryContext(gctx, ipQuery, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var results []model.ClientIPStat
		for rows.Next() {
			var stat model.ClientIPStat
			if err := rows.Scan(&stat.ClientIP, &stat.Count); err != nil {
				return err
			}
			results = append(results, stat)
		}
		mu.Lock()
		stats.TopClientIPs = results
		mu.Unlock()
		return nil
	})

	// 4. Top user agents
	g.Go(func() error {
		uaQuery := fmt.Sprintf(`
			SELECT http_user_agent, COUNT(*) as count
			FROM logs_partitioned
			WHERE http_user_agent IS NOT NULL AND http_user_agent != '' AND %s
			GROUP BY http_user_agent
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)
		rows, err := r.db.QueryContext(gctx, uaQuery, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var results []model.UserAgentStat
		for rows.Next() {
			var stat model.UserAgentStat
			if err := rows.Scan(&stat.UserAgent, &stat.Count); err != nil {
				return err
			}
			results = append(results, stat)
		}
		mu.Lock()
		stats.TopUserAgents = results
		mu.Unlock()
		return nil
	})

	// 5. Top attacked URIs
	g.Go(func() error {
		uriLogType := "modsec"
		if filter != nil && filter.LogType != nil && *filter.LogType == "access" {
			uriLogType = "access"
		}
		uriQuery := fmt.Sprintf(`
			SELECT request_uri, COUNT(*) as count
			FROM logs_partitioned
			WHERE log_type = '%s' AND request_uri IS NOT NULL AND %s
			GROUP BY request_uri
			ORDER BY count DESC
			LIMIT 10
		`, uriLogType, whereClause)
		rows, err := r.db.QueryContext(gctx, uriQuery, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var results []model.URIStat
		for rows.Next() {
			var stat model.URIStat
			if err := rows.Scan(&stat.URI, &stat.Count); err != nil {
				return err
			}
			results = append(results, stat)
		}
		mu.Lock()
		stats.TopAttackedURIs = results
		mu.Unlock()
		return nil
	})

	// 6. Top rule IDs
	g.Go(func() error {
		ruleQuery := fmt.Sprintf(`
			SELECT rule_id, COALESCE(rule_message, 'Unknown'), COUNT(*) as count
			FROM logs_partitioned
			WHERE log_type = 'modsec' AND rule_id IS NOT NULL AND %s
			GROUP BY rule_id, rule_message
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)
		rows, err := r.db.QueryContext(gctx, ruleQuery, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var results []model.RuleIDStat
		for rows.Next() {
			var stat model.RuleIDStat
			if err := rows.Scan(&stat.RuleID, &stat.Message, &stat.Count); err != nil {
				return err
			}
			results = append(results, stat)
		}
		mu.Lock()
		stats.TopRuleIDs = results
		mu.Unlock()
		return nil
	})

	// 7. Top countries
	g.Go(func() error {
		countryQuery := fmt.Sprintf(`
			SELECT
				COALESCE(geo_country_code, 'Unknown') as country_code,
				COALESCE(geo_country, 'Unknown') as country,
				COUNT(*) as count
			FROM logs_partitioned
			WHERE %s
			GROUP BY geo_country_code, geo_country
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)
		rows, err := r.db.QueryContext(gctx, countryQuery, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var results []model.CountryStat
		for rows.Next() {
			var stat model.CountryStat
			if err := rows.Scan(&stat.CountryCode, &stat.Country, &stat.Count); err != nil {
				return err
			}
			results = append(results, stat)
		}
		mu.Lock()
		stats.TopCountries = results
		mu.Unlock()
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("failed to get log stats: %w", err)
	}

	// Cache the result
	if r.cache != nil {
		cacheKey := statsFilterCacheKey(filter)
		if err := r.cache.Set(ctx, cacheKey, stats, statsCacheTTL); err != nil {
			log.Printf("[LogRepository] Failed to cache stats: %v", err)
		}
	}

	return stats, nil
}
