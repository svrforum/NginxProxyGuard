package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"nginx-proxy-guard/internal/model"
)

// autocomplete cache TTL
const autocompleteCacheTTL = 1 * time.Hour

// GetDistinctHosts returns unique hosts from logs for autocomplete
func (r *LogRepository) GetDistinctHosts(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	// Cache initial load (no search term)
	if search == "" && r.cache != nil {
		var cached []string
		if err := r.cache.Get(ctx, "autocomplete:hosts", &cached); err == nil {
			if len(cached) > limit {
				return cached[:limit], nil
			}
			return cached, nil
		}
	}

	query := `
		SELECT DISTINCT host
		FROM logs_partitioned
		WHERE host IS NOT NULL AND host != ''
		  AND created_at >= NOW() - INTERVAL '7 days'
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

	if search == "" && r.cache != nil {
		r.cache.Set(ctx, "autocomplete:hosts", hosts, autocompleteCacheTTL)
	}
	return hosts, nil
}

// GetDistinctIPs returns unique client IPs from logs for autocomplete
func (r *LogRepository) GetDistinctIPs(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	if search == "" && r.cache != nil {
		var cached []string
		if err := r.cache.Get(ctx, "autocomplete:ips", &cached); err == nil {
			if len(cached) > limit {
				return cached[:limit], nil
			}
			return cached, nil
		}
	}

	// Use host() function to get IP without /32 suffix
	query := `
		SELECT DISTINCT host(client_ip) as ip
		FROM logs_partitioned
		WHERE client_ip IS NOT NULL
		  AND created_at >= NOW() - INTERVAL '7 days'
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

	if search == "" && r.cache != nil {
		r.cache.Set(ctx, "autocomplete:ips", ips, autocompleteCacheTTL)
	}
	return ips, nil
}

// GetDistinctUserAgents returns unique user agents from logs for autocomplete
func (r *LogRepository) GetDistinctUserAgents(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	if search == "" && r.cache != nil {
		var cached []string
		if err := r.cache.Get(ctx, "autocomplete:user_agents", &cached); err == nil {
			if len(cached) > limit {
				return cached[:limit], nil
			}
			return cached, nil
		}
	}

	query := `
		SELECT DISTINCT http_user_agent
		FROM logs_partitioned
		WHERE http_user_agent IS NOT NULL AND http_user_agent != ''
		  AND created_at >= NOW() - INTERVAL '7 days'
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

	if search == "" && r.cache != nil {
		r.cache.Set(ctx, "autocomplete:user_agents", agents, autocompleteCacheTTL)
	}
	return agents, nil
}

// GetDistinctCountries returns unique country codes with counts from logs
func (r *LogRepository) GetDistinctCountries(ctx context.Context) ([]model.CountryStat, error) {
	if r.cache != nil {
		var cached []model.CountryStat
		if err := r.cache.Get(ctx, "autocomplete:countries", &cached); err == nil {
			return cached, nil
		}
	}

	query := `
		SELECT geo_country_code, geo_country, COUNT(*) as count
		FROM logs_partitioned
		WHERE geo_country_code IS NOT NULL AND geo_country_code != ''
		  AND created_at >= NOW() - INTERVAL '7 days'
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

	if r.cache != nil {
		r.cache.Set(ctx, "autocomplete:countries", countries, autocompleteCacheTTL)
	}
	return countries, nil
}

// GetDistinctURIs returns unique URIs from logs for autocomplete
func (r *LogRepository) GetDistinctURIs(ctx context.Context, search string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	if search == "" && r.cache != nil {
		var cached []string
		if err := r.cache.Get(ctx, "autocomplete:uris", &cached); err == nil {
			if len(cached) > limit {
				return cached[:limit], nil
			}
			return cached, nil
		}
	}

	query := `
		SELECT DISTINCT request_uri
		FROM logs_partitioned
		WHERE request_uri IS NOT NULL AND request_uri != ''
			AND request_uri NOT IN ('/health', '/nginx_status')
			AND request_uri NOT LIKE '/.well-known/%'
			AND created_at >= NOW() - INTERVAL '7 days'
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

	if search == "" && r.cache != nil {
		r.cache.Set(ctx, "autocomplete:uris", uris, autocompleteCacheTTL)
	}
	return uris, nil
}

// GetDistinctMethods returns unique HTTP methods from logs
func (r *LogRepository) GetDistinctMethods(ctx context.Context) ([]string, error) {
	if r.cache != nil {
		var cached []string
		if err := r.cache.Get(ctx, "autocomplete:methods", &cached); err == nil {
			return cached, nil
		}
	}

	query := `
		SELECT DISTINCT request_method
		FROM logs_partitioned
		WHERE request_method IS NOT NULL AND request_method != ''
		  AND created_at >= NOW() - INTERVAL '7 days'
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

	if r.cache != nil {
		r.cache.Set(ctx, "autocomplete:methods", methods, autocompleteCacheTTL)
	}
	return methods, nil
}
