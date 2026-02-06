package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// Maximum number of items allowed in filter arrays to prevent DoS
const maxFilterArraySize = 100

type LogHandler struct {
	logRepo       *repository.LogRepository
	redisCache    *cache.RedisClient
	rateLimitRepo *repository.RateLimitRepository
}

func NewLogHandler(logRepo *repository.LogRepository, redisCache *cache.RedisClient, rateLimitRepo *repository.RateLimitRepository) *LogHandler {
	return &LogHandler{logRepo: logRepo, redisCache: redisCache, rateLimitRepo: rateLimitRepo}
}

// limitArray limits the size of a string slice to prevent DoS
func limitArray(arr []string, max int) []string {
	if len(arr) > max {
		return arr[:max]
	}
	return arr
}

func (h *LogHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	// Build filter from query params
	filter := &model.LogFilter{}

	if logType := r.URL.Query().Get("log_type"); logType != "" {
		lt := model.LogType(logType)
		filter.LogType = &lt
	}
	if host := r.URL.Query().Get("host"); host != "" {
		filter.Host = &host
	}
	if clientIP := r.URL.Query().Get("client_ip"); clientIP != "" {
		filter.ClientIP = &clientIP
	}
	// Array filters for multi-select support
	if hosts := r.URL.Query()["hosts"]; len(hosts) > 0 {
		filter.Hosts = limitArray(hosts, maxFilterArraySize)
	}
	if clientIPs := r.URL.Query()["client_ips"]; len(clientIPs) > 0 {
		filter.ClientIPs = limitArray(clientIPs, maxFilterArraySize)
	}
	if uris := r.URL.Query()["uris"]; len(uris) > 0 {
		filter.URIs = limitArray(uris, maxFilterArraySize)
	}
	if userAgents := r.URL.Query()["user_agents"]; len(userAgents) > 0 {
		filter.UserAgents = limitArray(userAgents, maxFilterArraySize)
	}
	if statusCode := r.URL.Query().Get("status_code"); statusCode != "" {
		if code, err := strconv.Atoi(statusCode); err == nil {
			filter.StatusCode = &code
		}
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		sev := model.LogSeverity(severity)
		filter.Severity = &sev
	}
	if ruleID := r.URL.Query().Get("rule_id"); ruleID != "" {
		if id, err := strconv.ParseInt(ruleID, 10, 64); err == nil {
			filter.RuleID = &id
		}
	}
	if proxyHostID := r.URL.Query().Get("proxy_host_id"); proxyHostID != "" {
		filter.ProxyHostID = &proxyHostID
	}
	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = &t
		}
	}
	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = &t
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}

	// Extended filters
	if userAgent := r.URL.Query().Get("user_agent"); userAgent != "" {
		filter.UserAgent = &userAgent
	}
	if uri := r.URL.Query().Get("uri"); uri != "" {
		filter.URI = &uri
	}
	if method := r.URL.Query().Get("method"); method != "" {
		filter.Method = &method
	}
	if geoCountryCode := r.URL.Query().Get("geo_country_code"); geoCountryCode != "" {
		filter.GeoCountryCode = &geoCountryCode
	}
	if statusCodes := r.URL.Query()["status_codes"]; len(statusCodes) > 0 {
		for _, sc := range statusCodes {
			if code, err := strconv.Atoi(sc); err == nil {
				filter.StatusCodes = append(filter.StatusCodes, code)
			}
		}
	}
	if minSize := r.URL.Query().Get("min_size"); minSize != "" {
		if size, err := strconv.ParseInt(minSize, 10, 64); err == nil {
			filter.MinSize = &size
		}
	}
	if maxSize := r.URL.Query().Get("max_size"); maxSize != "" {
		if size, err := strconv.ParseInt(maxSize, 10, 64); err == nil {
			filter.MaxSize = &size
		}
	}
	if minRequestTime := r.URL.Query().Get("min_request_time"); minRequestTime != "" {
		if t, err := strconv.ParseFloat(minRequestTime, 64); err == nil {
			filter.MinRequestTime = &t
		}
	}

	// Block reason filters
	if blockReason := r.URL.Query().Get("block_reason"); blockReason != "" {
		br := model.BlockReason(blockReason)
		filter.BlockReason = &br
	}
	if botCategory := r.URL.Query().Get("bot_category"); botCategory != "" {
		filter.BotCategory = &botCategory
	}
	if exploitRule := r.URL.Query().Get("exploit_rule"); exploitRule != "" {
		filter.ExploitRule = &exploitRule
	}

	// Sorting
	if sortBy := r.URL.Query().Get("sort_by"); sortBy != "" {
		filter.SortBy = &sortBy
	}
	if sortOrder := r.URL.Query().Get("sort_order"); sortOrder != "" {
		filter.SortOrder = &sortOrder
	}

	// Exclude filters - apply size limits to prevent DoS
	if excludeIPs := r.URL.Query()["exclude_ips"]; len(excludeIPs) > 0 {
		filter.ExcludeIPs = limitArray(excludeIPs, maxFilterArraySize)
	}
	if excludeUserAgents := r.URL.Query()["exclude_user_agents"]; len(excludeUserAgents) > 0 {
		filter.ExcludeUserAgents = limitArray(excludeUserAgents, maxFilterArraySize)
	}
	if excludeURIs := r.URL.Query()["exclude_uris"]; len(excludeURIs) > 0 {
		filter.ExcludeURIs = limitArray(excludeURIs, maxFilterArraySize)
	}
	if excludeHosts := r.URL.Query()["exclude_hosts"]; len(excludeHosts) > 0 {
		filter.ExcludeHosts = limitArray(excludeHosts, maxFilterArraySize)
	}
	if excludeCountries := r.URL.Query()["exclude_countries"]; len(excludeCountries) > 0 {
		filter.ExcludeCountries = limitArray(excludeCountries, maxFilterArraySize)
	}

	logs, total, err := h.logRepo.List(ctx, filter, page, perPage)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich logs with ban status (DB batch lookup for accuracy)
	if h.rateLimitRepo != nil && len(logs) > 0 {
		uniqueIPs := make(map[string]bool)
		var ipList []string
		for _, l := range logs {
			if l.ClientIP != nil {
				ip := l.ClientIP.String()
				if !uniqueIPs[ip] {
					uniqueIPs[ip] = true
					ipList = append(ipList, ip)
				}
			}
		}
		if len(ipList) > 0 {
			bannedSet, err := h.rateLimitRepo.GetActiveBannedIPSet(ctx, ipList)
			if err == nil {
				for i := range logs {
					if logs[i].ClientIP != nil {
						logs[i].IsBanned = bannedSet[logs[i].ClientIP.String()]
					}
				}
			}
		}
	}

	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}

	response := model.LogListResponse{
		Data:       logs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *LogHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Build filter from query params (same as List)
	filter := &model.LogFilter{}

	if logType := r.URL.Query().Get("log_type"); logType != "" {
		lt := model.LogType(logType)
		filter.LogType = &lt
	}
	if host := r.URL.Query().Get("host"); host != "" {
		filter.Host = &host
	}
	if clientIP := r.URL.Query().Get("client_ip"); clientIP != "" {
		filter.ClientIP = &clientIP
	}
	// Array filters for multi-select support
	if hosts := r.URL.Query()["hosts"]; len(hosts) > 0 {
		filter.Hosts = limitArray(hosts, maxFilterArraySize)
	}
	if clientIPs := r.URL.Query()["client_ips"]; len(clientIPs) > 0 {
		filter.ClientIPs = limitArray(clientIPs, maxFilterArraySize)
	}
	if uris := r.URL.Query()["uris"]; len(uris) > 0 {
		filter.URIs = limitArray(uris, maxFilterArraySize)
	}
	if userAgents := r.URL.Query()["user_agents"]; len(userAgents) > 0 {
		filter.UserAgents = limitArray(userAgents, maxFilterArraySize)
	}
	if statusCode := r.URL.Query().Get("status_code"); statusCode != "" {
		if code, err := strconv.Atoi(statusCode); err == nil {
			filter.StatusCode = &code
		}
	}
	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = &t
		}
	}
	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = &t
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}
	if userAgent := r.URL.Query().Get("user_agent"); userAgent != "" {
		filter.UserAgent = &userAgent
	}
	if uri := r.URL.Query().Get("uri"); uri != "" {
		filter.URI = &uri
	}
	if method := r.URL.Query().Get("method"); method != "" {
		filter.Method = &method
	}
	if geoCountryCode := r.URL.Query().Get("geo_country_code"); geoCountryCode != "" {
		filter.GeoCountryCode = &geoCountryCode
	}
	if statusCodes := r.URL.Query()["status_codes"]; len(statusCodes) > 0 {
		for _, sc := range statusCodes {
			if code, err := strconv.Atoi(sc); err == nil {
				filter.StatusCodes = append(filter.StatusCodes, code)
			}
		}
	}
	if minSize := r.URL.Query().Get("min_size"); minSize != "" {
		if size, err := strconv.ParseInt(minSize, 10, 64); err == nil {
			filter.MinSize = &size
		}
	}
	if maxSize := r.URL.Query().Get("max_size"); maxSize != "" {
		if size, err := strconv.ParseInt(maxSize, 10, 64); err == nil {
			filter.MaxSize = &size
		}
	}
	if minRequestTime := r.URL.Query().Get("min_request_time"); minRequestTime != "" {
		if t, err := strconv.ParseFloat(minRequestTime, 64); err == nil {
			filter.MinRequestTime = &t
		}
	}

	// Exclude filters - apply size limits to prevent DoS
	if excludeIPs := r.URL.Query()["exclude_ips"]; len(excludeIPs) > 0 {
		filter.ExcludeIPs = limitArray(excludeIPs, maxFilterArraySize)
	}
	if excludeUserAgents := r.URL.Query()["exclude_user_agents"]; len(excludeUserAgents) > 0 {
		filter.ExcludeUserAgents = limitArray(excludeUserAgents, maxFilterArraySize)
	}
	if excludeURIs := r.URL.Query()["exclude_uris"]; len(excludeURIs) > 0 {
		filter.ExcludeURIs = limitArray(excludeURIs, maxFilterArraySize)
	}
	if excludeHosts := r.URL.Query()["exclude_hosts"]; len(excludeHosts) > 0 {
		filter.ExcludeHosts = limitArray(excludeHosts, maxFilterArraySize)
	}
	if excludeCountries := r.URL.Query()["exclude_countries"]; len(excludeCountries) > 0 {
		filter.ExcludeCountries = limitArray(excludeCountries, maxFilterArraySize)
	}

	stats, err := h.logRepo.GetStatsWithFilter(ctx, filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *LogHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	settings, err := h.logRepo.GetSettings(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (h *LogHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req model.UpdateLogSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	settings, err := h.logRepo.UpdateSettings(ctx, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (h *LogHandler) Cleanup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get retention days from settings
	settings, err := h.logRepo.GetSettings(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deleted, err := h.logRepo.DeleteOld(ctx, settings.RetentionDays)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted": deleted,
		"message": "Old logs cleaned up successfully",
	})
}

// Create allows manual log ingestion via API
func (h *LogHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req model.CreateLogRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log, err := h.logRepo.Create(ctx, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(log)
}

// Autocomplete endpoints for filter suggestions

// GetDistinctHosts returns unique hosts for autocomplete
func (h *LogHandler) GetDistinctHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}

	hosts, err := h.logRepo.GetDistinctHosts(ctx, search, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// GetDistinctIPs returns unique client IPs for autocomplete
func (h *LogHandler) GetDistinctIPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}

	ips, err := h.logRepo.GetDistinctIPs(ctx, search, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

// GetDistinctUserAgents returns unique user agents for autocomplete
func (h *LogHandler) GetDistinctUserAgents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}

	agents, err := h.logRepo.GetDistinctUserAgents(ctx, search, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

// GetDistinctCountries returns unique country codes with counts
func (h *LogHandler) GetDistinctCountries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	countries, err := h.logRepo.GetDistinctCountries(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(countries)
}

// GetDistinctURIs returns unique URIs for autocomplete
func (h *LogHandler) GetDistinctURIs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}

	uris, err := h.logRepo.GetDistinctURIs(ctx, search, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uris)
}

// GetDistinctMethods returns unique HTTP methods
func (h *LogHandler) GetDistinctMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	methods, err := h.logRepo.GetDistinctMethods(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(methods)
}
