package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// FilterSubscriptionService handles filter subscription business logic
type FilterSubscriptionService struct {
	repo             *repository.FilterSubscriptionRepository
	proxyHostService *ProxyHostService
	nginxManager     NginxManager
	nginxReloader    *NginxReloader
	httpClient       *http.Client
}

// NewFilterSubscriptionService creates a new filter subscription service
func NewFilterSubscriptionService(repo *repository.FilterSubscriptionRepository, proxyHostService *ProxyHostService, nginxManager NginxManager, nginxReloader *NginxReloader) *FilterSubscriptionService {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %w", err)
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil && isFilterPrivateIP(ip) {
					return nil, fmt.Errorf("connection to private IP blocked: %s", ipStr)
				}
			}
			dialer := &net.Dialer{Timeout: config.FilterFetchConnectTimeout}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
	}

	client := &http.Client{
		Timeout:   config.FilterFetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.FilterMaxRedirects {
				return fmt.Errorf("too many redirects (max %d)", config.FilterMaxRedirects)
			}
			// Block redirects to private IPs
			host := req.URL.Hostname()
			if isPrivateAddr(host) {
				return fmt.Errorf("redirect to private address blocked: %s", host)
			}
			return nil
		},
	}

	return &FilterSubscriptionService{
		repo:             repo,
		proxyHostService: proxyHostService,
		nginxManager:     nginxManager,
		nginxReloader:    nginxReloader,
		httpClient:       client,
	}
}

// SetProxyHostService sets the proxy host service (used to avoid circular deps)
func (s *FilterSubscriptionService) SetProxyHostService(phs *ProxyHostService) {
	s.proxyHostService = phs
}

// List returns a paginated list of filter subscriptions
func (s *FilterSubscriptionService) List(ctx context.Context, page, perPage int) (*model.FilterSubscriptionListResponse, error) {
	return s.repo.List(ctx, page, perPage)
}

// GetByID returns a filter subscription by ID
func (s *FilterSubscriptionService) GetByID(ctx context.Context, id string) (*model.FilterSubscription, error) {
	return s.repo.GetByID(ctx, id)
}

// GetDetail returns a filter subscription with entries and exclusions
func (s *FilterSubscriptionService) GetDetail(ctx context.Context, id string) (*model.FilterSubscriptionDetail, error) {
	sub, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, nil
	}

	entries, err := s.repo.GetEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	exclusions, err := s.repo.ListExclusions(ctx, id)
	if err != nil {
		return nil, err
	}

	entryExclusions, err := s.repo.ListEntryExclusions(ctx, id)
	if err != nil {
		return nil, err
	}

	return &model.FilterSubscriptionDetail{
		FilterSubscription: *sub,
		Entries:            entries,
		Exclusions:         exclusions,
		EntryExclusions:    entryExclusions,
	}, nil
}

// Create creates a new filter subscription
func (s *FilterSubscriptionService) Create(ctx context.Context, req *model.CreateFilterSubscriptionRequest) (*model.FilterSubscription, error) {
	// Validate URL
	if req.URL == "" {
		return nil, fmt.Errorf("url is required")
	}

	// SSRF protection: check for private URLs
	if isPrivateURL(req.URL) {
		return nil, fmt.Errorf("invalid URL: private addresses are not allowed")
	}

	// Check if URL already subscribed
	existing, err := s.repo.GetByURL(ctx, req.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing subscription: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("subscription for this URL already exists")
	}

	// Check total entry limit
	totalCount, err := s.repo.GetTotalEntryCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check total entry count: %w", err)
	}
	if totalCount >= config.FilterMaxTotalEntries {
		return nil, fmt.Errorf("total entry limit reached (%d)", config.FilterMaxTotalEntries)
	}

	// Fetch and parse the URL
	entries, format, listName, listDescription, filterType, err := s.fetchAndParse(ctx, req.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch filter list: %w", err)
	}

	// Apply per-file limit
	if len(entries) > config.FilterMaxEntriesPerFile {
		entries = entries[:config.FilterMaxEntriesPerFile]
	}

	// Determine name
	name := req.Name
	if name == "" {
		name = listName
	}
	if name == "" {
		name = req.URL
	}

	// Determine type
	subType := req.Type
	if subType == "" {
		subType = filterType
	}
	if subType == "" {
		subType = "ip"
	}

	// Validate type
	validTypes := map[string]bool{"ip": true, "cidr": true, "user_agent": true}
	if !validTypes[subType] {
		return nil, fmt.Errorf("invalid type: must be ip, cidr, or user_agent")
	}

	// Determine refresh settings
	refreshType := req.RefreshType
	if refreshType == "" {
		refreshType = "interval"
	}
	refreshValue := req.RefreshValue
	if refreshValue == "" {
		refreshValue = "24h"
	}

	// Validate refresh_type
	validRefreshTypes := map[string]bool{"interval": true, "daily": true, "cron": true}
	if !validRefreshTypes[refreshType] {
		return nil, fmt.Errorf("invalid refresh_type: must be interval, daily, or cron")
	}

	// Validate refresh_value based on type
	switch refreshType {
	case "interval":
		validIntervals := map[string]bool{"6h": true, "12h": true, "24h": true, "48h": true}
		if !validIntervals[refreshValue] {
			return nil, fmt.Errorf("invalid interval: must be 6h, 12h, 24h, or 48h")
		}
	case "daily":
		parts := strings.Split(refreshValue, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid daily value: must be HH:MM format")
		}
	}

	sub := &model.FilterSubscription{
		Name:         name,
		Description:  listDescription,
		URL:          req.URL,
		Format:       format,
		Type:         subType,
		Enabled:      false,
		RefreshType:  refreshType,
		RefreshValue: refreshValue,
		EntryCount:   len(entries),
	}

	created, err := s.repo.Create(ctx, sub)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription: %w", err)
	}

	// Store entries
	if len(entries) > 0 {
		if err := s.repo.ReplaceEntries(ctx, created.ID, entries); err != nil {
			// Cleanup: delete the subscription to avoid orphan
			s.repo.Delete(ctx, created.ID)
			return nil, fmt.Errorf("failed to store entries: %w", err)
		}
	}

	// Update fetch status
	if err := s.repo.UpdateFetchStatus(ctx, created.ID, true, len(entries), ""); err != nil {
		log.Printf("[FilterSubscription] Failed to update fetch status: %v", err)
	}

	// Trigger async nginx reload
	s.triggerNginxReload()

	return created, nil
}

// Update updates a filter subscription
func (s *FilterSubscriptionService) Update(ctx context.Context, id string, req *model.UpdateFilterSubscriptionRequest) (*model.FilterSubscription, error) {
	updated, err := s.repo.Update(ctx, id, req)
	if err != nil {
		return nil, err
	}

	// If enabled state or exclude_private_ips changed, trigger nginx reload
	if req.Enabled != nil || req.ExcludePrivateIPs != nil {
		s.triggerNginxReload()
	}

	return updated, nil
}

// Delete deletes a filter subscription
func (s *FilterSubscriptionService) Delete(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}

// Refresh re-fetches a subscription and updates entries
func (s *FilterSubscriptionService) Refresh(ctx context.Context, id string) (*model.FilterSubscription, error) {
	sub, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	if sub == nil {
		return nil, fmt.Errorf("subscription not found")
	}

	// Fetch and parse
	entries, _, _, _, _, fetchErr := s.fetchAndParse(ctx, sub.URL)
	if fetchErr != nil {
		// Record failure but don't remove existing entries
		if err := s.repo.UpdateFetchStatus(ctx, id, false, sub.EntryCount, fetchErr.Error()); err != nil {
			log.Printf("[FilterSubscription] Failed to update fetch status: %v", err)
		}
		return nil, fmt.Errorf("failed to fetch filter list: %w", fetchErr)
	}

	// Empty response protection: if 0 entries fetched, keep existing
	if len(entries) == 0 {
		log.Printf("[FilterSubscription] Empty response for subscription %s, keeping existing %d entries", id, sub.EntryCount)
		if err := s.repo.UpdateFetchStatus(ctx, id, true, sub.EntryCount, ""); err != nil {
			log.Printf("[FilterSubscription] Failed to update fetch status: %v", err)
		}
		sub, _ = s.repo.GetByID(ctx, id)
		return sub, nil
	}

	// Check total entry limit (exclude current subscription's existing count)
	totalCount, err := s.repo.GetTotalEntryCount(ctx)
	if err == nil {
		otherEntries := totalCount - sub.EntryCount
		if otherEntries+len(entries) > config.FilterMaxTotalEntries {
			entries = entries[:config.FilterMaxTotalEntries-otherEntries]
			if len(entries) <= 0 {
				log.Printf("[FilterSubscription] Total entry limit reached during refresh for %s", sub.Name)
				s.repo.UpdateFetchStatus(ctx, id, true, sub.EntryCount, "")
				return s.repo.GetByID(ctx, id)
			}
		}
	}

	// Apply per-file limit
	if len(entries) > config.FilterMaxEntriesPerFile {
		entries = entries[:config.FilterMaxEntriesPerFile]
	}

	// Replace entries in transaction
	if err := s.repo.ReplaceEntries(ctx, id, entries); err != nil {
		return nil, fmt.Errorf("failed to replace entries: %w", err)
	}

	// Update fetch status
	if err := s.repo.UpdateFetchStatus(ctx, id, true, len(entries), ""); err != nil {
		log.Printf("[FilterSubscription] Failed to update fetch status: %v", err)
	}

	// Trigger async nginx reload
	s.triggerNginxReload()

	// Return updated subscription
	sub, _ = s.repo.GetByID(ctx, id)
	return sub, nil
}

// GetEntries returns entries for a subscription
func (s *FilterSubscriptionService) GetEntries(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionEntry, error) {
	return s.repo.GetEntries(ctx, subscriptionID)
}

// GetEntriesForHost returns entries applicable to a specific host
func (s *FilterSubscriptionService) GetEntriesForHost(ctx context.Context, hostID, filterType string) ([]model.FilterSubscriptionEntry, error) {
	return s.repo.GetEntriesForHost(ctx, hostID, filterType)
}

// ListExclusions returns host exclusions for a subscription
func (s *FilterSubscriptionService) ListExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionHostExclusion, error) {
	return s.repo.ListExclusions(ctx, subscriptionID)
}

// AddExclusion adds a host exclusion
func (s *FilterSubscriptionService) AddExclusion(ctx context.Context, subscriptionID, hostID string) error {
	if err := s.repo.AddExclusion(ctx, subscriptionID, hostID); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}

// RemoveExclusion removes a host exclusion
func (s *FilterSubscriptionService) RemoveExclusion(ctx context.Context, subscriptionID, hostID string) error {
	if err := s.repo.RemoveExclusion(ctx, subscriptionID, hostID); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}

// ListEntryExclusions returns entry exclusions for a subscription
func (s *FilterSubscriptionService) ListEntryExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionEntryExclusion, error) {
	return s.repo.ListEntryExclusions(ctx, subscriptionID)
}

// AddEntryExclusion adds an entry exclusion
func (s *FilterSubscriptionService) AddEntryExclusion(ctx context.Context, subscriptionID, value string) error {
	if err := s.repo.AddEntryExclusion(ctx, subscriptionID, value); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}

// RemoveEntryExclusion removes an entry exclusion
func (s *FilterSubscriptionService) RemoveEntryExclusion(ctx context.Context, subscriptionID, value string) error {
	if err := s.repo.RemoveEntryExclusion(ctx, subscriptionID, value); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}

// GetCatalog fetches the npg-filters index.json and marks subscribed lists
func (s *FilterSubscriptionService) GetCatalog(ctx context.Context) (*model.FilterCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.FilterCatalogIndexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create catalog request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, config.FilterMaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog body: %w", err)
	}

	var catalog model.FilterCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse catalog: %w", err)
	}

	// Mark subscribed lists
	subscribedURLs, err := s.repo.GetSubscribedURLs(ctx)
	if err != nil {
		log.Printf("[FilterSubscription] Failed to get subscribed URLs: %v", err)
	} else {
		for i := range catalog.Lists {
			fullURL := config.FilterCatalogBaseURL + catalog.Lists[i].Path
			if subscribedURLs[fullURL] {
				catalog.Lists[i].Subscribed = true
			}
		}
	}

	return &catalog, nil
}

// SubscribeFromCatalog subscribes to lists from the catalog
func (s *FilterSubscriptionService) SubscribeFromCatalog(ctx context.Context, req *model.CatalogSubscribeRequest) ([]model.FilterSubscription, error) {
	var subscribed []model.FilterSubscription

	for _, path := range req.Paths {
		fullURL := config.FilterCatalogBaseURL + path

		// Check if already subscribed
		existing, err := s.repo.GetByURL(ctx, fullURL)
		if err != nil {
			log.Printf("[FilterSubscription] Error checking existing subscription for %s: %v", path, err)
			continue
		}
		if existing != nil {
			subscribed = append(subscribed, *existing)
			continue
		}

		createReq := &model.CreateFilterSubscriptionRequest{
			URL:          fullURL,
			RefreshType:  req.RefreshType,
			RefreshValue: req.RefreshValue,
		}

		sub, err := s.Create(ctx, createReq)
		if err != nil {
			log.Printf("[FilterSubscription] Failed to subscribe to %s: %v", path, err)
			continue
		}
		subscribed = append(subscribed, *sub)
	}

	return subscribed, nil
}

// GetEnabledSubscriptions returns all enabled subscriptions
func (s *FilterSubscriptionService) GetEnabledSubscriptions(ctx context.Context) ([]model.FilterSubscription, error) {
	return s.repo.GetEnabledSubscriptions(ctx)
}

// fetchAndParse fetches a URL and auto-detects the format
func (s *FilterSubscriptionService) fetchAndParse(ctx context.Context, fetchURL string) ([]model.FilterSubscriptionEntry, string, string, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "NginxProxyGuard/"+config.AppVersion)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", "", "", fmt.Errorf("URL returned status %d", resp.StatusCode)
	}

	// Read with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, config.FilterMaxResponseSize))
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to read response: %w", err)
	}

	content := strings.TrimSpace(string(body))
	if content == "" {
		return []model.FilterSubscriptionEntry{}, "plaintext", "", "", "ip", nil
	}

	// Auto-detect format
	if strings.HasPrefix(content, "{") {
		return s.parseJSON(content)
	}

	return s.parsePlaintext(content)
}

// parseJSON parses NPG JSON format
func (s *FilterSubscriptionService) parseJSON(content string) ([]model.FilterSubscriptionEntry, string, string, string, string, error) {
	var list model.NPGFilterList
	if err := json.Unmarshal([]byte(content), &list); err != nil {
		return nil, "", "", "", "", fmt.Errorf("invalid JSON format: %w", err)
	}

	// Check for entries key
	if list.Entries == nil {
		return nil, "", "", "", "", fmt.Errorf("JSON format missing 'entries' key")
	}

	filterType := list.Type
	if filterType == "" {
		filterType = "ip"
	}

	entries := make([]model.FilterSubscriptionEntry, 0, len(list.Entries))
	seen := make(map[string]bool)
	for _, e := range list.Entries {
		if e.Value == "" {
			continue
		}
		// Validate each entry value based on list type
		if !validateEntryValue(filterType, e.Value) {
			continue
		}
		// Skip duplicates
		if seen[e.Value] {
			continue
		}
		seen[e.Value] = true
		entries = append(entries, model.FilterSubscriptionEntry{
			Value:  e.Value,
			Reason: e.Reason,
		})
	}

	return entries, "npg-json", list.Name, list.Description, filterType, nil
}

// validateEntryValue validates an entry value based on type.
// Returns true if valid, false if it should be skipped.
func validateEntryValue(entryType, value string) bool {
	switch entryType {
	case "ip":
		return net.ParseIP(value) != nil
	case "cidr":
		_, _, err := net.ParseCIDR(value)
		return err == nil
	case "user_agent":
		// Reject patterns longer than 200 characters
		if len(value) > 200 {
			return false
		}
		// Reject entries containing nginx-dangerous characters
		if strings.ContainsAny(value, ";{}()\"\\$") {
			return false
		}
		// Must compile as valid regex
		_, err := regexp.Compile(value)
		return err == nil
	default:
		return false
	}
}

// parsePlaintext parses plaintext IP/CIDR lists
func (s *FilterSubscriptionService) parsePlaintext(content string) ([]model.FilterSubscriptionEntry, string, string, string, string, error) {
	entries := []model.FilterSubscriptionEntry{}
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Remove inline comments (# and ;)
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Validate as IP or CIDR
		if !isValidIPOrCIDR(line) {
			continue
		}

		// Skip duplicates
		if seen[line] {
			continue
		}
		seen[line] = true

		entries = append(entries, model.FilterSubscriptionEntry{
			Value: line,
		})
	}

	// Auto-detect type: if majority of entries are CIDRs, type as "cidr"
	detectedType := "ip"
	cidrCount := 0
	for _, e := range entries {
		if strings.Contains(e.Value, "/") {
			cidrCount++
		}
	}
	if len(entries) > 0 && cidrCount > len(entries)/2 {
		detectedType = "cidr"
	}

	return entries, "plaintext", "", "", detectedType, scanner.Err()
}

// isValidIPOrCIDR checks if a string is a valid IP address or CIDR notation
func isValidIPOrCIDR(s string) bool {
	// Check CIDR
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	// Check IP
	return net.ParseIP(s) != nil
}

// isPrivateURL checks if a URL points to a private/internal address
func isPrivateURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true // Invalid URL, treat as private for safety
	}

	host := parsed.Hostname()
	return isPrivateAddr(host)
}

// isPrivateAddr checks if an address is in a private IP range
func isPrivateAddr(host string) bool {
	// Check for localhost
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	// Resolve hostname
	ips, err := net.LookupHost(host)
	if err != nil {
		// Can't resolve, check if it's already an IP
		ip := net.ParseIP(host)
		if ip != nil {
			return isFilterPrivateIP(ip)
		}
		return false
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && isFilterPrivateIP(ip) {
			return true
		}
	}

	return false
}

// isFilterPrivateIP checks if an IP is in a private range
func isFilterPrivateIP(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1 → 127.0.0.1)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	privateRanges := []struct {
		network string
	}{
		{"0.0.0.0/8"},
		{"10.0.0.0/8"},
		{"100.64.0.0/10"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"127.0.0.0/8"},
		{"169.254.0.0/16"},
		{"::1/128"},
		{"fc00::/7"},
		{"fe80::/10"},
	}

	for _, r := range privateRanges {
		_, network, err := net.ParseCIDR(r.network)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isPrivateIPOrCIDR checks if a string (IP or CIDR) falls within private ranges
func isPrivateIPOrCIDR(value string) bool {
	if strings.Contains(value, "/") {
		ip, _, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		return isFilterPrivateIP(ip)
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return isFilterPrivateIP(ip)
}

// triggerNginxReload regenerates shared filter subscription config files and triggers nginx reload.
// Instead of regenerating ALL host configs (which duplicated 50k+ entries per host),
// this writes two shared files (filter_sub_ips.conf, filter_sub_uas.conf) and reloads once.
func (s *FilterSubscriptionService) triggerNginxReload() {
	if s.nginxManager == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[FilterSubscription] Panic during nginx reload: %v", r)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), config.ContextTimeout)
		defer cancel()

		if err := s.regenerateSharedConfigs(ctx); err != nil {
			log.Printf("[FilterSubscription] Failed to regenerate shared configs: %v", err)
			return
		}

		// Request single debounced reload
		if s.nginxReloader != nil {
			s.nginxReloader.RequestReload(ctx)
		}
	}()
}

// regenerateSharedConfigs fetches all enabled filter entries and writes the shared config files.
func (s *FilterSubscriptionService) regenerateSharedConfigs(ctx context.Context) error {
	// Fetch all IP and CIDR entries from enabled subscriptions
	ips, err := s.repo.GetAllEnabledEntriesByType(ctx, "ip")
	if err != nil {
		return fmt.Errorf("failed to get IP entries: %w", err)
	}
	cidrs, err := s.repo.GetAllEnabledEntriesByType(ctx, "cidr")
	if err != nil {
		return fmt.Errorf("failed to get CIDR entries: %w", err)
	}

	// Merge IPs and CIDRs, deduplicating
	seen := make(map[string]bool, len(ips)+len(cidrs))
	var allIPs []string
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			allIPs = append(allIPs, ip)
		}
	}
	for _, cidr := range cidrs {
		if !seen[cidr] {
			seen[cidr] = true
			allIPs = append(allIPs, cidr)
		}
	}

	// Filter out private IPs if any enabled subscription has exclude_private_ips=true
	hasExcludePrivate, err := s.repo.HasExcludePrivateIPsEnabled(ctx)
	if err != nil {
		log.Printf("[FilterSubscription] Warning: failed to check exclude_private_ips: %v", err)
	}
	if hasExcludePrivate {
		filteredIPs := make([]string, 0, len(allIPs))
		for _, ipStr := range allIPs {
			if isPrivateIPOrCIDR(ipStr) {
				continue
			}
			filteredIPs = append(filteredIPs, ipStr)
		}
		allIPs = filteredIPs
	}

	// Fetch all UA entries
	uas, err := s.repo.GetAllEnabledEntriesByType(ctx, "user_agent")
	if err != nil {
		return fmt.Errorf("failed to get UA entries: %w", err)
	}

	// Generate shared config files
	if err := s.nginxManager.GenerateFilterSubscriptionConfigs(ctx, allIPs, uas); err != nil {
		return fmt.Errorf("failed to generate shared filter configs: %w", err)
	}

	log.Printf("[FilterSubscription] Shared configs regenerated: %d IPs/CIDRs, %d UAs", len(allIPs), len(uas))
	return nil
}

// RegenerateSharedConfigs is a public method for regenerating shared config files.
// Called during startup to ensure the files exist.
func (s *FilterSubscriptionService) RegenerateSharedConfigs(ctx context.Context) error {
	return s.regenerateSharedConfigs(ctx)
}
