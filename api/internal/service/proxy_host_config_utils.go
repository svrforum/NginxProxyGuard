package service

import (
	"net"
	"regexp"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// parseNginxErrorForHost extracts the failing host's domain from an nginx error message
func parseNginxErrorForHost(errorMsg string) string {
	// Pattern matches config filenames like "proxy_host_example_com.conf:123" or "/etc/nginx/conf.d/proxy_host_example_com.conf:123"
	re := regexp.MustCompile(`proxy_host_([a-zA-Z0-9_-]+(?:_[a-zA-Z0-9_-]+)*)\.conf`)
	matches := re.FindStringSubmatch(errorMsg)
	if len(matches) > 1 {
		// Convert underscores back to dots (filename uses underscores, domain uses dots)
		return strings.ReplaceAll(matches[1], "_", ".")
	}
	return ""
}

// findHostByID finds a host by ID in the hosts slice
func findHostByID(hosts []model.ProxyHost, id string) *model.ProxyHost {
	for i := range hosts {
		if hosts[i].ID == id {
			return &hosts[i]
		}
	}
	return nil
}

// findHostByDomain finds which host in the results matches the given domain
// Returns the index in the hosts slice, or -1 if not found
func findHostByDomain(hosts []SyncHostResult, domain string) int {
	domain = strings.ToLower(domain)
	for i, host := range hosts {
		for _, d := range host.DomainNames {
			if strings.ToLower(d) == domain || strings.HasPrefix(strings.ToLower(d), domain+".") || strings.HasPrefix(domain, strings.ToLower(d)+".") {
				return i
			}
		}
	}
	return -1
}

// mergeURIBlocks merges global and host-specific URI block settings
// Global rules are applied first (higher priority), then host-specific rules
func mergeURIBlocks(global *model.GlobalURIBlock, host *model.URIBlock) *model.URIBlock {
	// If both are nil or disabled, return nil
	globalEnabled := global != nil && global.Enabled
	hostEnabled := host != nil && host.Enabled

	if !globalEnabled && !hostEnabled {
		return nil
	}

	// Create merged result
	result := &model.URIBlock{
		Enabled:      true,
		Rules:        []model.URIBlockRule{},
		ExceptionIPs: []string{},
		// AllowPrivateIPs defaults to false; set from global/host below via OR logic
		AllowPrivateIPs: false,
	}

	// If host has settings, use its ID and other properties
	if host != nil {
		result.ID = host.ID
		result.ProxyHostID = host.ProxyHostID
		result.CreatedAt = host.CreatedAt
		result.UpdatedAt = host.UpdatedAt
	}

	// Add global rules first (higher priority - checked first by nginx)
	if globalEnabled {
		for _, rule := range global.Rules {
			if rule.Enabled {
				result.Rules = append(result.Rules, rule)
			}
		}
		// Merge global exception IPs
		result.ExceptionIPs = append(result.ExceptionIPs, global.ExceptionIPs...)
		result.AllowPrivateIPs = global.AllowPrivateIPs
	}

	// Add host-specific rules
	if hostEnabled {
		for _, rule := range host.Rules {
			if rule.Enabled {
				// Check if rule already exists (by pattern and match type) to avoid duplicates
				exists := false
				for _, existing := range result.Rules {
					if existing.Pattern == rule.Pattern && existing.MatchType == rule.MatchType {
						exists = true
						break
					}
				}
				if !exists {
					result.Rules = append(result.Rules, rule)
				}
			}
		}
		// Merge host exception IPs (avoid duplicates)
		for _, ip := range host.ExceptionIPs {
			exists := false
			for _, existing := range result.ExceptionIPs {
				if existing == ip {
					exists = true
					break
				}
			}
			if !exists {
				result.ExceptionIPs = append(result.ExceptionIPs, ip)
			}
		}
		// AllowPrivateIPs: OR logic - true if EITHER global OR host enables it
		// Global acts as a safety net that cannot be overridden by host
		if host.Enabled {
			result.AllowPrivateIPs = host.AllowPrivateIPs || result.AllowPrivateIPs
		}
	}

	return result
}

// filterBannedByFilterSubscription removes banned IPs that already exist in filter subscription entries.
// This prevents nginx "duplicate network" errors in geo blocks where both the include file
// (filter_sub_ips.conf with value=2) and inline BannedIPs (value=1) contain the same IP.
func filterBannedByFilterSubscription(banned []model.BannedIP, filterSubIPs []string) []model.BannedIP {
	subSet := make(map[string]bool, len(filterSubIPs))
	for _, ip := range filterSubIPs {
		subSet[strings.TrimSpace(ip)] = true
	}

	filtered := make([]model.BannedIP, 0, len(banned))
	for _, b := range banned {
		ip := strings.TrimSpace(b.IPAddress)
		if !subSet[ip] {
			filtered = append(filtered, b)
		}
	}
	return filtered
}

// filterBannedByTrustedIPs removes banned IPs that match any trusted IP or fall within a trusted CIDR.
func filterBannedByTrustedIPs(banned []model.BannedIP, trusted []string) []model.BannedIP {
	exactTrusted := make(map[string]bool)
	var trustedNets []*net.IPNet
	for _, entry := range trusted {
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err == nil {
				trustedNets = append(trustedNets, network)
			}
		} else {
			exactTrusted[entry] = true
		}
	}

	filtered := make([]model.BannedIP, 0, len(banned))
	for _, b := range banned {
		ip := strings.TrimSpace(b.IPAddress)
		// Strip CIDR suffix if present (e.g., "1.2.3.4/32" → "1.2.3.4")
		if idx := strings.Index(ip, "/"); idx > 0 {
			ip = ip[:idx]
		}
		if exactTrusted[ip] {
			continue
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			skip := false
			for _, network := range trustedNets {
				if network.Contains(parsedIP) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
		}
		filtered = append(filtered, b)
	}
	return filtered
}
