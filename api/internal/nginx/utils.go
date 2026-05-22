package nginx

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// isCIDR checks if the given string is a CIDR notation
func isCIDR(ip string) bool {
	return strings.Contains(ip, "/")
}

// cidrToNginxPattern converts a CIDR notation to an nginx-compatible regex pattern
// Examples:
// - 192.168.1.0/24 -> ^192\.168\.1\.
// - 10.0.0.0/8 -> ^10\.
// - 172.16.0.0/16 -> ^172\.16\.
func cidrToNginxPattern(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// If not a valid CIDR, return escaped IP
		return strings.ReplaceAll(strings.TrimSpace(cidr), ".", "\\.")
	}

	// Get the network portion based on mask
	ones, _ := ipNet.Mask.Size()
	ip := ipNet.IP.String()
	parts := strings.Split(ip, ".")

	if len(parts) != 4 {
		return strings.ReplaceAll(cidr, ".", "\\.")
	}

	// Build regex pattern based on network mask
	var pattern strings.Builder
	pattern.WriteString("^")

	switch {
	case ones >= 24:
		// /24 or more specific - match first 3 octets
		pattern.WriteString(parts[0])
		pattern.WriteString("\\.")
		pattern.WriteString(parts[1])
		pattern.WriteString("\\.")
		pattern.WriteString(parts[2])
		pattern.WriteString("\\.")
	case ones >= 16:
		// /16-/23 - match first 2 octets
		pattern.WriteString(parts[0])
		pattern.WriteString("\\.")
		pattern.WriteString(parts[1])
		pattern.WriteString("\\.")
	case ones >= 8:
		// /8-/15 - match first octet
		pattern.WriteString(parts[0])
		pattern.WriteString("\\.")
	default:
		// Very broad CIDR, be more conservative
		pattern.WriteString(parts[0])
		pattern.WriteString("\\.")
	}

	return pattern.String()
}

// sanitizeFilename converts a domain name to a safe filename
func sanitizeFilename(domain string) string {
	// Replace dots and special characters with underscores
	reg := regexp.MustCompile(`[^a-zA-Z0-9-]`)
	safe := reg.ReplaceAllString(domain, "_")
	// Remove multiple underscores
	reg = regexp.MustCompile(`_+`)
	safe = reg.ReplaceAllString(safe, "_")
	// Trim underscores from ends
	safe = strings.Trim(safe, "_")
	// Lowercase
	return strings.ToLower(safe)
}

// GetConfigFilename returns the config filename for a proxy host
func GetConfigFilename(host *model.ProxyHost) string {
	if host != nil && host.IsStream() {
		return GetStreamConfigFilename(host)
	}
	if len(host.DomainNames) == 0 {
		return fmt.Sprintf("proxy_host_%s.conf", host.ID)
	}
	// Use first domain name for filename
	safeName := sanitizeFilename(host.DomainNames[0])
	if safeName == "" {
		return fmt.Sprintf("proxy_host_%s.conf", host.ID)
	}
	return fmt.Sprintf("proxy_host_%s.conf", safeName)
}

// GetStreamConfigFilename returns the config filename for a stream proxy host.
func GetStreamConfigFilename(host *model.ProxyHost) string {
	port := host.StreamListenPort
	if port <= 0 {
		port = host.ForwardPort
	}
	if len(host.DomainNames) == 0 {
		if port > 0 {
			return fmt.Sprintf("stream_host_%s_%d.conf", host.ID, port)
		}
		return fmt.Sprintf("stream_host_%s.conf", host.ID)
	}
	safeName := sanitizeFilename(host.DomainNames[0])
	if safeName == "" {
		safeName = host.ID
	}
	if port > 0 {
		return fmt.Sprintf("stream_host_%s_%d.conf", safeName, port)
	}
	return fmt.Sprintf("stream_host_%s.conf", safeName)
}

func formatHostPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "unix:") {
		return host
	}
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func formatListenAddress(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" || host == "*" {
		return strconv.Itoa(port)
	}
	return formatHostPort(host, port)
}

// GetRedirectConfigFilename returns the config filename for a redirect host
func GetRedirectConfigFilename(host *model.RedirectHost) string {
	if len(host.DomainNames) == 0 {
		return fmt.Sprintf("redirect_host_%s.conf", host.ID)
	}
	safeName := sanitizeFilename(host.DomainNames[0])
	if safeName == "" {
		return fmt.Sprintf("redirect_host_%s.conf", host.ID)
	}
	return fmt.Sprintf("redirect_host_%s.conf", safeName)
}
