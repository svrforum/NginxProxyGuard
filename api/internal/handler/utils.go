package handler

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
)

// Validation constants
const (
	// Pagination limits
	DefaultPage    = 1
	DefaultPerPage = 20
	MaxPerPage     = 100
	MinPerPage     = 1

	// String field length limits
	MaxNameLength        = 255
	MaxDescriptionLength = 2000
	MaxReasonLength      = 1000
	MaxURLLength         = 2048
	MaxDomainLength      = 253  // RFC 1035 max domain length
	MaxIPLength          = 45   // IPv6 max length
	MaxPathLength        = 4096 // URL path max length

	// Supported values
	LanguageKorean  = "ko"
	LanguageEnglish = "en"
)

// SupportedLanguages defines all supported language codes
var SupportedLanguages = []string{LanguageKorean, LanguageEnglish}

// domainRegex validates domain name format (RFC 1035)
var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ParsePaginationParams extracts and validates pagination parameters from request
func ParsePaginationParams(c echo.Context) (page, perPage int) {
	page, _ = strconv.Atoi(c.QueryParam("page"))
	if page < DefaultPage {
		page = DefaultPage
	}

	perPage, _ = strconv.Atoi(c.QueryParam("per_page"))
	if perPage < MinPerPage || perPage > MaxPerPage {
		perPage = DefaultPerPage
	}

	return page, perPage
}

// ParsePaginationParamsWithDefaults extracts pagination with custom defaults
func ParsePaginationParamsWithDefaults(c echo.Context, defaultPerPage int) (page, perPage int) {
	page, _ = strconv.Atoi(c.QueryParam("page"))
	if page < DefaultPage {
		page = DefaultPage
	}

	perPage, _ = strconv.Atoi(c.QueryParam("per_page"))
	if perPage < MinPerPage || perPage > MaxPerPage {
		perPage = defaultPerPage
	}

	return page, perPage
}

// ValidateStringLength checks if a string is within the maximum length
func ValidateStringLength(value string, maxLength int, fieldName string) error {
	if len(value) > maxLength {
		return &ValidationError{
			Field:   fieldName,
			Message: "exceeds maximum length of " + strconv.Itoa(maxLength),
		}
	}
	return nil
}

// ValidateRequired checks if a required field is not empty
func ValidateRequired(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{
			Field:   fieldName,
			Message: "is required",
		}
	}
	return nil
}

// ValidateDomainName validates a domain name format
func ValidateDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > MaxDomainLength {
		return false
	}
	// Allow wildcards
	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}
	return domainRegex.MatchString(domain)
}

// ValidateHostnameOrIP validates that a string is either a valid hostname or IP address
func ValidateHostnameOrIP(host string) bool {
	if len(host) == 0 || len(host) > MaxDomainLength {
		return false
	}

	// Check if it's an IP address
	if net.ParseIP(host) != nil {
		return true
	}

	// Check if it's a valid hostname
	return ValidateDomainName(host)
}

// ValidateURL validates a URL format
func ValidateURL(urlStr string) bool {
	if len(urlStr) == 0 || len(urlStr) > MaxURLLength {
		return false
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Must have scheme and host
	return u.Scheme != "" && u.Host != ""
}

// ValidateLanguage checks if the language code is supported
func ValidateLanguage(lang string) bool {
	for _, supported := range SupportedLanguages {
		if lang == supported {
			return true
		}
	}
	return false
}

// ValidationError represents a validation error for a specific field
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + " " + e.Message
}

// ValidatePort checks if a port number is valid
func ValidatePort(port int) bool {
	return port >= 1 && port <= 65535
}

// SanitizeString trims whitespace and limits length
func SanitizeString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// CalculateTotalPages calculates the total number of pages for pagination
func CalculateTotalPages(total, perPage int) int {
	if perPage <= 0 {
		perPage = DefaultPerPage
	}
	return (total + perPage - 1) / perPage
}

// GetHostDisplayName returns the first domain name of a host or a fallback value
func GetHostDisplayName(domainNames []string, fallback string) string {
	if len(domainNames) > 0 {
		return domainNames[0]
	}
	return fallback
}

// UserInfo holds extracted user information from context
type UserInfo struct {
	ID    *string
	Email string
}

// ExtractUserInfo extracts user ID and email from echo context
func ExtractUserInfo(c echo.Context) UserInfo {
	var info UserInfo

	if uid, ok := c.Get("user_id").(string); ok && uid != "" {
		info.ID = &uid
	}

	if email, ok := c.Get("username").(string); ok {
		info.Email = email
	}

	return info
}

// ValidateIPAddress validates a single IPv4 or IPv6 address
func ValidateIPAddress(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil
}

// ValidateCIDR validates an IP address or CIDR notation (e.g., "192.168.0.0/24")
func ValidateCIDR(address string) bool {
	address = strings.TrimSpace(address)
	if address == "all" {
		return true
	}
	if net.ParseIP(address) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(address)
	return err == nil
}

// ValidateIPList validates a list of IP addresses or CIDR notations.
// Returns a list of invalid entries, or nil if all are valid.
func ValidateIPList(ips []string) (invalid []string) {
	for _, ip := range ips {
		if !ValidateCIDR(ip) {
			invalid = append(invalid, ip)
		}
	}
	return invalid
}

const (
	// Regex safety limits
	MaxRegexLength     = 500
	MaxRegexGroupDepth = 3
)

const (
	MinPasswordLength = 10
)

// ValidatePasswordStrength validates password meets security requirements
// Returns nil if valid, error with specific requirement that failed
func ValidatePasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case 'A' <= ch && ch <= 'Z':
			hasUpper = true
		case 'a' <= ch && ch <= 'z':
			hasLower = true
		case '0' <= ch && ch <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	// Check common passwords
	if isCommonPassword(password) {
		return fmt.Errorf("password is too common, please choose a stronger password")
	}

	return nil
}

// isCommonPassword checks against a small blocklist of very common passwords
func isCommonPassword(password string) bool {
	common := []string{
		"password123", "admin12345", "qwerty1234",
		"letmein123", "welcome123", "monkey1234",
		"dragon1234", "master1234", "1234567890",
		"abcdefghij", "Password1!", "Admin@1234",
		"Qwerty123!", "P@ssw0rd12", "Ch@ngeme1!",
	}
	lower := strings.ToLower(password)
	for _, c := range common {
		if strings.ToLower(c) == lower {
			return true
		}
	}
	return false
}

// ValidateRegexPattern validates a regex pattern for safety (ReDoS prevention).
// Returns nil if safe, error with description if unsafe.
func ValidateRegexPattern(pattern string) error {
	if len(pattern) > MaxRegexLength {
		return fmt.Errorf("pattern exceeds maximum length of %d characters", MaxRegexLength)
	}

	// Check for nested quantifiers (common ReDoS pattern: (a+)+, (a*)*,  (a+)* etc.)
	nestedQuantifier := regexp.MustCompile(`[+*]\)[\s]*[+*?{]`)
	if nestedQuantifier.MatchString(pattern) {
		return fmt.Errorf("pattern contains nested quantifiers which may cause performance issues")
	}

	// Check for excessive group nesting depth
	depth, maxDepth := 0, 0
	for _, ch := range pattern {
		if ch == '(' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if ch == ')' {
			depth--
		}
	}
	if maxDepth > MaxRegexGroupDepth {
		return fmt.Errorf("pattern nesting depth %d exceeds maximum of %d", maxDepth, MaxRegexGroupDepth)
	}

	// Try to compile the regex (catches syntax errors)
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}

	return nil
}
