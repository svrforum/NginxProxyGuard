package service

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Access log format (with host and timing):
// 172.19.0.1 - - [02/Dec/2025:00:47:05 +0000] "app.local" "GET / HTTP/2.0" 200 595 "-" "Mozilla/5.0..." "-" rt=0.001 ... block="bot_filter" bot="ai_bot"
var accessLogRegex = regexp.MustCompile(
	`^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"`,
)

// Regex patterns for parsing additional log fields
var (
	blockReasonRegex          = regexp.MustCompile(`block="([^"]*)"`)
	botCategoryRegex          = regexp.MustCompile(`bot="([^"]*)"`)
	exploitRuleRegex          = regexp.MustCompile(`exploit_rule="([^"]*)"`)
	requestTimeRegex          = regexp.MustCompile(`rt=([0-9.]+)`)
	geoCountryRegex           = regexp.MustCompile(`geo="([^"]*)"`)
	upstreamResponseTimeRegex = regexp.MustCompile(`urt="([^"]*)"`)
	// $upstream_addr / $upstream_status from nginx. On retries these become comma-separated
	// lists, e.g. ua="10.0.0.1:8080, 10.0.0.2:8080" / us="502, 200". We preserve the raw
	// value so the UI can show the full retry path; the DB column is text (not inet/int).
	upstreamAddrRegex     = regexp.MustCompile(`ua="([^"]*)"`)
	upstreamStatusRegex   = regexp.MustCompile(`us="([^"]*)"`)
	errorLogClientIPRegex = regexp.MustCompile(`client:\s+([0-9a-fA-F:.]+)`)
)

// Old access log format (without host) - fallback
var accessLogRegexOld = regexp.MustCompile(
	`^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"`,
)

func (c *LogCollector) parseAccessLog(line string) (*model.CreateLogRequest, error) {
	// Try new format with host first
	matches := accessLogRegex.FindStringSubmatch(line)
	if matches != nil && len(matches) >= 13 {
		// New format: client - user [time] "host" "method uri protocol" status bytes "referer" "ua" "xff"
		timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[3])
		if err != nil {
			timestamp = time.Now()
		}

		statusCode, _ := strconv.Atoi(matches[8])
		bodyBytes, _ := strconv.ParseInt(matches[9], 10, 64)

		host := matches[4]
		referer := matches[10]
		if referer == "-" {
			referer = ""
		}

		xForwardedFor := matches[12]
		if xForwardedFor == "-" {
			xForwardedFor = ""
		}

		// Extract block_reason, bot_category, and exploit_rule from log line (set by nginx)
		var blockReason model.BlockReason
		var botCategory string
		var exploitRule string

		if brMatches := blockReasonRegex.FindStringSubmatch(line); brMatches != nil {
			reason := model.ParseBlockReason(brMatches[1])
			// Only set access_denied if the request was actually denied (403)
			// This prevents false positives when Access List is configured but request is allowed
			if reason == model.BlockReasonAccessDenied && statusCode != 403 {
				blockReason = model.BlockReasonNone
			} else {
				blockReason = reason
			}
		}
		if bcMatches := botCategoryRegex.FindStringSubmatch(line); bcMatches != nil && bcMatches[1] != "-" {
			botCategory = bcMatches[1]
		}
		if erMatches := exploitRuleRegex.FindStringSubmatch(line); erMatches != nil && erMatches[1] != "-" {
			exploitRule = erMatches[1]
		}

		// Extract geo country code from log line
		var geoCountryCode string
		if geoMatches := geoCountryRegex.FindStringSubmatch(line); geoMatches != nil && geoMatches[1] != "-" && geoMatches[1] != "" {
			geoCountryCode = geoMatches[1]
		}

		// Extract request_time from log line (rt=0.001)
		var requestTime float64
		if rtMatches := requestTimeRegex.FindStringSubmatch(line); rtMatches != nil {
			rawValue := rtMatches[1]
			if parsed, err := strconv.ParseFloat(rawValue, 64); err == nil {
				requestTime = validateRequestTime(parsed, rawValue)
			}
		}

		// Extract upstream_response_time from log line (urt="0.001", urt="-", urt="0.001, 0.002")
		var upstreamResponseTime float64
		if urtMatches := upstreamResponseTimeRegex.FindStringSubmatch(line); urtMatches != nil {
			urtValue := urtMatches[1]
			if urtValue != "-" && urtValue != "" {
				parts := strings.Split(urtValue, ",")
				rawValue := strings.TrimSpace(parts[len(parts)-1])
				if rawValue != "-" {
					if parsed, err := strconv.ParseFloat(rawValue, 64); err == nil {
						upstreamResponseTime = validateRequestTime(parsed, rawValue)
					}
				}
			}
		}

		// Preserve raw $upstream_addr / $upstream_status strings (may be "-" when no upstream
		// was reached, or a comma-separated list on retries). Normalize "-" to empty so the
		// DB stores NULL and the UI can render "direct" cleanly.
		upstreamAddr := extractUpstreamField(line, upstreamAddrRegex)
		upstreamStatus := extractUpstreamField(line, upstreamStatusRegex)

		return &model.CreateLogRequest{
			LogType:              model.LogTypeAccess,
			Timestamp:            timestamp,
			Host:                 host,
			ClientIP:             matches[1],
			RequestMethod:        matches[5],
			RequestURI:           matches[6],
			RequestProtocol:      matches[7],
			StatusCode:           statusCode,
			BodyBytesSent:        bodyBytes,
			HTTPReferer:          referer,
			HTTPUserAgent:        matches[11],
			HTTPXForwardedFor:    xForwardedFor,
			BlockReason:          blockReason,
			BotCategory:          botCategory,
			ExploitRule:          exploitRule,
			GeoCountryCode:       geoCountryCode,
			RequestTime:          requestTime,
			UpstreamResponseTime: upstreamResponseTime,
			UpstreamAddr:         upstreamAddr,
			UpstreamStatus:       upstreamStatus,
			RawLog:               line,
		}, nil
	}

	// Fallback to old format without host
	matches = accessLogRegexOld.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse access log: %s", line)
	}

	// Old format: client - user [time] "method uri protocol" status bytes "referer" "ua" "xff"
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[3])
	if err != nil {
		timestamp = time.Now()
	}

	statusCode, _ := strconv.Atoi(matches[7])
	bodyBytes, _ := strconv.ParseInt(matches[8], 10, 64)

	referer := matches[9]
	if referer == "-" {
		referer = ""
	}

	xForwardedFor := matches[11]
	if xForwardedFor == "-" {
		xForwardedFor = ""
	}

	return &model.CreateLogRequest{
		LogType:           model.LogTypeAccess,
		Timestamp:         timestamp,
		Host:              "",
		ClientIP:          matches[1],
		RequestMethod:     matches[4],
		RequestURI:        matches[5],
		RequestProtocol:   matches[6],
		StatusCode:        statusCode,
		BodyBytesSent:     bodyBytes,
		HTTPReferer:       referer,
		HTTPUserAgent:     matches[10],
		HTTPXForwardedFor: xForwardedFor,
		RawLog:            line,
	}, nil
}

// Error log format:
// 2025/12/01 14:37:15 [error] 1#1: *123 error message, client: 1.2.3.4, ...
var errorLogRegex = regexp.MustCompile(
	`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\d+#\d+:\s+(.+)`,
)

func (c *LogCollector) parseErrorLog(line string) (*model.CreateLogRequest, error) {
	matches := errorLogRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse error log: %s", line)
	}

	// Parse timestamp (nginx error log doesn't include timezone, use local)
	timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", matches[1], time.Local)
	if err != nil {
		timestamp = time.Now()
	}

	severity := model.LogSeverity(matches[2])

	// Try to extract client IP from message (supports IPv4, IPv6, IPv4-mapped IPv6)
	clientIP := ""
	if ipMatches := errorLogClientIPRegex.FindStringSubmatch(matches[3]); ipMatches != nil {
		clientIP = ipMatches[1]
	}

	return &model.CreateLogRequest{
		LogType:      model.LogTypeError,
		Timestamp:    timestamp,
		ClientIP:     clientIP,
		Severity:     severity,
		ErrorMessage: matches[3],
		RawLog:       line,
	}, nil
}

// ModSecAuditLog represents ModSecurity audit log in JSON format
type ModSecAuditLog struct {
	Transaction struct {
		TimeStamp     string  `json:"time_stamp"`
		ClientIP      string  `json:"client_ip"`
		ClientPort    int     `json:"client_port"`
		HostIP        string  `json:"host_ip"`
		HostPort      int     `json:"host_port"`
		UniqueID      string  `json:"unique_id"`
		Request       struct {
			Method      string            `json:"method"`
			URI         string            `json:"uri"`
			HTTPVersion float64           `json:"http_version"`
			Headers     map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int               `json:"http_code"`
			Headers  map[string]string `json:"headers"`
		} `json:"response"`
		Producer struct {
			ModSecurity string   `json:"modsecurity"`
			Connector   string   `json:"connector"`
			SeqRules    string   `json:"secrules_engine"`
		} `json:"producer"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				Match      string   `json:"match"`
				Reference  string   `json:"reference"`
				RuleID     string   `json:"ruleId"`
				File       string   `json:"file"`
				LineNumber string   `json:"lineNumber"`
				Data       string   `json:"data"`
				Severity   string   `json:"severity"`
				Ver        string   `json:"ver"`
				Rev        string   `json:"rev"`
				Tags       []string `json:"tags"`
				Maturity   string   `json:"maturity"`
				Accuracy   string   `json:"accuracy"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

func (c *LogCollector) parseModSecLog(line string) (*model.CreateLogRequest, error) {
	var auditLog ModSecAuditLog
	if err := json.Unmarshal([]byte(line), &auditLog); err != nil {
		return nil, fmt.Errorf("failed to parse modsec log: %w", err)
	}

	tx := auditLog.Transaction

	// Parse timestamp (format: "Tue Dec  2 00:42:29 2025")
	// ModSecurity timestamp doesn't include timezone, so use local timezone
	timestamp, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", tx.TimeStamp, time.Local)
	if err != nil {
		// Try alternate format with double space for single digit day
		timestamp, err = time.ParseInLocation("Mon Jan  2 15:04:05 2006", tx.TimeStamp, time.Local)
		if err != nil {
			timestamp = time.Now()
		}
	}

	// Get first meaningful rule info (skip the final anomaly evaluation rule)
	var ruleID int64
	var ruleMessage, ruleSeverity, ruleData, attackType string
	for _, msg := range tx.Messages {
		// Skip the anomaly evaluation message, we want the actual attack rule
		if strings.Contains(msg.Message, "Anomaly Score Exceeded") {
			continue
		}
		ruleMessage = msg.Message
		ruleSeverity = msg.Details.Severity
		ruleData = msg.Details.Data
		if id, err := strconv.ParseInt(msg.Details.RuleID, 10, 64); err == nil {
			ruleID = id
		}
		// Extract attack type from tags
		for _, tag := range msg.Details.Tags {
			if strings.HasPrefix(tag, "attack-") {
				attackType = strings.TrimPrefix(tag, "attack-")
				break
			}
		}
		if attackType == "" && len(msg.Details.Tags) > 0 {
			attackType = msg.Details.Tags[0]
		}
		break // Use first meaningful message
	}

	// If we only have anomaly message, use it
	if ruleID == 0 && len(tx.Messages) > 0 {
		msg := tx.Messages[0]
		ruleMessage = msg.Message
		if id, err := strconv.ParseInt(msg.Details.RuleID, 10, 64); err == nil {
			ruleID = id
		}
	}

	// Skip logging if no WAF rules were triggered (messages is empty)
	// This prevents logging bot filter blocks, rate limits, etc. as WAF events
	if len(tx.Messages) == 0 {
		return nil, fmt.Errorf("no WAF rules triggered, skipping (likely bot filter or other block)")
	}

	// Determine action taken based on SecRuleEngine mode and response code
	// In DetectionOnly mode, WAF never blocks - any error codes are from other sources (rate limit, etc.)
	actionTaken := "logged"
	isDetectionOnly := strings.EqualFold(tx.Producer.SeqRules, "DetectionOnly")
	if !isDetectionOnly && tx.Response.HTTPCode == 403 {
		// Only mark as blocked if:
		// 1. WAF is in blocking mode (SecRuleEngine On)
		// 2. Response is 403 (WAF's default blocking response)
		// Note: Other error codes (404, 405, 429, 500) are from upstream or other nginx modules, not WAF
		actionTaken = "blocked"
	}
	// Check if this is an excluded rule (pass action)
	if strings.Contains(ruleMessage, "[EXCLUDED]") {
		actionTaken = "excluded"
		// Clean up the message by removing [EXCLUDED] prefix
		ruleMessage = strings.TrimSpace(strings.Replace(ruleMessage, "[EXCLUDED]", "", 1))
	}

	// Get host from request headers (case-insensitive lookup)
	// HTTP/1.1 and HTTP/2 use "Host" header, HTTP/3 uses ":authority" pseudo-header
	var host string
	for k, v := range tx.Request.Headers {
		lowerKey := strings.ToLower(k)
		if lowerKey == "host" || k == ":authority" {
			host = v
			// Strip port suffix: "example.com:443" → "example.com"
			if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
				host = h
			}
			break
		}
	}

	// Fallback 1: extract host from response "Link" header (WordPress/API response headers)
	// This is more reliable than Referer since it's from the actual server response
	if host == "" {
		for k, v := range tx.Response.Headers {
			if strings.ToLower(k) == "link" && v != "" {
				// Link header format: <https://example.com/wp-json/>; rel="..."
				if strings.Contains(v, "://") {
					start := strings.Index(v, "://") + 3
					end := strings.Index(v[start:], "/")
					if end > 0 {
						host = v[start : start+end]
						break
					}
				}
			}
		}
	}

	// Fallback 2: extract host from response "X-Pingback" or other headers with full URL
	if host == "" {
		for k, v := range tx.Response.Headers {
			lowerKey := strings.ToLower(k)
			if (lowerKey == "x-pingback" || lowerKey == "location") && strings.Contains(v, "://") {
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					host = u.Host
					break
				}
			}
		}
	}

	// Fallback 3: extract host from referer header (NOT recommended - can be incorrect)
	// Only use this as last resort since referer domain often differs from request host
	if host == "" {
		for k, v := range tx.Request.Headers {
			if strings.ToLower(k) == "referer" && v != "" {
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					host = u.Host
				}
				break
			}
		}
	}

	// Determine block reason for WAF events
	var blockReason model.BlockReason
	if actionTaken == "blocked" {
		blockReason = model.BlockReasonWAF
	}

	return &model.CreateLogRequest{
		LogType:         model.LogTypeModSec,
		Timestamp:       timestamp,
		Host:            host,
		ClientIP:        tx.ClientIP,
		RequestMethod:   tx.Request.Method,
		RequestURI:      tx.Request.URI,
		RequestProtocol: fmt.Sprintf("HTTP/%.1f", tx.Request.HTTPVersion),
		StatusCode:      tx.Response.HTTPCode,
		RuleID:          ruleID,
		RuleMessage:     ruleMessage,
		RuleSeverity:    ruleSeverity,
		RuleData:        ruleData,
		AttackType:      attackType,
		ActionTaken:     actionTaken,
		BlockReason:     blockReason,
		RawLog:          line,
	}, nil
}

// extractUpstreamField reads a "key=value" pair like ua="..." from a log line.
// Returns "" when the field is missing, quoted as "-", or empty — nginx uses "-"
// for requests that never reached an upstream (e.g. local 403 / cached responses).
func extractUpstreamField(line string, re *regexp.Regexp) string {
	matches := re.FindStringSubmatch(line)
	if matches == nil {
		return ""
	}
	value := strings.TrimSpace(matches[1])
	if value == "" || value == "-" {
		return ""
	}
	return value
}
