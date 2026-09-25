package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/service"
)

// Every rule that contributed to one WAF event.
//
// CRS blocks by anomaly score: a request is refused when the SUM of the rules
// that matched crosses the threshold, and a single SQLi probe typically trips
// three or four of them. The log row keeps only one — the first — so the event
// screen showed one rule, the operator disabled it, and the next request was
// blocked again under a different number. Measured: 942190, then 942270, then
// 942360, and only the third exclusion let the request through. From the
// outside that reads as "the exclusion did not work" (#306).
//
// The full audit record is already stored with the row, so this reads it back
// and lists every contributing rule, with the exclusions each one already has
// on the host — which is also what the "already disabled" 409 was about.

type wafEventRule struct {
	RuleID   int    `json:"rule_id"`
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
	Data     string `json:"data,omitempty"`
	Category string `json:"category,omitempty"`
	// Existing exclusions for this rule on the event's host, so the screen can
	// say "already disabled for /api" instead of answering a click with a 409.
	Excluded []wafEventRuleScope `json:"excluded"`
}

type wafEventRuleScope struct {
	ScopeType  string `json:"scope_type"`
	ScopeValue string `json:"scope_value,omitempty"`
}

type wafEventRulesResponse struct {
	ProxyHostID string         `json:"proxy_host_id,omitempty"`
	Rules       []wafEventRule `json:"rules"`
}

// isScoreBookkeeping reports the CRS rules that do not describe an attack: the
// blocking evaluation (949110 "Inbound Anomaly Score Exceeded") and the 980xxx
// correlation/reporting rules. Disabling them would not unblock anything the
// operator can reason about, so they are not offered.
func isScoreBookkeeping(ruleID int, message string) bool {
	return ruleID == 949110 || ruleID == 959100 || (ruleID >= 980000 && ruleID < 981000) ||
		strings.Contains(message, "Anomaly Score Exceeded")
}

// GetEventRules handles GET /api/v1/waf/events/:logId/rules?at=<RFC3339>.
//
// `at` is the row's created_at and is required: it pins the lookup to one
// chunk of a compressed hypertable instead of scanning all of them.
func (h *WAFHandler) GetEventRules(c echo.Context) error {
	logID := c.Param("logId")
	if _, err := uuid.Parse(logID); err != nil {
		return badRequestError(c, "logId: "+ErrMsgInvalidIdentifier)
	}
	at, err := time.Parse(time.RFC3339Nano, c.QueryParam("at"))
	if err != nil {
		return badRequestError(c, "at: expected the event's created_at as RFC 3339")
	}
	if h.logRepo == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "log repository not available"})
	}

	ctx := c.Request().Context()
	ev, err := h.logRepo.GetModSecEventRaw(ctx, logID, at)
	if err != nil {
		return databaseError(c, "load WAF event", err)
	}
	if ev == nil || ev.RawLog == "" {
		return notFoundError(c, "WAF event")
	}

	var audit service.ModSecAuditLog
	if err := json.Unmarshal([]byte(ev.RawLog), &audit); err != nil {
		return internalError(c, "parse WAF event", err)
	}

	// Resolve the host the same way the per-host disable does, so the
	// exclusions shown are the ones that disable would collide with.
	hostID := ev.ProxyHostID
	if hostID == "" && ev.Host != "" && h.proxyHostRepo != nil {
		lookup := ev.Host
		if hh, _, splitErr := net.SplitHostPort(lookup); splitErr == nil {
			lookup = hh
		}
		if host, lookupErr := h.proxyHostRepo.GetByDomain(ctx, lookup); lookupErr == nil && host != nil {
			hostID = host.ID
		}
	}

	existing := map[int][]wafEventRuleScope{}
	if hostID != "" {
		exclusions, exErr := h.wafRepo.GetExclusionsByProxyHost(ctx, hostID)
		if exErr != nil {
			return databaseError(c, "load WAF exclusions", exErr)
		}
		for _, e := range exclusions {
			scope := e.ScopeType
			if scope == "" {
				scope = "host"
			}
			existing[e.RuleID] = append(existing[e.RuleID], wafEventRuleScope{ScopeType: scope, ScopeValue: e.ScopeValue})
		}
	}

	resp := wafEventRulesResponse{ProxyHostID: hostID, Rules: []wafEventRule{}}
	seen := map[int]bool{}
	for _, msg := range audit.Transaction.Messages {
		id, convErr := strconv.Atoi(msg.Details.RuleID)
		if convErr != nil || seen[id] || isScoreBookkeeping(id, msg.Message) {
			continue
		}
		seen[id] = true

		category := ""
		for _, tag := range msg.Details.Tags {
			if strings.HasPrefix(tag, "attack-") {
				category = strings.TrimPrefix(tag, "attack-")
				break
			}
		}
		scopes := existing[id]
		if scopes == nil {
			scopes = []wafEventRuleScope{}
		}
		resp.Rules = append(resp.Rules, wafEventRule{
			RuleID:   id,
			Message:  msg.Message,
			Severity: msg.Details.Severity,
			Data:     msg.Details.Data,
			Category: category,
			Excluded: scopes,
		})
	}

	return c.JSON(http.StatusOK, resp)
}
