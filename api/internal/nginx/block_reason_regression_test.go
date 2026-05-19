package nginx

// Block-reason regression guard for the proxy_host template.
//
// Asserts that the rendered nginx config emits the expected
//   set $block_reason_var "<reason>";
//   return <status>;
// (and bot_category_var, where relevant) for each of the 17 security-layer
// activation paths in _security.conf.tmpl.
//
// This is the FAST unit-level companion to the planned E2E ingestion spec
// (M3.5–M3.7). It catches the regression pattern behind #130, #133, #134,
// and f0be478 — where a security layer fires but forgets to tag the access
// log — in milliseconds, before the slower E2E catches it.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestBlockReasonRegression(t *testing.T) {
	cases := []struct {
		name        string
		apply       func(ProxyHostConfigData) ProxyHostConfigData
		wantReason  string
		wantStatus  int      // 0 means skip status check (e.g. challenge/deny paths)
		wantNeedles []string // additional substrings (e.g. bot_category_var)
	}{
		{
			name: "geo_block_blacklist",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.GeoRestriction = &model.GeoRestriction{
					Enabled:   true,
					Mode:      "blacklist",
					Countries: []string{"CN", "RU"},
				}
				return d
			},
			wantReason: "geo_block",
			wantStatus: 403,
		},
		{
			name: "geo_block_whitelist",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.GeoRestriction = &model.GeoRestriction{
					Enabled:   true,
					Mode:      "whitelist",
					Countries: []string{"KR"},
				}
				return d
			},
			wantReason: "geo_block",
			wantStatus: 403,
		},
		{
			name: "geo_challenge_mode",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.GeoRestriction = &model.GeoRestriction{
					Enabled:       true,
					Mode:          "blacklist",
					Countries:     []string{"CN"},
					ChallengeMode: true,
				}
				return d
			},
			wantReason: "geo_block",
			// Challenge mode sets $geo_blocked + $block_reason_var but does NOT
			// emit `return 403` at the security partial; later challenge logic
			// handles the redirect. Status check skipped.
			wantStatus: 0,
		},
		{
			name: "access_list_deny",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				alID := "00000000-0000-0000-0000-0000000000a1"
				d.Host.AccessListID = &alID
				d.AccessList = &model.AccessList{
					ID:         alID,
					Name:       "deny-list",
					SatisfyAny: false,
					Items: []model.AccessListItem{
						{Directive: "deny", Address: "all", SortOrder: 1},
					},
				}
				return d
			},
			wantReason: "access_denied",
			// Access list uses `deny all;` directive, not `return <N>`. Status
			// check skipped intentionally.
			wantStatus: 0,
		},
		{
			name: "exploit_query_string",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.Host.BlockExploits = true
				d.ExploitBlockRules = []model.ExploitBlockRuleForRender{
					{
						ExploitBlockRule: model.ExploitBlockRule{
							ID:          "QS-001",
							Category:    "sql_injection",
							Name:        "SQLi UNION",
							Pattern:     "union.*select",
							PatternType: "query_string",
							Severity:    "critical",
							Enabled:     true,
						},
						IDSanitized: "QS_001",
					},
				}
				return d
			},
			wantReason: "exploit_block",
			wantStatus: 403,
		},
		{
			name: "exploit_request_uri",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.Host.BlockExploits = true
				d.ExploitBlockRules = []model.ExploitBlockRuleForRender{
					{
						ExploitBlockRule: model.ExploitBlockRule{
							ID:          "URI-001",
							Category:    "path_traversal",
							Name:        "Path Traversal",
							Pattern:     "/etc/passwd",
							PatternType: "request_uri",
							Severity:    "critical",
							Enabled:     true,
						},
						IDSanitized: "URI_001",
					},
				}
				return d
			},
			wantReason: "exploit_block",
			wantStatus: 403,
		},
		{
			name: "exploit_user_agent_scanner",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.Host.BlockExploits = true
				d.ExploitBlockRules = []model.ExploitBlockRuleForRender{
					{
						ExploitBlockRule: model.ExploitBlockRule{
							ID:          "UA-001",
							Category:    "scanner",
							Name:        "sqlmap UA",
							Pattern:     "sqlmap",
							PatternType: "user_agent",
							Severity:    "warning",
							Enabled:     true,
						},
						IDSanitized: "UA_001",
					},
				}
				return d
			},
			wantReason:  "exploit_block",
			wantStatus:  403,
			wantNeedles: []string{`set $bot_category_var "scanner"`},
		},
		{
			name: "exploit_request_method_trace",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.Host.BlockExploits = true
				d.ExploitBlockRules = []model.ExploitBlockRuleForRender{
					{
						ExploitBlockRule: model.ExploitBlockRule{
							ID:          "METHOD-001",
							Category:    "http_method",
							Name:        "TRACE method",
							Pattern:     "TRACE",
							PatternType: "request_method",
							Severity:    "warning",
							Enabled:     true,
						},
						IDSanitized: "METHOD_001",
					},
				}
				return d
			},
			wantReason: "exploit_block",
			wantStatus: 405,
		},
		{
			name: "banned_ip_manual",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				hostID := d.Host.ID
				d.BannedIPs = []model.BannedIP{
					{
						ID:          "ban1",
						ProxyHostID: &hostID,
						IPAddress:   "203.0.113.10",
						Reason:      "test",
					},
				}
				return d
			},
			wantReason: "banned_ip",
			wantStatus: 403,
		},
		{
			name: "filter_subscription_ip",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.UseFilterSubscription = true
				d.BannedIPs = []model.BannedIP{
					{
						ID:        "ban1",
						IPAddress: "1.2.3.4",
						Reason:    "filter sub",
					},
				}
				return d
			},
			wantReason: "filter_subscription",
			wantStatus: 403,
		},
		{
			name: "cloud_provider_block",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.BlockedCloudIPRanges = []string{"104.16.0.0/13"}
				return d
			},
			wantReason: "cloud_provider_block",
			wantStatus: 403,
		},
		{
			name: "cloud_provider_challenge",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.BlockedCloudIPRanges = []string{"104.16.0.0/13"}
				d.CloudProviderChallengeMode = true
				return d
			},
			wantReason: "cloud_provider_challenge",
			wantStatus: 418,
		},
		{
			name: "bot_filter_bad_bot",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.BotFilter = &model.BotFilter{
					Enabled:      true,
					BlockBadBots: true,
				}
				d.BadBotsList = "AhrefsBot\nSemrushBot"
				return d
			},
			wantReason:  "bot_filter",
			wantStatus:  403,
			wantNeedles: []string{`set $bot_category_var "bad_bot"`},
		},
		{
			name: "bot_filter_ai_bot",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.BotFilter = &model.BotFilter{
					Enabled:     true,
					BlockAIBots: true,
				}
				d.AIBotsList = "GPTBot\nClaude-Web"
				return d
			},
			wantReason:  "bot_filter",
			wantStatus:  403,
			wantNeedles: []string{`set $bot_category_var "ai_bot"`},
		},
		{
			name: "bot_filter_suspicious",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.BotFilter = &model.BotFilter{
					Enabled:                true,
					BlockSuspiciousClients: true,
				}
				d.SuspiciousClientsList = "curl\nwget"
				return d
			},
			wantReason:  "bot_filter",
			wantStatus:  403,
			wantNeedles: []string{`set $bot_category_var "suspicious"`},
		},
		{
			name: "bot_filter_custom",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.BotFilter = &model.BotFilter{
					Enabled:             true,
					CustomBlockedAgents: "MyEvilBot",
				}
				return d
			},
			wantReason:  "bot_filter",
			wantStatus:  403,
			wantNeedles: []string{`set $bot_category_var "custom"`},
		},
		{
			name: "uri_block_prefix",
			apply: func(d ProxyHostConfigData) ProxyHostConfigData {
				d.URIBlock = &model.URIBlock{
					Enabled: true,
					Rules: []model.URIBlockRule{
						{Pattern: "/admin", MatchType: model.URIMatchPrefix, Description: "block admin", Enabled: true},
					},
				}
				return d
			},
			wantReason: "uri_block",
			wantStatus: 403,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			host := baseHost("00000000-0000-0000-0000-0000000000b1", "127.0.0.1", true)
			host.DomainNames = []string{"example.com"}

			data := tc.apply(ProxyHostConfigData{
				Host:           host,
				GlobalSettings: baseGlobalSettings(),
			})

			var buf bytes.Buffer
			if err := renderProxyHostConfig(context.Background(), &buf, data); err != nil {
				t.Fatalf("renderProxyHostConfig: %v", err)
			}
			out := buf.String()

			wantReasonDirective := fmt.Sprintf(`set $block_reason_var "%s"`, tc.wantReason)
			if !strings.Contains(out, wantReasonDirective) {
				t.Errorf("missing block_reason directive %q in rendered config\n--- rendered ---\n%s", wantReasonDirective, out)
			}

			if tc.wantStatus != 0 {
				wantStatus := fmt.Sprintf("return %d", tc.wantStatus)
				if !strings.Contains(out, wantStatus) {
					t.Errorf("missing status directive %q in rendered config\n--- rendered ---\n%s", wantStatus, out)
				}
			}

			for _, needle := range tc.wantNeedles {
				if !strings.Contains(out, needle) {
					t.Errorf("missing additional directive %q in rendered config\n--- rendered ---\n%s", needle, out)
				}
			}
		})
	}
}
