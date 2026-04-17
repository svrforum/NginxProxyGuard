package service

// Characterization tests for the WAF-exclusion merge logic.
//
// These tests freeze the CURRENT behavior of mergeWAFExclusions (which was
// extracted out of ProxyHostService.getMergedWAFExclusions to enable unit
// testing). See waf_merge.go for the extraction note.
//
// Observations worth noting for the refactor phases:
//   - The current rule is "host wins on duplicate RuleID": when both lists
//     contain the same rule_id, the host entry is kept verbatim and the
//     global entry is dropped. This is what the production code has always
//     done. The test `merged_with_duplicate` pins exactly that.
//   - Global-only entries are rewritten into WAFRuleExclusion with
//     ProxyHostID="global" and " (global)" appended to the Reason field.

import (
	"sort"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

func TestMergeWAFExclusions_Characterization(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		host     []model.WAFRuleExclusion
		global   []model.GlobalWAFRuleExclusion
		wantIDs  []int // expected rule IDs, order-independent
		checkFor func(t *testing.T, got []model.WAFRuleExclusion)
	}{
		{
			name: "global_only",
			host: nil,
			global: []model.GlobalWAFRuleExclusion{
				{ID: "g1", RuleID: 942100, RuleCategory: "sql_injection", Reason: "legacy admin", DisabledBy: "admin", CreatedAt: now},
				{ID: "g2", RuleID: 941100, RuleCategory: "xss", Reason: "false positive", DisabledBy: "admin", CreatedAt: now},
			},
			wantIDs: []int{942100, 941100},
			checkFor: func(t *testing.T, got []model.WAFRuleExclusion) {
				for _, ex := range got {
					if ex.ProxyHostID != "global" {
						t.Errorf("expected global-only entry to have ProxyHostID=\"global\", got %q (rule %d)", ex.ProxyHostID, ex.RuleID)
					}
					// Reason is suffixed with " (global)".
					if len(ex.Reason) < len(" (global)") || ex.Reason[len(ex.Reason)-len(" (global)"):] != " (global)" {
						t.Errorf("expected Reason suffix \" (global)\" for rule %d, got %q", ex.RuleID, ex.Reason)
					}
				}
			},
		},
		{
			name: "host_only",
			host: []model.WAFRuleExclusion{
				{ID: "h1", ProxyHostID: "host-1", RuleID: 932100, RuleCategory: "rce", Reason: "known false positive", DisabledBy: "user", CreatedAt: now},
			},
			global:  nil,
			wantIDs: []int{932100},
			checkFor: func(t *testing.T, got []model.WAFRuleExclusion) {
				if len(got) != 1 {
					t.Fatalf("expected 1 result, got %d", len(got))
				}
				if got[0].ProxyHostID != "host-1" {
					t.Errorf("host entry should preserve ProxyHostID; got %q", got[0].ProxyHostID)
				}
				if got[0].Reason != "known false positive" {
					t.Errorf("host entry Reason should NOT be suffixed; got %q", got[0].Reason)
				}
			},
		},
		{
			name: "merged_with_duplicate",
			host: []model.WAFRuleExclusion{
				{ID: "h-dup", ProxyHostID: "host-1", RuleID: 942100, RuleCategory: "sql_injection", Reason: "host-specific reason", DisabledBy: "user", CreatedAt: now},
				{ID: "h2", ProxyHostID: "host-1", RuleID: 920100, RuleCategory: "protocol", Reason: "host-only", DisabledBy: "user", CreatedAt: now},
			},
			global: []model.GlobalWAFRuleExclusion{
				{ID: "g-dup", RuleID: 942100, RuleCategory: "sql_injection", Reason: "global-conflict", DisabledBy: "admin", CreatedAt: now},
				{ID: "g3", RuleID: 941100, RuleCategory: "xss", Reason: "global-only", DisabledBy: "admin", CreatedAt: now},
			},
			// Duplicate 942100 → host wins and appears once; 920100 from host;
			// 941100 from global-only.
			wantIDs: []int{942100, 920100, 941100},
			checkFor: func(t *testing.T, got []model.WAFRuleExclusion) {
				// Find entry for the duplicate rule_id and assert the host
				// version won (ProxyHostID is the host's, not "global";
				// Reason is the host one, not the global one).
				var dup *model.WAFRuleExclusion
				for i := range got {
					if got[i].RuleID == 942100 {
						dup = &got[i]
						break
					}
				}
				if dup == nil {
					t.Fatalf("expected merged result to contain rule_id 942100")
				}
				if dup.ProxyHostID != "host-1" {
					t.Errorf("duplicate rule: expected host to win (ProxyHostID=host-1), got %q", dup.ProxyHostID)
				}
				if dup.Reason != "host-specific reason" {
					t.Errorf("duplicate rule: expected host Reason, got %q", dup.Reason)
				}
				// Count occurrences of the duplicate rule ID - must be exactly one.
				count := 0
				for _, ex := range got {
					if ex.RuleID == 942100 {
						count++
					}
				}
				if count != 1 {
					t.Errorf("duplicate rule_id must appear exactly once in output, got %d", count)
				}
			},
		},
		{
			name:    "both_empty",
			host:    nil,
			global:  nil,
			wantIDs: nil,
			checkFor: func(t *testing.T, got []model.WAFRuleExclusion) {
				if len(got) != 0 {
					t.Errorf("expected empty result, got %d entries", len(got))
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := mergeWAFExclusions(tc.host, tc.global)

			// Order-independent rule-id set comparison.
			gotIDs := make([]int, 0, len(got))
			for _, ex := range got {
				gotIDs = append(gotIDs, ex.RuleID)
			}
			sort.Ints(gotIDs)
			wantIDs := make([]int, len(tc.wantIDs))
			copy(wantIDs, tc.wantIDs)
			sort.Ints(wantIDs)

			if !intSliceEqual(gotIDs, wantIDs) {
				t.Errorf("rule IDs mismatch\n got:  %v\n want: %v", gotIDs, wantIDs)
			}

			if tc.checkFor != nil {
				tc.checkFor(t, got)
			}
		})
	}
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
