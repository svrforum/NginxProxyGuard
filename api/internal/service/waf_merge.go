package service

import "nginx-proxy-guard/internal/model"

// mergeWAFExclusions merges host-specific WAF rule exclusions with global
// exclusions. A host-WIDE exclusion takes precedence — the global entry for that
// rule is dropped as redundant. A narrow (uri/param) host exclusion does not:
// the host still wants the global "off everywhere" directive, and suppressing it
// on the strength of a one-path exemption left the rule enforcing where the
// operator had globally switched it off. (#286)
//
// Output shape per entry:
//   - host-specific entries: copied verbatim
//   - global-only entries:  rewritten as WAFRuleExclusion with
//     ProxyHostID="global" and Reason suffixed with " (global)".
//
// Ordering: host exclusions first (in their incoming order), then the
// non-duplicate global exclusions (in their incoming order). The resulting
// slice is a newly allocated slice; callers may mutate it without aliasing
// the input slices.
//
// This is the pure-function extraction of ProxyHostService.getMergedWAFExclusions;
// it exists to be unit-testable without a database. The service method calls
// this function after loading both slices from the repository.
func mergeWAFExclusions(hostExclusions []model.WAFRuleExclusion, globalExclusions []model.GlobalWAFRuleExclusion) []model.WAFRuleExclusion {
	hostExclusionMap := make(map[int]bool, len(hostExclusions))
	for _, ex := range hostExclusions {
		if ex.ScopeType == "" || ex.ScopeType == model.WAFScopeHost {
			hostExclusionMap[ex.RuleID] = true
		}
	}

	merged := make([]model.WAFRuleExclusion, len(hostExclusions))
	copy(merged, hostExclusions)

	for _, gex := range globalExclusions {
		if !hostExclusionMap[gex.RuleID] {
			merged = append(merged, model.WAFRuleExclusion{
				ID:              gex.ID,
				ProxyHostID:     "global",
				RuleID:          gex.RuleID,
				RuleCategory:    gex.RuleCategory,
				RuleDescription: gex.RuleDescription,
				Reason:          gex.Reason + " (global)",
				DisabledBy:      gex.DisabledBy,
				ScopeType:       model.WAFScopeHost,
				CreatedAt:       gex.CreatedAt,
			})
		}
	}

	return merged
}
