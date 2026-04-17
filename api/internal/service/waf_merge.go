package service

import "nginx-proxy-guard/internal/model"

// mergeWAFExclusions merges host-specific WAF rule exclusions with global
// exclusions. Host-specific exclusions take precedence — any global exclusion
// whose RuleID already appears in host exclusions is dropped.
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
		hostExclusionMap[ex.RuleID] = true
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
				CreatedAt:       gex.CreatedAt,
			})
		}
	}

	return merged
}
