export interface WAFRule {
  id: number;
  category: string;
  description?: string;
  severity?: string;
  tags?: string[];
  /** False only when the rule is off for the whole host. A uri/param scope
   *  narrows the rule without disabling it, so it stays true. (#286) */
  enabled: boolean;
  globally_disabled?: boolean;
  /** The host-wide exclusion, present only when the rule is fully disabled. */
  exclusion?: WAFRuleExclusion;
  global_exclusion?: GlobalWAFRuleExclusion;
  /** Every host exclusion on this rule, narrow ones included. (#286) */
  exclusions?: WAFRuleExclusion[];
}

export interface WAFRuleCategory {
  id: string;
  name: string;
  description: string;
  file_name: string;
  rule_count: number;
  rules?: WAFRule[];
}

export interface WAFRulesResponse {
  categories: WAFRuleCategory[];
  total_rules: number;
}

export interface WAFRuleExclusion {
  id: string;
  proxy_host_id: string;
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  reason?: string;
  disabled_by?: string;
  /** How narrowly the rule is switched off: the whole host, one path prefix,
   *  or one request argument. (#231) */
  scope_type: WAFExclusionScope;
  /** The path prefix (uri) or argument name (param); empty for host. */
  scope_value?: string;
  created_at: string;
}

export type WAFExclusionScope = 'host' | 'uri' | 'param';

export interface WAFHostConfig {
  proxy_host_id: string;
  proxy_host_name: string;
  waf_enabled: boolean;
  waf_mode: string;
  exclusions?: WAFRuleExclusion[];
  exclusion_count: number;
}

export interface WAFHostConfigListResponse {
  hosts: WAFHostConfig[];
  total: number;
}

export interface CreateWAFRuleExclusionRequest {
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  reason?: string;
  scope_type?: WAFExclusionScope;
  scope_value?: string;
}

export interface WAFPolicyHistory {
  id: string;
  proxy_host_id: string;
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  action: 'disabled' | 'enabled';
  reason?: string;
  changed_by?: string;
  created_at: string;
}

export interface WAFPolicyHistoryResponse {
  history: WAFPolicyHistory[];
  total: number;
}

// Global WAF Rule Exclusions
export interface GlobalWAFRuleExclusion {
  id: string;
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  reason?: string;
  disabled_by?: string;
  created_at: string;
  updated_at: string;
}

export interface GlobalWAFRule extends Omit<WAFRule, 'exclusion'> {
  globally_disabled: boolean;
  global_exclusion?: GlobalWAFRuleExclusion;
}

export interface GlobalWAFRuleCategory {
  id: string;
  name: string;
  description: string;
  file_name: string;
  rule_count: number;
  rules?: GlobalWAFRule[];
}

export interface GlobalWAFRulesResponse {
  categories: GlobalWAFRuleCategory[];
  total_rules: number;
  global_exclusions: GlobalWAFRuleExclusion[];
}

export interface CreateGlobalWAFRuleExclusionRequest {
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  reason?: string;
}

export interface GlobalWAFPolicyHistory {
  id: string;
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  action: 'disabled' | 'enabled';
  reason?: string;
  changed_by?: string;
  created_at: string;
}

export interface GlobalWAFPolicyHistoryResponse {
  history: GlobalWAFPolicyHistory[];
  total: number;
}
