import type {
  WAFRulesResponse,
  WAFHostConfig,
  WAFHostConfigListResponse,
  WAFRuleExclusion,
  WAFExclusionScope,
  CreateWAFRuleExclusionRequest,
  WAFPolicyHistoryResponse,
} from '../types/waf';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

// Get all OWASP CRS rules (optionally filtered by proxy_host_id)
export async function fetchWAFRules(proxyHostId?: string): Promise<WAFRulesResponse> {
  const params = new URLSearchParams();
  if (proxyHostId) {
    params.set('proxy_host_id', proxyHostId);
  }

  const url = params.toString()
    ? `${API_BASE}/waf/rules?${params}`
    : `${API_BASE}/waf/rules`;

  const res = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch WAF rules');
  return res.json();
}

// Get WAF config for all proxy hosts
export async function fetchWAFHostConfigs(): Promise<WAFHostConfigListResponse> {
  const res = await fetch(`${API_BASE}/waf/hosts`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch WAF host configs');
  return res.json();
}

// Get WAF config for a specific proxy host
export async function fetchWAFHostConfig(hostId: string): Promise<WAFHostConfig> {
  const res = await fetch(`${API_BASE}/waf/hosts/${hostId}/config`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch WAF host config');
  return res.json();
}

// Disable a rule for a proxy host
export async function disableWAFRule(
  hostId: string,
  ruleId: number,
  request?: CreateWAFRuleExclusionRequest
): Promise<WAFRuleExclusion> {
  const res = await fetch(`${API_BASE}/waf/hosts/${hostId}/rules/${ruleId}/disable`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request || { rule_id: ruleId }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || 'Failed to disable WAF rule');
  }
  return res.json();
}

// Enable a rule for a proxy host (remove exclusion).
// Naming a scope removes just that exemption; omitting it re-enables the rule
// outright, dropping every scope it carries. (#286)
export async function enableWAFRule(
  hostId: string,
  ruleId: number,
  scope?: { scope_type: WAFExclusionScope; scope_value?: string }
): Promise<void> {
  const query = scope
    ? `?${new URLSearchParams({ scope_type: scope.scope_type, scope_value: scope.scope_value || '' })}`
    : '';
  const res = await fetch(`${API_BASE}/waf/hosts/${hostId}/rules/${ruleId}/disable${query}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || 'Failed to enable WAF rule');
  }
}

// Disable a rule by host domain name (used from log viewer)
export interface DisableRuleByHostRequest {
  host: string;
  rule_id: number;
  rule_category?: string;
  rule_description?: string;
  reason?: string;
  /** How narrowly to switch the rule off. Omitted means the whole host, which
   *  is what every client got before scoped exclusions existed. (#231) */
  scope_type?: 'host' | 'uri' | 'param';
  /** The path prefix (uri) or argument name (param) the scope applies to. */
  scope_value?: string;
}

/** Thrown for a 409 from disable-by-host: this rule already has this exclusion. */
export class RuleAlreadyDisabledError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuleAlreadyDisabledError';
  }
}

export async function disableWAFRuleByHost(request: DisableRuleByHostRequest): Promise<WAFRuleExclusion> {
  const res = await fetch(`${API_BASE}/waf/rules/disable-by-host`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    const errorText = await res.text();
    // A 409 means the goal is already met. Distinguishing it lets a caller
    // that disables several rules at once skip the ones already done instead
    // of failing the whole batch on the first (#306).
    if (res.status === 409) {
      throw new RuleAlreadyDisabledError(errorText || 'Rule already disabled');
    }
    throw new Error(errorText || 'Failed to disable WAF rule');
  }
  return res.json();
}

export interface WAFEventRuleScope {
  scope_type: 'host' | 'uri' | 'param';
  scope_value?: string;
}

export interface WAFEventRule {
  rule_id: number;
  message: string;
  severity?: string;
  data?: string;
  category?: string;
  /** Exclusions this rule already has on the event's host. */
  excluded: WAFEventRuleScope[];
}

/**
 * Every CRS rule that contributed to one WAF event. The log row keeps only the
 * first; CRS blocks on the SUM of several, so disabling the one shown usually
 * leaves the request blocked under another number (#306). `createdAt` is the
 * row's created_at — the server needs it to find the row cheaply.
 */
export async function fetchWAFEventRules(logId: string, createdAt: string): Promise<{ proxy_host_id?: string; rules: WAFEventRule[] }> {
  const res = await fetch(`${API_BASE}/waf/events/${encodeURIComponent(logId)}/rules?at=${encodeURIComponent(createdAt)}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to load the rules behind this event');
  return res.json();
}

// Get policy change history for a proxy host
export async function fetchWAFPolicyHistory(hostId: string, limit?: number): Promise<WAFPolicyHistoryResponse> {
  const params = new URLSearchParams();
  if (limit) {
    params.set('limit', limit.toString());
  }

  const url = params.toString()
    ? `${API_BASE}/waf/hosts/${hostId}/history?${params}`
    : `${API_BASE}/waf/hosts/${hostId}/history`;

  const res = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch WAF policy history');
  return res.json();
}

// ============================================================================
// Global WAF Rule Management
// ============================================================================

import type {
  GlobalWAFRulesResponse,
  GlobalWAFRuleExclusion,
  GlobalWAFPolicyHistoryResponse,
  CreateGlobalWAFRuleExclusionRequest,
} from '../types/waf';

// Get all WAF rules with global exclusion status
export async function fetchGlobalWAFRules(): Promise<GlobalWAFRulesResponse> {
  const res = await fetch(`${API_BASE}/waf/global/rules`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch global WAF rules');
  return res.json();
}

// Get all global WAF exclusions
export async function fetchGlobalWAFExclusions(): Promise<{ exclusions: GlobalWAFRuleExclusion[]; total: number }> {
  const res = await fetch(`${API_BASE}/waf/global/exclusions`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch global WAF exclusions');
  return res.json();
}

// Disable a rule globally (applies to all hosts)
export async function disableGlobalWAFRule(
  ruleId: number,
  request?: CreateGlobalWAFRuleExclusionRequest
): Promise<GlobalWAFRuleExclusion> {
  const res = await fetch(`${API_BASE}/waf/global/rules/${ruleId}/disable`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request || { rule_id: ruleId }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || 'Failed to disable global WAF rule');
  }
  return res.json();
}

// Enable a rule globally (remove global exclusion)
export async function enableGlobalWAFRule(ruleId: number): Promise<void> {
  const res = await fetch(`${API_BASE}/waf/global/rules/${ruleId}/disable`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || 'Failed to enable global WAF rule');
  }
}

// Get global policy change history
export async function fetchGlobalWAFPolicyHistory(limit?: number): Promise<GlobalWAFPolicyHistoryResponse> {
  const params = new URLSearchParams();
  if (limit) {
    params.set('limit', limit.toString());
  }

  const url = params.toString()
    ? `${API_BASE}/waf/global/history?${params}`
    : `${API_BASE}/waf/global/history`;

  const res = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch global WAF policy history');
  return res.json();
}
