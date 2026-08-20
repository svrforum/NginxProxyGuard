import type {
  RateLimit,
  CreateRateLimitRequest,
  Fail2banConfig,
  CreateFail2banRequest,
  BannedIP,
  BannedIPListResponse,
  BanIPRequest,
  BotFilter,
  CreateBotFilterRequest,
  KnownBots,
  SecurityHeaders,
  CreateSecurityHeadersRequest,
  Upstream,
  CreateUpstreamRequest,
  UpstreamHealthStatus,
  IPBanHistoryListResponse,
  IPBanHistoryFilter,
  IPBanHistoryStats,
  URIBlock,
  URIMatchType,
  CreateURIBlockRequest,
  AddURIBlockRuleRequest,
} from '../types/security';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

// Rate Limit API
export async function getRateLimit(proxyHostId: string): Promise<RateLimit> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/rate-limit`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch rate limit config');
  return res.json();
}

export async function updateRateLimit(proxyHostId: string, data: CreateRateLimitRequest): Promise<RateLimit> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/rate-limit`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    // A 400 here names the exception-list entry the server rejected (#263) —
    // dropping the body left the operator staring at a generic failure with a
    // value only the error message had ever mentioned.
    const body = await res.json().catch(() => ({}) as { error?: string });
    throw new Error(body.error || 'Failed to update rate limit config');
  }
  return res.json();
}

export async function deleteRateLimit(proxyHostId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/rate-limit`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete rate limit config');
}

// Fail2ban API
export async function getFail2ban(proxyHostId: string): Promise<Fail2banConfig> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/fail2ban`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch fail2ban config');
  return res.json();
}

export async function updateFail2ban(proxyHostId: string, data: CreateFail2banRequest): Promise<Fail2banConfig> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/fail2ban`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update fail2ban config');
  return res.json();
}

export async function deleteFail2ban(proxyHostId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/fail2ban`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete fail2ban config');
}

// Banned IPs API
export async function listBannedIPs(
  proxyHostId?: string,
  page = 1,
  perPage = 20
): Promise<BannedIPListResponse> {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });
  if (proxyHostId) params.set('proxy_host_id', proxyHostId);

  const res = await fetch(`${API_BASE}/banned-ips?${params}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch banned IPs');
  return res.json();
}

export async function banIP(data: BanIPRequest): Promise<BannedIP> {
  const res = await fetch(`${API_BASE}/banned-ips`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to ban IP');
  return res.json();
}

export async function unbanIP(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/banned-ips/${id}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to unban IP');
}

export async function unbanIPByAddress(ip: string): Promise<void> {
  const res = await fetch(`${API_BASE}/banned-ips?ip=${encodeURIComponent(ip)}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to unban IP');
}

// Bot Filter API
export async function getBotFilter(proxyHostId: string): Promise<BotFilter> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/bot-filter`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch bot filter config');
  return res.json();
}

export async function updateBotFilter(proxyHostId: string, data: CreateBotFilterRequest, skipReload = false): Promise<BotFilter> {
  const url = skipReload
    ? `${API_BASE}/proxy-hosts/${proxyHostId}/bot-filter?skip_reload=true`
    : `${API_BASE}/proxy-hosts/${proxyHostId}/bot-filter`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update bot filter config');
  return res.json();
}

export async function deleteBotFilter(proxyHostId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/bot-filter`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete bot filter config');
}

export async function getKnownBots(): Promise<KnownBots> {
  const res = await fetch(`${API_BASE}/bots/known`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch known bots');
  return res.json();
}

// Security Headers API
export async function getSecurityHeaders(proxyHostId: string): Promise<SecurityHeaders> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/security-headers`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch security headers config');
  return res.json();
}

export async function updateSecurityHeaders(
  proxyHostId: string,
  data: CreateSecurityHeadersRequest
): Promise<SecurityHeaders> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/security-headers`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update security headers config');
  return res.json();
}

export async function deleteSecurityHeaders(proxyHostId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/security-headers`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete security headers config');
}

export async function getSecurityHeaderPresets(): Promise<Record<string, SecurityHeaders>> {
  const res = await fetch(`${API_BASE}/security-headers/presets`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch security header presets');
  return res.json();
}

export async function applySecurityHeaderPreset(proxyHostId: string, preset: string): Promise<SecurityHeaders> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/security-headers/preset/${preset}`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to apply security header preset');
  return res.json();
}

// Upstream API
export async function getUpstream(proxyHostId: string): Promise<Upstream> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/upstream`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch upstream config');
  return res.json();
}

export async function updateUpstream(proxyHostId: string, data: CreateUpstreamRequest): Promise<Upstream> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/upstream`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update upstream config');
  return res.json();
}

export async function deleteUpstream(proxyHostId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/upstream`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete upstream config');
}

export async function getUpstreamHealth(upstreamId: string): Promise<UpstreamHealthStatus> {
  const res = await fetch(`${API_BASE}/upstreams/${upstreamId}/health`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch upstream health');
  return res.json();
}

// IP Ban History API
export async function getIPBanHistory(filter: IPBanHistoryFilter = {}): Promise<IPBanHistoryListResponse> {
  const params = new URLSearchParams();
  if (filter.ip_address) params.set('ip_address', filter.ip_address);
  if (filter.event_type) params.set('event_type', filter.event_type);
  if (filter.source) params.set('source', filter.source);
  if (filter.proxy_host_id) params.set('proxy_host_id', filter.proxy_host_id);
  if (filter.start_date) params.set('start_date', filter.start_date);
  if (filter.end_date) params.set('end_date', filter.end_date);
  if (filter.page) params.set('page', String(filter.page));
  if (filter.per_page) params.set('per_page', String(filter.per_page));

  const res = await fetch(`${API_BASE}/banned-ips/history?${params}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch IP ban history');
  return res.json();
}

export async function getIPBanHistoryByIP(ip: string, page = 1, perPage = 20): Promise<IPBanHistoryListResponse> {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });

  const res = await fetch(`${API_BASE}/banned-ips/history/ip/${encodeURIComponent(ip)}?${params}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch IP ban history');
  return res.json();
}

export async function getIPBanHistoryStats(): Promise<IPBanHistoryStats> {
  const res = await fetch(`${API_BASE}/banned-ips/history/stats`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch IP ban history stats');
  return res.json();
}

// URI Block API
export async function getURIBlock(proxyHostId: string): Promise<URIBlock> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/uri-block`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch URI block config');
  return res.json();
}

export async function updateURIBlock(
  proxyHostId: string,
  data: CreateURIBlockRequest,
  skipReload = false
): Promise<URIBlock> {
  const url = skipReload
    ? `${API_BASE}/proxy-hosts/${proxyHostId}/uri-block?skip_reload=true`
    : `${API_BASE}/proxy-hosts/${proxyHostId}/uri-block`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update URI block config');
  return res.json();
}

export async function deleteURIBlock(proxyHostId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/uri-block`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete URI block config');
}

export async function addURIBlockRule(
  proxyHostId: string,
  rule: AddURIBlockRuleRequest
): Promise<URIBlock> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/uri-block/rules`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(rule),
  });
  if (!res.ok) throw new Error('Failed to add URI block rule');
  return res.json();
}

export async function removeURIBlockRule(proxyHostId: string, ruleId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/uri-block/rules/${ruleId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to remove URI block rule');
}

// URI Block with host info for listing
export interface URIBlockWithHost extends URIBlock {
  domain_names: string[];
  host_enabled: boolean;
}

export async function listAllURIBlocks(): Promise<URIBlockWithHost[]> {
  const res = await fetch(`${API_BASE}/uri-blocks`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to list URI blocks');
  return res.json();
}

export interface BulkAddURIBlockRuleRequest {
  pattern: string;
  match_type: URIMatchType;
  description?: string;
  host_ids?: string[]; // If empty, applies to all enabled hosts
}

export interface BulkAddURIBlockRuleResponse {
  added_count: number;
  total_hosts: number;
  pattern: string;
  match_type: string;
  errors?: string[];
}

export async function bulkAddURIBlockRule(
  request: BulkAddURIBlockRuleRequest
): Promise<BulkAddURIBlockRuleResponse> {
  const res = await fetch(`${API_BASE}/uri-blocks/bulk-add-rule`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  });
  if (!res.ok) throw new Error('Failed to bulk add URI block rule');
  return res.json();
}

// Global URI Block API
export interface GlobalURIBlock {
  id?: string;
  enabled: boolean;
  rules: Array<{
    id: string;
    pattern: string;
    match_type: URIMatchType;
    description?: string;
    enabled: boolean;
  }>;
  exception_ips: string[];
  allow_private_ips: boolean;
  created_at?: string;
  updated_at?: string;
}

export async function getGlobalURIBlock(): Promise<GlobalURIBlock> {
  const res = await fetch(`${API_BASE}/global-uri-block`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch global URI block config');
  return res.json();
}

export async function updateGlobalURIBlock(data: Partial<GlobalURIBlock>): Promise<GlobalURIBlock> {
  const res = await fetch(`${API_BASE}/global-uri-block`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update global URI block config');
  return res.json();
}

export async function addGlobalURIBlockRule(rule: AddURIBlockRuleRequest): Promise<GlobalURIBlock> {
  const res = await fetch(`${API_BASE}/global-uri-block/rules`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(rule),
  });
  if (!res.ok) throw new Error('Failed to add global URI block rule');
  return res.json();
}

export async function removeGlobalURIBlockRule(ruleId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/global-uri-block/rules/${ruleId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to remove global URI block rule');
}
