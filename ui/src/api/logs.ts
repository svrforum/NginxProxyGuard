import type { LogListResponse, LogStats, LogSettings, LogFilter, CountryStat } from '../types/log';
import { getAuthHeaders, clearToken } from './auth';

const API_BASE = '/api/v1';

// Handle 401 responses by clearing token and redirecting
async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      window.location.reload();
    }
    throw new Error(`HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchLogs(
  page = 1,
  perPage = 50,
  filter?: LogFilter
): Promise<LogListResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    per_page: perPage.toString(),
  });

  if (filter) {
    if (filter.log_type) params.set('log_type', filter.log_type);
    // Array filters (multi-select support)
    if (filter.hosts && filter.hosts.length > 0) {
      filter.hosts.forEach(host => params.append('hosts', host));
    }
    if (filter.client_ips && filter.client_ips.length > 0) {
      filter.client_ips.forEach(ip => params.append('client_ips', ip));
    }
    if (filter.uris && filter.uris.length > 0) {
      filter.uris.forEach(uri => params.append('uris', uri));
    }
    if (filter.user_agents && filter.user_agents.length > 0) {
      filter.user_agents.forEach(ua => params.append('user_agents', ua));
    }
    // Legacy single-value filters (for backward compatibility)
    if (filter.host) params.set('host', filter.host);
    if (filter.client_ip) params.set('client_ip', filter.client_ip);
    if (filter.uri) params.set('uri', filter.uri);
    if (filter.user_agent) params.set('user_agent', filter.user_agent);

    if (filter.status_code) params.set('status_code', filter.status_code.toString());
    if (filter.severity) params.set('severity', filter.severity);
    if (filter.rule_id) params.set('rule_id', filter.rule_id.toString());
    if (filter.proxy_host_id) params.set('proxy_host_id', filter.proxy_host_id);
    if (filter.start_time) params.set('start_time', filter.start_time);
    if (filter.end_time) params.set('end_time', filter.end_time);
    if (filter.search) params.set('search', filter.search);

    // Extended filters
    if (filter.method) params.set('method', filter.method);
    if (filter.geo_country_code) params.set('geo_country_code', filter.geo_country_code);
    if (filter.status_codes && filter.status_codes.length > 0) {
      filter.status_codes.forEach(code => params.append('status_codes', code.toString()));
    }
    if (filter.min_size) params.set('min_size', filter.min_size.toString());
    if (filter.max_size) params.set('max_size', filter.max_size.toString());
    if (filter.min_request_time) params.set('min_request_time', filter.min_request_time.toString());

    // Exclude filters
    if (filter.exclude_ips && filter.exclude_ips.length > 0) {
      filter.exclude_ips.forEach(ip => params.append('exclude_ips', ip));
    }
    if (filter.exclude_user_agents && filter.exclude_user_agents.length > 0) {
      filter.exclude_user_agents.forEach(ua => params.append('exclude_user_agents', ua));
    }
    if (filter.exclude_uris && filter.exclude_uris.length > 0) {
      filter.exclude_uris.forEach(uri => params.append('exclude_uris', uri));
    }
    if (filter.exclude_hosts && filter.exclude_hosts.length > 0) {
      filter.exclude_hosts.forEach(host => params.append('exclude_hosts', host));
    }
    if (filter.exclude_countries && filter.exclude_countries.length > 0) {
      filter.exclude_countries.forEach(country => params.append('exclude_countries', country));
    }

    // Sorting
    if (filter.sort_by) params.set('sort_by', filter.sort_by);
    if (filter.sort_order) params.set('sort_order', filter.sort_order);

    // Block reason filters
    if (filter.block_reason) params.set('block_reason', filter.block_reason);
    if (filter.bot_category) params.set('bot_category', filter.bot_category);
  }

  const res = await fetch(`${API_BASE}/logs?${params}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<LogListResponse>(res);
}

export async function fetchLogStats(filter?: LogFilter): Promise<LogStats> {
  const params = new URLSearchParams();

  if (filter) {
    if (filter.log_type) params.set('log_type', filter.log_type);
    // Array filters (multi-select support)
    if (filter.hosts && filter.hosts.length > 0) {
      filter.hosts.forEach(host => params.append('hosts', host));
    }
    if (filter.client_ips && filter.client_ips.length > 0) {
      filter.client_ips.forEach(ip => params.append('client_ips', ip));
    }
    if (filter.uris && filter.uris.length > 0) {
      filter.uris.forEach(uri => params.append('uris', uri));
    }
    if (filter.user_agents && filter.user_agents.length > 0) {
      filter.user_agents.forEach(ua => params.append('user_agents', ua));
    }
    // Legacy single-value filters
    if (filter.host) params.set('host', filter.host);
    if (filter.client_ip) params.set('client_ip', filter.client_ip);
    if (filter.uri) params.set('uri', filter.uri);
    if (filter.user_agent) params.set('user_agent', filter.user_agent);

    if (filter.status_code) params.set('status_code', filter.status_code.toString());
    if (filter.start_time) params.set('start_time', filter.start_time);
    if (filter.end_time) params.set('end_time', filter.end_time);
    if (filter.search) params.set('search', filter.search);
    if (filter.method) params.set('method', filter.method);
    if (filter.geo_country_code) params.set('geo_country_code', filter.geo_country_code);
    if (filter.status_codes && filter.status_codes.length > 0) {
      filter.status_codes.forEach(code => params.append('status_codes', code.toString()));
    }
    if (filter.min_size) params.set('min_size', filter.min_size.toString());
    if (filter.max_size) params.set('max_size', filter.max_size.toString());
    if (filter.min_request_time) params.set('min_request_time', filter.min_request_time.toString());

    // Exclude filters
    if (filter.exclude_ips && filter.exclude_ips.length > 0) {
      filter.exclude_ips.forEach(ip => params.append('exclude_ips', ip));
    }
    if (filter.exclude_user_agents && filter.exclude_user_agents.length > 0) {
      filter.exclude_user_agents.forEach(ua => params.append('exclude_user_agents', ua));
    }
    if (filter.exclude_uris && filter.exclude_uris.length > 0) {
      filter.exclude_uris.forEach(uri => params.append('exclude_uris', uri));
    }
    if (filter.exclude_hosts && filter.exclude_hosts.length > 0) {
      filter.exclude_hosts.forEach(host => params.append('exclude_hosts', host));
    }
    if (filter.exclude_countries && filter.exclude_countries.length > 0) {
      filter.exclude_countries.forEach(country => params.append('exclude_countries', country));
    }
  }

  const res = await fetch(`${API_BASE}/logs/stats?${params}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<LogStats>(res);
}

export async function fetchLogSettings(): Promise<LogSettings> {
  const res = await fetch(`${API_BASE}/logs/settings`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<LogSettings>(res);
}

export async function updateLogSettings(
  settings: Partial<LogSettings>
): Promise<LogSettings> {
  const res = await fetch(`${API_BASE}/logs/settings`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(settings),
  });
  return handleResponse<LogSettings>(res);
}

export async function cleanupLogs(): Promise<{ deleted: number; message: string }> {
  const res = await fetch(`${API_BASE}/logs/cleanup`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  return handleResponse<{ deleted: number; message: string }>(res);
}

// Autocomplete API functions

export async function fetchDistinctHosts(search?: string, limit = 20): Promise<string[]> {
  const params = new URLSearchParams();
  if (search) params.set('q', search);
  params.set('limit', limit.toString());

  const res = await fetch(`${API_BASE}/logs/autocomplete/hosts?${params}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<string[]>(res);
}

export async function fetchDistinctIPs(search?: string, limit = 20): Promise<string[]> {
  const params = new URLSearchParams();
  if (search) params.set('q', search);
  params.set('limit', limit.toString());

  const res = await fetch(`${API_BASE}/logs/autocomplete/ips?${params}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<string[]>(res);
}

export async function fetchDistinctUserAgents(search?: string, limit = 20): Promise<string[]> {
  const params = new URLSearchParams();
  if (search) params.set('q', search);
  params.set('limit', limit.toString());

  const res = await fetch(`${API_BASE}/logs/autocomplete/user-agents?${params}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<string[]>(res);
}

export async function fetchDistinctCountries(): Promise<CountryStat[]> {
  const res = await fetch(`${API_BASE}/logs/autocomplete/countries`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<CountryStat[]>(res);
}

export async function fetchDistinctURIs(search?: string, limit = 20): Promise<string[]> {
  const params = new URLSearchParams();
  if (search) params.set('q', search);
  params.set('limit', limit.toString());

  const res = await fetch(`${API_BASE}/logs/autocomplete/uris?${params}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<string[]>(res);
}

export async function fetchDistinctMethods(): Promise<string[]> {
  const res = await fetch(`${API_BASE}/logs/autocomplete/methods`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<string[]>(res);
}
