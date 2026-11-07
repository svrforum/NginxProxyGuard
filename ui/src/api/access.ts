import { AccessList, CreateAccessListRequest, RedirectHost, CreateRedirectHostRequest, GeoRestriction, CreateGeoRestrictionRequest } from '../types/access';
import type { DNSConfirmRequest, DNSEntryStatus } from '../types/dnsEntries';
import { getAuthHeaders } from './auth';
import { apiDelete, apiGet, apiPost, apiPut, responseError } from './client';

const API_BASE = '/api/v1';

// Access Lists go through the shared client: a 409 nginx_reload_rejected keeps
// its code (isNginxReloadRefusal), and a 400 keeps the rule it names (field).
export async function getAccessLists(page = 1, perPage = 20): Promise<{ data: AccessList[]; total: number }> {
  return apiGet<{ data: AccessList[]; total: number }>(`${API_BASE}/access-lists?page=${page}&per_page=${perPage}`);
}

// The API gives at most 100 lists a page. The access list page and the host
// form's picker both show every list; they stopped at the first 20 and the
// first 100 (#369). A list that moves between pages while they are read is
// kept once. An install without lists gets data: null.
export async function getAllAccessLists(): Promise<AccessList[]> {
  const perPage = 100;
  const lists = new Map<string, AccessList>();
  for (let page = 1; ; page++) {
    const { data, total } = await getAccessLists(page, perPage);
    const onPage = data ?? [];
    for (const list of onPage) lists.set(list.id, list);
    if (onPage.length < perPage || page * perPage >= total) return [...lists.values()];
  }
}

export async function getAccessList(id: string): Promise<AccessList> {
  return apiGet<AccessList>(`${API_BASE}/access-lists/${id}`);
}

export async function createAccessList(data: CreateAccessListRequest): Promise<AccessList> {
  return apiPost<AccessList>(`${API_BASE}/access-lists`, data);
}

export async function updateAccessList(id: string, data: Partial<CreateAccessListRequest>): Promise<AccessList> {
  return apiPut<AccessList>(`${API_BASE}/access-lists/${id}`, data);
}

export async function deleteAccessList(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/access-lists/${id}`);
}

/** Allows a domain in review again, with the values the operator was shown (#320). */
export async function confirmAccessListDNS(listId: string, body: DNSConfirmRequest): Promise<DNSEntryStatus> {
  return apiPost<DNSEntryStatus>(`${API_BASE}/access-lists/${listId}/dns-confirm`, body);
}

// Redirect Hosts
export async function getRedirectHosts(page = 1, perPage = 20): Promise<{ data: RedirectHost[]; total: number }> {
  const res = await fetch(`${API_BASE}/redirect-hosts?page=${page}&per_page=${perPage}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch redirect hosts');
  return res.json();
}

export async function getRedirectHost(id: string): Promise<RedirectHost> {
  const res = await fetch(`${API_BASE}/redirect-hosts/${id}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch redirect host');
  return res.json();
}

export async function createRedirectHost(data: CreateRedirectHostRequest): Promise<RedirectHost> {
  const res = await fetch(`${API_BASE}/redirect-hosts`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to create redirect host');
  }
  return res.json();
}

export async function updateRedirectHost(id: string, data: Partial<CreateRedirectHostRequest>): Promise<RedirectHost> {
  const res = await fetch(`${API_BASE}/redirect-hosts/${id}`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to update redirect host');
  }
  return res.json();
}

export async function deleteRedirectHost(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/redirect-hosts/${id}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete redirect host');
}

// Geo Restrictions
export async function getGeoRestriction(proxyHostId: string): Promise<GeoRestriction> {
  const res = await fetch(`${API_BASE}/proxy-hosts/${proxyHostId}/geo`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch geo restriction');
  return res.json();
}

export async function setGeoRestriction(proxyHostId: string, data: CreateGeoRestrictionRequest, skipReload = false): Promise<GeoRestriction> {
  const url = skipReload
    ? `${API_BASE}/proxy-hosts/${proxyHostId}/geo?skip_reload=true`
    : `${API_BASE}/proxy-hosts/${proxyHostId}/geo`;
  const res = await fetch(url, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  // Keeps the 400's field and code, so the form marks the domain it names (#320).
  if (!res.ok) throw await responseError(res, 'Failed to set geo restriction');
  return res.json();
}

export async function deleteGeoRestriction(proxyHostId: string, skipReload = false): Promise<void> {
  const url = skipReload
    ? `${API_BASE}/proxy-hosts/${proxyHostId}/geo?skip_reload=true`
    : `${API_BASE}/proxy-hosts/${proxyHostId}/geo`;
  const res = await fetch(url, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete geo restriction');
}

export async function getCountryCodes(): Promise<Record<string, string>> {
  const res = await fetch(`${API_BASE}/geo/countries`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch country codes');
  return res.json();
}
