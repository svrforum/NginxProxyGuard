import type {
  FilterSubscription,
  FilterSubscriptionDetail,
  FilterSubscriptionListResponse,
  FilterSubscriptionHostExclusion,
  FilterSubscriptionEntryExclusion,
  CreateFilterSubscriptionRequest,
  UpdateFilterSubscriptionRequest,
  CatalogSubscribeRequest,
  FilterCatalog,
} from '../types/filter-subscription'
import { apiGet, apiPost, apiPut, apiDelete } from './client'

const API_BASE = '/api/v1/filter-subscriptions'

export async function fetchFilterSubscriptions(
  page = 1,
  perPage = 50
): Promise<FilterSubscriptionListResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    per_page: perPage.toString(),
  })
  return apiGet<FilterSubscriptionListResponse>(`${API_BASE}?${params.toString()}`)
}

export async function fetchFilterSubscription(id: string): Promise<FilterSubscriptionDetail> {
  return apiGet<FilterSubscriptionDetail>(`${API_BASE}/${id}`)
}

export async function createFilterSubscription(
  data: CreateFilterSubscriptionRequest
): Promise<FilterSubscription> {
  return apiPost<FilterSubscription>(API_BASE, data)
}

export async function updateFilterSubscription(
  id: string,
  data: UpdateFilterSubscriptionRequest
): Promise<FilterSubscription> {
  return apiPut<FilterSubscription>(`${API_BASE}/${id}`, data)
}

export async function deleteFilterSubscription(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/${id}`)
}

export async function refreshFilterSubscription(id: string): Promise<FilterSubscription> {
  return apiPost<FilterSubscription>(`${API_BASE}/${id}/refresh`)
}

export async function fetchFilterCatalog(): Promise<FilterCatalog> {
  return apiGet<FilterCatalog>(`${API_BASE}/catalog`)
}

export async function subscribeFromCatalog(
  data: CatalogSubscribeRequest
): Promise<FilterSubscription[]> {
  return apiPost<FilterSubscription[]>(`${API_BASE}/catalog/subscribe`, data)
}

export async function fetchExclusions(
  subscriptionId: string
): Promise<FilterSubscriptionHostExclusion[]> {
  return apiGet<FilterSubscriptionHostExclusion[]>(`${API_BASE}/${subscriptionId}/exclusions`)
}

export async function addExclusion(
  subscriptionId: string,
  hostId: string
): Promise<void> {
  await apiPost(`${API_BASE}/${subscriptionId}/exclusions/${hostId}`)
}

export async function removeExclusion(
  subscriptionId: string,
  hostId: string
): Promise<void> {
  return apiDelete(`${API_BASE}/${subscriptionId}/exclusions/${hostId}`)
}

export async function fetchEntryExclusions(
  subscriptionId: string
): Promise<FilterSubscriptionEntryExclusion[]> {
  return apiGet<FilterSubscriptionEntryExclusion[]>(`${API_BASE}/${subscriptionId}/entry-exclusions`)
}

export async function addEntryExclusion(
  subscriptionId: string,
  value: string
): Promise<void> {
  await apiPost(`${API_BASE}/${subscriptionId}/entry-exclusions`, { value })
}

export async function removeEntryExclusion(
  subscriptionId: string,
  value: string
): Promise<void> {
  return apiDelete(`${API_BASE}/${subscriptionId}/entry-exclusions?value=${encodeURIComponent(value)}`)
}

/** One subscription that contains an address or user-agent, and the entry that matched. */
export interface FilterMatch {
  subscription_id: string
  subscription_name: string
  type: string
  matched_value: string
  enabled: boolean
  reason?: string
}

/**
 * Ask which subscriptions contain this address or user-agent (#230).
 *
 * The access log records that a filter list refused a request but not which
 * one, because nginx resolves them all through a single shared radix tree.
 */
export async function matchFilterSubscriptions(
  ip: string,
  userAgent: string
): Promise<{ ip_matches: FilterMatch[]; user_agent_matches: FilterMatch[] }> {
  const params = new URLSearchParams()
  if (ip) params.set('ip', ip)
  if (userAgent) params.set('user_agent', userAgent)
  return apiGet(`${API_BASE}/match?${params.toString()}`)
}
