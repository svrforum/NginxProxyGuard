export interface FilterSubscription {
  id: string;
  name: string;
  description?: string;
  url: string;
  format: string;
  type: string;
  enabled: boolean;
  refresh_type: string;
  refresh_value: string;
  last_fetched_at?: string;
  last_success_at?: string;
  last_error?: string;
  entry_count: number;
  created_at: string;
  updated_at: string;
}

export interface FilterSubscriptionEntry {
  id: string;
  subscription_id: string;
  value: string;
  reason?: string;
  created_at: string;
}

export interface FilterSubscriptionHostExclusion {
  id: string;
  subscription_id: string;
  proxy_host_id: string;
  created_at: string;
}

export interface FilterSubscriptionDetail extends FilterSubscription {
  entries: FilterSubscriptionEntry[];
  exclusions: FilterSubscriptionHostExclusion[];
}

export interface FilterSubscriptionListResponse {
  data: FilterSubscription[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface CreateFilterSubscriptionRequest {
  url: string;
  name?: string;
  type?: string;
  refresh_type?: string;
  refresh_value?: string;
}

export interface UpdateFilterSubscriptionRequest {
  name?: string;
  enabled?: boolean;
  refresh_type?: string;
  refresh_value?: string;
}

export interface CatalogSubscribeRequest {
  paths: string[];
  refresh_type?: string;
  refresh_value?: string;
}

export interface FilterCatalog {
  version: number;
  generated_at: string;
  lists: FilterCatalogEntry[];
}

export interface FilterCatalogEntry {
  name: string;
  description: string;
  type: string;
  path: string;
  entry_count: number;
  updated_at: string;
  subscribed?: boolean;
}
