export interface DDNSRecord {
  id: string
  hostname: string
  dns_provider_id: string
  record_type: string
  proxied: boolean
  ttl: number
  enabled: boolean
  last_ip: string
  last_synced_at?: string
  last_status: string
  last_error: string
  proxy_host_id?: string
  created_at: string
  updated_at: string
}
export interface CreateDDNSRecordRequest {
  hostname: string
  dns_provider_id: string
  proxied: boolean
  ttl: number
  enabled: boolean
}
export interface UpdateDDNSRecordRequest {
  hostname?: string
  dns_provider_id?: string
  proxied?: boolean
  ttl?: number
  enabled?: boolean
}
export interface DDNSRecordListResponse {
  data: DDNSRecord[]; total: number; page: number; per_page: number; total_pages: number
}
