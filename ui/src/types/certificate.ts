export interface Certificate {
  id: string;
  domain_names: string[];
  dns_provider_id?: string;
  status: 'pending' | 'issued' | 'expired' | 'error' | 'renewing';
  provider: 'letsencrypt' | 'selfsigned' | 'custom';
  auto_renew: boolean;
  expires_at?: string;
  issued_at?: string;
  renewal_attempted_at?: string;
  error_message?: string;
  certificate_path?: string;
  private_key_path?: string;
  created_at: string;
  updated_at: string;
  dns_provider?: DNSProvider;
  days_until_expiry?: number;
  needs_renewal?: boolean;
}

export interface CreateCertificateRequest {
  domain_names: string[];
  dns_provider_id?: string;
  provider: 'letsencrypt' | 'selfsigned' | 'custom';
  auto_renew?: boolean;
  validity_days?: number; // For self-signed
}

export interface UploadCertificateRequest {
  domain_names: string[];
  certificate_pem: string;
  private_key_pem: string;
  issuer_pem?: string;
}

export interface DNSProvider {
  id: string;
  name: string;
  provider_type: 'cloudflare' | 'route53' | 'duckdns' | 'dynu' | 'manual';
  is_default: boolean;
  has_credentials: boolean;
  created_at: string;
  updated_at: string;
}

export interface CloudflareCredentials {
  api_token?: string;
  api_key?: string;
  email?: string;
  zone_id?: string;
}

export interface CreateDNSProviderRequest {
  name: string;
  provider_type: 'cloudflare' | 'route53' | 'duckdns' | 'dynu' | 'manual';
  credentials: CloudflareCredentials | Record<string, string>;
  is_default?: boolean;
}

export interface CertificateListResponse {
  data: Certificate[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface DNSProviderListResponse {
  data: DNSProvider[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface CertificateLog {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
  step?: string;
}

export interface CertificateLogResponse {
  certificate_id: string;
  status: 'pending' | 'issued' | 'expired' | 'error' | 'renewing';
  logs: CertificateLog[];
  is_complete: boolean;
}

export interface CertificateHistory {
  id: string;
  certificate_id: string;
  action: 'issued' | 'renewed' | 'error' | 'expired';
  status: 'success' | 'error';
  message?: string;
  domain_names: string[];
  provider: 'letsencrypt' | 'selfsigned' | 'custom';
  expires_at?: string;
  logs?: string; // JSON array of CertificateLog
  created_at: string;
}

export interface CertificateHistoryListResponse {
  data: CertificateHistory[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}
