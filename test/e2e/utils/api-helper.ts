import { APIRequestContext } from '@playwright/test';
import { TEST_CREDENTIALS, API_ENDPOINTS } from '../fixtures/test-data';

/**
 * API Helper for direct API calls in tests.
 * Useful for setup/teardown and verifying backend state.
 */
export class APIHelper {
  private request: APIRequestContext;
  private token: string | null = null;

  constructor(request: APIRequestContext) {
    this.request = request;
  }

  /**
   * Get authorization headers.
   */
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  /**
   * Login and store token.
   */
  async login(
    username: string = TEST_CREDENTIALS.username,
    password: string = TEST_CREDENTIALS.password
  ): Promise<string> {
    const response = await this.request.post(API_ENDPOINTS.login, {
      data: { username, password },
    });

    if (!response.ok()) {
      throw new Error(`Login failed: ${response.status()}`);
    }

    const data = await response.json();
    this.token = data.token;
    return this.token;
  }

  /**
   * Logout and clear token.
   */
  async logout(): Promise<void> {
    if (this.token) {
      await this.request.post(API_ENDPOINTS.logout, {
        headers: this.getHeaders(),
      });
      this.token = null;
    }
  }

  /**
   * Get all proxy hosts.
   */
  async getProxyHosts(): Promise<ProxyHostData[]> {
    const response = await this.request.get(API_ENDPOINTS.proxyHosts, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get proxy hosts: ${response.status()}`);
    }

    const result = await response.json();
    // API returns paginated response: { data: [...], total, page, per_page, total_pages }
    return result.data || [];
  }

  /**
   * Create a new proxy host.
   */
  async createProxyHost(data: CreateProxyHostData): Promise<ProxyHostData> {
    const response = await this.request.post(API_ENDPOINTS.proxyHosts, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create proxy host: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Update a proxy host.
   */
  async updateProxyHost(id: number, data: Partial<CreateProxyHostData>): Promise<ProxyHostData> {
    const response = await this.request.put(`${API_ENDPOINTS.proxyHosts}/${id}`, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update proxy host: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a proxy host.
   */
  async deleteProxyHost(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.proxyHosts}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete proxy host: ${response.status()}`);
    }
  }

  /**
   * Sync all proxy hosts.
   */
  async syncAllProxyHosts(): Promise<SyncResult> {
    const response = await this.request.post(`${API_ENDPOINTS.proxyHosts}/sync`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to sync proxy hosts: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Get all certificates.
   */
  async getCertificates(): Promise<CertificateData[]> {
    const response = await this.request.get(API_ENDPOINTS.certificates, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get certificates: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a proxy host by domain name.
   */
  async deleteProxyHostByDomain(domain: string): Promise<boolean> {
    const hosts = await this.getProxyHosts();
    const host = hosts.find(h => h.domain_names?.includes(domain));

    if (host) {
      await this.deleteProxyHost(host.id);
      return true;
    }
    return false;
  }

  /**
   * Clean up test proxy hosts (by domain pattern).
   */
  async cleanupTestHosts(pattern: RegExp = /test-e2e-|secure-e2e-/i): Promise<number> {
    const hosts = await this.getProxyHosts();
    let deleted = 0;

    for (const host of hosts) {
      const domains = host.domain_names || [];
      if (domains.some((d: string) => pattern.test(d))) {
        await this.deleteProxyHost(host.id);
        deleted++;
      }
    }

    return deleted;
  }

  /**
   * Get health status.
   */
  async getHealth(): Promise<HealthData> {
    const response = await this.request.get('/health');

    if (!response.ok()) {
      throw new Error(`Health check failed: ${response.status()}`);
    }

    return response.json();
  }

  // ==================== Redirect Hosts ====================

  /**
   * Get all redirect hosts.
   */
  async getRedirectHosts(): Promise<RedirectHostData[]> {
    const response = await this.request.get(API_ENDPOINTS.redirectHosts, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get redirect hosts: ${response.status()}`);
    }

    const result = await response.json();
    return result.data || [];
  }

  /**
   * Create a new redirect host.
   */
  async createRedirectHost(data: CreateRedirectHostData): Promise<RedirectHostData> {
    const response = await this.request.post(API_ENDPOINTS.redirectHosts, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create redirect host: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Update a redirect host.
   */
  async updateRedirectHost(id: number, data: Partial<CreateRedirectHostData>): Promise<RedirectHostData> {
    const response = await this.request.put(`${API_ENDPOINTS.redirectHosts}/${id}`, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update redirect host: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a redirect host.
   */
  async deleteRedirectHost(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.redirectHosts}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete redirect host: ${response.status()}`);
    }
  }

  /**
   * Clean up test redirect hosts.
   */
  async cleanupTestRedirectHosts(pattern: RegExp = /test-e2e-|redirect-e2e-/i): Promise<number> {
    const hosts = await this.getRedirectHosts();
    let deleted = 0;

    for (const host of hosts) {
      const domains = host.domain_names || [];
      if (domains.some((d: string) => pattern.test(d))) {
        await this.deleteRedirectHost(host.id);
        deleted++;
      }
    }

    return deleted;
  }

  // ==================== DNS Providers ====================

  /**
   * Get all DNS providers.
   */
  async getDnsProviders(): Promise<DnsProviderData[]> {
    const response = await this.request.get(API_ENDPOINTS.dnsProviders, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get DNS providers: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Create a new DNS provider.
   */
  async createDnsProvider(data: CreateDnsProviderData): Promise<DnsProviderData> {
    const response = await this.request.post(API_ENDPOINTS.dnsProviders, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create DNS provider: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Update a DNS provider.
   */
  async updateDnsProvider(id: number, data: Partial<CreateDnsProviderData>): Promise<DnsProviderData> {
    const response = await this.request.put(`${API_ENDPOINTS.dnsProviders}/${id}`, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update DNS provider: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a DNS provider.
   */
  async deleteDnsProvider(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.dnsProviders}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete DNS provider: ${response.status()}`);
    }
  }

  /**
   * Clean up test DNS providers.
   */
  async cleanupTestDnsProviders(pattern: RegExp = /test-.*-e2e|e2e-test/i): Promise<number> {
    const providers = await this.getDnsProviders();
    let deleted = 0;

    for (const provider of providers) {
      if (pattern.test(provider.name)) {
        await this.deleteDnsProvider(provider.id);
        deleted++;
      }
    }

    return deleted;
  }

  // ==================== Access Lists ====================

  /**
   * Get all access lists.
   */
  async getAccessLists(): Promise<AccessListData[]> {
    const response = await this.request.get(API_ENDPOINTS.accessLists, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get access lists: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Create a new access list.
   */
  async createAccessList(data: CreateAccessListData): Promise<AccessListData> {
    const response = await this.request.post(API_ENDPOINTS.accessLists, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create access list: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Update an access list.
   */
  async updateAccessList(id: number, data: Partial<CreateAccessListData>): Promise<AccessListData> {
    const response = await this.request.put(`${API_ENDPOINTS.accessLists}/${id}`, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update access list: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete an access list.
   */
  async deleteAccessList(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.accessLists}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete access list: ${response.status()}`);
    }
  }

  /**
   * Clean up test access lists.
   */
  async cleanupTestAccessLists(pattern: RegExp = /test-acl-|e2e-acl/i): Promise<number> {
    const lists = await this.getAccessLists();
    let deleted = 0;

    for (const list of lists) {
      if (pattern.test(list.name)) {
        await this.deleteAccessList(list.id);
        deleted++;
      }
    }

    return deleted;
  }

  // ==================== Certificates ====================

  /**
   * Request a new Let's Encrypt certificate.
   */
  async requestCertificate(data: RequestCertificateData): Promise<CertificateData> {
    const response = await this.request.post(API_ENDPOINTS.certificatesRequest, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to request certificate: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a certificate.
   */
  async deleteCertificate(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.certificates}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete certificate: ${response.status()}`);
    }
  }

  /**
   * Renew a certificate.
   */
  async renewCertificate(id: number): Promise<CertificateData> {
    const response = await this.request.post(`${API_ENDPOINTS.certificates}/${id}/renew`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to renew certificate: ${error.error || response.status()}`);
    }

    return response.json();
  }

  // ==================== API Tokens ====================

  /**
   * Get all API tokens.
   */
  async getApiTokens(): Promise<ApiTokenData[]> {
    const response = await this.request.get(API_ENDPOINTS.apiTokens, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get API tokens: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Create a new API token.
   */
  async createApiToken(data: CreateApiTokenData): Promise<ApiTokenData & { token: string }> {
    const response = await this.request.post(API_ENDPOINTS.apiTokens, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create API token: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Revoke an API token.
   */
  async revokeApiToken(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.apiTokens}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to revoke API token: ${response.status()}`);
    }
  }

  /**
   * Clean up test API tokens.
   */
  async cleanupTestApiTokens(pattern: RegExp = /test-.*token|e2e-token/i): Promise<number> {
    const tokens = await this.getApiTokens();
    let deleted = 0;

    for (const token of tokens) {
      if (pattern.test(token.name)) {
        await this.revokeApiToken(token.id);
        deleted++;
      }
    }

    return deleted;
  }

  // ==================== Backups ====================

  /**
   * Get all backups.
   */
  async getBackups(): Promise<BackupData[]> {
    const response = await this.request.get(API_ENDPOINTS.settingsBackups, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get backups: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Create a new backup.
   */
  async createBackup(): Promise<BackupData> {
    const response = await this.request.post(API_ENDPOINTS.settingsBackups, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create backup: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a backup.
   */
  async deleteBackup(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.settingsBackups}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete backup: ${response.status()}`);
    }
  }

  // ==================== Account Settings ====================

  /**
   * Get account settings.
   */
  async getAccountSettings(): Promise<AccountData> {
    const response = await this.request.get(API_ENDPOINTS.account, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get account settings: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Update account password.
   */
  async updatePassword(currentPassword: string, newPassword: string): Promise<void> {
    const response = await this.request.put(API_ENDPOINTS.accountPassword, {
      headers: this.getHeaders(),
      data: { current_password: currentPassword, new_password: newPassword },
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update password: ${error.error || response.status()}`);
    }
  }

  // ==================== Global Settings ====================

  /**
   * Get global settings.
   */
  async getGlobalSettings(): Promise<GlobalSettingsData> {
    const response = await this.request.get(API_ENDPOINTS.settingsGlobal, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get global settings: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Update global settings.
   */
  async updateGlobalSettings(data: Partial<GlobalSettingsData>): Promise<GlobalSettingsData> {
    const response = await this.request.put(API_ENDPOINTS.settingsGlobal, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update global settings: ${error.error || response.status()}`);
    }

    return response.json();
  }

  // ==================== WAF ====================

  /**
   * Get WAF banned IPs.
   */
  async getWafBannedIps(): Promise<WafBannedIpData[]> {
    const response = await this.request.get(API_ENDPOINTS.wafBannedIps, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get WAF banned IPs: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Ban an IP address.
   */
  async banIp(ip: string, reason?: string): Promise<void> {
    const response = await this.request.post(API_ENDPOINTS.wafBannedIps, {
      headers: this.getHeaders(),
      data: { ip, reason },
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to ban IP: ${error.error || response.status()}`);
    }
  }

  /**
   * Unban an IP address.
   */
  async unbanIp(ip: string): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.wafBannedIps}/${encodeURIComponent(ip)}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to unban IP: ${response.status()}`);
    }
  }

  /**
   * Get WAF URI blocks.
   */
  async getWafUriBlocks(): Promise<WafUriBlockData[]> {
    const response = await this.request.get(API_ENDPOINTS.wafUriBlocks, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get WAF URI blocks: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Create a URI block rule.
   */
  async createWafUriBlock(data: CreateWafUriBlockData): Promise<WafUriBlockData> {
    const response = await this.request.post(API_ENDPOINTS.wafUriBlocks, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create URI block: ${error.error || response.status()}`);
    }

    return response.json();
  }

  /**
   * Delete a URI block rule.
   */
  async deleteWafUriBlock(id: number): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.wafUriBlocks}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete URI block: ${response.status()}`);
    }
  }

  /**
   * Get WAF exploit rules.
   */
  async getWafExploitRules(): Promise<WafExploitRuleData[]> {
    const response = await this.request.get(API_ENDPOINTS.wafExploitRules, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get WAF exploit rules: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Test a WAF payload.
   */
  async testWafPayload(payload: string): Promise<WafTestResult> {
    const response = await this.request.post(API_ENDPOINTS.wafTest, {
      headers: this.getHeaders(),
      data: { payload },
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to test WAF payload: ${error.error || response.status()}`);
    }

    return response.json();
  }

  // ==================== Logs ====================

  /**
   * Get access logs.
   */
  async getAccessLogs(params?: LogQueryParams): Promise<LogEntry[]> {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', params.page.toString());
    if (params?.perPage) queryParams.set('per_page', params.perPage.toString());
    if (params?.hostId) queryParams.set('host_id', params.hostId.toString());

    const response = await this.request.get(`${API_ENDPOINTS.logsAccess}?${queryParams}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get access logs: ${response.status()}`);
    }

    const result = await response.json();
    return result.data || [];
  }

  /**
   * Get audit logs.
   */
  async getAuditLogs(params?: LogQueryParams): Promise<AuditLogEntry[]> {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', params.page.toString());
    if (params?.perPage) queryParams.set('per_page', params.perPage.toString());

    const response = await this.request.get(`${API_ENDPOINTS.logsAudit}?${queryParams}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get audit logs: ${response.status()}`);
    }

    const result = await response.json();
    return result.data || [];
  }
}

// Type definitions
export interface ProxyHostData {
  id: number;
  domain_names: string[];
  forward_scheme: string;
  forward_host: string;
  forward_port: number;
  enabled: boolean;
  ssl_enabled: boolean;
  http2_enabled: boolean;
  http3_enabled: boolean;
  waf_enabled: boolean;
  waf_mode: string;
  bot_filter_enabled: boolean;
  geoip_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateProxyHostData {
  domain_names: string[];
  forward_scheme: string;
  forward_host: string;
  forward_port: number;
  enabled?: boolean;
  ssl_enabled?: boolean;
  http2_enabled?: boolean;
  http3_enabled?: boolean;
  waf_enabled?: boolean;
  waf_mode?: string;
  bot_filter_enabled?: boolean;
  geoip_enabled?: boolean;
}

export interface SyncResult {
  total_hosts: number;
  success_count: number;
  failed_count: number;
  hosts: Array<{ id: number; domain: string; success: boolean; error?: string }>;
  test_success: boolean;
  test_error?: string;
  reload_success: boolean;
}

export interface CertificateData {
  id: number;
  name: string;
  domains: string[];
  expires_at: string;
  created_at: string;
}

export interface HealthData {
  status: string;
  version: string;
  database: string;
}

// Redirect Host Types
export interface RedirectHostData {
  id: number;
  domain_names: string[];
  forward_domain: string;
  redirect_code: number;
  preserve_path: boolean;
  enabled: boolean;
  ssl_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRedirectHostData {
  domain_names: string[];
  forward_domain: string;
  redirect_code: number;
  preserve_path?: boolean;
  enabled?: boolean;
  ssl_enabled?: boolean;
}

// DNS Provider Types
export interface DnsProviderData {
  id: number;
  name: string;
  type: string;
  credentials: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateDnsProviderData {
  name: string;
  type: string;
  credentials: Record<string, string>;
}

// Access List Types
export interface AccessListData {
  id: number;
  name: string;
  allowed_ips: string[];
  denied_ips: string[];
  proxy_host_count?: number;
  created_at: string;
  updated_at: string;
}

export interface CreateAccessListData {
  name: string;
  allowed_ips?: string[];
  denied_ips?: string[];
}

// Certificate Request Type
export interface RequestCertificateData {
  domains: string[];
  dns_provider_id?: number;
  email?: string;
}

// API Token Types
export interface ApiTokenData {
  id: number;
  name: string;
  permissions: string[];
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
}

export interface CreateApiTokenData {
  name: string;
  permissions: string[];
  expires_at?: string;
}

// Backup Types
export interface BackupData {
  id: number;
  filename: string;
  size: number;
  created_at: string;
}

// Account Types
export interface AccountData {
  id: number;
  username: string;
  email?: string;
  two_factor_enabled: boolean;
  language: string;
  font?: string;
  created_at: string;
}

// Global Settings Types
export interface GlobalSettingsData {
  nginx_worker_processes?: number;
  nginx_worker_connections?: number;
  default_waf_mode?: string;
  default_paranoia_level?: number;
  geoip_enabled?: boolean;
  geoip_license_key?: string;
  bot_filter_default?: boolean;
  waf_auto_ban_enabled?: boolean;
  waf_auto_ban_threshold?: number;
  ssl_dhparam_bits?: number;
}

// WAF Types
export interface WafBannedIpData {
  ip: string;
  reason?: string;
  banned_at: string;
  expires_at?: string;
}

export interface WafUriBlockData {
  id: number;
  pattern: string;
  is_regex: boolean;
  description?: string;
  enabled: boolean;
  created_at: string;
}

export interface CreateWafUriBlockData {
  pattern: string;
  is_regex?: boolean;
  description?: string;
  enabled?: boolean;
}

export interface WafExploitRuleData {
  id: number;
  name: string;
  pattern: string;
  enabled: boolean;
  category: string;
}

export interface WafTestResult {
  blocked: boolean;
  matched_rules: string[];
  details?: string;
}

// Log Types
export interface LogQueryParams {
  page?: number;
  perPage?: number;
  hostId?: number;
  startDate?: string;
  endDate?: string;
}

export interface LogEntry {
  id: number;
  host_id: number;
  remote_addr: string;
  request_uri: string;
  status: number;
  response_time: number;
  timestamp: string;
}

export interface AuditLogEntry {
  id: number;
  user_id: number;
  action: string;
  resource_type: string;
  resource_id?: number;
  details?: Record<string, unknown>;
  ip_address: string;
  timestamp: string;
}
