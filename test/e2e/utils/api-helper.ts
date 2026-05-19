import { APIRequestContext } from '@playwright/test';
import { TEST_CREDENTIALS, API_ENDPOINTS } from '../fixtures/test-data';

// Delay helper for rate limiting
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Retry configuration
const RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 500, // 500ms base delay
  maxDelay: 5000, // 5s max delay
};

/**
 * API Helper for direct API calls in tests.
 * Useful for setup/teardown and verifying backend state.
 */
export class APIHelper {
  private request: APIRequestContext;
  private token: string | null = null;
  private createdHostIds: string[] = [];
  private createdRedirectHostIds: string[] = [];
  private createdDnsProviderIds: string[] = [];
  private createdAccessListIds: string[] = [];
  // Block-reason regression spec creates these — track for cleanup so a failing
  // test never leaves a stale ban that poisons a later test's expected_block_reason.
  private bannedIpIds: string[] = [];

  constructor(request: APIRequestContext) {
    this.request = request;
  }

  /**
   * Execute a request with retry logic for rate limiting.
   */
  private async withRetry<T>(
    operation: () => Promise<T>,
    operationName: string
  ): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < RETRY_CONFIG.maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        const errorMessage = lastError.message || '';

        // Check if it's a rate limit error (429)
        if (errorMessage.includes('429')) {
          const delayTime = Math.min(
            RETRY_CONFIG.baseDelay * Math.pow(2, attempt),
            RETRY_CONFIG.maxDelay
          );
          console.log(
            `Rate limited on ${operationName}, retrying in ${delayTime}ms (attempt ${attempt + 1}/${RETRY_CONFIG.maxRetries})`
          );
          await delay(delayTime);
          continue;
        }

        // For other errors, don't retry
        throw lastError;
      }
    }

    throw lastError || new Error(`${operationName} failed after ${RETRY_CONFIG.maxRetries} retries`);
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
    return this.withRetry(async () => {
      const response = await this.request.post(API_ENDPOINTS.login, {
        data: { username, password },
      });

      if (!response.ok()) {
        throw new Error(`Login failed: ${response.status()}`);
      }

      const data = await response.json();
      this.token = data.token;
      return this.token;
    }, 'login');
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
    return this.withRetry(async () => {
      const response = await this.request.get(`${API_ENDPOINTS.proxyHosts}?per_page=500`, {
        headers: this.getHeaders(),
      });

      if (!response.ok()) {
        throw new Error(`Failed to get proxy hosts: ${response.status()}`);
      }

      const result = await response.json();
      // API returns paginated response: { data: [...], total, page, per_page, total_pages }
      // data may be null when no hosts exist
      return result.data ?? [];
    }, 'getProxyHosts');
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

    const host = await response.json();
    this.createdHostIds.push(host.id);
    return host;
  }

  /**
   * Update a proxy host.
   */
  async updateProxyHost(id: string, data: Partial<CreateProxyHostData>): Promise<ProxyHostData> {
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
  async deleteProxyHost(id: string): Promise<void> {
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

    const result = await response.json();
    return result.data || [];
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
   * Clean up test proxy hosts created by this APIHelper instance.
   * Only deletes hosts that were created via createProxyHost() to avoid
   * interfering with parallel test workers.
   */
  async cleanupTestHosts(_pattern?: RegExp): Promise<number> {
    let deleted = 0;

    // Only delete hosts created by this instance (safe for parallel execution)
    for (const id of this.createdHostIds) {
      try {
        await this.deleteProxyHost(id);
        deleted++;
      } catch {
        // Host may already be deleted or never created successfully
      }
    }
    this.createdHostIds = [];
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

  // ==================== Bot Filter ====================

  /**
   * Get bot filter settings for a proxy host.
   */
  async getBotFilter(proxyHostId: string): Promise<{ enabled: boolean } | null> {
    const response = await this.request.get(`${API_ENDPOINTS.proxyHosts}/${proxyHostId}/bot-filter`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      return null;
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

    const host = await response.json();
    this.createdRedirectHostIds.push(host.id);
    return host;
  }

  /**
   * Update a redirect host.
   */
  async updateRedirectHost(id: string, data: Partial<CreateRedirectHostData>): Promise<RedirectHostData> {
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
  async deleteRedirectHost(id: string): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.redirectHosts}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete redirect host: ${response.status()}`);
    }
  }

  /**
   * Clean up test redirect hosts.
   * Errors during cleanup are logged but not thrown, to avoid cascade failures.
   */
  async cleanupTestRedirectHosts(_pattern?: RegExp): Promise<number> {
    let deleted = 0;

    // Only delete redirect hosts created by this instance (safe for parallel execution)
    for (const id of this.createdRedirectHostIds) {
      try {
        await this.deleteRedirectHost(id);
        deleted++;
      } catch {
        // Host may already be deleted
      }
    }
    this.createdRedirectHostIds = [];

    return deleted;
  }

  // ==================== DNS Providers ====================

  /**
   * Get all DNS providers.
   */
  async getDnsProviders(): Promise<DnsProviderData[]> {
    return this.withRetry(async () => {
      const response = await this.request.get(API_ENDPOINTS.dnsProviders, {
        headers: this.getHeaders(),
      });

      if (!response.ok()) {
        throw new Error(`Failed to get DNS providers: ${response.status()}`);
      }

      const data = await response.json();
      // Ensure we return an array
      return Array.isArray(data) ? data : [];
    }, 'getDnsProviders');
  }

  /**
   * Create a new DNS provider.
   */
  async createDnsProvider(data: CreateDnsProviderData): Promise<DnsProviderData> {
    // Map 'type' to 'provider_type' for API compatibility
    const apiData = {
      name: data.name,
      provider_type: data.provider_type || data.type,
      credentials: data.credentials,
    };
    const response = await this.request.post(API_ENDPOINTS.dnsProviders, {
      headers: this.getHeaders(),
      data: apiData,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create DNS provider: ${error.error || response.status()}`);
    }

    const provider = await response.json();
    this.createdDnsProviderIds.push(provider.id);
    return provider;
  }

  /**
   * Update a DNS provider.
   */
  async updateDnsProvider(id: string, data: Partial<CreateDnsProviderData>): Promise<DnsProviderData> {
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
  async deleteDnsProvider(id: string): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.dnsProviders}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete DNS provider: ${response.status()}`);
    }
  }

  /**
   * Clean up test DNS providers.
   * Errors during cleanup are logged but not thrown, to avoid cascade failures.
   */
  async cleanupTestDnsProviders(_pattern?: RegExp): Promise<number> {
    let deleted = 0;

    // Only delete providers created by this instance (safe for parallel execution)
    for (const id of this.createdDnsProviderIds) {
      try {
        await this.deleteDnsProvider(id);
        deleted++;
      } catch {
        // Provider may already be deleted
      }
    }
    this.createdDnsProviderIds = [];
    return deleted;
  }

  // ==================== Access Lists ====================

  /**
   * Get all access lists.
   */
  async getAccessLists(): Promise<AccessListData[]> {
    return this.withRetry(async () => {
      const response = await this.request.get(API_ENDPOINTS.accessLists, {
        headers: this.getHeaders(),
      });

      if (!response.ok()) {
        throw new Error(`Failed to get access lists: ${response.status()}`);
      }

      const result = await response.json();
      // API returns paginated response: { data: [...], total, page, per_page, total_pages }
      if (result.data && Array.isArray(result.data)) return result.data;
      return Array.isArray(result) ? result : [];
    }, 'getAccessLists');
  }

  /**
   * Convert allowed_ips/denied_ips to items format for the API.
   */
  private convertAccessListData(data: CreateAccessListData | Partial<CreateAccessListData>): Record<string, unknown> {
    const apiData: Record<string, unknown> = { name: data.name };
    if (data.description !== undefined) apiData.description = data.description;
    if (data.satisfy_any !== undefined) apiData.satisfy_any = data.satisfy_any;
    if (data.pass_auth !== undefined) apiData.pass_auth = data.pass_auth;

    // If items are provided directly, use them
    if (data.items) {
      apiData.items = data.items;
    } else {
      // Convert allowed_ips/denied_ips to items format
      const items: Array<{ directive: string; address: string; sort_order: number }> = [];
      let sortOrder = 0;
      if (data.allowed_ips) {
        for (const ip of data.allowed_ips) {
          items.push({ directive: 'allow', address: ip, sort_order: sortOrder++ });
        }
      }
      if (data.denied_ips) {
        for (const ip of data.denied_ips) {
          items.push({ directive: 'deny', address: ip, sort_order: sortOrder++ });
        }
      }
      if (items.length > 0) {
        apiData.items = items;
      }
    }

    return apiData;
  }

  /**
   * Create a new access list.
   */
  async createAccessList(data: CreateAccessListData): Promise<AccessListData> {
    const apiData = this.convertAccessListData(data);
    const response = await this.request.post(API_ENDPOINTS.accessLists, {
      headers: this.getHeaders(),
      data: apiData,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create access list: ${error.error || response.status()}`);
    }

    const list = await response.json();
    this.createdAccessListIds.push(list.id);
    return list;
  }

  /**
   * Update an access list.
   */
  async updateAccessList(id: string, data: Partial<CreateAccessListData>): Promise<AccessListData> {
    const apiData = this.convertAccessListData(data);
    const response = await this.request.put(`${API_ENDPOINTS.accessLists}/${id}`, {
      headers: this.getHeaders(),
      data: apiData,
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
  async deleteAccessList(id: string): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.accessLists}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete access list: ${response.status()}`);
    }
  }

  /**
   * Clean up test access lists.
   * Errors during cleanup are logged but not thrown, to avoid cascade failures.
   */
  async cleanupTestAccessLists(_pattern?: RegExp): Promise<number> {
    let deleted = 0;

    // Only delete lists created by this instance (safe for parallel execution)
    for (const id of this.createdAccessListIds) {
      try {
        await this.deleteAccessList(id);
        deleted++;
      } catch {
        // List may already be deleted
      }
    }
    this.createdAccessListIds = [];
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
  async deleteCertificate(id: string): Promise<void> {
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
  async renewCertificate(id: string): Promise<CertificateData> {
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
  async revokeApiToken(id: string): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.apiTokens}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to revoke API token: ${response.status()}`);
    }
  }

  /**
   * Clean up test API tokens.
   * Errors during cleanup are logged but not thrown, to avoid cascade failures.
   */
  async cleanupTestApiTokens(pattern: RegExp = /test-.*token|e2e-token|readonly-token-|full-access-token-|expiring-token-|specific-perms-|copy-test-/i): Promise<number> {
    let tokens: ApiTokenData[];
    try {
      tokens = await this.getApiTokens();
    } catch {
      console.warn('cleanupTestApiTokens: failed to list API tokens, skipping cleanup');
      return 0;
    }
    let deleted = 0;

    for (const token of tokens) {
      if (pattern.test(token.name)) {
        try {
          await this.revokeApiToken(token.id);
          deleted++;
        } catch (error) {
          console.warn(`cleanupTestApiTokens: failed to revoke token ${token.id}: ${error}`);
        }
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

    const result = await response.json();
    // API returns paginated response: { data: [...], total, ... }
    // data may be null when no backups exist
    return result.data ?? [];
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
  async deleteBackup(id: string): Promise<void> {
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
    const response = await this.request.post(API_ENDPOINTS.accountPassword, {
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

  // ==================== System Settings ====================

  /**
   * Get system settings.
   */
  async getSystemSettings(): Promise<SystemSettingsData> {
    const response = await this.request.get(API_ENDPOINTS.systemSettings, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get system settings: ${response.status()}`);
    }

    return response.json();
  }

  /**
   * Update system settings.
   */
  async updateSystemSettings(data: Partial<SystemSettingsData>): Promise<SystemSettingsData> {
    const response = await this.request.put(API_ENDPOINTS.systemSettings, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to update system settings: ${error.error || response.status()}`);
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

    const result = await response.json();
    // API returns paginated response: { data: [...], total, ... }
    // data may be null when no banned IPs exist
    return result.data ?? [];
  }

  /**
   * Ban an IP address. Optionally specify proxy_host_id for host-specific ban.
   */
  async banIp(ip: string, reason?: string, proxyHostId?: string): Promise<void> {
    const data: Record<string, string | undefined> = { ip_address: ip, reason };
    if (proxyHostId) {
      data.proxy_host_id = proxyHostId;
    }
    const response = await this.request.post(API_ENDPOINTS.wafBannedIps, {
      headers: this.getHeaders(),
      data,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to ban IP: ${error.error || response.status()}`);
    }
  }

  /**
   * Sync all proxy host configs (triggers nginx config regeneration).
   */
  async syncAllConfigs(): Promise<{ test_success: boolean; reload_success: boolean }> {
    const response = await this.request.post(`${API_ENDPOINTS.proxyHosts}/sync`, {
      headers: this.getHeaders(),
      timeout: 30000,
    });
    if (!response.ok()) {
      throw new Error(`Failed to sync configs: ${response.status()}`);
    }
    return response.json();
  }

  /**
   * Unban an IP address by database ID.
   */
  async unbanIp(id: string): Promise<void> {
    const response = await this.request.delete(`${API_ENDPOINTS.wafBannedIps}/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to unban IP: ${response.status()}`);
    }
  }

  /**
   * Get WAF URI blocks (host-level).
   */
  async getWafUriBlocks(): Promise<WafUriBlockData[]> {
    return this.withRetry(async () => {
      const response = await this.request.get(API_ENDPOINTS.wafUriBlocks, {
        headers: this.getHeaders(),
      });

      if (!response.ok()) {
        throw new Error(`Failed to get WAF URI blocks: ${response.status()}`);
      }

      const data = await response.json();
      // Ensure we return an array
      return Array.isArray(data) ? data : [];
    }, 'getWafUriBlocks');
  }

  /**
   * Get global URI block settings (includes all global rules).
   */
  async getGlobalUriBlock(): Promise<{ rules: Array<{ id: string; pattern: string; match_type: string; description?: string; enabled: boolean }> }> {
    const response = await this.request.get('/api/v1/global-uri-block', {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      return { rules: [] };
    }

    return response.json();
  }

  /**
   * Create a global URI block rule.
   * Uses POST /api/v1/global-uri-block/rules endpoint.
   * The API returns the full GlobalURIBlock object, so we extract the matching rule.
   */
  async createWafUriBlock(data: CreateWafUriBlockData): Promise<WafUriBlockData> {
    // Translate is_regex convenience field to match_type
    const matchType = data.match_type || (data.is_regex ? 'regex' : 'prefix');
    const apiData = {
      pattern: data.pattern,
      match_type: matchType,
      description: data.description,
      enabled: data.enabled,
    };
    const response = await this.request.post('/api/v1/global-uri-block/rules', {
      headers: this.getHeaders(),
      data: apiData,
    });

    if (!response.ok()) {
      const error = await response.json();
      throw new Error(`Failed to create URI block: ${error.error || response.status()}`);
    }

    const block = await response.json();
    // API returns the full GlobalURIBlock with all rules; extract the newly added rule
    const rules: Array<{ id: string; pattern: string; match_type: string; description?: string; enabled: boolean }> = block.rules || [];
    const addedRule = rules.find(r => r.pattern === data.pattern) || rules[rules.length - 1];
    if (!addedRule) {
      throw new Error('Failed to find created URI block rule in response');
    }
    return {
      id: addedRule.id,
      pattern: addedRule.pattern,
      is_regex: addedRule.match_type === 'regex',
      description: addedRule.description,
      enabled: addedRule.enabled,
      created_at: block.created_at || '',
    };
  }

  /**
   * Delete a global URI block rule.
   * Uses DELETE /api/v1/global-uri-block/rules/:ruleId endpoint.
   */
  async deleteWafUriBlock(id: string): Promise<void> {
    const response = await this.request.delete(`/api/v1/global-uri-block/rules/${id}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete URI block: ${response.status()}`);
    }
  }

  /**
   * Get WAF exploit rules.
   * Backend returns { categories: [...], total_rules, global_exclusions }.
   */
  async getWafExploitRules(): Promise<WafExploitRulesResponse> {
    const response = await this.request.get(API_ENDPOINTS.wafExploitRules, {
      headers: this.getHeaders(),
    });

    if (!response.ok()) {
      throw new Error(`Failed to get WAF exploit rules: ${response.status()}`);
    }

    const result = await response.json();
    // API returns { categories: [...], total_rules, global_exclusions }
    // Normalize to always have categories array
    if (!result.categories) {
      return { categories: Array.isArray(result) ? result : [], total_rules: 0 };
    }
    return result;
  }

  /**
   * Test a WAF attack type.
   * Valid attack_type values: sql_injection, sql_injection_union, xss_script, xss_event,
   * path_traversal, path_traversal_encoded, command_injection, command_injection_pipe,
   * scanner_sqlmap, scanner_nikto, rce_php, protocol_attack
   */
  async testWafPayload(attackType: string, targetUrl?: string): Promise<WafTestResult> {
    const response = await this.request.post(API_ENDPOINTS.wafTest, {
      headers: this.getHeaders(),
      data: {
        target_url: targetUrl || 'http://localhost',
        attack_type: attackType,
      },
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
    return this.withRetry(async () => {
      const queryParams = new URLSearchParams();
      if (params?.perPage) queryParams.set('limit', params.perPage.toString());
      if (params?.page && params?.perPage) {
        queryParams.set('offset', ((params.page - 1) * params.perPage).toString());
      }

      const response = await this.request.get(`${API_ENDPOINTS.logsAudit}?${queryParams}`, {
        headers: this.getHeaders(),
      });

      if (!response.ok()) {
        throw new Error(`Failed to get audit logs: ${response.status()}`);
      }

      const result = await response.json();
      // API returns { logs: [...], total, limit, offset }
      return result.logs || [];
    }, 'getAuditLogs');
  }

  // ==================== Block-Reason Regression Helpers ====================
  //
  // The block_reason E2E spec needs to flip individual security features on a
  // per-host basis and then verify the resulting log row carries the right
  // reason. Each helper below maps a single feature to its actual API endpoint
  // (verified against api/internal/bootstrap/routes.go, NOT guessed) and uses
  // the smallest viable request body the handler accepts.
  //
  // Anything that creates a globally-scoped resource (banned IP, custom exploit
  // rule) is tracked so the per-spec teardown can roll it back — leaking a ban
  // would poison every subsequent test that uses the same IP.

  /**
   * Generic logs query used by pollForLog. Returns the rows array from
   * /api/v1/logs (paginated response shape: { data, total, page, per_page, ... }).
   *
   * IMPORTANT: filtering by `host` (domain) is more reliable than by
   * `proxy_host_id` for tests that just created a fresh host. The
   * log_collector's domain→host-id cache (`getHostIDByDomain`) refreshes only
   * every 60s, so freshly-created hosts may have proxy_host_id=NULL in their
   * rows for the first minute. The `host` field is set directly from the
   * nginx log line, so it's always populated.
   */
  async getLogs(params: {
    host_id?: string;
    host?: string;
    limit?: number;
    block_reason?: string;
  }): Promise<LogRow[]> {
    const qs = new URLSearchParams();
    if (params.host_id) qs.set('proxy_host_id', params.host_id);
    if (params.host) qs.set('host', params.host);
    if (params.limit) qs.set('per_page', params.limit.toString());
    if (params.block_reason) qs.set('block_reason', params.block_reason);
    qs.set('sort_by', 'timestamp');
    qs.set('sort_order', 'desc');
    const response = await this.request.get(`${API_ENDPOINTS.logs}?${qs.toString()}`, {
      headers: this.getHeaders(),
    });
    if (!response.ok()) {
      throw new Error(`Failed to get logs: ${response.status()}`);
    }
    const result = await response.json();
    return result.data ?? [];
  }

  /**
   * POST /api/v1/proxy-hosts/:id/geo  →  GeoHandler.SetForProxyHost.
   * Body: { mode: "whitelist"|"blacklist", countries: [...], challenge_mode?, enabled? }.
   */
  async setGeoRestriction(
    hostId: string,
    opts: {
      mode: 'whitelist' | 'blacklist';
      countries: string[];
      challengeMode?: boolean;
      allowPrivateIPs?: boolean;
      allowSearchBots?: boolean;
      enabled?: boolean;
    }
  ): Promise<void> {
    const body: Record<string, unknown> = {
      mode: opts.mode,
      countries: opts.countries,
      enabled: opts.enabled ?? true,
    };
    if (opts.challengeMode !== undefined) body.challenge_mode = opts.challengeMode;
    // Defaults that protect us from the e2e test machine accidentally bypassing
    // geo restriction via its own private IP — we *want* the restriction to fire.
    body.allow_private_ips = opts.allowPrivateIPs ?? false;
    body.allow_search_bots = opts.allowSearchBots ?? false;

    const response = await this.request.post(`${API_ENDPOINTS.proxyHosts}/${hostId}/geo`, {
      headers: this.getHeaders(),
      data: body,
    });
    if (!response.ok()) {
      const err = await response.text();
      throw new Error(`setGeoRestriction failed: ${response.status()} ${err}`);
    }
  }

  /**
   * Two-step: create access list, then assign it to the host via PUT /proxy-hosts/:id.
   * AccessListHandler.Create accepts { name, items: [{ directive, address, sort_order }] }.
   */
  async setAccessList(
    hostId: string,
    items: Array<{ directive: 'allow' | 'deny'; address: string }>
  ): Promise<string> {
    const list = await this.createAccessList({
      name: `acl-blockreason-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      items: items.map((it, i) => ({ directive: it.directive, address: it.address, sort_order: i })),
    });
    await this.updateProxyHost(hostId, { access_list_id: list.id } as Partial<CreateProxyHostData>);
    return list.id;
  }

  /**
   * POST /api/v1/banned-ips → SecurityHandler.BanIP. Body: { ip_address, proxy_host_id?, reason?, ban_time? }.
   * Tracks the returned ID so teardown can unban — otherwise a stale ban survives across tests.
   */
  async setBannedIPs(hostId: string, ips: string[]): Promise<string[]> {
    const ids: string[] = [];
    for (const ip of ips) {
      const response = await this.request.post(API_ENDPOINTS.wafBannedIps, {
        headers: this.getHeaders(),
        data: {
          ip_address: ip,
          proxy_host_id: hostId,
          reason: 'e2e block_reason regression',
          ban_time: 60,
        },
      });
      if (!response.ok()) {
        const err = await response.text();
        throw new Error(`setBannedIPs(${ip}) failed: ${response.status()} ${err}`);
      }
      const body = await response.json();
      if (body.id) {
        ids.push(body.id);
        this.bannedIpIds.push(body.id);
      }
    }
    return ids;
  }

  /**
   * Enable the host's `block_exploits` flag. The exploit detection rules come
   * from two sources:
   *   1. Custom rules in the `exploit_block_rules` table (POST /api/v1/exploit-rules).
   *   2. A hardcoded fallback set inside _security.conf.tmpl, which fires whenever
   *      `block_exploits=true` and no DB rules exist for the matching pattern_type
   *      (SQLI-FALLBACK-001, RFI-FALLBACK-001, SCAN-FALLBACK-001, METHOD-FALLBACK-001).
   *
   * The custom-rule endpoint currently returns 500 due to a pq prepared-statement
   * type-inference bug (`pq: inconsistent types deduced for parameter $1` — see
   * api/internal/repository/exploit_block_rule.go:Create where `$1` is reused in
   * both VALUES and a COALESCE subquery). Until that is fixed, the spec uses
   * the fallback patterns, which still exercise the block_reason="exploit_block"
   * code path in the template + log_collector.
   */
  async enableBlockExploits(hostId: string): Promise<void> {
    await this.updateProxyHost(hostId, { block_exploits: true } as Partial<CreateProxyHostData>);
  }

  /**
   * PUT /api/v1/proxy-hosts/:proxyHostId/bot-filter → SecurityHandler.UpsertBotFilter.
   * Body: { enabled, block_bad_bots?, block_ai_bots?, block_suspicious_clients?, custom_blocked_agents?, ... }.
   */
  async setBotFilter(
    hostId: string,
    opts: {
      blockBadBots?: boolean;
      blockAiBots?: boolean;
      blockSuspiciousClients?: boolean;
      allowSearchEngines?: boolean;
      customBlockedAgents?: string;
      customAllowedAgents?: string;
    }
  ): Promise<void> {
    const body: Record<string, unknown> = {
      enabled: true,
      // Default both off; the caller flips the one its test cares about. This
      // keeps each case's expected bot_category unambiguous.
      block_bad_bots: opts.blockBadBots ?? false,
      block_ai_bots: opts.blockAiBots ?? false,
      block_suspicious_clients: opts.blockSuspiciousClients ?? false,
      allow_search_engines: opts.allowSearchEngines ?? false,
    };
    if (opts.customBlockedAgents !== undefined) body.custom_blocked_agents = opts.customBlockedAgents;
    if (opts.customAllowedAgents !== undefined) body.custom_allowed_agents = opts.customAllowedAgents;

    const response = await this.request.put(`${API_ENDPOINTS.proxyHosts}/${hostId}/bot-filter`, {
      headers: this.getHeaders(),
      data: body,
    });
    if (!response.ok()) {
      const err = await response.text();
      throw new Error(`setBotFilter failed: ${response.status()} ${err}`);
    }
  }

  /**
   * PUT /api/v1/proxy-hosts/:proxyHostId/uri-block → SecurityHandler.UpsertURIBlock.
   */
  async setURIBlock(
    hostId: string,
    pattern: string,
    matchType: 'exact' | 'prefix' | 'regex' = 'prefix'
  ): Promise<void> {
    const body = {
      enabled: true,
      rules: [
        {
          pattern,
          match_type: matchType,
          description: 'e2e block_reason regression',
          enabled: true,
        },
      ],
    };
    const response = await this.request.put(`${API_ENDPOINTS.proxyHosts}/${hostId}/uri-block`, {
      headers: this.getHeaders(),
      data: body,
    });
    if (!response.ok()) {
      const err = await response.text();
      throw new Error(`setURIBlock failed: ${response.status()} ${err}`);
    }
  }

  /**
   * Flip waf_enabled on the proxy host (block_reason="waf" rows). Caller can
   * override mode/paranoia for ModSecurity testing variants.
   */
  async enableWAF(
    hostId: string,
    opts?: { mode?: 'detection' | 'blocking'; paranoiaLevel?: number; anomalyThreshold?: number }
  ): Promise<void> {
    const update: Record<string, unknown> = {
      waf_enabled: true,
      waf_mode: opts?.mode ?? 'blocking',
    };
    if (opts?.paranoiaLevel !== undefined) update.waf_paranoia_level = opts.paranoiaLevel;
    if (opts?.anomalyThreshold !== undefined) update.waf_anomaly_threshold = opts.anomalyThreshold;
    await this.updateProxyHost(hostId, update as Partial<CreateProxyHostData>);
  }

  /**
   * Roll back banned IPs created during the spec. Host-scoped state (geo,
   * access list, bot filter, URI block, block_exploits) is removed implicitly
   * when the host itself is deleted by cleanupTestHosts().
   */
  async cleanupBlockReasonState(): Promise<void> {
    for (const id of this.bannedIpIds) {
      try { await this.unbanIp(id); } catch { /* already gone */ }
    }
    this.bannedIpIds = [];
  }
}

// Shape of a row returned by /api/v1/logs — kept loose so the spec can assert
// on optional fields (bot_category, exploit_rule, geo_country_code) without
// failing on rows where the field is genuinely absent.
export interface LogRow {
  id: string;
  log_type?: string;
  timestamp?: string;
  host?: string;
  client_ip?: string;
  geo_country_code?: string;
  request_method?: string;
  request_uri?: string;
  status_code?: number;
  http_user_agent?: string;
  block_reason?: string;
  bot_category?: string;
  exploit_rule?: string;
  [key: string]: unknown;
}

// Type definitions
export interface ProxyHostData {
  id: string;
  domain_names: string[];
  forward_scheme: string;
  forward_host: string;
  forward_port: number;
  enabled: boolean;
  ssl_enabled: boolean;
  ssl_http2: boolean;
  ssl_http3: boolean;
  waf_enabled: boolean;
  waf_mode: string;
  created_at: string;
  updated_at: string;
  [key: string]: unknown; // allow additional fields
}

export interface CreateProxyHostData {
  domain_names: string[];
  forward_scheme: string;
  forward_host: string;
  forward_port: number;
  enabled?: boolean;
  ssl_enabled?: boolean;
  ssl_http2?: boolean;
  ssl_http3?: boolean;
  waf_enabled?: boolean;
  waf_mode?: string;
  [key: string]: unknown; // allow additional fields
}

export interface SyncResult {
  total_hosts: number;
  success_count: number;
  failed_count: number;
  hosts: Array<{ id: string; domain: string; success: boolean; error?: string }>;
  test_success: boolean;
  test_error?: string;
  reload_success: boolean;
}

export interface CertificateData {
  id: string;
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
  id: string;
  domain_names: string[];
  forward_domain_name: string;
  redirect_code: number;
  preserve_path: boolean;
  enabled: boolean;
  ssl_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRedirectHostData {
  domain_names: string[];
  forward_domain_name: string;
  redirect_code: number;
  preserve_path?: boolean;
  enabled?: boolean;
  ssl_enabled?: boolean;
}

// DNS Provider Types
export interface DnsProviderData {
  id: string;
  name: string;
  type: string;
  credentials: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateDnsProviderData {
  name: string;
  type?: string;
  provider_type?: string;
  credentials: Record<string, string>;
}

// Access List Types
export interface AccessListItemData {
  id?: string;
  access_list_id?: string;
  directive: string;  // "allow" or "deny"
  address: string;    // IP, CIDR, or "all"
  description?: string;
  sort_order?: number;
}

export interface AccessListData {
  id: string;
  name: string;
  description?: string;
  satisfy_any?: boolean;
  pass_auth?: boolean;
  items?: AccessListItemData[];
  created_at: string;
  updated_at: string;
}

export interface CreateAccessListData {
  name: string;
  description?: string;
  satisfy_any?: boolean;
  pass_auth?: boolean;
  items?: Array<{ directive: string; address: string; description?: string; sort_order?: number }>;
  // Legacy fields for convenience - converted to items before sending
  allowed_ips?: string[];
  denied_ips?: string[];
}

// Certificate Request Type
export interface RequestCertificateData {
  domains: string[];
  dns_provider_id?: string;
  email?: string;
}

// API Token Types
export interface ApiTokenData {
  id: string;
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
  id: string;
  filename: string;
  size: number;
  created_at: string;
}

// Account Types
export interface AccountData {
  id: string;
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
  proxy_buffering?: string;
  proxy_request_buffering?: string;
  global_trusted_ips?: string;

  // nginx.conf generation (issue #121)
  brotli_enabled?: boolean;
  custom_http_config?: string;
  custom_stream_config?: string;
  direct_ip_access_action?: string;
}

export interface SystemSettingsData {
  global_trusted_ips?: string;
  [key: string]: unknown;
}

// WAF Types
export interface WafBannedIpData {
  id: string;
  ip_address: string;
  proxy_host_id?: string;
  reason?: string;
  fail_count: number;
  banned_at: string;
  expires_at?: string;
  is_permanent: boolean;
  is_auto_banned: boolean;
  created_at: string;
}

export interface WafUriBlockData {
  id: string;
  pattern: string;
  is_regex: boolean;
  description?: string;
  enabled: boolean;
  created_at: string;
}

export interface CreateWafUriBlockData {
  pattern: string;
  match_type?: 'exact' | 'prefix' | 'regex';
  is_regex?: boolean;  // Convenience alias: when true, sets match_type to 'regex'
  description?: string;
  enabled?: boolean;
}

export interface WafExploitRuleData {
  id: string;
  name: string;
  pattern: string;
  enabled: boolean;
  category: string;
  globally_disabled?: boolean;
}

export interface WafExploitRuleCategoryData {
  id: string;
  name: string;
  description: string;
  rule_count: number;
  rules: WafExploitRuleData[];
}

export interface WafExploitRulesResponse {
  categories: WafExploitRuleCategoryData[];
  total_rules: number;
  global_exclusions?: Array<{ id: string; rule_id: string }>;
}

export interface WafTestResult {
  attack_type: string;
  test_url: string;
  status_code: number;
  blocked: boolean;
  response_time_ms: number;
  description: string;
}

// Log Types
export interface LogQueryParams {
  page?: number;
  perPage?: number;
  hostId?: string;
  startDate?: string;
  endDate?: string;
}

export interface LogEntry {
  id: string;
  host_id: string;
  remote_addr: string;
  request_uri: string;
  status: number;
  response_time: number;
  timestamp: string;
}

export interface AuditLogEntry {
  id: string;
  username: string;
  user_id?: string;
  action: string;
  action_label?: string;
  resource_type: string;
  resource_id?: string;
  resource_name?: string;
  details?: Record<string, unknown>;
  ip_address: string;
  user_agent?: string;
  timestamp?: string;
  created_at?: string;
}
