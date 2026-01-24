import {
  CreateProxyHostData,
  CreateRedirectHostData,
  CreateAccessListData,
  CreateDnsProviderData,
  CreateApiTokenData,
  CreateWafUriBlockData,
} from './api-helper';

/**
 * Factory for generating test data.
 * Uses timestamps and random values to ensure uniqueness.
 */
export class TestDataFactory {
  /**
   * Generate a unique domain name for testing.
   */
  static generateDomain(prefix: string = 'test-e2e'): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `${prefix}-${timestamp}-${random}.example.local`;
  }

  /**
   * Generate multiple unique domain names.
   */
  static generateDomains(count: number = 2, prefix: string = 'test-e2e'): string[] {
    return Array.from({ length: count }, () => this.generateDomain(prefix));
  }

  /**
   * Generate a valid proxy host configuration.
   */
  static createProxyHost(overrides: Partial<CreateProxyHostData> = {}): CreateProxyHostData {
    return {
      domain_names: [this.generateDomain()],
      forward_scheme: 'http',
      forward_host: '192.168.1.100',
      forward_port: 8080,
      enabled: true,
      ssl_enabled: false,
      http2_enabled: false,
      http3_enabled: false,
      waf_enabled: false,
      bot_filter_enabled: false,
      geoip_enabled: false,
      ...overrides,
    };
  }

  /**
   * Generate a proxy host with SSL enabled.
   */
  static createSSLProxyHost(overrides: Partial<CreateProxyHostData> = {}): CreateProxyHostData {
    return this.createProxyHost({
      domain_names: [this.generateDomain('secure-e2e')],
      ssl_enabled: true,
      http2_enabled: true,
      http3_enabled: false, // HTTP/3 may need special setup
      ...overrides,
    });
  }

  /**
   * Generate a proxy host with WAF enabled.
   */
  static createWAFProxyHost(overrides: Partial<CreateProxyHostData> = {}): CreateProxyHostData {
    return this.createProxyHost({
      domain_names: [this.generateDomain('waf-e2e')],
      waf_enabled: true,
      waf_mode: 'DetectionOnly',
      ...overrides,
    });
  }

  /**
   * Generate a proxy host with full security settings.
   */
  static createSecureProxyHost(overrides: Partial<CreateProxyHostData> = {}): CreateProxyHostData {
    return this.createProxyHost({
      domain_names: [this.generateDomain('full-security-e2e')],
      ssl_enabled: true,
      http2_enabled: true,
      waf_enabled: true,
      waf_mode: 'On',
      bot_filter_enabled: true,
      geoip_enabled: false, // GeoIP needs license key
      ...overrides,
    });
  }

  /**
   * Generate invalid proxy host data for testing validation.
   */
  static createInvalidProxyHost(): Partial<CreateProxyHostData> {
    return {
      domain_names: [], // Invalid: empty domain names
      forward_scheme: 'http',
      forward_host: '', // Invalid: empty host
      forward_port: -1, // Invalid: negative port
    };
  }

  /**
   * Generate random IP address.
   */
  static generateIP(): string {
    const octet = () => Math.floor(Math.random() * 254) + 1;
    return `192.168.${octet()}.${octet()}`;
  }

  /**
   * Generate random port number.
   */
  static generatePort(min: number = 1024, max: number = 65535): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  /**
   * Generate test email address.
   */
  static generateEmail(): string {
    const timestamp = Date.now();
    return `test-${timestamp}@example.local`;
  }

  /**
   * Generate batch of proxy hosts for load testing.
   */
  static createProxyHostBatch(count: number): CreateProxyHostData[] {
    return Array.from({ length: count }, () => this.createProxyHost());
  }

  /**
   * Create config variations for parameterized tests.
   */
  static getProxyHostVariations(): CreateProxyHostData[] {
    return [
      // Basic HTTP proxy
      this.createProxyHost(),
      // HTTPS proxy
      this.createSSLProxyHost(),
      // WAF-enabled proxy
      this.createWAFProxyHost(),
      // Fully secured proxy
      this.createSecureProxyHost(),
      // Multi-domain proxy
      this.createProxyHost({
        domain_names: this.generateDomains(3, 'multi-domain-e2e'),
      }),
      // Custom port proxy
      this.createProxyHost({
        forward_port: 3000,
        domain_names: [this.generateDomain('custom-port-e2e')],
      }),
      // HTTPS upstream proxy
      this.createProxyHost({
        forward_scheme: 'https',
        forward_port: 443,
        domain_names: [this.generateDomain('https-upstream-e2e')],
      }),
    ];
  }

  // ==================== Redirect Hosts ====================

  /**
   * Generate a valid redirect host configuration.
   */
  static createRedirectHost(overrides: Partial<CreateRedirectHostData> = {}): CreateRedirectHostData {
    return {
      domain_names: [this.generateDomain('redirect-e2e')],
      forward_domain: 'https://target.example.com',
      redirect_code: 301,
      preserve_path: true,
      enabled: true,
      ssl_enabled: false,
      ...overrides,
    };
  }

  /**
   * Generate a temporary redirect host (302).
   */
  static createTemporaryRedirect(overrides: Partial<CreateRedirectHostData> = {}): CreateRedirectHostData {
    return this.createRedirectHost({
      domain_names: [this.generateDomain('temp-redirect-e2e')],
      redirect_code: 302,
      preserve_path: false,
      ...overrides,
    });
  }

  /**
   * Generate a permanent redirect with SSL (308).
   */
  static createSecureRedirect(overrides: Partial<CreateRedirectHostData> = {}): CreateRedirectHostData {
    return this.createRedirectHost({
      domain_names: [this.generateDomain('secure-redirect-e2e')],
      redirect_code: 308,
      ssl_enabled: true,
      ...overrides,
    });
  }

  /**
   * Create redirect host variations for parameterized tests.
   */
  static getRedirectHostVariations(): CreateRedirectHostData[] {
    return [
      this.createRedirectHost({ redirect_code: 301 }),
      this.createRedirectHost({ redirect_code: 302 }),
      this.createRedirectHost({ redirect_code: 307 }),
      this.createRedirectHost({ redirect_code: 308 }),
      this.createRedirectHost({ preserve_path: true }),
      this.createRedirectHost({ preserve_path: false }),
    ];
  }

  // ==================== Access Lists ====================

  /**
   * Generate a valid access list configuration.
   */
  static createAccessList(overrides: Partial<CreateAccessListData> = {}): CreateAccessListData {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 6);
    return {
      name: `test-acl-${timestamp}-${random}`,
      allowed_ips: ['192.168.1.0/24'],
      denied_ips: [],
      ...overrides,
    };
  }

  /**
   * Generate an access list with both allow and deny rules.
   */
  static createMixedAccessList(overrides: Partial<CreateAccessListData> = {}): CreateAccessListData {
    return this.createAccessList({
      name: `mixed-acl-${Date.now()}`,
      allowed_ips: ['192.168.1.0/24', '10.0.0.0/8'],
      denied_ips: ['192.168.1.100', '192.168.1.200'],
      ...overrides,
    });
  }

  /**
   * Generate an access list that denies all except specified IPs.
   */
  static createWhitelistOnlyAccessList(ips: string[]): CreateAccessListData {
    return this.createAccessList({
      name: `whitelist-acl-${Date.now()}`,
      allowed_ips: ips,
      denied_ips: ['0.0.0.0/0'],
    });
  }

  /**
   * Generate invalid access list data for testing validation.
   */
  static createInvalidAccessList(): Partial<CreateAccessListData> {
    return {
      name: '', // Invalid: empty name
      allowed_ips: ['invalid-ip'], // Invalid IP format
    };
  }

  // ==================== DNS Providers ====================

  /**
   * Generate a Cloudflare DNS provider configuration.
   */
  static createCloudflareDnsProvider(overrides: Partial<CreateDnsProviderData> = {}): CreateDnsProviderData {
    const timestamp = Date.now();
    return {
      name: `cf-provider-${timestamp}`,
      type: 'cloudflare',
      credentials: {
        api_token: 'test-cloudflare-api-token-123',
      },
      ...overrides,
    };
  }

  /**
   * Generate a DuckDNS provider configuration.
   */
  static createDuckDnsProvider(overrides: Partial<CreateDnsProviderData> = {}): CreateDnsProviderData {
    const timestamp = Date.now();
    return {
      name: `duckdns-provider-${timestamp}`,
      type: 'duckdns',
      credentials: {
        token: 'test-duckdns-token-456',
      },
      ...overrides,
    };
  }

  /**
   * Generate a Dynu DNS provider configuration.
   */
  static createDynuDnsProvider(overrides: Partial<CreateDnsProviderData> = {}): CreateDnsProviderData {
    const timestamp = Date.now();
    return {
      name: `dynu-provider-${timestamp}`,
      type: 'dynu',
      credentials: {
        username: 'testuser',
        password: 'testpass',
      },
      ...overrides,
    };
  }

  /**
   * Generate DNS provider variations for parameterized tests.
   */
  static getDnsProviderVariations(): CreateDnsProviderData[] {
    return [
      this.createCloudflareDnsProvider(),
      this.createDuckDnsProvider(),
      this.createDynuDnsProvider(),
    ];
  }

  // ==================== API Tokens ====================

  /**
   * Generate a read-only API token configuration.
   */
  static createReadOnlyApiToken(overrides: Partial<CreateApiTokenData> = {}): CreateApiTokenData {
    const timestamp = Date.now();
    return {
      name: `readonly-token-${timestamp}`,
      permissions: ['read:proxy-hosts', 'read:certificates', 'read:logs'],
      ...overrides,
    };
  }

  /**
   * Generate a full-access API token configuration.
   */
  static createFullAccessApiToken(overrides: Partial<CreateApiTokenData> = {}): CreateApiTokenData {
    const timestamp = Date.now();
    return {
      name: `full-access-token-${timestamp}`,
      permissions: ['read:*', 'write:*'],
      ...overrides,
    };
  }

  /**
   * Generate an API token with specific permissions.
   */
  static createApiToken(
    name: string,
    permissions: string[],
    overrides: Partial<CreateApiTokenData> = {}
  ): CreateApiTokenData {
    const timestamp = Date.now();
    return {
      name: `${name}-${timestamp}`,
      permissions,
      ...overrides,
    };
  }

  /**
   * Generate an API token with expiration.
   */
  static createExpiringApiToken(expiresInDays: number = 7): CreateApiTokenData {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);
    return {
      name: `expiring-token-${Date.now()}`,
      permissions: ['read:*'],
      expires_at: expiresAt.toISOString(),
    };
  }

  // ==================== WAF URI Blocks ====================

  /**
   * Generate a WAF URI block rule.
   */
  static createWafUriBlock(overrides: Partial<CreateWafUriBlockData> = {}): CreateWafUriBlockData {
    return {
      pattern: '/admin/*',
      is_regex: false,
      description: 'Test URI block rule',
      enabled: true,
      ...overrides,
    };
  }

  /**
   * Generate a regex-based WAF URI block rule.
   */
  static createRegexUriBlock(overrides: Partial<CreateWafUriBlockData> = {}): CreateWafUriBlockData {
    return {
      pattern: '\\.(php|asp|aspx)$',
      is_regex: true,
      description: 'Block script extensions',
      enabled: true,
      ...overrides,
    };
  }

  // ==================== Test Payloads ====================

  /**
   * Generate SQL injection test payloads.
   */
  static getSqlInjectionPayloads(): string[] {
    return [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "1' AND '1'='1",
      "UNION SELECT * FROM users",
      "admin'--",
    ];
  }

  /**
   * Generate XSS test payloads.
   */
  static getXssPayloads(): string[] {
    return [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '"><script>alert(1)</script>',
      "javascript:alert('XSS')",
      '<svg onload=alert(1)>',
    ];
  }

  /**
   * Generate path traversal test payloads.
   */
  static getPathTraversalPayloads(): string[] {
    return [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '....//....//....//etc/passwd',
    ];
  }

  /**
   * Generate safe/benign test payloads.
   */
  static getSafePayloads(): string[] {
    return [
      'Hello World',
      'user@example.com',
      '/api/v1/users',
      '{"name": "test"}',
      'SELECT * FROM products WHERE id = 1',
    ];
  }
}
