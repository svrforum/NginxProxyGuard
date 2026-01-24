/**
 * Test data constants for E2E tests.
 */

// Default admin credentials (default for fresh install)
export const DEFAULT_ADMIN_CREDENTIALS = {
  username: 'admin',
  password: 'admin',
} as const;

// Test credentials after initial setup (used by all tests)
export const TEST_CREDENTIALS = {
  username: process.env.TEST_USERNAME || 'testadmin',
  password: process.env.TEST_PASSWORD || 'TestAdmin123!',
} as const;

// API endpoints
export const API_ENDPOINTS = {
  // Auth
  login: '/api/v1/auth/login',
  logout: '/api/v1/auth/logout',
  status: '/api/v1/auth/status',

  // Proxy Hosts
  proxyHosts: '/api/v1/proxy-hosts',

  // Redirect Hosts
  redirectHosts: '/api/v1/redirect-hosts',

  // Certificates
  certificates: '/api/v1/certificates',
  certificatesRequest: '/api/v1/certificates/request',
  certificatesRenew: '/api/v1/certificates/renew',

  // DNS Providers
  dnsProviders: '/api/v1/dns-providers',

  // Access Lists
  accessLists: '/api/v1/access-lists',

  // WAF
  wafSettings: '/api/v1/waf/settings',
  wafBannedIps: '/api/v1/waf/banned-ips',
  wafUriBlocks: '/api/v1/waf/uri-blocks',
  wafExploitRules: '/api/v1/waf/exploit-rules',
  wafFail2ban: '/api/v1/waf/fail2ban',
  wafTest: '/api/v1/waf/test',

  // Logs
  logs: '/api/v1/logs',
  logsAccess: '/api/v1/logs/access',
  logsWaf: '/api/v1/logs/waf',
  logsAudit: '/api/v1/logs/audit',
  logsBotFilter: '/api/v1/logs/bot-filter',
  logsExploitBlocks: '/api/v1/logs/exploit-blocks',
  logsSystem: '/api/v1/logs/system',

  // Settings
  settingsGlobal: '/api/v1/settings/global',
  settingsBackups: '/api/v1/settings/backups',
  settingsCaptcha: '/api/v1/settings/captcha',
  settingsGeoip: '/api/v1/settings/geoip',
  settingsBotfilter: '/api/v1/settings/botfilter',
  settingsWafAutoBan: '/api/v1/settings/waf-auto-ban',
  settingsSsl: '/api/v1/settings/ssl',
  settingsMaintenance: '/api/v1/settings/maintenance',

  // API Tokens
  apiTokens: '/api/v1/api-tokens',

  // Account
  account: '/api/v1/account',
  accountPassword: '/api/v1/account/password',
  account2fa: '/api/v1/account/2fa',

  // Health
  health: '/health',
} as const;

// UI routes
export const ROUTES = {
  // Auth
  login: '/',

  // Main sections
  dashboard: '/dashboard',
  proxyHosts: '/proxy-hosts',
  redirectHosts: '/redirect-hosts',

  // WAF
  wafSettings: '/waf/settings',
  wafBannedIps: '/waf/banned-ips',
  wafUriBlocks: '/waf/uri-blocks',
  wafExploitRules: '/waf/exploit-rules',
  wafFail2ban: '/waf/fail2ban',
  wafTester: '/waf/tester',

  // Access
  accessLists: '/access/lists',

  // Certificates
  certificatesList: '/certificates/list',
  certificatesHistory: '/certificates/history',
  certificatesDnsProviders: '/certificates/dns-providers',

  // Logs
  logsAccess: '/logs/access',
  logsWafEvents: '/logs/waf-events',
  logsBotFilter: '/logs/bot-filter',
  logsExploitBlocks: '/logs/exploit-blocks',
  logsSystem: '/logs/system',
  logsAudit: '/logs/audit',
  logsRawFiles: '/logs/raw-files',

  // Settings
  settingsGlobal: '/settings/global',
  settingsAccount: '/settings/account',
  settingsApiTokens: '/settings/api-tokens',
  settingsCaptcha: '/settings/captcha',
  settingsGeoip: '/settings/geoip',
  settingsBotfilter: '/settings/botfilter',
  settingsWafAutoBan: '/settings/waf-auto-ban',
  settingsSsl: '/settings/ssl',
  settingsMaintenance: '/settings/maintenance',
  settingsBackups: '/settings/backups',
  settingsSystemLogs: '/settings/system-logs',
  settingsSecurityHeaders: '/settings/security-headers',
  settingsRateLimiting: '/settings/rate-limiting',
  settingsChallenge: '/settings/challenge',
} as const;

// Test proxy host data templates
export const TEST_PROXY_HOST = {
  // Valid proxy host configuration
  valid: {
    domain: 'test-e2e-{timestamp}.example.local',
    forwardHost: '192.168.1.100',
    forwardPort: 8080,
    forwardScheme: 'http' as const,
  },
  // HTTPS proxy host configuration
  https: {
    domain: 'secure-e2e-{timestamp}.example.local',
    forwardHost: '192.168.1.100',
    forwardPort: 443,
    forwardScheme: 'https' as const,
  },
  // Invalid configuration for error testing
  invalid: {
    domain: '',
    forwardHost: '',
    forwardPort: -1,
  },
} as const;

// Test redirect host data templates
export const TEST_REDIRECT_HOST = {
  valid: {
    domain: 'redirect-e2e-{timestamp}.example.local',
    forwardDomain: 'https://target.example.com',
    redirectCode: 301 as const,
    preservePath: true,
  },
  temporary: {
    domain: 'temp-redirect-e2e-{timestamp}.example.local',
    forwardDomain: 'https://temp-target.example.com',
    redirectCode: 302 as const,
    preservePath: false,
  },
  invalid: {
    domain: '',
    forwardDomain: '',
    redirectCode: 999,
  },
} as const;

// Test access list data templates
export const TEST_ACCESS_LIST = {
  valid: {
    name: 'test-acl-{timestamp}',
    allowedIps: ['192.168.1.0/24', '10.0.0.1'],
    deniedIps: ['0.0.0.0/0'],
  },
  allowOnly: {
    name: 'allow-only-{timestamp}',
    allowedIps: ['192.168.1.100'],
    deniedIps: [],
  },
  denyOnly: {
    name: 'deny-only-{timestamp}',
    allowedIps: [],
    deniedIps: ['192.168.1.200', '192.168.1.201'],
  },
} as const;

// Test DNS provider data templates
export const TEST_DNS_PROVIDER = {
  cloudflare: {
    name: 'test-cf-{timestamp}',
    type: 'cloudflare' as const,
    apiToken: 'test-api-token-123',
  },
  duckdns: {
    name: 'test-duck-{timestamp}',
    type: 'duckdns' as const,
    token: 'test-duck-token-456',
  },
  dynu: {
    name: 'test-dynu-{timestamp}',
    type: 'dynu' as const,
    username: 'testuser',
    password: 'testpass',
  },
} as const;

// Test API token data templates
export const TEST_API_TOKEN = {
  readOnly: {
    name: 'test-readonly-token-{timestamp}',
    permissions: ['read:proxy-hosts', 'read:certificates'],
  },
  fullAccess: {
    name: 'test-full-token-{timestamp}',
    permissions: ['read:*', 'write:*'],
  },
} as const;

// Redirect codes
export const REDIRECT_CODES = {
  permanent: 301,
  temporary: 302,
  seeOther: 303,
  temporaryRedirect: 307,
  permanentRedirect: 308,
} as const;

// DNS Provider types
export const DNS_PROVIDER_TYPES = [
  'cloudflare',
  'duckdns',
  'dynu',
  'godaddy',
  'route53',
  'digitalocean',
] as const;

// Common timeouts (in milliseconds)
export const TIMEOUTS = {
  short: 5000,
  medium: 10000,
  long: 30000,
  veryLong: 60000,
} as const;

// WAF modes
export const WAF_MODES = {
  detection: 'DetectionOnly',
  blocking: 'On',
  off: 'Off',
} as const;

// Paranoia levels
export const PARANOIA_LEVELS = [1, 2, 3, 4] as const;

// SSL certificate types
export const SSL_TYPES = {
  none: 'none',
  letsencrypt: 'letsencrypt',
  custom: 'custom',
} as const;

// Test selectors (data-testid attributes)
export const TEST_IDS = {
  // Login page
  loginForm: 'login-form',
  usernameInput: 'username-input',
  passwordInput: 'password-input',
  loginButton: 'login-button',
  loginError: 'login-error',

  // Navigation
  navDashboard: 'nav-dashboard',
  navProxyHosts: 'nav-proxy-hosts',
  navWaf: 'nav-waf',
  navCertificates: 'nav-certificates',
  navLogs: 'nav-logs',
  navSettings: 'nav-settings',

  // Proxy hosts
  addProxyHostButton: 'add-proxy-host',
  proxyHostList: 'proxy-host-list',
  proxyHostItem: 'proxy-host-item',
  proxyHostForm: 'proxy-host-form',
  proxyHostDomainInput: 'proxy-host-domain',
  proxyHostForwardHostInput: 'proxy-host-forward-host',
  proxyHostForwardPortInput: 'proxy-host-forward-port',
  proxyHostSaveButton: 'proxy-host-save',
  proxyHostDeleteButton: 'proxy-host-delete',

  // Header actions
  syncAllButton: 'sync-all-button',
  darkModeToggle: 'dark-mode-toggle',
  userMenuButton: 'user-menu',
  logoutButton: 'logout-button',
} as const;
