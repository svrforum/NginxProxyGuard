import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for Nginx Proxy Guard E2E tests.
 *
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  // Test directory
  testDir: './specs',

  // Run tests in files in parallel (disabled on CI for stability)
  fullyParallel: process.env.CI ? false : true,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Retry flaky tests (parallel execution can cause timing issues)
  retries: process.env.CI ? 2 : 1,

  // Limit workers to prevent OOM and test state contention.
  // CI: 1 worker for stability
  // Local: 2 workers (4 causes flakes in proxy-host/sync, waf, global-trusted-ips
  //                    specs due to shared DB/nginx state; 2 is the stable sweet spot)
  // Override via PLAYWRIGHT_WORKERS env if needed.
  workers: process.env.CI
    ? 1
    : process.env.PLAYWRIGHT_WORKERS
      ? Number(process.env.PLAYWRIGHT_WORKERS)
      : 2,

  // Reporter to use
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list'],
    ...(process.env.CI ? [['github' as const]] : []),
  ],

  // Shared settings for all the projects below
  use: {
    // Base URL to use in actions like `await page.goto('/')`
    baseURL: process.env.BASE_URL || 'https://localhost:18181',

    // Ignore HTTPS errors for self-signed certificates
    ignoreHTTPSErrors: true,

    // Collect trace only on CI retry - traces consume significant memory/disk
    trace: 'off',

    // Capture screenshot on failure
    screenshot: 'only-on-failure',

    // Video recording disabled - consumes significant memory per worker
    video: 'off',

    // Default timeout for actions
    actionTimeout: 10000,

    // Default timeout for navigation
    navigationTimeout: 30000,
  },

  // Global timeout for each test
  timeout: 45000,

  // Expect timeout
  expect: {
    timeout: 7000,
  },

  // Configure projects for major browsers
  projects: [
    // Setup project for authentication (looks in root e2e directory)
    {
      name: 'setup',
      testDir: '.',
      testMatch: /auth\.setup\.ts/,
    },

    // Main browser tests - Chromium only for speed and stability
    // Excludes login/logout tests which run in chromium-no-auth
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
      testIgnore: /.*\/(login|logout)\.spec\.ts/,
    },

    // Unauthenticated tests (login, etc.) - run serially AFTER setup to avoid rate limiting
    {
      name: 'chromium-no-auth',
      use: { ...devices['Desktop Chrome'] },
      testMatch: /.*\/(login|logout)\.spec\.ts/,
      dependencies: ['setup'],
      fullyParallel: false,
    },
  ],

  // Run local dev server before starting the tests (optional)
  // webServer: {
  //   command: 'cd ../.. && docker compose -f test/compose.yml up',
  //   url: 'http://localhost:18180',
  //   reuseExistingServer: !process.env.CI,
  //   timeout: 120000,
  // },

  // Output folder for test artifacts
  outputDir: 'test-results',
});
