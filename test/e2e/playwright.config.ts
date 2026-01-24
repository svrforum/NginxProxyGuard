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

  // Retry on CI only (increased for flaky tests)
  retries: process.env.CI ? 2 : 0,

  // Use single worker on CI to avoid rate limiting issues
  workers: process.env.CI ? 1 : undefined,

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

    // Collect trace when retrying the failed test (disabled on CI for speed)
    trace: process.env.CI ? 'off' : 'on-first-retry',

    // Capture screenshot on failure
    screenshot: 'only-on-failure',

    // Record video on failure (disabled on CI for speed)
    video: process.env.CI ? 'off' : 'on-first-retry',

    // Default timeout for actions
    actionTimeout: 15000,

    // Default timeout for navigation
    navigationTimeout: 30000,
  },

  // Global timeout for each test (reduced for CI)
  timeout: process.env.CI ? 45000 : 60000,

  // Expect timeout
  expect: {
    timeout: process.env.CI ? 8000 : 10000,
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

    // Unauthenticated tests (login, etc.) - run serially to avoid rate limiting
    {
      name: 'chromium-no-auth',
      use: { ...devices['Desktop Chrome'] },
      testMatch: /.*\/(login|logout)\.spec\.ts/,
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
