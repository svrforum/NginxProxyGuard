import { test as base, expect } from '@playwright/test';
import { TEST_CREDENTIALS, ROUTES, API_ENDPOINTS } from './test-data';
import { LoginPage } from '../pages/login.page';

/**
 * Extended test fixture with authentication support.
 */
export const test = base.extend<{
  authenticatedPage: typeof base;
}>({
  authenticatedPage: async ({ page }, use) => {
    // Login before the test
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);

    // Wait for dashboard to load
    await page.waitForURL(/\/(dashboard|proxy-hosts)/);

    await use(base);
  },
});

/**
 * Setup authentication state for use across tests.
 * This runs once and saves the auth state to a file.
 */
export async function globalSetup(page: ReturnType<typeof base['request']>['page']) {
  // Perform login via API
  const response = await page.request.post(API_ENDPOINTS.login, {
    data: {
      username: TEST_CREDENTIALS.username,
      password: TEST_CREDENTIALS.password,
    },
  });

  if (!response.ok()) {
    throw new Error(`Login failed: ${response.status()}`);
  }

  const data = await response.json();

  // Save auth state
  await page.context().storageState({ path: 'playwright/.auth/user.json' });

  return data.token;
}

export { expect };
