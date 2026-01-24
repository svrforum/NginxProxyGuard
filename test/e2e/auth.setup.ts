import { test as setup, expect } from '@playwright/test';
import { TEST_CREDENTIALS, DEFAULT_ADMIN_CREDENTIALS } from './fixtures/test-data';
import { LoginPage } from './pages/login.page';
import { execSync } from 'child_process';

const authFile = 'playwright/.auth/user.json';

// Clear rate limiting before auth setup
function clearRateLimiting() {
  try {
    execSync(
      'docker exec npg-test-db psql -U postgres -d nginx_guard_test -c "DELETE FROM login_attempts;"',
      { stdio: 'pipe' }
    );
  } catch {
    // Ignore errors
  }
}

/**
 * Check if we're on the InitialSetup page by looking for specific elements
 */
async function isInitialSetupPage(page: import('@playwright/test').Page): Promise<boolean> {
  // Check for elements unique to InitialSetup page
  const currentPasswordInput = page.locator('input#currentPassword');
  const newUsernameInput = page.locator('input#newUsername');

  try {
    await Promise.race([
      currentPasswordInput.waitFor({ state: 'visible', timeout: 3000 }),
      page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: 3000 }),
    ]);

    return await currentPasswordInput.isVisible() && await newUsernameInput.isVisible();
  } catch {
    return false;
  }
}

/**
 * Complete the InitialSetup form
 */
async function completeInitialSetup(
  page: import('@playwright/test').Page,
  currentPassword: string,
  newUsername: string,
  newPassword: string
): Promise<void> {
  // Fill in the InitialSetup form
  await page.fill('input#currentPassword', currentPassword);
  await page.fill('input#newUsername', newUsername);
  await page.fill('input#newPassword', newPassword);
  await page.fill('input#confirmPassword', newPassword);

  // Submit the form
  await page.click('button[type="submit"]');

  // Wait for the setup to complete (redirects to login page)
  await page.waitForURL('/', { timeout: 30000 });
}

/**
 * Authentication setup - runs once before all tests.
 * Handles both fresh install (InitialSetup) and existing credentials.
 * Logs in and saves the authentication state to a file.
 */
setup('authenticate', async ({ page }) => {
  // Clear any rate limiting before attempting login
  clearRateLimiting();

  const loginPage = new LoginPage(page);

  // Navigate to login page
  await loginPage.goto();

  // First, try to login with test credentials (in case InitialSetup was already done)
  await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);

  // Wait a moment for the page to respond
  await page.waitForTimeout(2000);

  // Check if we successfully logged in
  const url = page.url();
  if (url.includes('/dashboard') || url.includes('/proxy-hosts')) {
    // Already set up, verify logged in state
    await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);
    await page.context().storageState({ path: authFile });
    return;
  }

  // Check if login failed (still on login page with error)
  const loginError = page.locator('[data-testid="login-error"], .text-red-500, .bg-red-50');
  const hasLoginError = await loginError.isVisible().catch(() => false);

  if (hasLoginError || url === '/' || url.endsWith('/')) {
    // Login with test credentials failed, try with default admin credentials
    clearRateLimiting();

    // Clear form and retry with default credentials
    await loginPage.goto();
    await loginPage.login(DEFAULT_ADMIN_CREDENTIALS.username, DEFAULT_ADMIN_CREDENTIALS.password);

    // Wait for page to settle
    await page.waitForTimeout(2000);

    // Check if we're on the InitialSetup page
    if (await isInitialSetupPage(page)) {
      // Complete the initial setup with new test credentials
      await completeInitialSetup(
        page,
        DEFAULT_ADMIN_CREDENTIALS.password,
        TEST_CREDENTIALS.username,
        TEST_CREDENTIALS.password
      );

      // Clear rate limiting again before final login
      clearRateLimiting();

      // Now login with the new test credentials
      await loginPage.goto();
      await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);
    }
  }

  // Wait for successful navigation to dashboard or proxy-hosts
  await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/, { timeout: 30000 });

  // Verify logged in state
  await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);

  // Save signed-in state to the specified file
  await page.context().storageState({ path: authFile });
});
