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
 * Perform login without waiting for navigation (for handling InitialSetup)
 */
async function submitLogin(loginPage: LoginPage, username: string, password: string): Promise<void> {
  await loginPage.fillUsername(username);
  await loginPage.fillPassword(password);
  await loginPage.clickLogin();
  // Wait for response (either navigation, error, or InitialSetup page)
  await loginPage.page.waitForLoadState('networkidle');
  await loginPage.page.waitForTimeout(2000);
}

/**
 * Check if we're on the InitialSetup page
 */
async function isOnInitialSetupPage(page: import('@playwright/test').Page): Promise<boolean> {
  // Wait a moment for React to render
  await page.waitForTimeout(1000);

  const currentPasswordInput = page.locator('input#currentPassword');
  const newUsernameInput = page.locator('input#newUsername');

  const hasCurrentPassword = await currentPasswordInput.isVisible().catch(() => false);
  const hasNewUsername = await newUsernameInput.isVisible().catch(() => false);

  return hasCurrentPassword && hasNewUsername;
}

/**
 * Check if we're on the dashboard or proxy-hosts page (logged in)
 */
async function isLoggedIn(page: import('@playwright/test').Page): Promise<boolean> {
  const url = page.url();
  return url.includes('/dashboard') || url.includes('/proxy-hosts');
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
  console.log('Completing InitialSetup...');

  // Wait for the form to be ready
  await page.waitForSelector('input#currentPassword', { state: 'visible', timeout: 10000 });
  await page.waitForSelector('input#newUsername', { state: 'visible', timeout: 10000 });
  await page.waitForSelector('input#newPassword', { state: 'visible', timeout: 10000 });
  await page.waitForSelector('input#confirmPassword', { state: 'visible', timeout: 10000 });

  // Fill in the InitialSetup form
  await page.fill('input#currentPassword', currentPassword);
  await page.fill('input#newUsername', newUsername);
  await page.fill('input#newPassword', newPassword);
  await page.fill('input#confirmPassword', newPassword);

  // Submit the form
  const submitButton = page.locator('button[type="submit"]');
  await submitButton.click();

  // Wait for the setup to complete and return to login page
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(3000);

  console.log('InitialSetup completed, current URL:', page.url());
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
  console.log('Starting authentication setup at URL:', page.url());

  // First, try to login with test credentials (in case InitialSetup was already done)
  console.log('Attempting login with test credentials:', TEST_CREDENTIALS.username);
  await submitLogin(loginPage, TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);

  console.log('After login attempt, URL:', page.url());

  // Check if we successfully logged in
  if (await isLoggedIn(page)) {
    console.log('Successfully logged in with test credentials');
    await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username, { timeout: 10000 });
    await page.context().storageState({ path: authFile });
    return;
  }

  // Check if we got an error (wrong credentials)
  const hasError = await page.locator('.bg-red-50, .text-red-500').isVisible().catch(() => false);
  console.log('Login error visible:', hasError);

  // Test credentials didn't work, try with default admin credentials
  console.log('Test credentials failed, trying default admin credentials:', DEFAULT_ADMIN_CREDENTIALS.username);
  clearRateLimiting();

  await loginPage.goto();
  await submitLogin(loginPage, DEFAULT_ADMIN_CREDENTIALS.username, DEFAULT_ADMIN_CREDENTIALS.password);

  console.log('After default login attempt, URL:', page.url());

  // Check if we're on the InitialSetup page
  const onInitialSetup = await isOnInitialSetupPage(page);
  console.log('Is on InitialSetup page:', onInitialSetup);

  if (onInitialSetup) {
    console.log('InitialSetup page detected, completing setup...');

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
    console.log('Logging in with new credentials after setup:', TEST_CREDENTIALS.username);
    await loginPage.goto();
    await submitLogin(loginPage, TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);
  } else if (await isLoggedIn(page)) {
    // We're logged in with admin/admin (no InitialSetup required)
    console.log('Logged in directly with admin credentials');
    await page.context().storageState({ path: authFile });
    return;
  }

  console.log('Final URL after all login attempts:', page.url());

  // Wait for successful navigation to dashboard or proxy-hosts
  await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/, { timeout: 30000 });
  console.log('Successfully navigated to:', page.url());

  // Verify logged in state
  await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username, { timeout: 10000 });

  // Save signed-in state to the specified file
  await page.context().storageState({ path: authFile });
  console.log('Authentication state saved');
});
