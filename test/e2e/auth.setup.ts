import { test as setup, expect } from '@playwright/test';
import { TEST_CREDENTIALS } from './fixtures/test-data';
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
 * Authentication setup - runs once before all tests.
 * Logs in and saves the authentication state to a file.
 */
setup('authenticate', async ({ page }) => {
  // Clear any rate limiting before attempting login
  clearRateLimiting();

  const loginPage = new LoginPage(page);

  // Navigate to login page
  await loginPage.goto();

  // Perform login
  await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);

  // Wait for successful navigation to dashboard or proxy-hosts
  await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);

  // Verify logged in state
  await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);

  // Save signed-in state to the specified file
  await page.context().storageState({ path: authFile });
});
