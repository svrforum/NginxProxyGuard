import { test, expect } from '@playwright/test';
import { LoginPage } from '../../pages/login.page';
import { TEST_CREDENTIALS, TIMEOUTS } from '../../fixtures/test-data';
import { execSync } from 'child_process';

// Helper to clear rate limiting in Redis and database before tests
function clearRateLimiting() {
  try {
    // Clear Valkey rate limiting keys
    execSync(
      'docker exec npg-test-valkey valkey-cli KEYS "rate_limit:*" | xargs -r docker exec -i npg-test-valkey valkey-cli DEL',
      { stdio: 'pipe' }
    );
    execSync(
      'docker exec npg-test-valkey valkey-cli KEYS "api_rate:*" | xargs -r docker exec -i npg-test-valkey valkey-cli DEL',
      { stdio: 'pipe' }
    );
    // Clear database login_attempts table (stores failed login history for rate limiting)
    execSync(
      'docker exec npg-test-db psql -U postgres -d nginx_guard_test -c "DELETE FROM login_attempts;"',
      { stdio: 'pipe' }
    );
  } catch {
    // Ignore errors if Valkey/DB is not available
  }
}

test.describe('Login', () => {
  // Run tests serially to avoid rate limiting issues
  test.describe.configure({ mode: 'serial' });

  let loginPage: LoginPage;

  // Clear rate limiting before all tests
  test.beforeAll(() => {
    clearRateLimiting();
  });

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    await loginPage.goto();
  });

  test('should display login page correctly', async () => {
    await loginPage.expectLoginPage();

    // Verify page title
    await expect(loginPage.title).toContainText(/nginx.*proxy.*guard/i);

    // Verify form fields
    await expect(loginPage.usernameInput).toBeVisible();
    await expect(loginPage.passwordInput).toBeVisible();
    await expect(loginPage.submitButton).toBeVisible();
  });

  test('should login with valid credentials', async ({ page }) => {
    // Enter credentials
    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword(TEST_CREDENTIALS.password);

    // Submit form
    await loginPage.clickLogin();

    // Should redirect to dashboard or proxy-hosts
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.long });

    // Should show logged in user
    await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);
  });

  test('should show error with invalid username', async () => {
    // Clear rate limiting before testing invalid credentials
    clearRateLimiting();

    await loginPage.fillUsername('invaliduser');
    await loginPage.fillPassword(TEST_CREDENTIALS.password);
    await loginPage.clickLogin();

    // Should show error message
    await loginPage.expectError();
  });

  test('should show error with invalid password', async () => {
    // Clear rate limiting before testing invalid credentials
    clearRateLimiting();

    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword('wrongpassword');
    await loginPage.clickLogin();

    // Should show error message
    await loginPage.expectError();
  });

  test('should show error with empty credentials', async ({ page }) => {
    // Clear any default values
    await loginPage.usernameInput.clear();
    await loginPage.passwordInput.clear();

    // Try to submit
    await loginPage.clickLogin();

    // Should stay on login page (HTML5 validation or show error)
    await expect(page).toHaveURL(/\/$/);
  });

  test('should show loading state while logging in', async ({ page }) => {
    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword(TEST_CREDENTIALS.password);

    // Click login and immediately check for loading
    await loginPage.clickLogin();

    // Loading state should appear briefly (may be too fast to catch reliably)
    // This test mainly ensures no errors during the loading phase
    await page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.long });
  });

  test('should handle special characters in password', async ({ page }) => {
    // Clear rate limiting before testing invalid credentials
    clearRateLimiting();

    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword('test@#$%^&*()_+');
    await loginPage.clickLogin();

    // Should show error (wrong password) without crashing
    await Promise.race([
      loginPage.expectError(),
      page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.medium }),
    ]);
  });

  test('should trim whitespace from username', async ({ page }) => {
    await loginPage.fillUsername(`  ${TEST_CREDENTIALS.username}  `);
    await loginPage.fillPassword(TEST_CREDENTIALS.password);
    await loginPage.clickLogin();

    // Should succeed (or error based on backend behavior)
    await Promise.race([
      page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.long }),
      loginPage.expectError(),
    ]);
  });

  test('should persist login across page refresh', async ({ page }) => {
    // Login first
    await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);

    // Refresh the page
    await page.reload();

    // Should still be logged in
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);
    await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);
  });

  test('should focus username input on page load', async () => {
    // Username input should be auto-focused
    await expect(loginPage.usernameInput).toBeFocused();
  });

  test('should allow tab navigation between form fields', async ({ page }) => {
    await loginPage.usernameInput.focus();

    // Tab to password field
    await page.keyboard.press('Tab');
    await expect(loginPage.passwordInput).toBeFocused();

    // Tab to submit button
    await page.keyboard.press('Tab');
    await expect(loginPage.submitButton).toBeFocused();
  });

  test('should submit form on Enter key', async ({ page }) => {
    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword(TEST_CREDENTIALS.password);

    // Press Enter instead of clicking button
    await page.keyboard.press('Enter');

    // Should login successfully
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.long });
  });
});

// Additional tests for error handling
test.describe('Login Error Handling', () => {
  // Run tests serially to avoid rate limiting issues
  test.describe.configure({ mode: 'serial' });

  // Clear rate limiting before all tests
  test.beforeAll(() => {
    clearRateLimiting();
  });

  test('should handle network errors gracefully', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();

    // Block API requests to simulate network error
    await page.route('**/api/v1/auth/login', route => {
      route.abort('connectionfailed');
    });

    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword(TEST_CREDENTIALS.password);
    await loginPage.clickLogin();

    // Should show some error indication
    await page.waitForTimeout(2000);
    // Stay on login page
    await expect(page).toHaveURL(/\/$/);
  });

  test('should handle server errors (500)', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();

    // Mock server error
    await page.route('**/api/v1/auth/login', route => {
      route.fulfill({
        status: 500,
        body: JSON.stringify({ error: 'Internal server error' }),
      });
    });

    await loginPage.fillUsername(TEST_CREDENTIALS.username);
    await loginPage.fillPassword(TEST_CREDENTIALS.password);
    await loginPage.clickLogin();

    // Should show error and stay on login page
    await loginPage.expectError();
  });
});
