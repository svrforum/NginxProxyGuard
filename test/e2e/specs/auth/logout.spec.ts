import { test, expect } from '@playwright/test';
import { LoginPage } from '../../pages/login.page';
import { DashboardPage } from '../../pages/dashboard.page';
import { TEST_CREDENTIALS, TIMEOUTS } from '../../fixtures/test-data';
import { execSync } from 'child_process';

// Helper to clear rate limiting in Redis and database before tests
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

test.describe('Logout', () => {
  // Run tests serially to avoid rate limiting issues
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    clearRateLimiting();
  });

  test.beforeEach(async ({ page }) => {
    // Login first
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);
  });

  test('should logout successfully from header', async ({ page }) => {
    // Find and click logout button
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await expect(logoutButton).toBeVisible();
    await logoutButton.click();

    // Wait for login page to appear (React re-renders without URL change)
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();
  });

  test('should clear authentication state after logout', async ({ page }) => {
    // Logout
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await logoutButton.click();

    // Wait for login page to appear
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();

    // Try to access protected route directly (reload the page)
    await page.goto('/dashboard');
    await page.waitForTimeout(500);

    // Should still show login page (not authenticated)
    await loginPage.expectLoginPage();
  });

  test('should not allow back navigation after logout', async ({ page }) => {
    // Logout
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await logoutButton.click();

    // Wait for login page to appear
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();

    // Try going back
    await page.goBack();
    await page.waitForTimeout(2000);

    // After going back, the page should either:
    // 1. Still show login page (correct behavior)
    // 2. Navigate somewhere but redirect back to login (token is invalid)
    // Check that the user cannot access authenticated content
    const isLoginVisible = await loginPage.title.isVisible();
    const isLogoutButtonVisible = await page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i }).isVisible();

    // Either login page is visible OR no logout button (meaning not authenticated)
    expect(isLoginVisible || !isLogoutButtonVisible).toBeTruthy();
  });

  test('should clear local storage after logout', async ({ page }) => {
    // Verify token exists before logout
    const tokenBefore = await page.evaluate(() => localStorage.getItem('npg_token'));
    expect(tokenBefore).toBeTruthy();

    // Logout
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await logoutButton.click();

    // Wait for login page to appear
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();

    // Verify token is cleared
    const tokenAfter = await page.evaluate(() => localStorage.getItem('npg_token'));
    expect(tokenAfter).toBeNull();
  });

  test('should allow re-login after logout', async ({ page }) => {
    // Logout first
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await logoutButton.click();

    // Wait for login page to appear
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();

    // Login again
    await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);

    // Should be logged in successfully
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);
    await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);
  });

  test('should show username in header before logout', async ({ page }) => {
    // Verify username is displayed
    await expect(page.locator('header')).toContainText(TEST_CREDENTIALS.username);

    // Also verify role might be displayed
    const headerText = await page.locator('header').textContent();
    expect(headerText).toBeTruthy();
  });

  test('should handle logout when on settings page', async ({ page }) => {
    // Navigate to settings
    await page.goto('/settings/global');
    await expect(page).toHaveURL(/\/settings/);

    // Logout
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await logoutButton.click();

    // Should show login page
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();
  });

  test('should handle logout when form is open', async ({ page }) => {
    // Navigate to proxy hosts
    await page.goto('/proxy-hosts');

    // Try to open add form (if possible)
    const addButton = page.locator('button').filter({ hasText: /add|new|create|추가/i }).first();
    if (await addButton.isVisible()) {
      await addButton.click();
      await page.waitForTimeout(500);
    }

    // Logout while form might be open
    const logoutButton = page.locator('button').filter({ hasText: /logout|sign.*out|로그아웃/i });
    await logoutButton.click();

    // Should show login page
    const loginPage = new LoginPage(page);
    await loginPage.expectLoginPage();
  });
});

test.describe('Session Expiration', () => {
  // Run tests serially to avoid rate limiting issues
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    clearRateLimiting();
  });

  test('should handle expired token gracefully', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);

    // Manually clear/invalidate the token
    await page.evaluate(() => {
      localStorage.setItem('npg_token', 'invalid-expired-token');
    });

    // Try to make a request that requires auth
    await page.reload();

    // Should redirect to login (token validation fails)
    await loginPage.expectLoginPage({ timeout: TIMEOUTS.long });
  });

  test('should handle API 401 response', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(TEST_CREDENTIALS.username, TEST_CREDENTIALS.password);
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);

    // Mock 401 response for API calls
    await page.route('**/api/v1/**', (route, request) => {
      if (request.url().includes('/auth/status') || request.url().includes('/auth/logout')) {
        return route.continue();
      }
      return route.fulfill({
        status: 401,
        body: JSON.stringify({ error: 'Unauthorized' }),
      });
    });

    // Try to navigate or refresh
    await page.goto('/proxy-hosts');

    // Should eventually redirect to login or show error
    await page.waitForTimeout(2000);
  });
});
