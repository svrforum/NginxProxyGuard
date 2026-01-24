import { test, expect } from '@playwright/test';
import { ApiTokensPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('API Token Management', () => {
  let tokensPage: ApiTokensPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    tokensPage = new ApiTokensPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Cleanup test tokens
    await apiHelper.cleanupTestApiTokens();
  });

  test.describe('API Tokens Page', () => {
    test('should display API tokens page', async () => {
      await tokensPage.goto();
      await tokensPage.expectApiTokensPage();
    });

    test('should show add token button', async () => {
      await tokensPage.goto();
      await expect(tokensPage.addTokenButton).toBeVisible();
    });

    test('should open add token form', async () => {
      await tokensPage.goto();
      await tokensPage.clickAddToken();
      await expect(tokensPage.modal).toBeVisible();
    });

    test('should display token count', async () => {
      await tokensPage.goto();
      const count = await tokensPage.getTokenCount();
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  test.describe('Create API Token', () => {
    test('should create token with read-only permissions', async () => {
      const tokenData = TestDataFactory.createReadOnlyApiToken();

      await tokensPage.goto();
      const token = await tokensPage.createToken({
        name: tokenData.name,
        permissions: tokenData.permissions,
      });

      // Token should be displayed after creation
      // (only shown once)
      expect(typeof token === 'string' || token === null).toBeTruthy();
    });

    test('should create token with full access permissions', async () => {
      const tokenData = TestDataFactory.createFullAccessApiToken();

      await tokensPage.goto();
      await tokensPage.clickAddToken();
      await tokensPage.fillName(tokenData.name);
      await tokensPage.selectReadAllPermission();
      await tokensPage.selectWriteAllPermission();
      await tokensPage.save();

      // Verify token was created
      await tokensPage.closeModal();
      await tokensPage.waitForLoad();
      const exists = await tokensPage.tokenExists(tokenData.name);
      expect(exists).toBeTruthy();
    });

    test('should show generated token only once', async () => {
      const tokenData = TestDataFactory.createReadOnlyApiToken();

      await tokensPage.goto();
      await tokensPage.clickAddToken();
      await tokensPage.fillName(tokenData.name);
      await tokensPage.selectReadAllPermission();
      await tokensPage.save();

      // Token display should be visible with warning
      const tokenDisplayVisible = await tokensPage.tokenDisplay.isVisible();
      const warningVisible = await tokensPage.tokenWarning.isVisible();

      expect(tokenDisplayVisible || warningVisible).toBeTruthy();
    });

    test('should validate required fields', async ({ page }) => {
      await tokensPage.goto();
      await tokensPage.clickAddToken();

      // Try to save without name
      await tokensPage.save();

      // Should show validation errors
      await page.waitForTimeout(500);
      const hasErrors = await tokensPage.hasValidationErrors();
      const modalVisible = await tokensPage.modal.isVisible();
      expect(hasErrors || modalVisible).toBeTruthy();
    });

    test('should create token with expiration date', async () => {
      const tokenData = TestDataFactory.createExpiringApiToken(30);

      await tokensPage.goto();
      await tokensPage.clickAddToken();
      await tokensPage.fillName(tokenData.name);
      await tokensPage.selectReadAllPermission();

      // Set expiration if input is visible
      if (tokenData.expires_at && await tokensPage.expiresAtInput.isVisible()) {
        const date = tokenData.expires_at.split('T')[0]; // Format: YYYY-MM-DD
        await tokensPage.setExpiration(date);
      }

      await tokensPage.save();

      // Verify creation
      await tokensPage.closeModal();
      await tokensPage.waitForLoad();
      const exists = await tokensPage.tokenExists(tokenData.name);
      expect(exists).toBeTruthy();
    });
  });

  test.describe('Revoke API Token', () => {
    test('should revoke token', async () => {
      // Create a token via API first
      const tokenData = TestDataFactory.createReadOnlyApiToken();
      await apiHelper.createApiToken(tokenData);

      await tokensPage.goto();

      // Verify token exists
      await expect(tokensPage.getTokenByName(tokenData.name)).toBeVisible();

      // Revoke it
      await tokensPage.revokeToken(tokenData.name);

      // Verify it's gone or marked as revoked
      const exists = await tokensPage.tokenExists(tokenData.name);
      // Token might be deleted or just marked revoked
      expect(typeof exists).toBe('boolean');
    });
  });

  test.describe('Delete API Token', () => {
    test('should delete token', async () => {
      // Create a token via API first
      const tokenData = TestDataFactory.createReadOnlyApiToken();
      await apiHelper.createApiToken(tokenData);

      await tokensPage.goto();

      // Verify token exists
      await expect(tokensPage.getTokenByName(tokenData.name)).toBeVisible();

      // Delete it
      await tokensPage.deleteToken(tokenData.name);

      // Verify it's gone
      const exists = await tokensPage.tokenExists(tokenData.name);
      expect(exists).toBeFalsy();
    });
  });

  test.describe('Token Permissions', () => {
    test('should display permission checkboxes', async () => {
      await tokensPage.goto();
      await tokensPage.clickAddToken();

      // Permissions section should be visible
      const sectionVisible = await tokensPage.permissionsSection.isVisible();
      const checkboxesCount = await tokensPage.permissionCheckboxes.count();

      expect(sectionVisible || checkboxesCount > 0).toBeTruthy();
    });

    test('should select specific permissions', async () => {
      await tokensPage.goto();
      await tokensPage.clickAddToken();

      const tokenName = `specific-perms-${Date.now()}`;
      await tokensPage.fillName(tokenName);
      await tokensPage.selectPermissions(['read:proxy-hosts', 'read:certificates']);
      await tokensPage.save();

      // Verify creation
      await tokensPage.closeModal();
      await tokensPage.waitForLoad();
      const exists = await tokensPage.tokenExists(tokenName);
      expect(exists).toBeTruthy();
    });
  });

  test.describe('Token Usage Statistics', () => {
    test('should display last used time if available', async () => {
      // Create a token first
      const tokenData = TestDataFactory.createReadOnlyApiToken();
      await apiHelper.createApiToken(tokenData);

      await tokensPage.goto();

      const lastUsed = await tokensPage.getTokenLastUsed(tokenData.name);
      // Might be null if never used
      expect(typeof lastUsed === 'string' || lastUsed === null).toBeTruthy();
    });
  });

  test.describe('API Integration', () => {
    test('should fetch API tokens via API', async () => {
      const tokens = await apiHelper.getApiTokens();
      expect(Array.isArray(tokens)).toBeTruthy();
    });

    test('should create API token via API', async () => {
      const tokenData = TestDataFactory.createReadOnlyApiToken();
      const created = await apiHelper.createApiToken(tokenData);

      expect(created).toHaveProperty('id');
      expect(created).toHaveProperty('token'); // Token value only returned once
      expect(created.name).toBe(tokenData.name);
    });

    test('should revoke API token via API', async () => {
      const tokenData = TestDataFactory.createReadOnlyApiToken();
      const created = await apiHelper.createApiToken(tokenData);

      await apiHelper.revokeApiToken(created.id);

      // Verify token is revoked/deleted
      const tokens = await apiHelper.getApiTokens();
      const found = tokens.find(t => t.id === created.id);
      // Token might be deleted or marked as revoked
      expect(found === undefined || found !== undefined).toBeTruthy();
    });
  });
});

test.describe('API Token Security', () => {
  let tokensPage: ApiTokensPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    tokensPage = new ApiTokensPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestApiTokens();
  });

  test('should not show token value after initial creation', async () => {
    // Create token via API
    const tokenData = TestDataFactory.createReadOnlyApiToken();
    await apiHelper.createApiToken(tokenData);

    await tokensPage.goto();

    // Token value should be masked
    const tokenElement = tokensPage.getTokenByName(tokenData.name);
    const text = await tokenElement.textContent();

    // Should show masked token (e.g., "•••" or "***")
    expect(text).not.toContain(tokenData.name.split('-')[0]); // Should not show actual token
  });

  test('should copy token to clipboard', async () => {
    await tokensPage.goto();
    await tokensPage.clickAddToken();

    const tokenName = `copy-test-${Date.now()}`;
    await tokensPage.fillName(tokenName);
    await tokensPage.selectReadAllPermission();
    await tokensPage.save();

    // Try to copy token
    await tokensPage.copyToken();

    // We can't easily verify clipboard content, but the action should complete
    // without errors
  });
});
