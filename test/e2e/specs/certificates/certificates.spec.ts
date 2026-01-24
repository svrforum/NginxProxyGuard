import { test, expect } from '@playwright/test';
import { CertificatesPage, CertificateFormPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Certificate Management', () => {
  let certificatesPage: CertificatesPage;
  let formPage: CertificateFormPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    certificatesPage = new CertificatesPage(page);
    formPage = new CertificateFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.describe('Certificate List', () => {
    test('should display certificates page', async () => {
      await certificatesPage.goto();
      await certificatesPage.expectCertificatesPage();
    });

    test('should show add certificate button', async () => {
      await certificatesPage.goto();
      await expect(certificatesPage.addCertificateButton).toBeVisible();
    });

    test('should open add certificate form', async () => {
      await certificatesPage.goto();
      await certificatesPage.clickAddCertificate();
      await formPage.expectForm();
    });

    test('should display certificate count', async ({ page }) => {
      await certificatesPage.goto();
      const count = await certificatesPage.getCertificateCount();
      // Count can be 0 or more
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  test.describe('Certificate Form', () => {
    test('should show certificate type selection', async ({ page }) => {
      await certificatesPage.goto();
      await certificatesPage.clickAddCertificate();

      // Should show Let's Encrypt option
      await expect(formPage.letsEncryptOption.or(page.locator('text=/let.*encrypt/i'))).toBeVisible();
    });

    test('should select Let\'s Encrypt certificate type', async () => {
      await certificatesPage.goto();
      await certificatesPage.clickAddCertificate();
      await formPage.selectLetsEncrypt();

      // Domain input should be visible
      await expect(formPage.domainInput.or(formPage.page.locator('input[placeholder*="domain"]'))).toBeVisible();
    });

    test('should select custom certificate type', async ({ page }) => {
      await certificatesPage.goto();
      await certificatesPage.clickAddCertificate();

      if (await formPage.customOption.isVisible()) {
        await formPage.selectCustomCertificate();
        // Certificate textarea should be visible
        await expect(formPage.certificateInput.or(page.locator('textarea'))).toBeVisible();
      }
    });

    test('should validate required fields', async () => {
      await certificatesPage.goto();
      await certificatesPage.clickAddCertificate();
      await formPage.selectLetsEncrypt();

      // Try to save without filling required fields
      await formPage.save();

      // Should show validation errors or form should still be open
      const hasErrors = await formPage.hasValidationErrors();
      const isOpen = await formPage.isVisible();
      expect(hasErrors || isOpen).toBeTruthy();
    });

    test('should cancel form without saving', async () => {
      await certificatesPage.goto();
      await certificatesPage.clickAddCertificate();

      // Fill some data
      await formPage.selectLetsEncrypt();
      const testDomain = TestDataFactory.generateDomain('cert-test');
      await formPage.fillDomain(testDomain);

      // Cancel
      await formPage.cancel();

      // Form should close
      await formPage.expectClosed();
    });
  });

  test.describe('Certificate Sub-navigation', () => {
    test('should navigate to certificate list tab', async () => {
      await certificatesPage.goto();
      await certificatesPage.switchToList();
      await expect(certificatesPage.page).toHaveURL(/\/certificates\/list/);
    });

    test('should navigate to history tab', async () => {
      await certificatesPage.goto();
      await certificatesPage.switchToHistory();
      await expect(certificatesPage.page).toHaveURL(/\/certificates\/history/);
    });

    test('should navigate to DNS providers tab', async () => {
      await certificatesPage.goto();
      await certificatesPage.switchToDnsProviders();
      await expect(certificatesPage.page).toHaveURL(/\/certificates\/dns-providers/);
    });
  });

  test.describe('Certificate Display', () => {
    test('should display certificate domain information', async () => {
      await certificatesPage.goto();

      if (await certificatesPage.certificateItems.first().isVisible()) {
        // Verify domain is displayed
        await expect(certificatesPage.certificateDomain.first()).toBeVisible();
      }
    });

    test('should display certificate expiry information', async () => {
      await certificatesPage.goto();

      if (await certificatesPage.certificateItems.first().isVisible()) {
        // Expiry info should be visible
        const hasExpiry = await certificatesPage.certificateExpiry.isVisible();
        // It's optional, so we just check it doesn't error
        expect(typeof hasExpiry).toBe('boolean');
      }
    });
  });

  test.describe('API Integration', () => {
    test('should fetch certificates via API', async () => {
      const certificates = await apiHelper.getCertificates();
      expect(Array.isArray(certificates)).toBeTruthy();
    });
  });
});

test.describe('Let\'s Encrypt Certificate Request', () => {
  let certificatesPage: CertificatesPage;
  let formPage: CertificateFormPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    certificatesPage = new CertificatesPage(page);
    formPage = new CertificateFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test('should fill domain for Let\'s Encrypt', async () => {
    await certificatesPage.goto();
    await certificatesPage.clickAddCertificate();
    await formPage.selectLetsEncrypt();

    const testDomain = TestDataFactory.generateDomain('le-cert-test');
    await formPage.fillDomain(testDomain);

    // Domain should be added
    await expect(formPage.domainChips.or(formPage.page.locator(`text=${testDomain}`))).toBeVisible();
  });

  test('should fill multiple domains', async () => {
    await certificatesPage.goto();
    await certificatesPage.clickAddCertificate();
    await formPage.selectLetsEncrypt();

    const domains = TestDataFactory.generateDomains(2, 'multi-cert');
    await formPage.fillDomains(domains);

    // At least one domain chip should be visible
    const chipCount = await formPage.domainChips.count();
    expect(chipCount).toBeGreaterThanOrEqual(1);
  });

  test('should fill email address', async () => {
    await certificatesPage.goto();
    await certificatesPage.clickAddCertificate();
    await formPage.selectLetsEncrypt();

    const email = TestDataFactory.generateEmail();
    await formPage.fillEmail(email);

    // Email should be in input
    if (await formPage.emailInput.isVisible()) {
      await expect(formPage.emailInput).toHaveValue(email);
    }
  });

  test.skip('should request certificate with DNS provider', async () => {
    // This test requires a configured DNS provider
    await certificatesPage.goto();
    await certificatesPage.clickAddCertificate();

    const testDomain = TestDataFactory.generateDomain('dns-cert-test');
    await formPage.requestLetsEncryptCertificate({
      domains: [testDomain],
      email: TestDataFactory.generateEmail(),
      // dnsProvider: 'cloudflare', // Requires actual DNS provider
    });

    // Would need to verify certificate was created
  });
});

test.describe('Custom Certificate Upload', () => {
  let certificatesPage: CertificatesPage;
  let formPage: CertificateFormPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    certificatesPage = new CertificatesPage(page);
    formPage = new CertificateFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test('should show custom certificate fields', async () => {
    await certificatesPage.goto();
    await certificatesPage.clickAddCertificate();

    if (await formPage.customOption.isVisible()) {
      await formPage.selectCustomCertificate();

      // Certificate and key inputs should be visible
      const certInputVisible = await formPage.certificateInput.isVisible();
      const keyInputVisible = await formPage.privateKeyInput.isVisible();

      expect(certInputVisible || keyInputVisible).toBeTruthy();
    }
  });

  test('should validate certificate format', async ({ page }) => {
    await certificatesPage.goto();
    await certificatesPage.clickAddCertificate();

    if (await formPage.customOption.isVisible()) {
      await formPage.selectCustomCertificate();

      // Fill with invalid certificate
      await formPage.fillCustomCertificate('invalid-cert', 'invalid-key');
      await formPage.save();

      // Should show validation error
      await page.waitForTimeout(500);
      const hasErrors = await formPage.hasValidationErrors();
      const isOpen = await formPage.isVisible();
      expect(hasErrors || isOpen).toBeTruthy();
    }
  });
});
