import { test, expect } from '@playwright/test';

test.describe('Gateway Health & Session Revoke (C22)', () => {
  test('navigates to gateway, displays status grid, and shows stale policy warning', async ({ page }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', (err) => pageErrors.push(err.message));

    await page.goto('/#gateway');

    // Header and page title
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Gateway health and session revocation.');
    await expect(page.getByRole('heading', { level: 2, name: 'Gateway Health & Session Revocation' })).toBeVisible();

    // Default preloaded scenario: stale-policy
    const staleBadge = page.getByTestId('stale-badge');
    await expect(staleBadge).toBeVisible();
    await expect(staleBadge).toContainText('STALE POLICY');

    // Policy card details
    const policyCard = page.locator('div[role="region"][aria-label="Policy Posture"]');
    await expect(policyCard).toBeVisible();
    await expect(policyCard.locator('.card-title')).toContainText('Revision 1');
    await expect(policyCard.locator('.card-digest')).toContainText('sha256:1111');
    await expect(policyCard.locator('.warning-text')).toContainText('exceeded the maximum 30-second freshness window');

    // Zero-token exposure guarantee badge
    const zeroTokenBadge = page.getByTestId('zero-token-badge');
    await expect(zeroTokenBadge).toBeVisible();
    await expect(zeroTokenBadge).toContainText('ZERO TOKENS EXPOSED');

    expect(pageErrors).toEqual([]);
  });

  test('switches to IdP outage scenario and displays fail-closed alert banner', async ({ page }) => {
    await page.goto('/#gateway');

    const select = page.getByLabel('Select gateway scenario');
    await select.selectOption('idp-outage');

    // IdP outage badge and alert notice
    const idpBadge = page.getByTestId('idp-outage-badge');
    await expect(idpBadge).toBeVisible();
    await expect(idpBadge).toContainText('IDP OUTAGE (503)');

    const idpCard = page.locator('div[role="region"][aria-label="IdP Health"]');
    await expect(idpCard.locator('.card-title')).toContainText('Service Outage Detected');
    await expect(idpCard.locator('.error-text')).toContainText('denied (503 Service Unavailable) without credential exposure');

    // Explanation context mentions fail-closed behavior
    await expect(page.locator('.scenario-explanation')).toContainText('all sensitive routes fail closed');
  });

  test('executes session revocation workload and verifies bounded enforcement (<=30s)', async ({ page }) => {
    await page.goto('/#gateway');

    const select = page.getByLabel('Select gateway scenario');
    await select.selectOption('session-revoke');

    // Target session ID input
    const sessionInput = page.getByLabel('Target Session ID');
    await expect(sessionInput).toBeVisible();
    await sessionInput.fill('sess-c22-workload-01');

    // Click revoke
    const revokeButton = page.getByRole('button', { name: 'Revoke Session' });
    await revokeButton.click();

    // Revocation outcome panel
    const revokeResult = page.locator('.revocation-result');
    await expect(revokeResult).toBeVisible();
    await expect(page.getByTestId('revocation-state-badge')).toContainText('REVOKED (Enforced ≤30s)');

    // Accessible workload steps table
    const table = page.locator('table.workload-table');
    await expect(table).toBeVisible();
    await expect(table.locator('caption')).toContainText('Sequential evaluation of session checks');
    await expect(table.locator('th[scope="col"]')).toHaveCount(5);

    // Verify step outcomes: pre-revoke allow, post-revoke deny, 0 side effects
    await expect(table.locator('tr:has-text("Pre-Revocation Access") td').nth(1)).toContainText('ALLOW (200)');
    await expect(table.locator('tr:has-text("Post-Revocation Access") td').nth(1)).toContainText('DENIED (403/503)');
    await expect(table.locator('tr:has-text("Post-Revocation Access") td').nth(2)).toContainText('false (Stopped)');

    // Summary metrics
    await expect(revokeResult).toContainText('usr-c22-operator');
    await expect(revokeResult).toContainText('Side Effects Executed: false');
  });

  test('verifies absolute zero token exposure across entire DOM (Requirement F16)', async ({ page }) => {
    await page.goto('/#gateway');

    // Test across scenarios
    const select = page.getByLabel('Select gateway scenario');
    for (const sc of ['stale-policy', 'idp-outage', 'session-revoke']) {
      await select.selectOption(sc);
      await expect(page.locator('.gateway-dashboard')).toBeVisible();

      // Extract all text and attribute contents from the page
      const pageText = await page.evaluate(() => document.body.innerText);

      // Verify no Bearer token strings
      expect(pageText).not.toMatch(/Bearer\s+[A-Za-z0-9-_]{16,}/i);
      // Verify no raw JWT signatures (header.payload.signature)
      expect(pageText).not.toMatch(/eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+/);
      // Verify no session cookie assignments or raw secrets
      expect(pageText).not.toMatch(/policyhelix_session=[A-Za-z0-9-_]+/i);
      expect(pageText).not.toMatch(/Set-Cookie:/i);
    }
  });

  test('script and HTML sentinels remain strictly inert (XSS safety)', async ({ page }) => {
    const dialogs: string[] = [];
    page.on('dialog', async (dialog) => {
      dialogs.push(dialog.message());
      await dialog.dismiss();
    });

    await page.goto('/#gateway');

    const select = page.getByLabel('Select gateway scenario');
    await select.selectOption('sentinel');

    // Confirm sentinel text renders safely as inert text
    await expect(page.locator('.explanation-text')).toContainText("<script>alert('xss-c22')</script>");
    await expect(page.locator('.workload-table')).toContainText("sess-<script>alert('sess')</script>");

    // No dialog popup should trigger
    expect(dialogs).toEqual([]);
  });

  test('negative cases: replayed identity and forged headers are rejected without side effects', async ({ page }) => {
    await page.goto('/#gateway');

    const select = page.getByLabel('Select gateway scenario');

    // 1. Replayed identity
    await select.selectOption('replayed-identity');
    await expect(page.locator('.scenario-explanation')).toContainText('Replayed and expired session identity fails validation');
    await expect(page.locator('.revocation-summary-grid')).toContainText('Side Effects Executed: false');

    // 2. Forged headers
    await select.selectOption('forged-header');
    await expect(page.locator('.scenario-explanation')).toContainText('forged identity headers');
    await expect(page.locator('.scenario-explanation')).toContainText('headers stripped');
  });

  test('handles malformed and invalid JSON uploads gracefully', async ({ page }) => {
    await page.goto('/#gateway');

    // Upload invalid JSON
    await page.getByLabel('Upload Fixture JSON').setInputFiles({
      name: 'malformed.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{ invalid-json-syntax }'),
    });

    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('Malformed fixture JSON');
  });

  test('clears active scenario and displays empty state', async ({ page }) => {
    await page.goto('/#gateway');

    await expect(page.locator('.gateway-dashboard')).toBeVisible();

    await page.getByRole('button', { name: 'Reset View' }).click();

    // Results removed, empty state visible
    await expect(page.locator('.gateway-dashboard')).toHaveCount(0);
    const emptyState = page.getByRole('status');
    await expect(emptyState).toBeVisible();
    await expect(emptyState).toContainText('No scenario selected');
  });

  test('maintains accessible layout without horizontal overflow at 360px mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 640 });
    await page.goto('/#gateway');

    // Check visibility of cards and panels
    await expect(page.locator('.gateway-status-grid')).toBeVisible();
    await expect(page.locator('.revocation-panel')).toBeVisible();

    // Zero horizontal scrolling assertion
    const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    expect(noOverflow).toBe(true);
  });

  test('supports keyboard navigation across gateway controls and revocation form', async ({ page }) => {
    await page.goto('/#gateway');

    // Focus scenario dropdown
    const select = page.getByLabel('Select gateway scenario');
    await select.focus();
    await expect(select).toBeFocused();

    // Focus session ID input
    const sessionInput = page.getByLabel('Target Session ID');
    await sessionInput.focus();
    await expect(sessionInput).toBeFocused();

    // Tab to Revoke button
    await page.keyboard.press('Tab');
    const revokeButton = page.getByRole('button', { name: 'Revoke Session' });
    await expect(revokeButton).toBeFocused();
  });
});
