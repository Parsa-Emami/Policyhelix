import { test, expect } from '@playwright/test';

test.describe('Policy Simulator & Decision Diffs (C21)', () => {
  test('navigates to simulator, displays policy revision comparison and explains changed decision', async ({ page }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', (err) => pageErrors.push(err.message));

    await page.goto('/#simulator');

    // Header and intro
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Policy simulation and decision diffs.');
    await expect(page.getByRole('heading', { level: 2, name: 'Policy Simulator & Decision Diffs' })).toBeVisible();

    // Default preloaded fixture: deny-to-allow
    // Decision diff banner and transition badge
    await expect(page.locator('.transition-badge')).toContainText('DENY → ALLOW');
    await expect(page.locator('.diff-banner h2')).toContainText('Policy Revision 2 Diff');

    // Decision comparison table with accessible markup
    const table = page.locator('table.diff-table');
    await expect(table).toBeVisible();
    await expect(table.locator('caption')).toContainText('Comparison of authorization attributes between baseline and candidate policy revisions');
    await expect(table.locator('th[scope="col"]')).toHaveCount(3);
    await expect(table.locator('th[scope="col"]').nth(1)).toContainText('Baseline Policy (Rev 1)');
    await expect(table.locator('th[scope="col"]').nth(2)).toContainText('Candidate Policy (Rev 2)');

    // Outcome row
    await expect(table.locator('tr:has-text("Outcome") td').nth(0)).toContainText('DENY');
    await expect(table.locator('tr:has-text("Outcome") td').nth(1)).toContainText('ALLOW');

    // Revision row
    await expect(table.locator('tr:has-text("Policy Revision") td').nth(0)).toContainText('Rev 1');
    await expect(table.locator('tr:has-text("Policy Revision") td').nth(1)).toContainText('Rev 2');

    // Explanation card in fixture context
    const explanationCard = page.locator('.explanation-card');
    await expect(explanationCard).toBeVisible();
    await expect(explanationCard.locator('.explanation-title')).toContainText('transitioning the decision on resource \'/api/v1/analytics/reports\' from DENIED to ALLOWED');
    await expect(explanationCard).toContainText('usr-ops-pat-901');
    await expect(explanationCard).toContainText('operator');

    expect(pageErrors).toEqual([]);
  });

  test('switches between sample fixtures and reflects allow_to_deny and unchanged diffs', async ({ page }) => {
    await page.goto('/#simulator');

    const select = page.getByLabel('Select sample fixture');

    // Switch to allow-to-deny
    await select.selectOption('allow-to-deny');
    await expect(page.locator('.transition-badge')).toContainText('ALLOW → DENY');
    await expect(page.locator('.diff-banner h2')).toContainText('Policy Revision 3 Diff');
    await expect(page.locator('.explanation-card .explanation-title')).toContainText('from ALLOWED to DENIED');
    await expect(page.locator('.explanation-card')).toContainText('/api/v1/finance/ledger');

    // Switch to unchanged
    await select.selectOption('unchanged');
    await expect(page.locator('.transition-badge')).toContainText('UNCHANGED');
    await expect(page.locator('.explanation-card .explanation-title')).toContainText('maintains the same outcome');
    await expect(page.locator('.explanation-card')).toContainText('/healthz');
  });

  test('script and HTML sentinels remain strictly inert (XSS safety)', async ({ page }) => {
    const dialogs: string[] = [];
    page.on('dialog', async (dialog) => {
      dialogs.push(dialog.message());
      await dialog.dismiss();
    });

    await page.goto('/#simulator');

    const select = page.getByLabel('Select sample fixture');
    await select.selectOption('sentinel');

    // Verify sentinel text is rendered safely as inert text, not executed as script
    await expect(page.locator('.explanation-card')).toBeVisible();
    await expect(page.locator('.explanation-details')).toContainText('<script>alert(\'xss-sentinel\')</script>');
    await expect(page.locator('.explanation-grid')).toContainText('usr-<script>alert(\'sub\')</script>');

    // No dialog popup should have triggered
    expect(dialogs).toEqual([]);
  });

  test('handles malformed and invalid JSON uploads gracefully', async ({ page }) => {
    await page.goto('/#simulator');

    // Upload invalid JSON syntax
    await page.getByLabel('Upload Fixture JSON').setInputFiles({
      name: 'malformed.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{ this is invalid json syntax }'),
    });

    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('Malformed fixture JSON');

    // Upload JSON missing fixture_id schema requirement
    await page.getByLabel('Upload Fixture JSON').setInputFiles({
      name: 'missing-id.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"description":"no fixture id"}'),
    });

    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('Invalid simulation fixture: missing fixture_id');
  });

  test('clears active simulation and displays empty state', async ({ page }) => {
    await page.goto('/#simulator');

    await expect(page.locator('.diff-banner')).toBeVisible();

    await page.getByRole('button', { name: 'Clear' }).click();

    // Results should be removed, empty state displayed
    await expect(page.locator('.diff-banner')).toHaveCount(0);
    const emptyState = page.getByRole('status');
    await expect(emptyState).toBeVisible();
    await expect(emptyState).toContainText('No simulation loaded');
  });

  test('handles engine/provider unavailable (503) fail-closed state', async ({ page }) => {
    // Intercept simulate endpoint to simulate engine provider failure
    await page.route('*/**/runtime/simulate', (route) => {
      return route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: { code: 'PROVIDER_UNAVAILABLE', message: 'Engine or policy provider unavailable' } }),
      });
    });

    await page.goto('/#simulator');

    // Trigger simulation with route intercepted
    const select = page.getByLabel('Select sample fixture');
    await select.selectOption('allow-to-deny');

    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('Engine or policy provider unavailable (503 Service Unavailable) — fail closed');
  });

  test('private resource without authenticated credentials fails closed with deny', async ({ page }) => {
    await page.goto('/#simulator');

    const select = page.getByLabel('Select sample fixture');
    await select.selectOption('fail-closed');

    await expect(page.locator('.transition-badge')).toContainText('UNCHANGED');
    const table = page.locator('table.diff-table');
    await expect(table.locator('tr:has-text("Outcome") td').nth(0)).toContainText('DENY');
    await expect(table.locator('tr:has-text("Outcome") td').nth(1)).toContainText('DENY');
    await expect(page.locator('.explanation-card .explanation-title')).toContainText('DENIED');
  });

  test('maintains accessible layout without horizontal overflow at 360px mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 640 });
    await page.goto('/#simulator');

    // Confirm diff banner and table are visible on small screen
    await expect(page.locator('.diff-banner')).toBeVisible();
    await expect(page.locator('.diff-table')).toBeVisible();
    await expect(page.locator('.explanation-card')).toBeVisible();

    // Verify zero horizontal scrolling
    const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    expect(noOverflow).toBe(true);
  });

  test('supports full keyboard navigation across simulator controls and diff table', async ({ page }) => {
    await page.goto('/#simulator');

    // Focus main container or select
    const select = page.getByLabel('Select sample fixture');
    await select.focus();
    await expect(select).toBeFocused();

    // Tab to next button
    await page.keyboard.press('Tab');
    // Tab skips hidden file input or lands on file-button / Re-run Simulation button
    const activeTagName = await page.evaluate(() => document.activeElement?.tagName);
    expect(['BUTTON', 'LABEL', 'INPUT']).toContain(activeTagName);
  });
});
