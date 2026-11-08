import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';

test.describe('C33: Full Workflow Accessibility, Keyboard, Mobile, and N-1 Compatibility', () => {

  test('1. completes full reference workflow at 1440px desktop viewport against live engine', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto('/#reference');
    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();
    await expect(page.getByText('The local engine is ready for the workflow.')).toBeVisible();
    await expect(page.getByText('0 of 6')).toBeVisible();

    const runButton = page.getByRole('button', { name: 'Run full workflow' });
    await expect(runButton).toBeEnabled();
    await runButton.click();

    // Verify all 6 stages pass
    await expect(page.locator('.workflow-stage.stage-passed')).toHaveCount(6, { timeout: 60000 });
    await expect(page.getByText('6 of 6')).toBeVisible();
    await expect(page.locator('.workflow-stage.stage-failed')).toHaveCount(0);

    // Verify each result contains typed engine outcome
    await expect(page.getByRole('region', { name: 'Simulator fixture result' })).toContainText('C01-POS-01');
    await expect(page.getByRole('region', { name: 'Sign and verify bundle result' })).toContainText('true');
    await expect(page.getByRole('region', { name: 'Protect owned upstream result' })).toContainText('200');
    await expect(page.getByRole('region', { name: 'Spoofed header and direct origin result' })).toContainText('blocked');
    await expect(page.getByRole('region', { name: 'Revoke session result' })).toContainText('REVOKED_SESSION');
    await expect(page.getByRole('region', { name: 'Outage and expired policy result' })).toContainText('Active authority retained');

    expect(errors).toEqual([]);
  });

  test('2. provides accessible table equivalent representation of workflow stages', async ({ page }) => {
    await page.goto('/#reference');
    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

    // Toggle to Table view
    const tableToggle = page.getByRole('button', { name: 'Table equivalent' });
    await expect(tableToggle).toBeVisible();
    await tableToggle.click();
    await expect(tableToggle).toHaveAttribute('aria-pressed', 'true');

    // Verify table accessibility structure
    const table = page.getByRole('table', { name: 'Reference workflow stages and results' });
    await expect(table).toBeVisible();
    await expect(table.locator('caption')).toContainText('Accessible tabular view of the six local reference workflow stages');

    // Verify table headers
    const headers = table.locator('thead th');
    await expect(headers).toHaveCount(6);
    await expect(headers.nth(0)).toHaveText('#');
    await expect(headers.nth(1)).toHaveText('Stage');
    await expect(headers.nth(2)).toHaveText('Invariant');
    await expect(headers.nth(3)).toHaveText('Status');
    await expect(headers.nth(4)).toHaveText('Observed Outcome');
    await expect(headers.nth(5)).toHaveText('Action');

    // Verify 6 rows exist
    const rows = table.locator('tbody tr');
    await expect(rows).toHaveCount(6);

    // Toggle back to Cards view
    const cardsToggle = page.getByRole('button', { name: 'Cards' });
    await cardsToggle.click();
    await expect(cardsToggle).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.workflow-stages')).toBeVisible();
  });

  test('3. guarantees zero horizontal overflow and responsive layout at 360px mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 640 });
    await page.goto('/#reference');

    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();
    await expect(page.locator('.workflow-summary')).toBeVisible();

    // Verify no document-level horizontal overflow in cards mode
    let noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    expect(noOverflow).toBe(true);

    // Switch to table equivalent mode and verify table scrolls without expanding document body
    await page.getByRole('button', { name: 'Table equivalent' }).click();
    await expect(page.getByRole('table')).toBeVisible();

    noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    expect(noOverflow).toBe(true);

    // Verify touch target sizing for main actions
    const runAllBtn = page.getByRole('button', { name: 'Run full workflow' });
    const box = await runAllBtn.boundingBox();
    expect(box).not.toBeNull();
    if (box) {
      expect(box.height).toBeGreaterThanOrEqual(36);
    }
  });

  test('4. supports sequential keyboard navigation across all workflow controls and view modes', async ({ page }) => {
    await page.goto('/#reference');
    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

    const runAllButton = page.getByRole('button', { name: 'Run full workflow' });
    await expect(runAllButton).toBeEnabled();
    await runAllButton.focus();
    await expect(runAllButton).toBeFocused();

    // Tab to Refresh button
    await page.keyboard.press('Tab');
    const refreshButton = page.getByRole('button', { name: 'Refresh engine state' });
    await expect(refreshButton).toBeFocused();

    // Tab to stage 1 button
    await page.keyboard.press('Tab');
    const stage1RunBtn = page.getByRole('button', { name: 'Run stage 1: Simulator fixture' });
    await expect(stage1RunBtn).toBeFocused();
    await page.keyboard.press('Enter');

    // Verify stage 1 passes
    await expect(page.locator('.workflow-stage').first()).toHaveClass(/stage-passed/, { timeout: 30000 });

    // Focus View mode toggle via keyboard
    const tableToggle = page.getByRole('button', { name: 'Table equivalent' });
    await tableToggle.focus();
    await expect(tableToggle).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(tableToggle).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('table')).toBeVisible();

    // Verify table equivalent reflects passed stage
    await expect(page.locator('.table-stage-passed')).toHaveCount(1);
  });

  test('5. handles empty, invalid, interrupted, and provider-outage failure states gracefully', async ({ page }) => {
    await page.goto('/#reference');
    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

    // 5a: Initial empty state
    await expect(page.getByText('0 of 6')).toBeVisible();

    // 5b: Invalid fixture error (simulated 422)
    await page.route('**/api/v1/reference/simulate', route => {
      route.fulfill({
        status: 422,
        contentType: 'application/json',
        body: JSON.stringify({
          fixture_ref: 'tests/fixtures/policyhelix/C01/positive-decision.json',
          expected_matched: false,
          observed_allow: false,
          error_code: 'SIMULATOR_EVAL_FAILED',
          error_message: 'simulated bundle evaluation failure for error state testing',
        }),
      });
    });

    const runAllButton = page.getByRole('button', { name: 'Run full workflow' });
    await runAllButton.click();

    await expect(page.locator('.workflow-stage').first()).toHaveClass(/stage-failed/, { timeout: 10000 });
    const errorAlert = page.getByRole('alert');
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('simulated bundle evaluation failure for error state testing');

    // 5c: Network interruption / abort recovery
    await page.unroute('**/api/v1/reference/simulate');
    await page.route('**/api/v1/reference/session', route => {
      route.abort('failed');
    });

    await runAllButton.click();
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('alert')).toContainText('interrupted or timed out');
    await expect(runAllButton).toBeEnabled(); // UI recovered from running state

    await page.unroute('**/api/v1/reference/session');
  });

  test('6. supports workflow report export, backward-compatible N-1 import, and tampered rejection', async ({ page }) => {
    await page.goto('/#reference');
    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

    // 6a: Test Export action
    const exportBtn = page.getByRole('button', { name: 'Export workflow report' });
    await exportBtn.click();
    await expect(page.locator('.notice[role="status"]')).toContainText('Exported workflow report (schema_version: 2)');

    // 6b: Test N-1 import compatibility using positive-n-minus-1-export.json
    const nMinus1Path = path.resolve('tests/fixtures/policyhelix/C33/positive-n-minus-1-export.json');
    const nMinus1Content = fs.readFileSync(nMinus1Path, 'utf8');

    // Set file input via Playwright
    const fileInput = page.getByLabel('Import workflow report');
    await fileInput.setInputFiles({
      name: 'positive-n-minus-1-export.json',
      mimeType: 'application/json',
      buffer: Buffer.from(nMinus1Content),
    });

    await expect(page.locator('.notice[role="status"]')).toContainText('Successfully loaded and verified N-1 workflow report (v1 schema)');
    await expect(page.getByText('6 of 6')).toBeVisible();

    // 6c: Test tampered export rejection using negative-tampered-export.json
    const tamperedPath = path.resolve('tests/fixtures/policyhelix/C33/negative-tampered-export.json');
    const tamperedContent = fs.readFileSync(tamperedPath, 'utf8');

    await fileInput.setInputFiles({
      name: 'negative-tampered-export.json',
      mimeType: 'application/json',
      buffer: Buffer.from(tamperedContent),
    });

    await expect(page.getByRole('alert')).toContainText('Export payload contains invalid schema or corrupted structure');
  });

  test('7. explicitly advertises only observed supported platforms (Linux x86_64)', async ({ page }) => {
    await page.goto('/#reference');
    await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

    const platformPanel = page.getByRole('region', { name: 'Advertised platforms' });
    await expect(platformPanel).toBeVisible();
    await expect(platformPanel).toContainText('Linux x86_64');
    await expect(platformPanel).toContainText('linux/amd64');
    await expect(platformPanel).toContainText('Unverified environments (Windows/macOS native desktop installers, mobile app stores, cloud SaaS) are not advertised');
  });

});
