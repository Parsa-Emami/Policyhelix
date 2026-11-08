import { test, expect } from '@playwright/test';

test('the six-stage clone-to-value reference workflow completes against the live engine', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));

  await page.goto('/#reference');
  await expect(page.getByRole('heading', { name: 'The full local reference workflow.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();
  await expect(page.getByText('The local engine is ready for the workflow.')).toBeVisible();

  const runButton = page.getByRole('button', { name: 'Run full workflow' });
  await expect(runButton).toBeEnabled();
  await runButton.click();

  await expect(page.locator('.workflow-stage.stage-passed')).toHaveCount(6, { timeout: 60000 });
  await expect(page.getByText('6 of 6')).toBeVisible();
  await expect(page.locator('.workflow-stage.stage-failed')).toHaveCount(0);

  // Every stage must show its real engine result, not a placeholder preview.
  await expect(page.getByRole('region', { name: 'Simulator fixture result' })).toContainText('C01-POS-01');
  await expect(page.getByRole('region', { name: 'Sign and verify bundle result' })).toContainText('true');
  await expect(page.getByRole('region', { name: 'Protect owned upstream result' })).toContainText('200');
  await expect(page.getByRole('region', { name: 'Spoofed header and direct origin result' })).toContainText('blocked');
  await expect(page.getByRole('region', { name: 'Revoke session result' })).toContainText('REVOKED_SESSION');
  await expect(page.getByRole('region', { name: 'Outage and expired policy result' })).toContainText('Active authority retained');

  // The durable bundle is read back from local storage after a fresh page load.
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();
  await expect(page.getByText(/Restored bundle bundle-reference-v\d+ at revision \d+/)).toBeVisible();
  await expect(page.getByText('The local engine is ready for the workflow.')).toBeVisible();

  expect(errors).toEqual([]);
});

test('maintains accessible layout without horizontal overflow at 360px mobile viewport', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 640 });
  await page.goto('/#reference');

  await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();
  await expect(page.locator('.workflow-summary')).toBeVisible();
  await expect(page.locator('.workflow-stages')).toBeVisible();

  // Verify no horizontal overflow at 360px viewport width
  const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  expect(noOverflow).toBe(true);
});

test('supports keyboard navigation across workflow controls and individual stages', async ({ page }) => {
  await page.goto('/#reference');
  await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();
  await expect(page.getByText('The local engine is ready for the workflow.')).toBeVisible();

  const runAllButton = page.getByRole('button', { name: 'Run full workflow' });
  await expect(runAllButton).toBeEnabled();
  await runAllButton.focus();
  await expect(runAllButton).toBeFocused();

  await page.keyboard.press('Tab');
  const refreshButton = page.getByRole('button', { name: 'Refresh engine state' });
  await expect(refreshButton).toBeFocused();

  await page.keyboard.press('Tab');
  const stage1Button = page.getByRole('button', { name: 'Run stage 1: Simulator fixture' });
  await expect(stage1Button).toBeFocused();

  // Trigger stage 1 via keyboard Enter
  await page.keyboard.press('Enter');
  await expect(page.locator('.workflow-stage').first()).toHaveClass(/stage-passed/, { timeout: 30000 });
});

test('handles error and disabled states during execution and failure gracefully', async ({ page }) => {
  await page.goto('/#reference');
  await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

  // Mock route failure to verify error notice display and preserved error message
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

  // Verify runAll handles stage failure: displays preserved server error and disables controls while running
  const runAllButton = page.getByRole('button', { name: 'Run full workflow' });
  await expect(runAllButton).toBeEnabled();
  await runAllButton.click();

  // Verify the stage is marked failed and error alert is displayed with server message and stage title
  await expect(page.locator('.workflow-stage').first()).toHaveClass(/stage-failed/, { timeout: 10000 });
  const errorAlert = page.getByRole('alert');
  await expect(errorAlert).toBeVisible();
  await expect(errorAlert).toContainText('Simulator fixture');
  await expect(errorAlert).toContainText('simulated bundle evaluation failure');

  // Verify subsequent stages were stopped (not executed)
  await expect(page.locator('.workflow-stage').nth(1)).toHaveClass(/stage-idle/);

  // Verify buttons re-enabled after failure completes
  await expect(runAllButton).toBeEnabled();
  const stage1Button = page.getByRole('button', { name: 'Run stage 1: Simulator fixture' });
  await expect(stage1Button).toBeEnabled();

  // Individual stage execution also reflects server failure and preserves error
  await stage1Button.click();
  await expect(page.locator('.workflow-stage').first()).toHaveClass(/stage-failed/);
  await expect(errorAlert).toContainText('simulated bundle evaluation failure');
});

test('disables action buttons when engine reports unready state', async ({ page }) => {
  await page.route('**/api/v1/reference/state', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 'degraded',
        ready: false,
        storage_durable: false,
        storage_revision: 0,
        highest_revision: 0,
        session_count: 0,
        revoked_session_ids: [],
        stale_window_seconds: 5,
        issuer_mode: 'synthetic_local_demo',
      }),
    });
  });

  await page.goto('/#reference');
  await expect(page.getByRole('heading', { name: 'Complete the six-stage local workflow.' })).toBeVisible();

  // Buttons must be disabled when engine is not ready
  await expect(page.getByRole('button', { name: 'Run full workflow' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Run stage 1: Simulator fixture' })).toBeDisabled();
});
