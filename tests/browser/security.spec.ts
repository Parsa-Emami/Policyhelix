import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

test.describe('Security, Abuse & Authorization Boundaries (C27 / N27)', () => {
  test('enforces strict HTTP security headers, blocks path traversal, and rejects disallowed methods', async ({ page, request }) => {
    const res = await page.goto('/');
    expect(res).not.toBeNull();
    const headers = res!.headers();

    expect(headers['content-security-policy']).toContain("default-src 'none'");
    expect(headers['content-security-policy']).toContain("script-src 'self'");
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['permissions-policy']).toContain('camera=()');

    // Dot-segment & hidden file traversal attempts must be rejected
    for (const badPath of ['/.env', '/..%2fpackage.json', '/assets/..%2f..%2fSHA256SUMS.txt']) {
      const travRes = await request.get(badPath);
      expect([400, 404]).toContain(travRes.status());
      const body = await travRes.json();
      expect(['invalid_path', 'not_found']).toContain(body.error);
    }

    // Disallowed HTTP methods on read/post endpoints must return 405 Method Not Allowed
    const delHealth = await request.delete('/healthz');
    expect(delHealth.status()).toBe(405);
    const getSim = await request.get('/api/v1/runtime/simulate');
    expect(getSim.status()).toBe(405);
    const getSec = await request.get('/api/v1/security/verify');
    expect(getSec.status()).toBe(405);
  });

  test('overview JSON import blocks prototype pollution, oversized files, and XSS sentinels', async ({ page }) => {
    const dialogs: string[] = [];
    const pageErrors: string[] = [];
    page.on('dialog', async (d) => {
      dialogs.push(d.message());
      await d.dismiss();
    });
    page.on('pageerror', (err) => pageErrors.push(err.message));

    await page.goto('/');
    const fileInput = page.getByLabel('Choose JSON file');

    // 1. Prototype pollution via __proto__ key must be rejected
    await fileInput.setInputFiles({
      name: 'proto-pollution.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"__proto__":{"polluted":"yes"},"normal":1}'),
    });
    await expect(page.getByRole('alert')).toContainText('Unsafe document key.');

    // Verify Object.prototype in browser was never polluted
    const isPolluted = await page.evaluate(() => (Object.prototype as Record<string, unknown>).polluted !== undefined);
    expect(isPolluted).toBe(false);

    // 2. Prototype pollution via constructor.prototype must be rejected
    await fileInput.setInputFiles({
      name: 'constructor-pollution.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"constructor":{"prototype":{"isAdmin":true}}}'),
    });
    await expect(page.getByRole('alert')).toContainText('Unsafe document key.');

    // 3. Oversized payload (>1 MiB maxPreviewBytes) must be rejected
    const oversized = JSON.stringify({ data: 'x'.repeat(1100000) });
    await fileInput.setInputFiles({
      name: 'oversized.json',
      mimeType: 'application/json',
      buffer: Buffer.from(oversized),
    });
    await expect(page.getByRole('alert')).toContainText('File exceeds the preview limit.');

    // 4. XSS script & event-handler sentinels inside valid JSON render strictly as inert text
    await fileInput.setInputFiles({
      name: 'xss-sentinel.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"<script>alert(\'xss-overview\')</script>":"<img src=x onerror=alert(1)>"}'),
    });
    await expect(page.getByRole('status')).toContainText('xss-sentinel.json');
    await expect(page.getByRole('status')).toContainText("<script>alert('xss-overview')</script>");

    expect(dialogs).toEqual([]);
    expect(pageErrors).toEqual([]);
  });

  test('simulator and gateway surfaces enforce XSS inertness, schema validation, and zero token exposure', async ({ page }) => {
    const dialogs: string[] = [];
    const pageErrors: string[] = [];
    page.on('dialog', async (d) => {
      dialogs.push(d.message());
      await d.dismiss();
    });
    page.on('pageerror', (err) => pageErrors.push(err.message));

    // Surface S2: Simulator custom malicious fixture import
    await page.goto('/#simulator');
    const simUpload = page.getByLabel('Upload Fixture JSON');
    await simUpload.setInputFiles({
      name: 'sim-xss.json',
      mimeType: 'application/json',
      buffer: Buffer.from(
        JSON.stringify({
          fixture_id: "fx-<script>alert('sim-id')</script>",
          description: "<img src=x onerror=alert('sim-desc')>",
          baseline_revision: 1,
          candidate_revision: 2,
          baseline_decision: { allow: false, reasons: ["deny_<svg onload=alert(1)>"] },
          candidate_decision: { allow: false, reasons: ["deny_<svg onload=alert(1)>"] },
          subject: { id: "usr-<script>alert('sub')</script>", roles: ["viewer"] },
          resource: { id: "/api/v1/private/<script>", classification: "private" },
          action: "read",
        })
      ),
    });

    await expect(page.locator('.explanation-card')).toBeVisible();
    await expect(page.locator('.explanation-card')).toContainText("<img src=x onerror=alert('sim-desc')>");

    // Surface S3: Gateway custom malicious session input & zero-token invariant
    await page.goto('/#gateway');
    const select = page.getByLabel('Select gateway scenario');
    await select.selectOption('session-revoke');

    const sessionInput = page.getByLabel('Target Session ID');
    await sessionInput.fill("sess-<script>alert('revoke-xss')</script>");
    await page.getByRole('button', { name: 'Revoke Session' }).click();

    await expect(page.locator('.revocation-result')).toBeVisible();
    const domText = await page.evaluate(() => document.body.innerText);
    expect(domText).not.toMatch(/Bearer\s+[A-Za-z0-9-_]{16,}/i);
    expect(domText).not.toMatch(/eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+/);
    expect(domText).not.toMatch(/policyhelix_session=[A-Za-z0-9-_]+/i);

    expect(dialogs).toEqual([]);
    expect(pageErrors).toEqual([]);
  });

  test('executes C27 object/provider authorization (IDOR) and abuse fixtures against loopback engine', async ({ request }) => {
    const fixtureFiles = [
      {
        file: 'positive-authorized-owner-scope-access.json',
        expectedStatus: 200,
        expectedAllow: true,
        expectedSideEffects: true,
        expectedErrorCode: '',
      },
      {
        file: 'negative-missing-identity-denied.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'PRIVATE_RESOURCE_FAIL_CLOSED',
      },
      {
        file: 'negative-expired-replayed-identity-denied.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'REPLAYED_IDENTITY_DENIED',
      },
      {
        file: 'negative-idor-unrelated-owner-scope.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'UNRELATED_OWNER_SCOPE',
      },
      {
        file: 'negative-forged-header-privilege-escalation.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'FORGED_HEADER_REJECTED',
      },
      {
        file: 'negative-widened-path-traversal-denied.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'WIDENED_PERMISSION_DENIED',
      },
      {
        file: 'negative-widened-provider-upstream-denied.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'UPSTREAM_NOT_ALLOWLISTED',
      },
      {
        file: 'negative-idp-unavailable-sensitive-deny.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'PROVIDER_UNAVAILABLE',
      },
      {
        file: 'negative-xss-import-prototype-pollution-rejected.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'UNSAFE_IMPORT_PAYLOAD_REJECTED',
      },
      {
        file: 'negative-private-resource-fail-closed.json',
        expectedStatus: 200,
        expectedAllow: false,
        expectedSideEffects: false,
        expectedErrorCode: 'WIDENED_PERMISSION_DENIED',
      },
    ];

    for (const item of fixtureFiles) {
      const fxPath = resolve(process.cwd(), 'tests', 'fixtures', 'policyhelix', 'C27', item.file);
      const rawJson = readFileSync(fxPath, 'utf8');
      const response = await request.post('/api/v1/security/verify', {
        headers: { 'Content-Type': 'application/json' },
        data: rawJson,
      });

      expect(response.status()).toBe(item.expectedStatus);
      const report = await response.json();
      expect(report.passed).toBe(true);
      expect(report.allow).toBe(item.expectedAllow);
      expect(report.side_effects_executed).toBe(item.expectedSideEffects);
      expect(report.error_code ?? '').toBe(item.expectedErrorCode);
      expect(report.xss_inert).toBe(true);
    }
  });
});
