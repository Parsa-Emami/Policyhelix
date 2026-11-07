import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

test.describe('Capacity, Workload & Latency Boundaries (C28 / N28)', () => {
  test('rejects disallowed HTTP methods on benchmark endpoints', async ({ request }) => {
    // GET, PUT, DELETE must be rejected on POST-only benchmark endpoints
    const getRes = await request.get('/api/v1/benchmark/run');
    expect(getRes.status()).toBe(405);

    const delRes = await request.delete('/api/v1/benchmark/run');
    expect(delRes.status()).toBe(405);

    const getEval = await request.get('/api/v1/benchmark/evaluate');
    expect(getEval.status()).toBe(405);
  });

  test('enforces target bounded workload latency SLO (p95 <= 200ms) over supervisor proxy', async ({ request }) => {
    const fxPath = resolve(process.cwd(), 'tests', 'fixtures', 'policyhelix', 'C28', 'positive-target-bounded-workload.json');
    const rawJson = readFileSync(fxPath, 'utf8');

    const res = await request.post('/api/v1/benchmark/run', {
      headers: { 'Content-Type': 'application/json' },
      data: rawJson,
    });

    expect(res.status()).toBe(200);
    const rep = await res.json();
    expect(rep.passed).toBe(true);
    expect(rep.total_requests).toBe(10);
    expect(rep.allow_count).toBe(10);
    expect(rep.deny_count).toBe(0);
    expect(rep.latency_summary.p95_ms).toBeLessThanOrEqual(200.0);
  });

  test('verifies concurrent burst workload execution without race conditions', async ({ request }) => {
    const fxPath = resolve(process.cwd(), 'tests', 'fixtures', 'policyhelix', 'C28', 'positive-concurrency-burst.json');
    const rawJson = readFileSync(fxPath, 'utf8');

    const res = await request.post('/api/v1/benchmark/evaluate', {
      headers: { 'Content-Type': 'application/json' },
      data: rawJson,
    });

    expect(res.status()).toBe(200);
    const rep = await res.json();
    expect(rep.passed).toBe(true);
    expect(rep.total_requests).toBe(20);
    expect(rep.allow_count).toBe(20);
    expect(rep.latency_summary.p95_ms).toBeLessThanOrEqual(200.0);
  });

  test('verifies overload scenarios: payload limits, timeouts, cancellation, and saturation fail closed', async ({ request }) => {
    const overloadCases = [
      {
        file: 'negative-oversized-payload-exceeds-64k.json',
        expectedError: 'PAYLOAD_TOO_LARGE',
        expectedStatus: 413,
      },
      {
        file: 'negative-deadline-exceeded-timeout.json',
        expectedError: 'DECISION_TIMEOUT',
        expectedStatus: 504,
      },
      {
        file: 'negative-client-cancellation.json',
        expectedError: 'REQUEST_CANCELLED',
        expectedStatus: 499,
      },
      {
        file: 'negative-saturation-limit-fail-closed.json',
        expectedError: 'SATURATION_LIMIT_EXCEEDED',
        expectedStatus: 429,
      },
      {
        file: 'negative-private-resource-fail-closed.json',
        expectedError: 'WIDENED_PERMISSION_DENIED',
        expectedStatus: 200,
      },
      {
        file: 'negative-provider-unavailable-workload.json',
        expectedError: 'PROVIDER_UNAVAILABLE',
        expectedStatus: 200,
      },
    ];

    for (const tc of overloadCases) {
      const fxPath = resolve(process.cwd(), 'tests', 'fixtures', 'policyhelix', 'C28', tc.file);
      const rawJson = readFileSync(fxPath, 'utf8');

      const res = await request.post('/api/v1/benchmark/run', {
        headers: { 'Content-Type': 'application/json' },
        data: rawJson,
      });

      expect(res.status()).toBe(200);
      const rep = await res.json();
      expect(rep.passed).toBe(true);

      if (rep.step_results && rep.step_results.length > 0) {
        const matchingStep = rep.step_results.find((s: { status_code: number }) => s.status_code === tc.expectedStatus);
        expect(matchingStep).toBeDefined();
        expect(matchingStep.allow).toBe(false);
        expect(matchingStep.error_code).toBe(tc.expectedError);
      }
    }
  });

  test('verifies restart recovery durability under benchmark evaluation', async ({ request }) => {
    const fxPath = resolve(process.cwd(), 'tests', 'fixtures', 'policyhelix', 'C28', 'negative-restart-recovery-workload.json');
    const rawJson = readFileSync(fxPath, 'utf8');

    const res = await request.post('/api/v1/benchmark/run', {
      headers: { 'Content-Type': 'application/json' },
      data: rawJson,
    });

    expect(res.status()).toBe(200);
    const rep = await res.json();
    expect(rep.passed).toBe(true);
    expect(rep.allow_count).toBe(1);
    expect(rep.observed_limits.restart_recovery_verified).toBe(true);
  });

  test('rejects malformed benchmark fixture with HTTP 400 or typed error', async ({ request }) => {
    // 1. Broken JSON syntax
    const resBroken = await request.post('/api/v1/benchmark/run', {
      headers: { 'Content-Type': 'application/json' },
      data: '{"schema_version": "invalid-broken-json}',
    });

    expect(resBroken.status()).toBe(400);
    const bodyBroken = await resBroken.json();
    expect(bodyBroken.passed).toBe(false);
    expect(bodyBroken.error_code).toBe('MALFORMED_BENCHMARK_FIXTURE');

    // 2. Valid JSON with undeclared invalid schema_version
    const resInvalidSchema = await request.post('/api/v1/benchmark/run', {
      headers: { 'Content-Type': 'application/json' },
      data: JSON.stringify({
        fixture_id: 'fx-invalid-schema',
        schema_version: 'unsupported_v99',
        workload_type: 'target_bounded',
      }),
    });

    expect(resInvalidSchema.status()).toBe(400);
    const bodyInvalid = await resInvalidSchema.json();
    expect(bodyInvalid.passed).toBe(false);
    expect(bodyInvalid.error_code).toBe('MALFORMED_BENCHMARK_FIXTURE');
  });
});
