import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import { startSupervisor } from '../../scripts/start-local.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));

function getFreePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const port = s.address().port;
      s.close(() => res(port));
    });
    s.on('error', rej);
  });
}

test('domain contract schemas are valid JSON Schema draft 2020-12', async () => {
  const inputSchemaRaw = await readFile(resolve(root, 'contracts/input.schema.json'), 'utf8');
  const inputSchema = JSON.parse(inputSchemaRaw);
  assert.equal(inputSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(inputSchema.properties.schema_version.const, '1');
  assert.equal(inputSchema.additionalProperties, false);

  const resultSchemaRaw = await readFile(resolve(root, 'contracts/result.schema.json'), 'utf8');
  const resultSchema = JSON.parse(resultSchemaRaw);
  assert.equal(resultSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(resultSchema.properties.schema_version.const, '1');
  assert.equal(resultSchema.additionalProperties, false);
});

test('C04 fixture manifest is complete and matches file digests', async () => {
  const manifestRaw = await readFile(resolve(root, 'tests/fixtures/policyhelix/C04/manifest.json'), 'utf8');
  const manifest = JSON.parse(manifestRaw);
  assert.equal(manifest.commit_id, 'C04');
  assert.equal(manifest.project, 'PolicyHelix');
  assert.ok(Array.isArray(manifest.fixtures));
  assert.equal(manifest.fixtures.length, 5);

  const { createHash } = await import('node:crypto');
  for (const f of manifest.fixtures) {
    const content = await readFile(resolve(root, f.path));
    const digest = createHash('sha256').update(content).digest('hex');
    assert.equal(digest, f.sha256, `Digest mismatch for ${f.path}`);
  }
});

test('engine validates v1 domain contracts over loopback supervisor HTTP proxy', async t => {
  const port = await getFreePort();
  const enginePort = await getFreePort();

  const supervisor = await startSupervisor({ host: '127.0.0.1', port, enginePort });
  t.after(async () => {
    await supervisor.stop();
  });

  const base = `http://127.0.0.1:${port}`;
  const endpoint = `${base}/api/v1/runtime/evaluate-contract`;

  // 1. Positive operator allow fixture
  const posRaw = await readFile(resolve(root, 'tests/fixtures/policyhelix/C04/positive-operator-allow.json'), 'utf8');
  const posRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: posRaw,
  });
  assert.equal(posRes.status, 200);
  const posData = await posRes.json();
  assert.equal(posData.schema_version, '1');
  assert.equal(posData.status, 'complete');
  assert.equal(posData.decision.allow, true);
  assert.equal(posData.decision.subject, 'user_alice');
  assert.equal(posData.error, null);
  assert.ok(posData.input_digest.startsWith('sha256:'));
  assert.ok(posData.metrics.within_deadline);

  // 2. Negative unauthenticated private access -> allow: false, UNAUTHENTICATED_IDENTITY
  const unauthRaw = await readFile(resolve(root, 'tests/fixtures/policyhelix/C04/negative-private-unauthenticated.json'), 'utf8');
  const unauthRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: unauthRaw,
  });
  assert.equal(unauthRes.status, 200);
  const unauthData = await unauthRes.json();
  assert.equal(unauthData.decision.allow, false);
  assert.equal(unauthData.error.code, 'UNAUTHENTICATED_IDENTITY');

  // 3. Negative unsupported version -> 400, UNSUPPORTED_VERSION
  const badVerRaw = await readFile(resolve(root, 'tests/fixtures/policyhelix/C04/negative-unsupported-version.json'), 'utf8');
  const badVerRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: badVerRaw,
  });
  assert.equal(badVerRes.status, 400);
  const badVerData = await badVerRes.json();
  assert.equal(badVerData.status, 'failed');
  assert.equal(badVerData.error.code, 'UNSUPPORTED_VERSION');

  // 4. Negative cancellation / timeout -> 499 or 504
  const timeoutRaw = await readFile(resolve(root, 'tests/fixtures/policyhelix/C04/negative-oversized-or-timeout.json'), 'utf8');
  const timeoutRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: timeoutRaw,
  });
  assert.ok([499, 504].includes(timeoutRes.status));
  const timeoutData = await timeoutRes.json();
  assert.equal(timeoutData.decision.allow, false);
  assert.ok(['REQUEST_CANCELLED', 'DECISION_TIMEOUT'].includes(timeoutData.error.code));

  // 5. Negative provider outage fail-closed
  const provRaw = await readFile(resolve(root, 'tests/fixtures/policyhelix/C04/negative-unavailable-provider.json'), 'utf8');
  const provRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: provRaw,
  });
  assert.equal(provRes.status, 200);
  const provData = await provRes.json();
  assert.equal(provData.decision.allow, false);
  assert.equal(provData.error.code, 'PROVIDER_UNAVAILABLE');

  // 6. Malformed JSON rejected with 400
  const malformedRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{not valid json',
  });
  assert.equal(malformedRes.status, 400);
  const malformedData = await malformedRes.json();
  assert.equal(malformedData.error.code, 'INVALID_JSON');

  // 7. Oversized payload rejected with 413
  const oversizedPayload = JSON.stringify({
    schema_version: '1',
    request_id: 'oversized',
    huge_padding: 'x'.repeat(70000),
  });
  const oversizedRes = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: oversizedPayload,
  });
  assert.equal(oversizedRes.status, 413);
  const oversizedData = await oversizedRes.json();
  assert.equal(oversizedData.error.code, 'PAYLOAD_TOO_LARGE');

  // 8. Method not allowed on non-POST
  const getRes = await fetch(endpoint);
  assert.equal(getRes.status, 405);
});
