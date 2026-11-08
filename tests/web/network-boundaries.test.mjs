import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { createWebServer } from '../../scripts/serve-web.mjs';

const config = { projectId: 'test-project', apiBasePath: '/api', engineEnabled: true, maxPreviewBytes: 1048576 };

test('C32 network boundaries: local loopback launch, host validation, origin checks, and cache policies', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'c32-net-boundaries-'));
  const root = join(dir, 'public');
  await mkdir(join(root, 'assets'), { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>PolicyHelix Loopback</h1>');
  await writeFile(join(root, 'assets', 'bundle-xyz.js'), 'console.log("asset");');

  // Start server with optional allowedHosts for private hosting
  const server = createWebServer({
    root,
    config,
    projectId: 'test-project',
    allowedHosts: ['policyhelix.internal']
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });

  const sendWithHeaders = (path, headers) => new Promise((resolve, reject) => {
    const req = httpRequest(base + path, { agent: false, headers }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        body: data
      }));
    });
    req.on('error', reject);
    req.end();
  });

  // 1. Loopback Host Verification (No Public Domain Required)
  const loopbackHosts = [
    `localhost:${port}`,
    `127.0.0.1:${port}`,
    `[::1]:${port}`,
    'localhost',
    '127.0.0.1'
  ];
  for (const host of loopbackHosts) {
    const res = await sendWithHeaders('/healthz', { Host: host });
    assert.equal(res.statusCode, 200, `Loopback host ${host} must succeed`);
  }

  // 2. Untrusted Host Rejection (DNS-rebinding defense)
  const untrustedHosts = [
    'attacker.example.com',
    'evil.invalid',
    '192.168.1.100',
    '10.0.0.1',
    'localhost.evil.com',
    '127.0.0.1.attacker.org',
    'public.domain.com:8080'
  ];
  for (const host of untrustedHosts) {
    const res = await sendWithHeaders('/healthz', { Host: host });
    assert.equal(res.statusCode, 403, `Untrusted host ${host} must be rejected with 403`);
    assert.match(res.body, /invalid_host/);
  }

  // 3. Optional Private Ingress Allowed Host
  const allowedRes = await sendWithHeaders('/healthz', { Host: `policyhelix.internal:${port}` });
  assert.equal(allowedRes.statusCode, 200, 'Configured private host must succeed');

  // 4. Origin & Cross-Origin Validation
  // Trusted origins
  for (const origin of [`http://localhost:${port}`, `http://127.0.0.1:${port}`, `https://policyhelix.internal`]) {
    const res = await sendWithHeaders('/healthz', { Host: `127.0.0.1:${port}`, Origin: origin });
    assert.equal(res.statusCode, 200, `Trusted origin ${origin} must be accepted`);
  }

  // Untrusted origins (cross-origin attack defense)
  const untrustedOrigins = [
    'http://attacker.com',
    'https://malicious.org',
    'http://192.168.1.50:8080',
    'http://localhost.evil.com'
  ];
  for (const origin of untrustedOrigins) {
    const res = await sendWithHeaders('/healthz', { Host: `127.0.0.1:${port}`, Origin: origin });
    assert.equal(res.statusCode, 403, `Untrusted origin ${origin} must be rejected with 403`);
    assert.match(res.body, /invalid_origin/);
  }

  // 5. Cache-Control Boundaries
  // Dynamic & API endpoints must strictly be no-store
  const dynamicRoutes = ['/', '/healthz', '/readyz', '/runtime-config.json', '/api/v1/status'];
  for (const route of dynamicRoutes) {
    const res = await sendWithHeaders(route, { Host: `127.0.0.1:${port}` });
    const cc = res.headers['cache-control'] || '';
    assert.equal(cc, 'no-store', `Dynamic route ${route} must have Cache-Control: no-store`);
  }

  // Static assets must be immutable
  const assetRes = await sendWithHeaders('/assets/bundle-xyz.js', { Host: `127.0.0.1:${port}` });
  assert.equal(assetRes.statusCode, 200);
  assert.equal(assetRes.headers['cache-control'], 'public, max-age=31536000, immutable');

  // 6. Security Invariants & Headers
  const indexRes = await sendWithHeaders('/', { Host: `127.0.0.1:${port}` });
  assert.equal(indexRes.statusCode, 200);
  assert.equal(indexRes.headers['x-content-Type-options'] || indexRes.headers['x-content-type-options'], 'nosniff');
  assert.equal(indexRes.headers['x-frame-options'], 'DENY');
  assert.equal(indexRes.headers['referrer-policy'], 'no-referrer');
  assert.match(indexRes.headers['content-security-policy'], /connect-src 'self'/);
  assert.match(indexRes.headers['content-security-policy'], /frame-ancestors 'none'/);
});
