import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createWebServer } from '../../scripts/serve-web.mjs';

const config = { projectId: 'test-project', apiBasePath: '/api', engineEnabled: true, maxPreviewBytes: 1048576 };

test('C29: Web health vs engine readiness separation and secret-redacted diagnostics proxying', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'web-readiness-'));
  const root = join(dir, 'public');
  await mkdir(join(root, 'assets'), { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>PolicyHelix</h1>');

  // 1. Mock Go Engine Server for testing readiness & diagnostics proxying
  let engineReadyState = true;
  let simulateOPAOffline = false;

  const mockEngine = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');

    if (url.pathname === '/readyz') {
      const opaState = url.searchParams.get('opa_state');
      if (simulateOPAOffline || opaState === 'offline') {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'not_ready',
          ready: false,
          status_code: 503,
          failures: ['local_opa: OPA_PROVIDER_UNAVAILABLE (provider offline)'],
          storage: { ready: true },
          providers: { local_opa: { ready: false, error_code: 'OPA_PROVIDER_UNAVAILABLE' } }
        }));
        return;
      }

      res.writeHead(engineReadyState ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: engineReadyState ? 'ready' : 'not_ready',
        ready: engineReadyState,
        status_code: engineReadyState ? 200 : 503,
        storage: { ready: engineReadyState, revision: 1 },
        providers: {
          local_opa: { ready: true, status: 'connected' },
          self_hosted_keycloak: { ready: true, status: 'connected' },
          owned_synthetic_upstream: { ready: true, status: 'connected' }
        }
      }));
      return;
    }

    if (url.pathname === '/api/v1/runtime/readiness') {
      res.writeHead(engineReadyState ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: engineReadyState ? 'ready' : 'not_ready',
        ready: engineReadyState,
        status_code: engineReadyState ? 200 : 503,
        engine: 'policyhelix-engine',
        version: '0.0.1'
      }));
      return;
    }

    if (url.pathname === '/api/v1/runtime/diagnostics') {
      const auth = req.headers['authorization'];
      if (!auth) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'unauthorized',
          error_code: 'PRIVATE_RESOURCE_FAIL_CLOSED',
          private_resources_fail_closed: true
        }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        events: [
          {
            id: 1,
            level: 'info',
            message: 'Incoming request scrubbed: Bearer [REDACTED], sentinel=[REDACTED_SENTINEL]'
          }
        ]
      }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end('{"error":"not_found"}');
  });

  mockEngine.listen(0, '127.0.0.1');
  await once(mockEngine, 'listening');
  const engineUrl = `http://127.0.0.1:${mockEngine.address().port}`;

  // 2. Start Web Server with supervised engineUrl
  const server = createWebServer({ root, config, projectId: 'test-project', engineUrl });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    server.closeAllConnections();
    mockEngine.closeAllConnections();
    await new Promise(r => server.close(r));
    await new Promise(r => mockEngine.close(r));
    await rm(dir, { recursive: true });
  });

  // A. Liveness probe (/healthz) returns 200 ok for web-shell
  const healthRes = await fetch(base + '/healthz');
  assert.equal(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.equal(healthJson.status, 'ok');
  assert.equal(healthJson.scope, 'web-shell');

  // B. Default web readiness (/readyz) preserves backwards compatibility
  const readyWeb = await (await fetch(base + '/readyz')).json();
  assert.equal(readyWeb.status, 'ready');
  assert.equal(readyWeb.scope, 'web-shell');
  assert.equal(readyWeb.engineReady, false);

  // C. Deep readiness inspection via query (?check=engine)
  const readyDeep = await fetch(base + '/readyz?check=engine');
  assert.equal(readyDeep.status, 200);
  const readyDeepJson = await readyDeep.json();
  assert.equal(readyDeepJson.status, 'ready');
  assert.equal(readyDeepJson.scope, 'web-and-engine');
  assert.equal(readyDeepJson.engineReady, true);

  // D. Engine component failure is visible via ?check=engine (returns 503)
  simulateOPAOffline = true;
  const readyFailure = await fetch(base + '/readyz?check=engine');
  assert.equal(readyFailure.status, 503);
  const readyFailureJson = await readyFailure.json();
  assert.equal(readyFailureJson.status, 'not_ready');
  assert.equal(readyFailureJson.engineReady, false);
  simulateOPAOffline = false;

  // E. Proxying /api/v1/runtime/readiness
  const apiReadiness = await fetch(base + '/api/v1/runtime/readiness');
  assert.equal(apiReadiness.status, 200);
  const apiReadinessJson = await apiReadiness.json();
  assert.equal(apiReadinessJson.status, 'ready');

  // F. Diagnostics private endpoint fails closed without credentials (returns 401)
  const diagUnauth = await fetch(base + '/api/v1/runtime/diagnostics');
  assert.equal(diagUnauth.status, 401);
  const diagUnauthJson = await diagUnauth.json();
  assert.equal(diagUnauthJson.error_code, 'PRIVATE_RESOURCE_FAIL_CLOSED');
  assert.equal(diagUnauthJson.private_resources_fail_closed, true);

  // G. Diagnostics authorized access proxies and preserves sentinel redaction
  const diagAuth = await fetch(base + '/api/v1/runtime/diagnostics', {
    headers: { Authorization: 'Bearer test-admin-token' }
  });
  assert.equal(diagAuth.status, 200);
  const diagAuthJson = await diagAuth.json();
  assert.equal(diagAuthJson.status, 'ok');
  assert.ok(diagAuthJson.events[0].message.includes('Bearer [REDACTED]'));
  assert.ok(diagAuthJson.events[0].message.includes('[REDACTED_SENTINEL]'));
  assert.doesNotMatch(diagAuthJson.events[0].message, /SECRET_SENTINEL/);
});
