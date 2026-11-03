import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { setup } from '../../scripts/oss-bootstrap.mjs';
import { startSupervisor } from '../../scripts/start-local.mjs';

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

test('setup includes engine build step and validates parameters', () => {
  const check = setup(['--check']);
  assert.equal(check.executed, false);
  assert.ok(check.steps.some(step => step[1] === 'build:engine'));
  assert.equal(check.engineReady, false);

  const skip = setup(['--skip-install', '--check']);
  assert.ok(skip.steps.some(step => step[1] === 'build:engine'));
});

test('supervisor starts loopback web and engine, exposes runtime status, and shuts down cleanly', async t => {
  const port = await getFreePort();
  const enginePort = await getFreePort();

  const supervisor = await startSupervisor({
    host: '127.0.0.1',
    port,
    enginePort,
  });

  t.after(async () => {
    await supervisor.stop();
  });

  const base = `http://127.0.0.1:${port}`;
  const engineBase = `http://127.0.0.1:${enginePort}`;

  // 1. Web healthz
  const webHealth = await (await fetch(`${base}/healthz`)).json();
  assert.equal(webHealth.status, 'ok');
  assert.equal(webHealth.scope, 'web-shell');

  // 2. Engine healthz
  const engineHealth = await (await fetch(`${engineBase}/healthz`)).json();
  assert.equal(engineHealth.status, 'ok');
  assert.equal(engineHealth.engine, 'policyhelix-engine');
  assert.equal(engineHealth.version, '0.0.1');
  assert.equal(engineHealth.loopback, true);

  // 3. Web readyz maintains engineReady: false contract
  const readyz = await (await fetch(`${base}/readyz`)).json();
  assert.equal(readyz.status, 'ready');
  assert.equal(readyz.engineReady, false);

  // 4. Runtime status proxy through web server
  const statusRes = await fetch(`${base}/api/v1/runtime/status`);
  assert.equal(statusRes.status, 200);
  const status = await statusRes.json();
  assert.equal(status.engine, 'policyhelix-engine');
  assert.equal(status.version, '0.0.1');
  assert.equal(status.loopback, true);
  assert.equal(status.coreReady, false);
  assert.equal(status.businessFeaturesCompleted, false);
  assert.deepEqual(status.invariants, [
    'Private resources fail closed',
    'Only authenticated normalized identity enters policy',
    'Bundle signature plus freshness and monotonic revision',
  ]);

  // 5. Unimplemented API endpoints still fail closed with 503
  assert.equal((await fetch(`${base}/api/v1/unimplemented`)).status, 503);
  assert.equal((await fetch(`${base}/api`)).status, 503);
});

test('supervisor fails closed on occupied port', async t => {
  const occupiedPort = await getFreePort();
  const blocker = net.createServer();
  await new Promise(r => blocker.listen(occupiedPort, '127.0.0.1', r));

  t.after(() => new Promise(r => blocker.close(r)));

  const freeEnginePort = await getFreePort();
  await assert.rejects(
    () => startSupervisor({ host: '127.0.0.1', port: occupiedPort, enginePort: freeEnginePort }),
    /already in use/
  );
});

test('supervisor rejects non-loopback host', async () => {
  await assert.rejects(
    () => startSupervisor({ host: '192.168.1.50', port: 4173, enginePort: 4174 }),
    /must bind to loopback/
  );
});

test('supervisor rejects missing binary with clear error', async () => {
  await assert.rejects(
    () => startSupervisor({ engineBin: 'dist/engine/non-existent-binary' }),
    /Engine binary missing/
  );
});

test('supervisor can restart and preserve identical invariant posture', async () => {
  const port = await getFreePort();
  const enginePort = await getFreePort();

  // Run 1
  const sup1 = await startSupervisor({ host: '127.0.0.1', port, enginePort });
  const status1 = await (await fetch(`http://127.0.0.1:${port}/api/v1/runtime/status`)).json();
  await sup1.stop();

  // Wait brief pause for socket reuse
  await new Promise(r => setTimeout(r, 200));

  // Run 2 after restart
  const sup2 = await startSupervisor({ host: '127.0.0.1', port, enginePort });
  const status2 = await (await fetch(`http://127.0.0.1:${port}/api/v1/runtime/status`)).json();
  await sup2.stop();

  assert.deepEqual(status1, status2);
});

test('engine evaluate-fixture endpoint enforces private resource fail-closed and error semantics', async t => {
  const port = await getFreePort();
  const enginePort = await getFreePort();

  const supervisor = await startSupervisor({ host: '127.0.0.1', port, enginePort });
  t.after(async () => {
    await supervisor.stop();
  });

  const engineUrl = `http://127.0.0.1:${enginePort}`;

  // 1. Unauthenticated private resource fails closed
  const privRes = await fetch(`${engineUrl}/v1/runtime/evaluate-fixture`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      request: {
        subject: 'anonymous',
        resource: 'service:analytics:private',
        action: 'read',
        authenticated: false,
      },
    }),
  });
  assert.equal(privRes.status, 200);
  const privBody = await privRes.json();
  assert.equal(privBody.allow, false);
  assert.equal(privBody.error, 'unauthenticated_identity');
  assert.deepEqual(privBody.reasons, ['fail_closed_private_resource']);

  // 2. Missing provider fails closed
  const provRes = await fetch(`${engineUrl}/v1/runtime/evaluate-fixture`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      request: {
        subject: 'operator',
        resource: 'service:analytics',
        action: 'read',
        provider_required: 'local_opa',
        provider_state: 'unavailable',
      },
    }),
  });
  assert.equal(provRes.status, 200);
  const provBody = await provRes.json();
  assert.equal(provBody.allow, false);
  assert.equal(provBody.error, 'provider_unavailable');
  assert.deepEqual(provBody.reasons, ['fail_closed_provider_unavailable']);

  // 3. Malformed payload rejected with 400
  const badRes = await fetch(`${engineUrl}/v1/runtime/evaluate-fixture`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ corrupted: true }),
  });
  assert.equal(badRes.status, 400);
  const badBody = await badRes.json();
  assert.equal(badBody.allow, false);
  assert.equal(badBody.error, 'malformed_fixture');
});
