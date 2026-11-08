import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'oss-clone-'));
let supervisor;
let bareEngine;

function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stdout ?? ''}${result.stderr ?? result.error?.message ?? ''}`);
  }
  return result.stdout.trim();
}

function freePort() {
  return new Promise((accept, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close(() => accept(port));
    });
  });
}

async function waitFor(url, timeoutMs, label) {
  const start = Date.now();
  let lastError;
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (response.ok) return response;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise(accept => setTimeout(accept, 100));
  }
  throw new Error(`${label} did not become ready within ${timeoutMs}ms: ${lastError?.message ?? 'timeout'}`);
}

function startLocalSupervisor(checkout, port, enginePort) {
  const child = spawn(process.execPath, [
    'scripts/start-local.mjs', '--port', String(port), '--engine-port', String(enginePort),
  ], { cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stdout.on('data', chunk => { log += chunk.toString(); });
  child.stderr.on('data', chunk => { log += chunk.toString(); });
  return { child, log: () => log };
}

async function stopProcess(child, label) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise(accept => child.once('exit', accept)),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} did not stop within 15s`)), 15000)),
  ]);
}

async function readFixture(checkout, relPath) {
  return JSON.parse(await readFile(resolve(checkout, relPath), 'utf8'));
}

function substitute(value, sessions) {
  if (value === '$SESSION') return sessions.SESSION ?? '';
  if (value === '$SESSION_ACTIVE') return sessions.SESSION_ACTIVE ?? '';
  return value;
}

function applyBody(body, sessions) {
  return Object.fromEntries(Object.entries(body ?? {}).map(([key, value]) => [
    key, typeof value === 'string' ? substitute(value, sessions) : value,
  ]));
}

function fieldValue(key, data, sessions) {
  switch (key) {
    case 'decision_allow': {
      const decision = data?.decision;
      return { present: decision !== undefined && decision !== null, value: decision?.allow };
    }
    case 'side_effects_executed':
      if (Object.hasOwn(data ?? {}, key)) return { present: true, value: data.side_effects_executed };
      return { present: data?.access_check !== undefined, value: data?.access_check?.side_effects_executed };
    case 'active_bundle_present':
      return { present: true, value: data?.active_bundle !== undefined && data?.active_bundle !== null };
    case 'revoked_session_present': {
      const ids = Array.isArray(data?.revoked_session_ids) ? data.revoked_session_ids : [];
      return { present: true, value: sessions.SESSION ? ids.includes(sessions.SESSION) : ids.length > 0 };
    }
    case 'upstream_ready':
      return { present: data?.upstream !== undefined, value: data?.upstream?.ready };
    case 'provider_count':
      return { present: true, value: Array.isArray(data?.providers) ? data.providers.length : -1 };
    default:
      return { present: Object.hasOwn(data ?? {}, key), value: data?.[key] };
  }
}

function assertExpected(prefix, expected, status, data, sessions) {
  if (typeof expected.http_status === 'number' && status !== expected.http_status) {
    throw new Error(`${prefix}: expected HTTP ${expected.http_status}, got ${status} (${JSON.stringify(data).slice(0, 400)})`);
  }
  for (const [key, want] of Object.entries(expected)) {
    if (key === 'http_status') continue;
    const got = fieldValue(key, data, sessions);
    if (!got.present) {
      throw new Error(`${prefix}: expected field '${key}' is missing from ${JSON.stringify(data).slice(0, 400)}`);
    }
    if (JSON.stringify(got.value) !== JSON.stringify(want)) {
      throw new Error(`${prefix}: expected ${key}=${JSON.stringify(want)}, got ${JSON.stringify(got.value)}`);
    }
  }
}

async function executeStep(baseUrl, step, sessions) {
  const method = (step.method ?? 'POST').toUpperCase();
  const response = await fetch(baseUrl + step.endpoint, {
    method,
    headers: method === 'GET' ? undefined : { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : JSON.stringify(applyBody(step.body, sessions)),
    signal: AbortSignal.timeout(15000),
  });
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${step.step_id} ${step.endpoint} returned unreadable JSON: ${text.slice(0, 200)}`);
  }
  assertExpected(`${step.step_id} ${step.endpoint}`, step.expected ?? {}, response.status, data, sessions);
  if (step.stage === 'session' && typeof data.session_id === 'string') sessions.SESSION = data.session_id;
  if (step.stage === 'outage-session' && typeof data.session_id === 'string') sessions.SESSION_ACTIVE = data.session_id;
  return { response_status: response.status, data };
}

async function executeFixture(baseUrl, checkout, relPath, sessions, observations) {
  const fixture = await readFixture(checkout, relPath);
  if (!fixture.fixture_id || !Array.isArray(fixture.steps) || fixture.steps.length === 0) {
    throw new Error(`Fixture ${relPath} is missing its identity or executable steps`);
  }
  for (const step of fixture.steps) {
    const { response_status, data } = await executeStep(baseUrl, step, sessions);
    observations.set(`${fixture.fixture_id}:${step.step_id}`, { status: response_status, data });
  }
  return fixture.fixture_id;
}

function assertScenarioObservations(scenario, observations, sessions, includeRestart = true) {
  let checked = 0;
  for (const step of scenario.steps ?? []) {
    const ref = step.observed_from;
    if (!ref) throw new Error(`Scenario ${step.step_id} must declare observed_from`);
    const observation = observations.get(ref);
    if (!observation) throw new Error(`Scenario ${step.step_id} references unexecuted observation ${ref}`);
    assertExpected(`Scenario ${step.step_id} (${ref})`, step.expected_result ?? {}, observation.status, observation.data, sessions);
    checked++;
  }
  const restart = includeRestart ? scenario.restart_and_restore : null;
  if (restart?.observed_from) {
    const observation = observations.get(restart.observed_from);
    if (!observation) throw new Error(`restart_and_restore references unexecuted observation ${restart.observed_from}`);
    assertExpected('Scenario restart_and_restore', restart.expected_result ?? {}, observation.status, observation.data, sessions);
    checked++;
  }
  return checked;
}

async function engineWithoutStorage(checkout) {
  const port = await freePort();
  const binary = resolve(checkout, 'dist', 'engine', 'policyhelix');
  const child = spawn(binary, ['--host', '127.0.0.1', '--port', String(port)], {
    cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  child.stdout.on('data', chunk => { log += chunk.toString(); });
  child.stderr.on('data', chunk => { log += chunk.toString(); });
  try {
    const baseUrl = `http://127.0.0.1:${port}`;
    await waitFor(baseUrl + '/healthz', 10000, 'storage-less engine');
    return { baseUrl, child, log: () => log };
  } catch (error) {
    child.kill('SIGKILL');
    throw new Error(`${error.message}\n${log}`);
  }
}

try {
  // Test the index so contributors can verify a proposed commit before pushing.
  const tree = run('git', ['write-tree'], root);
  const identity = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Clone smoke', GIT_AUTHOR_EMAIL: 'clone@example.invalid',
    GIT_COMMITTER_NAME: 'Clone smoke', GIT_COMMITTER_EMAIL: 'clone@example.invalid',
  };
  const commit = run('git', ['commit-tree', tree, '-m', 'temporary staged source proof'], root, { env: identity });

  // Advertise the snapshot from an isolated repository. No source refs change;
  // a real transport clone collects every object, even from a shallow checkout.
  const source = join(temp, 'source.git');
  run('git', ['init', '--bare', '--quiet', source], temp);
  const objects = resolve(root, run('git', ['rev-parse', '--git-path', 'objects'], root));
  await mkdir(join(source, 'objects', 'info'), { recursive: true });
  await writeFile(join(source, 'objects', 'info', 'alternates'), objects + '\n');
  run('git', ['--git-dir=' + source, 'update-ref', 'refs/heads/snapshot', commit], temp);
  const checkout = join(temp, 'checkout');
  run('git', ['clone', '--quiet', '--no-local', '--branch', 'snapshot', source, checkout], temp);
  if (run('git', ['rev-parse', 'HEAD^{tree}'], checkout) !== tree) throw new Error('Cloned tree differs from index');
  if (!process.env.npm_execpath) throw new Error('Invoke through npm run test:clone.');

  // Clean-clone setup: locked install, web build, engine build.
  run(process.execPath, [process.env.npm_execpath, 'run', 'setup'], checkout);

  const port = await freePort();
  let enginePort = await freePort();
  while (enginePort === port) enginePort = await freePort();
  supervisor = startLocalSupervisor(checkout, port, enginePort);
  const baseUrl = `http://127.0.0.1:${port}`;
  await waitFor(baseUrl + '/readyz?check=all', 30000, 'supervised engine readiness').catch(error => {
    throw new Error(`${error.message}\n--- supervisor output ---\n${supervisor.log()}`);
  });
  const readiness = await (await fetch(baseUrl + '/readyz?check=all')).json();
  if (!readiness.engineReady || Object.keys(readiness.engine?.providers ?? {}).length !== 3) {
    throw new Error(`Supervised readiness is incomplete: ${JSON.stringify(readiness).slice(0, 500)}`);
  }
  for (const [provider, state] of Object.entries(readiness.engine.providers)) {
    if (!state.ready) throw new Error(`Required provider ${provider} is not ready: ${JSON.stringify(state)}`);
  }

  // Keep the web-only proof separately labeled from full engine readiness.
  const webShell = await fetch(baseUrl + '/');
  const webHealth = await (await fetch(baseUrl + '/healthz')).json();
  if (!webShell.ok || webHealth.scope !== 'web-shell') {
    throw new Error(`Web shell proof failed: / returned ${webShell.status}, healthz scope ${webHealth.scope}`);
  }

  const scenario = JSON.parse(await readFile(resolve(checkout, 'tests/scenarios/clone-to-value.json'), 'utf8'));
  const requiredNegative = scenario.required_negative_cases ?? [];
  if (requiredNegative.length === 0) throw new Error('Scenario declares no required negative cases');

  const sessions = {};
  const observations = new Map();
  const executed = [];

  // Stage 1-6: the positive workflow, including both issued sessions.
  executed.push(await executeFixture(baseUrl, checkout, scenario.steps[0].fixture_ref, sessions, observations));
  if (!sessions.SESSION || !sessions.SESSION_ACTIVE) throw new Error('Workflow did not issue both reference sessions');

  // Required negative fixtures, run against the same live workflow authority.
  for (const relPath of requiredNegative) {
    if (relPath.endsWith('negative-unavailable-runtime.json')) continue;
    executed.push(await executeFixture(baseUrl, checkout, relPath, sessions, observations));
  }

  const scenarioChecks = assertScenarioObservations(scenario, observations, sessions, false);

  // The missing-prerequisite case runs the actual engine binary without durable storage.
  const storageLessFixture = await readFixture(checkout, 'tests/fixtures/policyhelix/C30/negative-unavailable-runtime.json');
  bareEngine = await engineWithoutStorage(checkout);
  for (const step of storageLessFixture.steps) {
    const { response_status, data } = await executeStep(bareEngine.baseUrl, step, sessions);
    observations.set(`${storageLessFixture.fixture_id}:${step.step_id}`, { status: response_status, data });
  }
  executed.push(storageLessFixture.fixture_id);
  await stopProcess(bareEngine.child, 'storage-less engine');
  bareEngine = null;

  // Restart the supervisor against the same durable storage directory, then prove restore.
  await stopProcess(supervisor.child, 'supervisor');
  supervisor = null;
  supervisor = startLocalSupervisor(checkout, port, enginePort);
  await waitFor(baseUrl + '/readyz?check=all', 30000, 'restarted supervised engine readiness').catch(error => {
    throw new Error(`${error.message}\n--- restarted supervisor output ---\n${supervisor.log()}`);
  });
  executed.push(await executeFixture(baseUrl, checkout, scenario.restart_and_restore.fixture_ref, sessions, observations));
  const restartCheck = assertScenarioObservations(scenario, observations, sessions);

  const restoredState = observations.get(`${(await readFixture(checkout, scenario.restart_and_restore.fixture_ref)).fixture_id}:STEP-09`)?.data;
  console.log(JSON.stringify({
    passed: true,
    stagedTree: tree,
    commands: ['git clone', 'npm run setup', 'npm start (loopback supervisor)'],
    proof: 'real git clone -> npm run setup -> supervised engine -> six-stage reference workflow -> required negative cases -> restart and restore',
    webOnlyProof: 'git clone -> npm run setup -> web workspace / and /healthz (web-shell) served',
    engineReady: readiness.engineReady,
    providers: Object.fromEntries(Object.entries(readiness.engine.providers).map(([name, state]) => [name, state.status])),
    workflowStages: scenario.steps.length,
    negativeFixtures: requiredNegative.length,
    fixturesExecuted: [...new Set(executed)],
    scenarioChecks: scenarioChecks + restartCheck,
    activeBundleRevision: restoredState?.active_bundle?.revision ?? null,
    highestRevision: restoredState?.highest_revision ?? null,
    revokedSessions: restoredState?.revoked_session_ids?.length ?? null,
    browserSpec: scenario.browser_surface?.spec,
    coreReady: false,
  }));
} finally {
  if (bareEngine) await stopProcess(bareEngine.child, 'storage-less engine').catch(() => {});
  if (supervisor) await stopProcess(supervisor.child, 'supervisor').catch(() => {});
  await rm(temp, { recursive: true, force: true });
}
