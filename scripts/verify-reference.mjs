#!/usr/bin/env node
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../', import.meta.url));

export function isSafeRepoPath(targetPath) {
  if (typeof targetPath !== 'string' || targetPath.trim() === '') return false;
  if (isAbsolute(targetPath)) return false;
  if (targetPath.split(/[\\/]/).includes('..')) return false;
  const resolved = resolve(root, targetPath);
  const rel = relative(root, resolved);
  return !rel.startsWith('..') && !isAbsolute(rel);
}

export async function hashFile(relPath) {
  const content = await readFile(resolve(root, relPath));
  return createHash('sha256').update(content).digest('hex');
}

const requiredInvariants = [
  'Private resources fail closed',
  'Only authenticated normalized identity enters policy',
  'Bundle signature plus freshness and monotonic revision'
];

const allowedReferenceEndpoints = new Set([
  '/api/v1/reference/simulate',
  '/api/v1/reference/session',
  '/api/v1/reference/bundle',
  '/api/v1/reference/proxy',
  '/api/v1/reference/spoof',
  '/api/v1/reference/revoke',
  '/api/v1/reference/outage',
  '/api/v1/reference/state'
]);

export function validateScenarioStructure(scenario) {
  const errors = [];
  if (!scenario || typeof scenario !== 'object') {
    return ['Scenario must be a valid JSON object.'];
  }

  if (scenario.schema_version !== 2) {
    errors.push(`Unsupported scenario version: ${scenario.schema_version}; expected 2.`);
  }

  if (scenario.project !== 'PolicyHelix') {
    errors.push(`Project mismatch: expected 'PolicyHelix', got '${scenario.project}'.`);
  }

  if (scenario.engine_implemented !== true) {
    errors.push('Schema v2 requires engine_implemented=true backed by the C30 fixtures and clone proof.');
  }

  if (typeof scenario.status === 'string' && /\bpassed\b|certified domain proof/i.test(scenario.status)) {
    errors.push('Rejected scenario: status must not claim executed evidence; docs/evidence/C30.json carries command results.');
  }

  if (!scenario.license || typeof scenario.license !== 'string') {
    errors.push('Missing required repository license metadata.');
  }

  if (!scenario.provenance || typeof scenario.provenance !== 'string') {
    errors.push('Missing required provenance metadata.');
  }

  if (!Array.isArray(scenario.expected_invariants)) {
    errors.push('Scenario missing expected_invariants array.');
  } else {
    for (const inv of requiredInvariants) {
      if (!scenario.expected_invariants.includes(inv)) {
        errors.push(`Missing required domain invariant: '${inv}'.`);
      }
    }
  }

  if (!Array.isArray(scenario.steps) || scenario.steps.length !== 6) {
    errors.push('Scenario must declare exactly the six reference workflow stages.');
    if (!Array.isArray(scenario.steps) || scenario.steps.length === 0) return errors;
  }

  for (const step of scenario.steps) {
    const prefix = `Step ${step?.step_id ?? 'unnamed'}:`;
    for (const field of ['step_id', 'action', 'summary', 'fixture_ref']) {
      if (!step?.[field] || typeof step[field] !== 'string') errors.push(`${prefix} missing required ${field}.`);
    }
    if (step?.fixture_ref && !isSafeRepoPath(step.fixture_ref)) {
      errors.push(`${prefix} fixture path outside repository or unsafe traversal: '${step.fixture_ref}'.`);
    }
    if (!step?.expected_result || typeof step.expected_result !== 'object' || Object.keys(step.expected_result).length === 0) {
      errors.push(`${prefix} missing expected_result object.`);
    }
    if (!/^C30-(?:POS|NEG)-\d{2}:STEP-\d{2}$/.test(step?.observed_from ?? '')) {
      errors.push(`${prefix} must declare observed_from as a C30 fixture observation.`);
    }
    if (!Array.isArray(step?.invariants_checked) || step.invariants_checked.length === 0) {
      errors.push(`${prefix} missing invariants_checked list.`);
    }
    if (!Array.isArray(step?.engine_endpoints) || step.engine_endpoints.length === 0) {
      errors.push(`${prefix} must declare the engine endpoints it executes.`);
    } else {
      for (const endpoint of step.engine_endpoints) {
        if (!allowedReferenceEndpoints.has(endpoint)) errors.push(`${prefix} references an undeclared workflow endpoint: '${endpoint}'.`);
      }
    }
    if (typeof step?.execution_status === 'string' && /\bpassed\b/i.test(step.execution_status)) {
      errors.push(`${prefix} must not claim execution results; the clone smoke run records them.`);
    }
  }

  if (!scenario.restart_and_restore || typeof scenario.restart_and_restore !== 'object') {
    errors.push('Scenario must declare the restart_and_restore contract.');
  } else if (!scenario.restart_and_restore.fixture_ref || !isSafeRepoPath(scenario.restart_and_restore.fixture_ref)) {
    errors.push('restart_and_restore must reference a repository fixture.');
  } else if (!/^C30-(?:POS|NEG)-\d{2}:STEP-\d{2}$/.test(scenario.restart_and_restore.observed_from ?? '')) {
    errors.push('restart_and_restore must declare observed_from as a C30 fixture observation.');
  }

  return errors;
}

async function validateManifest(manifestPath, expectedCommit, requireSteps = false) {
  const errors = [];
  const manifest = JSON.parse(await readFile(resolve(root, manifestPath), 'utf8'));
  if (manifest.commit_id !== expectedCommit || manifest.project !== 'PolicyHelix') errors.push(`${manifestPath} identity mismatch.`);
  if (!manifest.license || !manifest.provenance) errors.push(`${manifestPath} missing license or provenance.`);
  if (!Array.isArray(manifest.fixtures) || manifest.fixtures.length === 0) errors.push(`${manifestPath} contains no fixture entries.`);

  const byPath = new Map();
  for (const item of manifest.fixtures ?? []) {
    if (!isSafeRepoPath(item.path)) {
      errors.push(`${manifestPath} fixture path outside repository: '${item.path}'.`);
      continue;
    }
    byPath.set(item.path, item);
    try {
      await access(resolve(root, item.path));
      const actual = await hashFile(item.path);
      if (actual !== item.sha256) errors.push(`Fixture hash mismatch for ${item.path}: expected ${item.sha256}, got ${actual}.`);
      const fixture = JSON.parse(await readFile(resolve(root, item.path), 'utf8'));
      if (!fixture.license || !fixture.provenance) errors.push(`Fixture ${item.path} missing license or provenance.`);
      if (!requireSteps) continue;
      if (!Array.isArray(fixture.steps) || fixture.steps.length === 0) {
        errors.push(`Fixture ${item.path} must declare executable steps.`);
        continue;
      }
      for (const step of fixture.steps) {
        if (!step.endpoint || !step.method || !step.expected || typeof step.expected.http_status !== 'number') {
          errors.push(`Fixture ${item.path} step ${step.step_id ?? '?'} must declare endpoint, method and expected http_status.`);
        }
      }
    } catch (err) {
      errors.push(`Failed to access or parse fixture ${item.path}: ${err.message}`);
    }
  }
  return { errors, manifest, byPath };
}

export async function validateLiveReferenceWorkflow() {
  const scenarioPath = 'tests/scenarios/clone-to-value.json';
  const scenario = JSON.parse(await readFile(resolve(root, scenarioPath), 'utf8'));
  const errors = validateScenarioStructure(scenario);

  const c30 = await validateManifest('tests/fixtures/policyhelix/C30/manifest.json', 'C30', true);
  errors.push(...c30.errors);
  // C01 fixtures remain the frozen simulator/negative source and must stay intact.
  const c01 = await validateManifest('tests/fixtures/policyhelix/C01/manifest.json', 'C01');
  errors.push(...c01.errors);

  for (const step of scenario.steps ?? []) {
    if (step.fixture_ref && isSafeRepoPath(step.fixture_ref) && !c30.byPath.has(step.fixture_ref)) {
      errors.push(`Step ${step.step_id} references fixture not declared in the C30 manifest: ${step.fixture_ref}`);
    }
  }
  if (scenario.restart_and_restore?.fixture_ref && !c30.byPath.has(scenario.restart_and_restore.fixture_ref)) {
    errors.push('restart_and_restore references a fixture not declared in the C30 manifest.');
  }

  const fixtureIds = new Set(c30.manifest.fixtures.map(item => item.fixture_id));
  for (const required of ['C30-POS-01', 'C30-POS-02', 'C30-NEG-01', 'C30-NEG-02', 'C30-NEG-03', 'C30-NEG-04', 'C30-NEG-05', 'C30-NEG-06', 'C30-NEG-07']) {
    if (!fixtureIds.has(required)) errors.push(`C30 manifest is missing declared fixture ${required}.`);
  }

  return errors;
}

function baseScenario(overrides = {}) {
  return {
    schema_version: 2,
    project: 'PolicyHelix',
    engine_implemented: true,
    license: 'Apache-2.0',
    provenance: 'test',
    expected_invariants: [...requiredInvariants],
    restart_and_restore: { fixture_ref: 'tests/fixtures/policyhelix/C30/positive-restart-restore.json', observed_from: 'C30-POS-02:STEP-09' },
    steps: [{
      step_id: 'STEP-01',
      action: 'simulate',
      summary: 'synthetic',
      fixture_ref: 'tests/fixtures/policyhelix/C30/positive-reference-workflow.json',
      expected_result: { allow: true },
      invariants_checked: ['Private resources fail closed'],
      engine_endpoints: ['/api/v1/reference/simulate'],
      observed_from: 'C30-POS-01:STEP-01',
      execution_status: 'executed by the clone smoke runner'
    }],
    ...overrides
  };
}

export function runNegativeRegressionSuite() {
  const tests = [
    { name: 'Missing six-stage workflow is rejected', scenario: baseScenario({ steps: [] }), match: /six reference workflow stages/ },
    { name: 'Missing action fails validation', scenario: baseScenario({ steps: [{ ...baseScenario().steps[0], action: undefined }] }), match: /missing required action/ },
    { name: 'Missing expected_result fails validation', scenario: baseScenario({ steps: [{ ...baseScenario().steps[0], expected_result: undefined }] }), match: /missing expected_result object/ },
    { name: 'Missing invariant fails validation', scenario: baseScenario({ expected_invariants: ['Private resources fail closed'] }), match: /Missing required domain invariant/ },
    { name: 'Missing provenance/license fails validation', scenario: baseScenario({ license: undefined }), match: /Missing required repository license metadata/ },
    { name: 'Fixture path outside repository is rejected', scenario: baseScenario({ steps: [{ ...baseScenario().steps[0], fixture_ref: '../outside.json' }] }), match: /fixture path outside repository or unsafe traversal/ },
    { name: 'Unsupported scenario version is rejected', scenario: baseScenario({ schema_version: 99 }), match: /Unsupported scenario version: 99/ },
    { name: 'Falsely claiming engine implementation without v2 is rejected', scenario: baseScenario({ engine_implemented: false }), match: /engine_implemented=true/ },
    { name: 'A declared pass without executed evidence is rejected', scenario: baseScenario({ status: 'passed' }), match: /must not claim executed evidence/ },
    { name: 'Undeclared workflow endpoint is rejected', scenario: baseScenario({ steps: [{ ...baseScenario().steps[0], engine_endpoints: ['/api/v1/admin'] }] }), match: /undeclared workflow endpoint/ },
    { name: 'A step without an executed observation is rejected', scenario: baseScenario({ steps: [{ ...baseScenario().steps[0], observed_from: undefined }] }), match: /must declare observed_from/ },
    { name: 'A restart claim without an executed observation is rejected', scenario: baseScenario({ restart_and_restore: { fixture_ref: 'tests/fixtures/policyhelix/C30/positive-restart-restore.json' } }), match: /restart_and_restore must declare observed_from/ }
  ];

  return tests.map(test => {
    const errors = validateScenarioStructure(test.scenario);
    return { name: test.name, passed: test.match.test(errors.join('\n')), errors };
  });
}

async function main() {
  console.log('--- Verifying PolicyHelix Reference Workflow Contract (C30) ---');

  const liveErrors = await validateLiveReferenceWorkflow();
  if (liveErrors.length > 0) {
    console.error('FAIL: Reference workflow validation failed with errors:');
    for (const e of liveErrors) console.error(` - ${e}`);
    process.exitCode = 1;
    return;
  }
  console.log('✔ Executed scenario contract, C30 fixtures and preserved C01 fixtures validated.');

  console.log('--- Running Validator Negative Regression Cases ---');
  let failed = 0;
  for (const res of runNegativeRegressionSuite()) {
    if (res.passed) console.log(`✔ [Negative Case] ${res.name} rejected as expected.`);
    else { console.error(`✖ [Negative Case] ${res.name} FAILED to reject invalid scenario.`); failed++; }
  }
  if (failed > 0) {
    console.error(`FAIL: ${failed} negative regression tests failed.`);
    process.exitCode = 1;
    return;
  }
  console.log('✔ Scenario structure, fixture integrity and negative validator cases pass.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => {
    console.error(`Unexpected validator failure: ${err.message}`);
    process.exitCode = 1;
  });
}
