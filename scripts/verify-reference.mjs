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

export function validateScenarioStructure(scenario) {
  const errors = [];
  if (!scenario || typeof scenario !== 'object') {
    return ['Scenario must be a valid JSON object.'];
  }

  if (scenario.schema_version !== 1) {
    errors.push(`Unsupported scenario version: ${scenario.schema_version}; expected 1.`);
  }

  if (scenario.project !== 'PolicyHelix') {
    errors.push(`Project mismatch: expected 'PolicyHelix', got '${scenario.project}'.`);
  }

  if (scenario.engine_implemented === true) {
    errors.push('Rejected scenario: cannot claim engine_implemented=true before C03/C30 engine realization.');
  }

  if (typeof scenario.status === 'string' && /passed|certified domain proof|completed engine/i.test(scenario.status)) {
    errors.push('Rejected scenario: status cannot claim executed engine domain proof in specification task C01.');
  }

  if (!scenario.license || typeof scenario.license !== 'string') {
    errors.push('Missing required repository license metadata.');
  }

  if (!scenario.provenance || typeof scenario.provenance !== 'string') {
    errors.push('Missing required provenance metadata.');
  }

  const requiredInvariants = [
    'Private resources fail closed',
    'Only authenticated normalized identity enters policy',
    'Bundle signature plus freshness and monotonic revision'
  ];

  if (!Array.isArray(scenario.expected_invariants)) {
    errors.push('Scenario missing expected_invariants array.');
  } else {
    for (const inv of requiredInvariants) {
      if (!scenario.expected_invariants.includes(inv)) {
        errors.push(`Missing required domain invariant: '${inv}'.`);
      }
    }
  }

  if (!Array.isArray(scenario.steps) || scenario.steps.length === 0) {
    errors.push('Scenario steps must be a non-empty array.');
    return errors;
  }

  for (let i = 0; i < scenario.steps.length; i++) {
    const step = scenario.steps[i];
    const prefix = `Step ${i + 1} (${step?.step_id ?? 'unnamed'}):`;

    if (!step.action || typeof step.action !== 'string' || step.action.trim() === '') {
      errors.push(`${prefix} missing required action name.`);
    }

    if (!step.fixture_ref || typeof step.fixture_ref !== 'string') {
      errors.push(`${prefix} missing fixture reference.`);
    } else if (!isSafeRepoPath(step.fixture_ref)) {
      errors.push(`${prefix} fixture path outside repository or unsafe traversal: '${step.fixture_ref}'.`);
    }

    if (!step.expected_result || typeof step.expected_result !== 'object') {
      errors.push(`${prefix} missing expected_result object.`);
    }

    if (!Array.isArray(step.invariants_checked) || step.invariants_checked.length === 0) {
      errors.push(`${prefix} missing invariants_checked list.`);
    }

    if (typeof step.execution_status === 'string' && /passed engine|verified runtime/i.test(step.execution_status)) {
      errors.push(`${prefix} invalid execution_status claiming unimplemented engine passed.`);
    }
  }

  return errors;
}

export async function validateLiveReferenceWorkflow() {
  const scenarioPath = 'tests/scenarios/clone-to-value.json';
  const manifestPath = 'tests/fixtures/policyhelix/C01/manifest.json';

  const scenarioRaw = await readFile(resolve(root, scenarioPath), 'utf8');
  const scenario = JSON.parse(scenarioRaw);

  const errors = validateScenarioStructure(scenario);

  // Validate manifest and fixtures
  const manifestRaw = await readFile(resolve(root, manifestPath), 'utf8');
  const manifest = JSON.parse(manifestRaw);

  if (manifest.commit_id !== 'C01' || manifest.project !== 'PolicyHelix') {
    errors.push('Manifest identity mismatch.');
  }
  if (!manifest.license || !manifest.provenance) {
    errors.push('Manifest missing license or provenance.');
  }
  if (!Array.isArray(manifest.fixtures) || manifest.fixtures.length === 0) {
    errors.push('Manifest contains no fixture entries.');
  }

  const manifestMap = new Map();
  for (const item of manifest.fixtures ?? []) {
    if (!isSafeRepoPath(item.path)) {
      errors.push(`Manifest fixture path outside repository: '${item.path}'.`);
      continue;
    }
    manifestMap.set(item.path, item);

    try {
      await access(resolve(root, item.path));
      const actualHash = await hashFile(item.path);
      if (actualHash !== item.sha256) {
        errors.push(`Fixture hash mismatch for ${item.path}: expected ${item.sha256}, got ${actualHash}.`);
      }

      // Check fixture payload schema
      const fixtureData = JSON.parse(await readFile(resolve(root, item.path), 'utf8'));
      if (!fixtureData.license || !fixtureData.provenance) {
        errors.push(`Fixture ${item.path} missing license or provenance.`);
      }
      if (fixtureData.expected_decision) {
        const ed = fixtureData.expected_decision;
        for (const f of ['subject', 'resource', 'action', 'policy_digest', 'allow', 'reasons', 'obligations']) {
          if (ed[f] === undefined) errors.push(`Fixture ${item.path} expected_decision missing field '${f}'.`);
        }
      }
    } catch (err) {
      errors.push(`Failed to access or parse fixture ${item.path}: ${err.message}`);
    }
  }

  // Ensure all steps point to known manifest fixtures
  for (const step of scenario.steps ?? []) {
    if (step.fixture_ref && isSafeRepoPath(step.fixture_ref) && !manifestMap.has(step.fixture_ref)) {
      errors.push(`Step ${step.step_id} references fixture not declared in C01 manifest: ${step.fixture_ref}`);
    }
  }

  return errors;
}

export function runNegativeRegressionSuite() {
  const tests = [
    {
      name: 'Missing action fails validation',
      scenario: {
        schema_version: 1,
        project: 'PolicyHelix',
        engine_implemented: false,
        license: 'Apache-2.0',
        provenance: 'test',
        expected_invariants: [
          'Private resources fail closed',
          'Only authenticated normalized identity enters policy',
          'Bundle signature plus freshness and monotonic revision'
        ],
        steps: [{ step_id: 'S1', fixture_ref: 'tests/f.json', expected_result: { allow: true }, invariants_checked: ['Private resources fail closed'] }]
      },
      match: /missing required action name/
    },
    {
      name: 'Missing expected_result fails validation',
      scenario: {
        schema_version: 1,
        project: 'PolicyHelix',
        engine_implemented: false,
        license: 'Apache-2.0',
        provenance: 'test',
        expected_invariants: [
          'Private resources fail closed',
          'Only authenticated normalized identity enters policy',
          'Bundle signature plus freshness and monotonic revision'
        ],
        steps: [{ step_id: 'S1', action: 'test', fixture_ref: 'tests/f.json', invariants_checked: ['Private resources fail closed'] }]
      },
      match: /missing expected_result object/
    },
    {
      name: 'Missing invariant fails validation',
      scenario: {
        schema_version: 1,
        project: 'PolicyHelix',
        engine_implemented: false,
        license: 'Apache-2.0',
        provenance: 'test',
        expected_invariants: ['Private resources fail closed'],
        steps: [{ step_id: 'S1', action: 'test', fixture_ref: 'tests/f.json', expected_result: {}, invariants_checked: ['Private resources fail closed'] }]
      },
      match: /Missing required domain invariant/
    },
    {
      name: 'Missing provenance/license fails validation',
      scenario: {
        schema_version: 1,
        project: 'PolicyHelix',
        engine_implemented: false,
        expected_invariants: [
          'Private resources fail closed',
          'Only authenticated normalized identity enters policy',
          'Bundle signature plus freshness and monotonic revision'
        ],
        steps: [{ step_id: 'S1', action: 'test', fixture_ref: 'tests/f.json', expected_result: {}, invariants_checked: ['Private resources fail closed'] }]
      },
      match: /Missing required repository license metadata/
    },
    {
      name: 'Fixture path outside repository is rejected',
      scenario: {
        schema_version: 1,
        project: 'PolicyHelix',
        engine_implemented: false,
        license: 'Apache-2.0',
        provenance: 'test',
        expected_invariants: [
          'Private resources fail closed',
          'Only authenticated normalized identity enters policy',
          'Bundle signature plus freshness and monotonic revision'
        ],
        steps: [{ step_id: 'S1', action: 'test', fixture_ref: '../outside.json', expected_result: {}, invariants_checked: ['Private resources fail closed'] }]
      },
      match: /fixture path outside repository or unsafe traversal/
    },
    {
      name: 'Unsupported scenario version is rejected',
      scenario: {
        schema_version: 99,
        project: 'PolicyHelix',
        engine_implemented: false,
        license: 'Apache-2.0',
        provenance: 'test',
        expected_invariants: [
          'Private resources fail closed',
          'Only authenticated normalized identity enters policy',
          'Bundle signature plus freshness and monotonic revision'
        ],
        steps: [{ step_id: 'S1', action: 'test', fixture_ref: 'tests/f.json', expected_result: {}, invariants_checked: ['Private resources fail closed'] }]
      },
      match: /Unsupported scenario version: 99/
    },
    {
      name: 'Falsely claiming unimplemented engine passed is rejected',
      scenario: {
        schema_version: 1,
        project: 'PolicyHelix',
        engine_implemented: true,
        status: 'passed engine proof',
        license: 'Apache-2.0',
        provenance: 'test',
        expected_invariants: [
          'Private resources fail closed',
          'Only authenticated normalized identity enters policy',
          'Bundle signature plus freshness and monotonic revision'
        ],
        steps: [{ step_id: 'S1', action: 'test', fixture_ref: 'tests/f.json', expected_result: {}, invariants_checked: ['Private resources fail closed'] }]
      },
      match: /cannot claim engine_implemented=true/
    }
  ];

  const results = [];
  for (const test of tests) {
    const errs = validateScenarioStructure(test.scenario);
    const joined = errs.join('\n');
    const passed = test.match.test(joined);
    results.push({ name: test.name, passed, errors: errs });
  }

  return results;
}

async function main() {
  console.log('--- Verifying PolicyHelix Reference Workflow Contract (C01) ---');

  const liveErrors = await validateLiveReferenceWorkflow();
  if (liveErrors.length > 0) {
    console.error('FAIL: Reference workflow validation failed with errors:');
    for (const e of liveErrors) console.error(` - ${e}`);
    process.exitCode = 1;
    return;
  }
  console.log('✔ Live scenario and synthetic fixtures validated successfully.');

  console.log('--- Running Negative Regression Cases ---');
  const negResults = runNegativeRegressionSuite();
  let negFailed = 0;
  for (const res of negResults) {
    if (res.passed) {
      console.log(`✔ [Negative Case] ${res.name} rejected as expected.`);
    } else {
      console.error(`✖ [Negative Case] ${res.name} FAILED to reject invalid scenario!`);
      negFailed++;
    }
  }

  if (negFailed > 0) {
    console.error(`FAIL: ${negFailed} negative regression tests failed.`);
    process.exitCode = 1;
    return;
  }

  console.log('✔ All positive and negative reference contract checks passed.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => {
    console.error(`Unexpected validator failure: ${err.message}`);
    process.exitCode = 1;
  });
}
