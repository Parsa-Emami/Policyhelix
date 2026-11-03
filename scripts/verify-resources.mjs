#!/usr/bin/env node
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

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

export function validateResourceEntry(name, entry) {
  const errors = [];
  if (!entry || typeof entry !== 'object') {
    return [`Resource '${name}' must be an object.`];
  }

  if (!entry.version || typeof entry.version !== 'string' || entry.version.trim() === '') {
    errors.push(`Resource '${name}' missing version.`);
  } else if (/^latest$|^edge$|^nightly$|^main$|^master$/i.test(entry.version) && !entry.digest) {
    errors.push(`Resource '${name}' uses floating/mutable tag '${entry.version}' without immutable digest.`);
  }

  if (!entry.digest || typeof entry.digest !== 'string' || entry.digest.trim() === '') {
    errors.push(`Resource '${name}' missing immutable digest.`);
  } else if (entry.digest !== 'in-repo source' && !/^sha256:[0-9a-f]{64}$/i.test(entry.digest)) {
    errors.push(`Resource '${name}' digest must be 'in-repo source' or 'sha256:<64-hex>'; got '${entry.digest}'.`);
  }

  if (!entry.license || typeof entry.license !== 'string' || entry.license.trim() === '') {
    errors.push(`Resource '${name}' missing declared open-source license.`);
  } else if (/proprietary|commercial|restricted/i.test(entry.license)) {
    errors.push(`Resource '${name}' specifies non-open-source license: '${entry.license}'.`);
  }

  if (!entry.source_url || typeof entry.source_url !== 'string' || entry.source_url.trim() === '') {
    errors.push(`Resource '${name}' missing official upstream source URL.`);
  }

  if (entry.paid_or_cloud_account_required === true) {
    errors.push(`Resource '${name}' requires forbidden paid/cloud account.`);
  }

  return errors;
}

export function validateToolchainLock(lock) {
  const errors = [];
  if (!lock || typeof lock !== 'object') return ['Toolchain lock must be a JSON object.'];

  if (lock.schema_version !== 1) {
    errors.push(`Unsupported toolchain lock schema_version: ${lock.schema_version}; expected 1.`);
  }

  if (!lock.runtime?.node || !lock.runtime?.npm) {
    errors.push('Missing runtime Node/npm lock definition.');
  }

  if (!lock.engine_toolchain?.language || !lock.engine_toolchain?.version || !lock.engine_toolchain?.license) {
    errors.push('Missing engine toolchain (Go) specification.');
  }

  if (lock.paid_or_cloud_account_required !== false) {
    errors.push('Toolchain lock must specify paid_or_cloud_account_required: false.');
  }

  if (!lock.providers || typeof lock.providers !== 'object') {
    errors.push('Toolchain lock missing providers map.');
    return errors;
  }

  for (const [name, prov] of Object.entries(lock.providers)) {
    errors.push(...validateResourceEntry(name, prov));
  }

  return errors;
}

export async function validateLiveToolchainAndFixtures() {
  const errors = [];
  const lockPath = 'docs/engineering/toolchain-lock.json';
  const reqPath = 'ops/runtime-requirements.json';
  const manifestPath = 'tests/fixtures/policyhelix/C02/manifest.json';

  // 1. Toolchain lock check
  const lockData = JSON.parse(await readFile(resolve(root, lockPath), 'utf8'));
  errors.push(...validateToolchainLock(lockData));

  // 2. Runtime requirements check
  const reqData = JSON.parse(await readFile(resolve(root, reqPath), 'utf8'));
  if (reqData.project !== 'PolicyHelix') errors.push('Runtime requirements project mismatch.');
  if (reqData.paid_or_cloud_account_required !== false) {
    errors.push('Runtime requirements must explicitly state paid_or_cloud_account_required: false.');
  }
  if (!Array.isArray(reqData.providers) || reqData.providers.length === 0) {
    errors.push('Runtime requirements missing providers list.');
  }

  // 3. Fixtures check
  const manifestData = JSON.parse(await readFile(resolve(root, manifestPath), 'utf8'));
  if (manifestData.commit_id !== 'C02' || manifestData.project !== 'PolicyHelix') {
    errors.push('C02 manifest identity mismatch.');
  }

  for (const item of manifestData.fixtures ?? []) {
    if (!isSafeRepoPath(item.path)) {
      errors.push(`Unsafe fixture path: ${item.path}`);
      continue;
    }
    try {
      await access(resolve(root, item.path));
      const actualHash = await hashFile(item.path);
      if (actualHash !== item.sha256) {
        errors.push(`Fixture hash mismatch for ${item.path}: expected ${item.sha256}, got ${actualHash}.`);
      }
    } catch (err) {
      errors.push(`Failed to access fixture ${item.path}: ${err.message}`);
    }
  }

  return errors;
}

export function probeInstalledToolchain() {
  const probes = [];

  // Node.js probe
  const nodeVer = process.version;
  const nodeOk = /^v24\./.test(nodeVer);
  probes.push({ tool: 'Node.js', version: nodeVer, required: '24.x', passed: nodeOk });

  // npm probe
  const npmRes = spawnSync('npm', ['--version'], { encoding: 'utf8' });
  const npmVer = npmRes.status === 0 ? npmRes.stdout.trim() : 'missing';
  probes.push({ tool: 'npm', version: npmVer, required: '11.x', passed: npmRes.status === 0 });

  // Go compiler probe
  const goRes = spawnSync('go', ['version'], { encoding: 'utf8' });
  const goVer = goRes.status === 0 ? goRes.stdout.trim() : 'missing';
  probes.push({ tool: 'Go compiler', version: goVer, required: 'Go 1.26+', passed: goRes.status === 0 });

  return probes;
}

export function runNegativeRegressionSuite() {
  const tests = [
    {
      name: 'Floating provider tag without digest is rejected',
      entry: {
        name: 'opa',
        version: 'latest',
        digest: null,
        license: 'Apache-2.0',
        source_url: 'https://openpolicyagent.org'
      },
      match: /floating\/mutable tag/
    },
    {
      name: 'Missing official source or license is rejected',
      entry: {
        name: 'test-tool',
        version: '1.0.0',
        digest: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        license: '',
        source_url: ''
      },
      match: /missing declared open-source license/
    },
    {
      name: 'Mandatory paid or cloud account requirement is rejected',
      entry: {
        name: 'cloud-vault',
        version: '1.0.0',
        digest: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        license: 'Apache-2.0',
        source_url: 'https://vault.example.com',
        paid_or_cloud_account_required: true
      },
      match: /requires forbidden paid\/cloud account/
    },
    {
      name: 'Proprietary license is rejected',
      entry: {
        name: 'proprietary-driver',
        version: '1.0.0',
        digest: 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
        license: 'Proprietary Commercial',
        source_url: 'https://vendor.example.com'
      },
      match: /specifies non-open-source license/
    },
    {
      name: 'Malformed digest format is rejected',
      entry: {
        name: 'bad-digest-tool',
        version: '1.0.0',
        digest: 'md5:badchecksum',
        license: 'Apache-2.0',
        source_url: 'https://tool.example.com'
      },
      match: /digest must be 'in-repo source' or 'sha256:<64-hex>'/
    }
  ];

  const results = [];
  for (const test of tests) {
    const errs = validateResourceEntry(test.entry.name, test.entry);
    const joined = errs.join('\n');
    const passed = test.match.test(joined);
    results.push({ name: test.name, passed, errors: errs });
  }

  return results;
}

async function main() {
  console.log('--- Verifying PolicyHelix Open-Source Resource Locks (C02) ---');

  const liveErrors = await validateLiveToolchainAndFixtures();
  if (liveErrors.length > 0) {
    console.error('FAIL: Resource validation failed with errors:');
    for (const e of liveErrors) console.error(` - ${e}`);
    process.exitCode = 1;
    return;
  }
  console.log('✔ docs/engineering/toolchain-lock.json and ops/runtime-requirements.json validated successfully.');

  console.log('--- Probing Installed System Toolchain ---');
  const probes = probeInstalledToolchain();
  for (const p of probes) {
    console.log(`[Probe] ${p.tool}: ${p.version} (Required: ${p.required}) -> ${p.passed ? 'PASSED' : 'MISSING'}`);
    if (!p.passed && (p.tool === 'Node.js' || p.tool === 'Go compiler')) {
      console.error(`FAIL: Required compiler/runtime ${p.tool} is not available.`);
      process.exitCode = 1;
      return;
    }
  }

  console.log('--- Running Negative Regression Cases ---');
  const negResults = runNegativeRegressionSuite();
  let negFailed = 0;
  for (const res of negResults) {
    if (res.passed) {
      console.log(`✔ [Negative Case] ${res.name} rejected as expected.`);
    } else {
      console.error(`✖ [Negative Case] ${res.name} FAILED to reject invalid resource!`);
      negFailed++;
    }
  }

  if (negFailed > 0) {
    console.error(`FAIL: ${negFailed} negative regression tests failed.`);
    process.exitCode = 1;
    return;
  }

  console.log('✔ All resource locks, toolchain probes, and negative regression tests passed.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => {
    console.error(`Unexpected validator failure: ${err.message}`);
    process.exitCode = 1;
  });
}
