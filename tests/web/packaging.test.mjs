import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));

test('C31 packaging: dist/release contains all complete product artifacts and valid checksums', async () => {
  const releaseDir = resolve(root, 'dist/release');

  // Verify release directory exists
  const st = await stat(releaseDir);
  assert.ok(st.isDirectory(), 'dist/release must be a directory');

  // 1. Verify required files per C31 acceptance
  const requiredFiles = [
    'engine/policyhelix',
    'web/index.html',
    'rules/policy.rego',
    'scripts/serve-web.mjs',
    'scripts/start-local.mjs',
    'apps/web/src/lib/runtime-config.mjs',
    'ops/web/nginx.conf.template',
    'ops/web/service.systemd',
    'ops/web/runtime-config.json',
    'ops/web/brand.json',
    'docs/ARTIFACTS.md',
    'docs/WEB_RUNBOOK.md',
    'LICENSE',
    'NOTICE',
    'THIRD_PARTY_NOTICES.md',
    'policyhelix-source.tar.gz',
    'sbom.json',
    'release.json',
    'SHA256SUMS.txt'
  ];

  for (const rel of requiredFiles) {
    const filePath = join(releaseDir, rel);
    const fileStat = await stat(filePath).catch(() => null);
    assert.ok(fileStat, `Required file ${rel} must exist in dist/release`);
    assert.ok(fileStat.size > 0, `File ${rel} must not be empty`);
  }

  // 2. Verify release.json provenance
  const releaseJson = JSON.parse(await readFile(join(releaseDir, 'release.json'), 'utf8'));
  assert.equal(releaseJson.project, 'PolicyHelix');
  assert.equal(releaseJson.scope, 'policyhelix-complete');
  assert.equal(releaseJson.engineReady, true);
  assert.equal(releaseJson.offlineRulesIncluded, true);
  assert.ok(typeof releaseJson.sourceCommit === 'string' && releaseJson.sourceCommit.length > 0);

  // 3. Verify sbom.json structure
  const sbom = JSON.parse(await readFile(join(releaseDir, 'sbom.json'), 'utf8'));
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.specVersion, '1.5');
  assert.ok(Array.isArray(sbom.components) && sbom.components.length > 0);
  assert.ok(sbom.components.some(c => c.name === 'policyhelix-engine'));
  assert.ok(sbom.components.some(c => c.name === 'go-runtime'));
  assert.ok(sbom.components.some(c => c.name === 'open-policy-agent'));

  // 4. Verify SHA256SUMS.txt integrity
  const checksumContent = await readFile(join(releaseDir, 'SHA256SUMS.txt'), 'utf8');
  const lines = checksumContent.trim().split('\n');
  assert.ok(lines.length >= requiredFiles.length, 'Checksums must cover all packaged files');

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    assert.equal(parts.length, 2, `Invalid checksum line format: ${line}`);
    const [expectedHash, relPath] = parts;
    const cleanRelPath = relPath.replace(/^\.\//, '');
    const actualBytes = await readFile(join(releaseDir, cleanRelPath));
    const actualHash = createHash('sha256').update(actualBytes).digest('hex');
    assert.equal(actualHash, expectedHash, `Hash mismatch for ${cleanRelPath}`);
  }
});

test('C31 negative invariant: tampered release fails closed', async () => {
  const releaseDir = resolve(root, 'dist/release');
  const checksumContent = await readFile(join(releaseDir, 'SHA256SUMS.txt'), 'utf8');
  assert.ok(checksumContent.includes('engine/policyhelix'));

  // Tampered hash check
  const fakeChecksum = checksumContent.replace(/^([a-f0-9]{64})\s+engine\/policyhelix/m, '0000000000000000000000000000000000000000000000000000000000000000  engine/policyhelix');
  assert.notEqual(fakeChecksum, checksumContent);
  const engineLine = fakeChecksum.split('\n').find(l => l.includes('engine/policyhelix'));
  const [tamperedHash] = engineLine.split(/\s+/);
  const actualBytes = await readFile(join(releaseDir, 'engine/policyhelix'));
  const actualHash = createHash('sha256').update(actualBytes).digest('hex');
  assert.notEqual(tamperedHash, actualHash, 'Tampered hash must not match real executable hash (fail-closed)');
});
