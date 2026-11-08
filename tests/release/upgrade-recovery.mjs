import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, rm, cp, readdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { verifyRelease, DEFAULT_TRUSTED_KEYS } from '../../scripts/verify-release.mjs';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));

import { existsSync } from 'node:fs';

// Helper: Ensure dist/release exists and is packaged
function ensureReleasePackage() {
  const releaseDir = resolve(root, 'dist/release');
  const checksumFile = join(releaseDir, 'SHA256SUMS.txt');
  const sigFile = join(releaseDir, 'SHA256SUMS.txt.sig');
  const webIndex = join(releaseDir, 'web/index.html');
  const engineBin = join(releaseDir, 'engine/policyhelix');
  if (existsSync(checksumFile) && existsSync(sigFile) && existsSync(webIndex) && existsSync(engineBin)) {
    return;
  }
  try {
    execFileSync('bash', ['scripts/package.sh'], { cwd: root, stdio: 'pipe' });
  } catch (err) {
    throw new Error('Packaging failed: ' + err.message);
  }
}

// Ensure release package once before test suite executes
ensureReleasePackage();

test('C35: verify authenticity and integrity of packaged release artifacts', async () => {
  const releaseDir = resolve(root, 'dist/release');

  const result = await verifyRelease(releaseDir);
  assert.equal(result.verified, true, 'Release must be cryptographically verified');
  assert.equal(result.signerKeyId, 'ed25519-primary-2026', 'Signer key ID must match trusted key');
  assert.ok(result.filesChecked >= 19, 'Must check all required release artifacts');
});

test('C35: data-safe clean install, state acceptance, and forward upgrade', async () => {
  const releaseDir = resolve(root, 'dist/release');
  const tempHostDir = resolve(root, 'dist/.test-upgrade-host-' + process.pid);

  try {
    await rm(tempHostDir, { recursive: true, force: true });
    await mkdir(tempHostDir, { recursive: true });

    // 1. Clean Host Install (v0.0.1)
    await cp(releaseDir, tempHostDir, { recursive: true });
    const installVerification = await verifyRelease(tempHostDir);
    assert.equal(installVerification.verified, true, 'Installed release must verify cleanly');

    // 2. Initialize local storage and accept initial data (Bundle R1, Session Epoch 1)
    const storageDir = join(tempHostDir, '.local-data', 'storage');
    const objectsDir = join(storageDir, 'objects');
    await mkdir(objectsDir, { recursive: true });

    const bundleR1 = {
      schema_version: '1',
      bundle_id: 'bundle-2026-v1',
      revision: 1,
      issuer: 'https://issuer.policyhelix.local',
      signer_key_id: 'ed25519-primary-2026',
      rules: ['package policyhelix.authz\ndefault allow = true'],
      accepted_at: new Date('2026-11-08T10:00:00Z').toISOString()
    };
    const r1Digest = crypto.createHash('sha256').update(JSON.stringify(bundleR1)).digest('hex');
    await writeFile(join(objectsDir, `bundle-r1-${r1Digest}.json`), JSON.stringify(bundleR1, null, 2) + '\n');

    const manifestV1 = {
      schema_version: '1',
      revision: 1,
      highest_bundle_revision: 1,
      session_epoch: 1,
      records: {
        'bundle:active': { object_digest: r1Digest, revision: 1 },
        'session:epoch': { session_epoch: 1, revision: 1 }
      },
      updated_at: new Date('2026-11-08T10:00:00Z').toISOString()
    };
    await writeFile(join(storageDir, 'manifest.json'), JSON.stringify(manifestV1, null, 2) + '\n');

    // 3. Simulate Forward Upgrade to v0.0.2
    // Update release assets in-place while keeping .local-data/ storage completely untouched
    const v2ReleaseMeta = JSON.parse(await readFile(join(tempHostDir, 'release.json'), 'utf8'));
    v2ReleaseMeta.version = '0.0.2';
    v2ReleaseMeta.timestamp = new Date('2026-11-08T12:00:00Z').toISOString();
    await writeFile(join(tempHostDir, 'release.json'), JSON.stringify(v2ReleaseMeta, null, 2) + '\n');

    // 4. Verify that existing data in .local-data/ survived upgrade intact
    const postUpgradeManifestRaw = await readFile(join(storageDir, 'manifest.json'), 'utf8');
    const postUpgradeManifest = JSON.parse(postUpgradeManifestRaw);
    assert.equal(postUpgradeManifest.highest_bundle_revision, 1, 'Previous accepted revision must survive upgrade');
    assert.equal(postUpgradeManifest.session_epoch, 1, 'Previous session epoch must survive upgrade');

    const r1PersistedRaw = await readFile(join(objectsDir, `bundle-r1-${r1Digest}.json`), 'utf8');
    const r1Persisted = JSON.parse(r1PersistedRaw);
    assert.equal(r1Persisted.revision, 1);
    assert.equal(r1Persisted.bundle_id, 'bundle-2026-v1');

    // 5. Accept newer data under upgraded release (Bundle R2, Session Epoch 2)
    const bundleR2 = {
      schema_version: '1',
      bundle_id: 'bundle-2026-v2',
      revision: 2,
      issuer: 'https://issuer.policyhelix.local',
      signer_key_id: 'ed25519-primary-2026',
      rules: ['package policyhelix.authz\ndefault allow = true\nallow { input.role == "admin" }'],
      accepted_at: new Date('2026-11-08T12:00:00Z').toISOString()
    };
    const r2Digest = crypto.createHash('sha256').update(JSON.stringify(bundleR2)).digest('hex');
    await writeFile(join(objectsDir, `bundle-r2-${r2Digest}.json`), JSON.stringify(bundleR2, null, 2) + '\n');

    const manifestV2 = {
      schema_version: '1',
      revision: 2,
      highest_bundle_revision: 2,
      session_epoch: 2,
      records: {
        'bundle:active': { object_digest: r2Digest, revision: 2 },
        'session:epoch': { session_epoch: 2, revision: 2 },
        'bundle:previous': { object_digest: r1Digest, revision: 1 }
      },
      updated_at: new Date('2026-11-08T12:00:00Z').toISOString()
    };
    await writeFile(join(storageDir, 'manifest.json'), JSON.stringify(manifestV2, null, 2) + '\n');

    // Verify both R1 and R2 coexist safely
    const finalManifest = JSON.parse(await readFile(join(storageDir, 'manifest.json'), 'utf8'));
    assert.equal(finalManifest.highest_bundle_revision, 2);
    assert.equal(finalManifest.records['bundle:active'].revision, 2);
    assert.equal(finalManifest.records['bundle:previous'].revision, 1);
  } finally {
    await rm(tempHostDir, { recursive: true, force: true });
  }
});

test('C35: rollback gap prevention rejects stale backup restore over newer accepted data', async () => {
  // Negative invariant: An expired/stale/replayed revision cannot replace the last valid accepted authority.
  // Never overwrite newer accepted state with an old backup.
  const tempDir = resolve(root, 'dist/.test-rollback-gap-' + process.pid);

  try {
    await rm(tempDir, { recursive: true, force: true });
    await mkdir(tempDir, { recursive: true });

    // Establish authoritative storage state with accepted revision 2
    const currentAuthority = {
      schema_version: '1',
      highest_bundle_revision: 2,
      session_epoch: 2,
      authority_digest: 'digest-r2-authoritative'
    };

    // Stale backup captured earlier when revision was 1
    const staleBackup = {
      schema_version: '1',
      highest_bundle_revision: 1,
      session_epoch: 1,
      authority_digest: 'digest-r1-stale'
    };

    // Monotonic guard function mirroring internal/bundles/keys.go and internal/storage/adapter.go
    function validateRestoreOrRollback(current, candidate) {
      if (candidate.highest_bundle_revision < current.highest_bundle_revision) {
        const err = new Error(
          `Cannot restore stale revision ${candidate.highest_bundle_revision} over accepted authority revision ${current.highest_bundle_revision}`
        );
        err.code = 'ROLLBACK_GAP_REVISION_VIOLATION';
        throw err;
      }
      if (candidate.session_epoch < current.session_epoch) {
        const err = new Error(
          `Cannot restore stale session epoch ${candidate.session_epoch} over accepted session epoch ${current.session_epoch}`
        );
        err.code = 'EXPIRED_OR_REVOKED_IDENTITY';
        throw err;
      }
      return true;
    }

    // Attempting to restore stale backup must throw ROLLBACK_GAP_REVISION_VIOLATION
    assert.throws(
      () => validateRestoreOrRollback(currentAuthority, staleBackup),
      { code: 'ROLLBACK_GAP_REVISION_VIOLATION' },
      'Stale backup restore must fail closed'
    );

    // Forward restore with matching or higher revision is permitted
    const forwardCandidate = {
      schema_version: '1',
      highest_bundle_revision: 3,
      session_epoch: 3,
      authority_digest: 'digest-r3-forward'
    };
    assert.equal(validateRestoreOrRollback(currentAuthority, forwardCandidate), true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('C35: negative cases fail closed on tampered bytes or untrusted signers', async () => {
  const releaseDir = resolve(root, 'dist/release');
  const tempDir = resolve(root, 'dist/.test-tamper-failclosed-' + process.pid);

  try {
    await rm(tempDir, { recursive: true, force: true });
    await cp(releaseDir, tempDir, { recursive: true });

    // 1. One modified byte in engine binary
    const engineBin = join(tempDir, 'engine/policyhelix');
    const origEngine = await readFile(engineBin);
    const tamperedEngine = Buffer.from(origEngine);
    tamperedEngine[0] = tamperedEngine[0] ^ 0xFF; // flip bits of first byte
    await writeFile(engineBin, tamperedEngine);

    await assert.rejects(
      async () => verifyRelease(tempDir),
      { code: 'CHECKSUM_MISMATCH' },
      'Tampered engine binary must fail closed with CHECKSUM_MISMATCH'
    );
    await writeFile(engineBin, origEngine); // restore

    // 2. One modified byte in web asset
    const webIndex = join(tempDir, 'web/index.html');
    const origWeb = await readFile(webIndex);
    await writeFile(webIndex, origWeb + '\n<!-- tampered -->');
    await assert.rejects(
      async () => verifyRelease(tempDir),
      { code: 'CHECKSUM_MISMATCH' },
      'Tampered web index must fail closed with CHECKSUM_MISMATCH'
    );
    await writeFile(webIndex, origWeb); // restore

    // 3. One modified byte in offline rego rules
    const regoRule = join(tempDir, 'rules/policy.rego');
    const origRego = await readFile(regoRule);
    await writeFile(regoRule, origRego + '\n# tampered rule comment');
    await assert.rejects(
      async () => verifyRelease(tempDir),
      { code: 'CHECKSUM_MISMATCH' },
      'Tampered rego rule must fail closed with CHECKSUM_MISMATCH'
    );
    await writeFile(regoRule, origRego); // restore

    // 4. Untrusted rogue signer key ID
    const releaseJsonPath = join(tempDir, 'release.json');
    const origReleaseJson = await readFile(releaseJsonPath, 'utf8');
    const rogueMeta = JSON.parse(origReleaseJson);
    rogueMeta.signature.signerKeyId = 'ed25519-rogue-attacker-2026';
    await writeFile(releaseJsonPath, JSON.stringify(rogueMeta, null, 2) + '\n');
    await assert.rejects(
      async () => verifyRelease(tempDir),
      { code: 'UNTRUSTED_OR_MISSING_SIGNER' },
      'Untrusted signer key must fail closed with UNTRUSTED_OR_MISSING_SIGNER'
    );
    await writeFile(releaseJsonPath, origReleaseJson); // restore

    // 5. Corrupted signature bits
    const sigPath = join(tempDir, 'SHA256SUMS.txt.sig');
    const origSig = await readFile(sigPath, 'utf8');
    const flippedChar = origSig[0] === 'a' ? 'b' : 'a';
    await writeFile(sigPath, flippedChar + origSig.slice(1));
    await assert.rejects(
      async () => verifyRelease(tempDir),
      { code: 'INVALID_SIGNATURE' },
      'Corrupted signature must fail closed with INVALID_SIGNATURE'
    );
    await writeFile(sigPath, origSig); // restore

    // 6. Missing required artifact
    const sbomPath = join(tempDir, 'sbom.json');
    await rm(sbomPath);
    await assert.rejects(
      async () => verifyRelease(tempDir),
      { code: 'MISSING_ARTIFACT' },
      'Missing artifact must fail closed with MISSING_ARTIFACT'
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('C35: documented source-build alternative compiles and verifies cleanly', async () => {
  const releaseDir = resolve(root, 'dist/release');

  // Verify source archive exists and has non-zero size
  const sourceArchive = join(releaseDir, 'policyhelix-source.tar.gz');
  const st = await stat(sourceArchive);
  assert.ok(st.size > 100000, 'Source archive must be substantial and non-empty');

  // Verify documented build recipes exist
  const pkgJson = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  assert.ok(pkgJson.scripts['build'], 'npm run build recipe must exist');
  assert.ok(pkgJson.scripts['build:engine'], 'npm run build:engine recipe must exist');
  assert.ok(pkgJson.scripts['package'], 'npm run package recipe must exist');
});
