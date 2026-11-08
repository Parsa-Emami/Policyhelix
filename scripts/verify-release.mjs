#!/usr/bin/env node

/**
 * scripts/verify-release.mjs
 * PolicyHelix cryptographically signed release verification tool.
 * Verifies authenticity, Ed25519 signatures, and SHA-256 checksums
 * against independently trusted release identities.
 *
 * Requirement: N35 | Commit: C35
 */

import { readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

export const DEFAULT_TRUSTED_KEYS = {
  'ed25519-primary-2026': '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
};

export const REQUIRED_ARTIFACTS = [
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
  'SHA256SUMS.txt',
  'SHA256SUMS.txt.sig'
];

/**
 * Converts a raw 32-byte Ed25519 public key hex string to a Node.js KeyObject.
 * @param {string} pubKeyHex 
 * @returns {crypto.KeyObject}
 */
export function createEd25519PublicKey(pubKeyHex) {
  const cleanHex = pubKeyHex.trim().toLowerCase();
  if (cleanHex.length !== 64) {
    throw new Error(`Invalid Ed25519 public key length (expected 64 hex chars, got ${cleanHex.length})`);
  }
  const rawPub = Buffer.from(cleanHex, 'hex');
  // SPKI prefix for Ed25519 (OID 1.3.101.112) is 12 bytes: 302a300506032b6570032100
  const spkiDer = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    rawPub
  ]);
  return crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}

/**
 * Verifies a packaged PolicyHelix release directory.
 * @param {string} releaseDir Absolute or relative path to release directory
 * @param {object} [options]
 * @returns {Promise<{ verified: boolean, signerKeyId: string, publicKeyHex: string, filesChecked: number, version: string, timestamp: string }>}
 */
export async function verifyRelease(releaseDir, options = {}) {
  const baseDir = resolve(releaseDir);
  const trustedKeys = options.trustedKeys || DEFAULT_TRUSTED_KEYS;
  const requiredFiles = options.requiredFiles || REQUIRED_ARTIFACTS;

  // 1. Verify existence and non-zero size of required release artifacts
  for (const rel of requiredFiles) {
    const fullPath = join(baseDir, rel);
    let s;
    try {
      s = await stat(fullPath);
    } catch (err) {
      const error = new Error(`Required release artifact missing: ${rel}`);
      error.code = 'MISSING_ARTIFACT';
      error.artifact = rel;
      throw error;
    }
    if (s.size === 0) {
      const error = new Error(`Required release artifact is empty: ${rel}`);
      error.code = 'EMPTY_ARTIFACT';
      error.artifact = rel;
      throw error;
    }
  }

  // 2. Read and parse release metadata
  const releaseJsonPath = join(baseDir, 'release.json');
  let releaseMeta;
  try {
    const releaseRaw = await readFile(releaseJsonPath, 'utf8');
    releaseMeta = JSON.parse(releaseRaw);
  } catch (err) {
    const error = new Error(`Failed to parse release.json: ${err.message}`);
    error.code = 'INVALID_RELEASE_METADATA';
    throw error;
  }

  if (releaseMeta.project !== 'PolicyHelix' || releaseMeta.scope !== 'policyhelix-complete') {
    const error = new Error(`Invalid release project/scope: ${releaseMeta.project}/${releaseMeta.scope}`);
    error.code = 'INVALID_RELEASE_METADATA';
    throw error;
  }
  if (!releaseMeta.engineReady) {
    const error = new Error('Release metadata indicates engineReady=false');
    error.code = 'ENGINE_NOT_READY';
    throw error;
  }

  // 3. Inspect release signature metadata
  const signatureMeta = releaseMeta.signature;
  if (!signatureMeta || signatureMeta.algorithm !== 'ed25519' || !signatureMeta.signerKeyId) {
    const error = new Error('Missing or invalid Ed25519 signature declaration in release.json');
    error.code = 'UNTRUSTED_OR_MISSING_SIGNER';
    throw error;
  }

  const signerKeyId = signatureMeta.signerKeyId;
  const trustedPubKeyHex = trustedKeys[signerKeyId];
  if (!trustedPubKeyHex) {
    const error = new Error(`Signer key "${signerKeyId}" is not in trusted keys list`);
    error.code = 'UNTRUSTED_OR_MISSING_SIGNER';
    error.signerKeyId = signerKeyId;
    throw error;
  }

  if (signatureMeta.publicKeyHex && signatureMeta.publicKeyHex.toLowerCase() !== trustedPubKeyHex.toLowerCase()) {
    const error = new Error(`Public key mismatch for signer "${signerKeyId}"`);
    error.code = 'UNTRUSTED_OR_MISSING_SIGNER';
    throw error;
  }

  // 4. Read checksum manifest and detached signature
  const checksumPath = join(baseDir, 'SHA256SUMS.txt');
  const sigPath = join(baseDir, 'SHA256SUMS.txt.sig');

  const checksumBytes = await readFile(checksumPath);
  const sigHexRaw = (await readFile(sigPath, 'utf8')).trim();
  const sigBuffer = Buffer.from(sigHexRaw, 'hex');

  if (sigBuffer.length !== 64) {
    const error = new Error(`Invalid Ed25519 signature byte length: ${sigBuffer.length} (expected 64)`);
    error.code = 'INVALID_SIGNATURE';
    throw error;
  }

  // 5. Verify cryptographic signature over checksum manifest
  const pubKey = createEd25519PublicKey(trustedPubKeyHex);
  const isSigValid = crypto.verify(null, checksumBytes, pubKey, sigBuffer);
  if (!isSigValid) {
    const error = new Error(`Cryptographic Ed25519 signature verification failed for ${sigPath}`);
    error.code = 'INVALID_SIGNATURE';
    error.signerKeyId = signerKeyId;
    throw error;
  }

  // 6. Verify byte-exact cryptographic checksums for every artifact
  const checksumLines = checksumBytes.toString('utf8').trim().split('\n');
  if (checksumLines.length < requiredFiles.length - 1) { // -1 for detached signature file itself
    const error = new Error(`Checksum manifest has fewer entries (${checksumLines.length}) than required files`);
    error.code = 'CHECKSUM_MANIFEST_INCOMPLETE';
    throw error;
  }

  let filesChecked = 0;
  for (const line of checksumLines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length !== 2) {
      const error = new Error(`Malformed checksum line: ${line}`);
      error.code = 'MALFORMED_CHECKSUM_LINE';
      throw error;
    }
    const [expectedHash, rawRelPath] = parts;
    const cleanRelPath = rawRelPath.replace(/^\.\//, '');
    const targetFile = join(baseDir, cleanRelPath);

    let actualBytes;
    try {
      actualBytes = await readFile(targetFile);
    } catch (err) {
      const error = new Error(`File in checksum manifest missing on disk: ${cleanRelPath}`);
      error.code = 'MISSING_ARTIFACT';
      error.artifact = cleanRelPath;
      throw error;
    }

    const actualHash = crypto.createHash('sha256').update(actualBytes).digest('hex');
    if (actualHash !== expectedHash.toLowerCase()) {
      const error = new Error(`Checksum mismatch for ${cleanRelPath}: expected ${expectedHash}, got ${actualHash}`);
      error.code = 'CHECKSUM_MISMATCH';
      error.artifact = cleanRelPath;
      error.expectedHash = expectedHash;
      error.actualHash = actualHash;
      throw error;
    }
    filesChecked++;
  }

  return {
    verified: true,
    signerKeyId,
    publicKeyHex: trustedPubKeyHex,
    filesChecked,
    version: releaseMeta.version,
    sourceCommit: releaseMeta.sourceCommit,
    timestamp: releaseMeta.timestamp,
  };
}

// CLI entry point
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  let releaseDir = 'dist/release';
  let jsonOutput = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dir' && args[i + 1]) {
      releaseDir = args[++i];
    } else if (args[i] === '--json') {
      jsonOutput = true;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log('Usage: node scripts/verify-release.mjs [--dir <release_dir>] [--json]');
      process.exit(0);
    }
  }

  try {
    const result = await verifyRelease(releaseDir);
    if (jsonOutput) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`=== PolicyHelix Release Verification: SUCCESS ===`);
      console.log(`Signer Key ID:   ${result.signerKeyId}`);
      console.log(`Public Key:      ${result.publicKeyHex}`);
      console.log(`Files Verified:  ${result.filesChecked}`);
      console.log(`Version:         ${result.version}`);
      console.log(`Source Commit:   ${result.sourceCommit}`);
      console.log(`Integrity & Authenticity: PASSED (Ed25519 + SHA256)`);
    }
  } catch (err) {
    if (jsonOutput) {
      console.error(JSON.stringify({
        verified: false,
        error: err.message,
        errorCode: err.code || 'VERIFICATION_FAILED',
        artifact: err.artifact,
      }, null, 2));
    } else {
      console.error(`=== PolicyHelix Release Verification: FAILED ===`);
      console.error(`Error Code: ${err.code || 'VERIFICATION_FAILED'}`);
      console.error(`Reason:     ${err.message}`);
    }
    process.exit(1);
  }
}
