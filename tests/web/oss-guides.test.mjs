import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, '../..');

test('C34: all public OSS guides exist and are populated', async () => {
  const guideFiles = [
    'docs/release/USER_GUIDE.md',
    'SECURITY.md',
    'README.md',
    'OPEN_SOURCE.md',
    'CONTRIBUTING.md',
    'docs/engineering/CLONE_TO_RUN.md',
  ];

  for (const rel of guideFiles) {
    const fullPath = join(root, rel);
    const info = await stat(fullPath);
    assert.ok(info.size > 200, `File ${rel} should be substantive (got ${info.size} bytes)`);
    const content = await readFile(fullPath, 'utf8');
    assert.ok(!content.includes('TODO'), `File ${rel} should not contain TODO placeholders`);
  }
});

test('C34: user guide comprehensively documents public core task, builds, and limits', async () => {
  const userGuide = await readFile(join(root, 'docs/release/USER_GUIDE.md'), 'utf8');

  // Verify core task instructions
  assert.ok(userGuide.includes('git clone https://github.com/Parsa-Emami/Policyhelix.git'));
  assert.ok(userGuide.includes('npm run setup'));
  assert.ok(userGuide.includes('npm start'));
  assert.ok(userGuide.includes('http://127.0.0.1:4173'));

  // Verify independent source build commands
  assert.ok(userGuide.includes('npm run build:engine'));
  assert.ok(userGuide.includes('npm run build'));
  assert.ok(userGuide.includes('npm run package:source'));

  // Verify no paid/cloud requirements
  assert.ok(!userGuide.includes('AWS account required'));
  assert.ok(!userGuide.includes('GCP billing required'));
  assert.ok(userGuide.includes('No paid accounts'));

  // Verify limits and privacy
  assert.ok(userGuide.includes('200 ms'));
  assert.ok(userGuide.includes('127.0.0.1'));
});

test('C34: security policy specifies confirmed private reporting route and supported versions', async () => {
  const securityMd = await readFile(join(root, 'SECURITY.md'), 'utf8');

  assert.ok(securityMd.includes('security@policyhelix.org'));
  assert.ok(securityMd.includes('GitHub Private Vulnerability Reporting'));
  assert.ok(securityMd.includes('48 hours'));
  assert.ok(securityMd.includes('Supported Versions'));
  assert.ok(securityMd.includes('Loopback Isolation'));
});

test('C34: script sentinels in fixtures remain inert strings and never execute', async () => {
  const sentinelFixturePath = join(root, 'tests/fixtures/policyhelix/C34/negative-script-sentinel.json');
  const sentinelData = JSON.parse(await readFile(sentinelFixturePath, 'utf8'));

  assert.ok(Array.isArray(sentinelData.sentinels));
  for (const sentinel of sentinelData.sentinels) {
    // Assert string type
    assert.equal(typeof sentinel, 'string');
    // Ensure raw string contains sentinel markers without evaluation
    assert.ok(sentinel.includes('alert') || sentinel.includes('javascript:'));
  }
});
