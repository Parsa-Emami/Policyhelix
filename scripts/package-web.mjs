import { cp, mkdir, readdir, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

// Standalone web-only packaging script.
// Note: Per C31 / Requirement N31, a web-only artifact alone cannot satisfy
// the complete-product release gate (use scripts/package.sh for complete product).
const output = 'dist/release';

await mkdir(output, { recursive: true });
await rm(output + '/web', { recursive: true, force: true });
await cp('dist/web', output + '/web', { recursive: true });
await cp('scripts/serve-web.mjs', output + '/scripts/serve-web.mjs');
await cp('apps/web/src/lib/runtime-config.mjs', output + '/apps/web/src/lib/runtime-config.mjs');
await cp('ops/web', output + '/ops/web', { recursive: true });
await cp('LICENSE', output + '/LICENSE');
await cp('NOTICE', output + '/NOTICE');
await cp('docs/engineering/WEB_RUNBOOK.md', output + '/README.md');

let source;
try {
  source = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
} catch {
  throw new Error('Package from a git checkout so provenance is explicit.');
}

const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], { encoding: 'utf8' }).trim() !== '';

// If complete release exists, preserve complete release metadata; otherwise record web-only release metadata
let releaseMeta = { sourceCommit: source, dirty, scope: 'web-foundation', engineReady: false };
try {
  const existing = JSON.parse(await readFile(output + '/release.json', 'utf8'));
  if (existing.scope === 'policyhelix-complete') {
    releaseMeta = { ...existing, sourceCommit: source, dirty };
  }
} catch {}

await writeFile(output + '/release.json', JSON.stringify(releaseMeta, null, 2) + '\n');

const files = [];
async function walk(path, prefix = '') {
  for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = prefix + entry.name;
    if (entry.isDirectory()) await walk(join(path, entry.name), name + '/');
    else if (entry.name !== 'SHA256SUMS.txt') {
      files.push(createHash('sha256').update(await readFile(join(path, entry.name))).digest('hex') + '  ' + name);
    }
  }
}

await walk(output);
await writeFile(output + '/SHA256SUMS.txt', files.join('\n') + '\n');
console.log('Packaged release in ' + output + '; engineReady=' + releaseMeta.engineReady + '; scope=' + releaseMeta.scope);
