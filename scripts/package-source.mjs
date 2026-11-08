import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../', import.meta.url)));

export async function packageSource(options = {}) {
  const outputDir = resolve(root, options.outputDir ?? 'dist/release');
  const archiveName = options.archiveName ?? 'policyhelix-source.tar.gz';
  const targetTarGz = resolve(outputDir, archiveName);

  await mkdir(outputDir, { recursive: true });

  // Get current git commit and tree
  let commit;
  try {
    commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  } catch {
    throw new Error('Packaging source requires a valid git checkout.');
  }

  // Use git archive with deterministic options (mtime pinned to commit timestamp, zero owner/group)
  // git archive natively produces bit-for-bit reproducible tar archives from a commit
  const commitTimestamp = execFileSync('git', ['log', '-1', '--format=%cI', commit], { cwd: root, encoding: 'utf8' }).trim();

  // Create tar.gz using git archive with prefix
  const tarBuffer = execFileSync('git', [
    'archive',
    '--format=tar.gz',
    `--prefix=policyhelix-${commit.slice(0, 8)}/`,
    commit,
  ], { cwd: root, maxBuffer: 100 * 1024 * 1024 });

  await writeFile(targetTarGz, tarBuffer);

  const digest = createHash('sha256').update(tarBuffer).digest('hex');

  const metadata = {
    archive: archiveName,
    commit,
    commitTimestamp,
    sha256: digest,
    byteSize: tarBuffer.length,
    recipe: 'git archive --format=tar.gz',
  };

  return metadata;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const options = {};
    for (let i = 0; i < args.length; i += 2) {
      if (args[i] === '--output-dir' && args[i + 1]) options.outputDir = args[i + 1];
      else if (args[i] === '--archive-name' && args[i + 1]) options.archiveName = args[i + 1];
    }
    const meta = await packageSource(options);
    console.log(JSON.stringify(meta, null, 2));
  } catch (err) {
    console.error('Failed to package source:', err.message);
    process.exitCode = 1;
  }
}
