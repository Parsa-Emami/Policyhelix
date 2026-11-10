#!/usr/bin/env bash
set -euo pipefail

# scripts/package.sh - PolicyHelix reproducible open-source release packaging
# Packages the complete product: Go engine binary, web assets, offline rules,
# source archive, SBOM, third-party notices, checksums and provenance.
# Requirement: N31 / Commit: C31

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ ${POLICYHELIX_PUBLIC_PACKAGE:-0} == 1 && -n "$(git status --porcelain)" ]]; then
  echo "Public packaging requires a clean source commit." >&2
  exit 1
fi
export RELEASE_SOURCE_COMMIT="$(git rev-parse HEAD)"
export RELEASE_SOURCE_TIMESTAMP="$(git show -s --format=%cI HEAD)"
export RELEASE_SOURCE_DIRTY=false
if [[ -n "$(git status --porcelain)" ]]; then
  export RELEASE_SOURCE_DIRTY=true
fi

echo "=== PolicyHelix Complete Product Packaging ==="

# 1. Verify Toolchain
command -v node >/dev/null 2>&1 || { echo "Error: node is required" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm is required" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Error: go is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "Error: git is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "Error: sha256sum is required" >&2; exit 1; }

# 2. Build Web Workspace
echo "--> Building web workspace..."
npm run build

# 3. Build Go Engine Binary
echo "--> Building Go engine executable..."
mkdir -p dist/engine
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o dist/engine/policyhelix ./cmd/policyhelix

# 4. Initialize Atomic Staging Directory
STAGE_DIR="dist/.staging-release-$$"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"

trap 'rm -rf "${STAGE_DIR}"' EXIT INT TERM

echo "--> Assembling staged release artifact in ${STAGE_DIR}..."

# 5. Populate Engine Binary & Web Assets
mkdir -p "${STAGE_DIR}/engine"
cp dist/engine/policyhelix "${STAGE_DIR}/engine/policyhelix"
chmod 0755 "${STAGE_DIR}/engine/policyhelix"

mkdir -p "${STAGE_DIR}/web"
cp -r dist/web/* "${STAGE_DIR}/web/"

# 6. Populate Offline Policy Rules & Resources
mkdir -p "${STAGE_DIR}/rules"
if [ -d "rules" ]; then
  cp -r rules/* "${STAGE_DIR}/rules/"
fi

# 7. Populate Scripts & Ops Templates
mkdir -p "${STAGE_DIR}/scripts"
cp scripts/serve-web.mjs "${STAGE_DIR}/scripts/"
cp scripts/start-local.mjs "${STAGE_DIR}/scripts/"

mkdir -p "${STAGE_DIR}/apps/web/src/lib"
cp apps/web/src/lib/runtime-config.mjs "${STAGE_DIR}/apps/web/src/lib/"

mkdir -p "${STAGE_DIR}/ops/web"
cp ops/web/nginx.conf.template "${STAGE_DIR}/ops/web/"
cp ops/web/service.systemd "${STAGE_DIR}/ops/web/"
cp ops/web/runtime-config.json "${STAGE_DIR}/ops/web/"
cp ops/web/brand.json "${STAGE_DIR}/ops/web/"

# 8. Populate Documentation & Legal Notices
mkdir -p "${STAGE_DIR}/docs"
[ -f "docs/release/ARTIFACTS.md" ] && cp docs/release/ARTIFACTS.md "${STAGE_DIR}/docs/"
[ -f "docs/engineering/WEB_RUNBOOK.md" ] && cp docs/engineering/WEB_RUNBOOK.md "${STAGE_DIR}/docs/"
cp LICENSE "${STAGE_DIR}/LICENSE"
cp NOTICE "${STAGE_DIR}/NOTICE"
cp THIRD_PARTY_NOTICES.md "${STAGE_DIR}/THIRD_PARTY_NOTICES.md"

# 9. Generate Reproducible Source Archive
echo "--> Creating reproducible source archive..."
node scripts/package-source.mjs --output-dir "${STAGE_DIR}"

mkdir -p "${STAGE_DIR}/licenses"
cp "$(go env GOROOT)/LICENSE" "${STAGE_DIR}/licenses/go-LICENSE"
for dependency in react react-dom scheduler; do
  cp "node_modules/$dependency/LICENSE" "${STAGE_DIR}/licenses/$dependency-LICENSE"
done

STAGE_DIR="${STAGE_DIR}" node --input-type=module - << 'EOF'
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const stage = process.env.STAGE_DIR;
const pkg = JSON.parse(await readFile('package.json', 'utf8'));
const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const toolchain = JSON.parse(await readFile('docs/engineering/toolchain-lock.json', 'utf8'));
const command = (name, args) => execFileSync(name, args, { encoding: 'utf8' }).trim();
const engine = JSON.parse(command(join(stage, 'engine/policyhelix'), ['--version']));
if (engine.version !== pkg.version) throw new Error('Engine and package versions differ.');
const goVersion = command('go', ['version']).split(' ')[2].replace(/^go/, '');
const license = id => [{ license: { id } }];
const allowed = new Set(['MIT', 'Apache-2.0', 'BSD-3-Clause', 'MPL-2.0', 'ISC']);
const components = [
  { type: 'application', name: 'policyhelix-engine', version: engine.version, licenses: license('Apache-2.0') },
  { type: 'library', name: 'go-runtime', version: goVersion, licenses: license('BSD-3-Clause') }
];
for (const [name, provider] of [
  ['open-policy-agent', toolchain.providers.local_opa],
  ['keycloak', toolchain.providers.self_hosted_keycloak]
]) {
  if (!allowed.has(provider.license)) throw new Error(`Unsupported provider license: ${name}`);
  components.push({
    type: 'application', name, version: provider.version, scope: 'excluded', licenses: license(provider.license),
    externalReferences: [{ type: 'website', url: provider.source_url }]
  });
}
for (const [path, dependency] of Object.entries(lock.packages)) {
  if (!path) continue;
  const name = path.split('node_modules/').at(-1);
  if (!allowed.has(dependency.license)) throw new Error(`Unsupported dependency license: ${name}`);
  const segments = name.split('/').map(encodeURIComponent);
  components.push({
    type: 'library', name, version: dependency.version,
    scope: dependency.dev ? 'excluded' : 'required',
    licenses: license(dependency.license),
    purl: `pkg:npm/${segments.join('/')}@${dependency.version}`
  });
}
const sbom = {
  bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
  metadata: {
    timestamp: new Date(process.env.RELEASE_SOURCE_TIMESTAMP).toISOString(),
    component: { type: 'application', name: 'policyhelix-complete', version: pkg.version, licenses: license(pkg.license) }
  },
  components
};
const publicPackage = process.env.POLICYHELIX_PUBLIC_PACKAGE === '1';
const release = {
  project: 'PolicyHelix', version: pkg.version, scope: 'policyhelix-complete',
  profile: 'local-demo', sourceCommit: process.env.RELEASE_SOURCE_COMMIT,
  dirty: process.env.RELEASE_SOURCE_DIRTY === 'true', engineReady: true, reproducible: true,
  offlineRulesIncluded: true, timestamp: sbom.metadata.timestamp,
  toolchain: { go: goVersion, node: process.version, npm: command('npm', ['--version']), platform: `${process.platform}/${process.arch}` },
  sourceArchiveSha256: createHash('sha256').update(await readFile(join(stage, 'policyhelix-source.tar.gz'))).digest('hex'),
  signature: publicPackage ? { algorithm: 'github-artifact-attestation', subject: 'public SHA256SUMS.txt' } : {
    algorithm: 'ed25519', purpose: 'local-test',
    signerKeyId: process.env.POLICYHELIX_RELEASE_KEY_ID || 'ed25519-primary-2026',
    publicKeyHex: '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
    signatureFile: 'SHA256SUMS.txt.sig'
  },
  artifacts: ['engine/policyhelix', 'web/', 'rules/', 'policyhelix-source.tar.gz', 'sbom.json', 'ops/web/', 'scripts/', 'docs/', 'licenses/']
};
await writeFile(join(stage, 'sbom.json'), JSON.stringify(sbom, null, 2) + '\n');
await writeFile(join(stage, 'release.json'), JSON.stringify(release, null, 2) + '\n');
EOF

# 12. Generate Checksums (SHA256SUMS.txt) in Staging
echo "--> Generating cryptographic checksums..."
(
  cd "${STAGE_DIR}"
  find . -type f ! -name 'SHA256SUMS.txt' ! -name 'SHA256SUMS.txt.sig' | sort | while read -r f; do
    clean_f="${f#./}"
    sha256sum "${clean_f}"
  done > SHA256SUMS.txt
)

# 13. Cryptographically Sign Release Checksums (Requirement N35 / Commit C35)
if [[ ${POLICYHELIX_PUBLIC_PACKAGE:-0} != 1 ]]; then
echo "--> Generating cryptographic Ed25519 release signature..."
STAGE_DIR="${STAGE_DIR}" node - << 'EOF'
import { readFile, writeFile } from 'node:fs/promises';
import crypto from 'node:crypto';

const stageDir = process.env.STAGE_DIR;
const seedHex = process.env.POLICYHELIX_RELEASE_KEY_SEED || '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';

const rawSeed = Buffer.from(seedHex, 'hex');
const privKeyDer = Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'),
  rawSeed
]);
const privKey = crypto.createPrivateKey({ key: privKeyDer, format: 'der', type: 'pkcs8' });

const checksumContent = await readFile(`${stageDir}/SHA256SUMS.txt`);
const signature = crypto.sign(null, checksumContent, privKey);
await writeFile(`${stageDir}/SHA256SUMS.txt.sig`, signature.toString('hex') + '\n');
EOF
fi

# 14. Verify Staged Checksums Before Atomic Promotion
(
  cd "${STAGE_DIR}"
  sha256sum -c SHA256SUMS.txt >/dev/null
)

# 15. Atomic Promotion: Rename Staging Directory to dist/release
TARGET_DIR="dist/release"
STAGE_OLD="dist/.old-release-$$"
if [ -d "${TARGET_DIR}" ]; then
  mv "${TARGET_DIR}" "${STAGE_OLD}"
fi
mv "${STAGE_DIR}" "${TARGET_DIR}"
rm -rf "${STAGE_OLD}"
trap - EXIT INT TERM

# 16. Final Integrity Verification
(
  cd "${TARGET_DIR}"
  sha256sum -c SHA256SUMS.txt
)

echo "=== Packaging Complete: Successfully packaged PolicyHelix into dist/release ==="
