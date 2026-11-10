# PolicyHelix release artifacts specification

Requirement: N31 | Commit: C31

This document specifies the layout, integrity verification, provenance, and durability guarantees of PolicyHelix open-source release artifacts packaged by `scripts/package.sh`.

## Complete product release overview

A complete PolicyHelix release package satisfies Requirement N31:
> "Package the actual engine, web UI and offline rules/resources, source archive/build recipes, SBOM, upstream notices, checksums and provenance. A web-only artifact cannot satisfy this complete-product task."

The packaged output resides in `dist/release/` and is runnable offline on Linux x86_64 with Node 24.19 or a newer Node 24 release. The local-demo package contains the embedded evaluator, demo identity and owned loopback upstream.

## Release layout (`dist/release`)

```text
dist/release/
├── engine/
│   └── policyhelix                     # Compiled Go executable (supervisor & engine gateway)
├── web/
│   ├── index.html                      # Single-page application entry point
│   └── assets/                         # Fingerprinted CSS/JS assets
├── rules/
│   └── policy.rego                     # Offline default Rego authorization policy rules
├── scripts/
│   ├── serve-web.mjs                   # Hardened HTTP static server and proxy
│   └── start-local.mjs                 # Unified supervisor orchestrating web & engine
├── apps/web/src/lib/
│   └── runtime-config.mjs              # Nonsecret configuration validator
├── ops/web/
│   ├── nginx.conf.template             # TLS reverse proxy ingress template with header stripping
│   ├── service.systemd                 # Sandboxed systemd service configuration
│   ├── runtime-config.json             # Nonsecret runtime configuration
│   └── brand.json                      # Product brand metadata
├── docs/
│   ├── ARTIFACTS.md                    # This artifact specification
│   └── WEB_RUNBOOK.md                  # Deployment and operations runbook
├── LICENSE                             # Apache-2.0 license
├── NOTICE                              # Project attribution notice
├── THIRD_PARTY_NOTICES.md              # Complete third-party dependency licenses and SBOM inventory
├── policyhelix-source.tar.gz           # Reproducible source archive with build recipes
├── sbom.json                           # Machine-readable Software Bill of Materials (CycloneDX 1.5)
├── release.json                        # Provenance metadata, Git commit, scope, and signature metadata
├── SHA256SUMS.txt                      # Cryptographic checksums of all package files
└── SHA256SUMS.txt.sig                  # Synthetic detached signature for local C35 rehearsal only
```

## Atomic staging & crash resilience

1. **Staged-byte boundary**:
   All artifacts are assembled into an isolated staging directory `dist/.staging-release-<pid>`. Files are written, synced, and verified against SHA-256 digests prior to promotion.
2. **Atomic promotion**:
   After checksum verification, a directory rename promotes the complete staging tree to `dist/release`. Public provenance is added by the GitHub release workflow.
3. **Crash recovery**:
   If a writer process is killed at the staging boundary or during assembly, the destination `dist/release` is unaffected. If promotion is interrupted after moving an existing release aside, the prior complete tree remains under `dist/.old-release-*` for inspection and recovery.
4. **Quota exhaustion and replay resilience**:
   Packaging is idempotent. A handled staging failure removes temporary files via the exit trap and leaves the prior release available.

## Verify and install the public GitHub release

Download the Linux runtime, matching source archive, SBOM, build metadata and
checksum manifest from [GitHub Releases](https://github.com/Parsa-Emami/Policyhelix/releases).
The hosted release workflow attests the checksum manifest, tests the candidate
before publication and repeats the complete workflow from the public download.

Use a trusted copy of the release verifier and independently confirm the full
release commit. GitHub CLI with artifact attestation support checks the GitHub
repository, release workflow, source branch and commit before extraction.

```sh
git fetch --tags origin
expected_commit=$(git rev-parse 'v1.0.0^{commit}')
bash scripts/release-assets.sh download /absolute/new-download-directory "$expected_commit"
bash scripts/release-assets.sh verify /absolute/new-download-directory "$expected_commit" /absolute/new-install-directory
cd /absolute/new-install-directory
node scripts/start-local.mjs --root web --engine-bin engine/policyhelix --storage-dir /absolute/private/policyhelix-data
```

Open http://127.0.0.1:4173 and select **Reference Workflow**. The download verifier
uses the network for GitHub provenance. The installed local-demo workflow runs
offline and uses synthetic sessions and the embedded policy evaluator. External
OPA and Keycloak deployments are outside this release profile.

The local C35 rehearsal uses a synthetic Ed25519 key. Its signature and
`npm run verify:release` belong to local testing. Public packages use GitHub
attestations as their distribution trust mechanism.

The maintainer can retry **Actions → publish-v1 → Run workflow** from `main` once
the five current-source checks are green. Existing drafts and tags are inspected
separately before any retry. The workflow refuses to overwrite either.

## Software Bill of Materials (SBOM)

The file `sbom.json` complies with CycloneDX 1.5 JSON format:
- Lists locked npm packages with versions, scopes and declared licenses.
- Identifies the exact Go standard library version compiled into the engine.
- The upstream license inventory describes the optional OPA and Keycloak references.

## Zero-network build recipe

The included source archive can build offline when the locked npm dependencies are cached. Repackaging also needs a Git checkout to bind the source archive to its original commit.

```bash
tar -xzf policyhelix-source.tar.gz
cd policyhelix-*
npm ci --ignore-scripts --offline
go build -o dist/engine/policyhelix ./cmd/policyhelix
npm run build
```
