# PolicyHelix release artifacts specification

Requirement: N31 | Commit: C31

This document specifies the layout, integrity verification, provenance, and durability guarantees of PolicyHelix open-source release artifacts packaged by `scripts/package.sh`.

## Complete product release overview

A complete PolicyHelix release package satisfies Requirement N31:
> "Package the actual engine, web UI and offline rules/resources, source archive/build recipes, SBOM, upstream notices, checksums and provenance. A web-only artifact cannot satisfy this complete-product task."

The packaged output resides in `dist/release/` and is standalone, self-contained, and runnable on an air-gapped or clean host without network access.

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
└── SHA256SUMS.txt.sig                  # Detached Ed25519 signature of checksum manifest
```

## Atomic staging & crash resilience

1. **Staged-byte boundary**:
   All artifacts are assembled into an isolated staging directory `dist/.staging-release-<pid>`. Files are written, synced, and verified against SHA-256 digests prior to promotion.
2. **Atomic promotion**:
   Once all files, checksums, and Ed25519 detached signatures pass verification, the staging directory is promoted to `dist/release` using an atomic directory move (`rename`).
3. **Crash recovery**:
   If a writer process is killed at the staging boundary or during assembly, the destination `dist/release` is unaffected. A restart or subsequent packaging run cleans any stale staging directory and either retains the prior valid release or produces a complete new release.
4. **Quota exhaustion and replay resilience**:
   Packaging is idempotent. If disk quota is exhausted or write fails, the staging directory is cleaned up via traps, leaving no orphan corrupt files in `dist/release`.

## Integrity & cryptographic authenticity verification

To verify both cryptographic authenticity and file checksums of a downloaded or packaged release:

```bash
# Automated cryptographic verification against trusted release key
node scripts/verify-release.mjs

# Or verify raw checksums on any Linux host
cd dist/release
sha256sum -c SHA256SUMS.txt
```

Every file must report `OK`, and the Ed25519 signature over `SHA256SUMS.txt` must verify against the trusted signer identity (`ed25519-primary-2026`). Any modified byte, tampered binary, altered rule, untrusted signer, or missing signature triggers an immediate verification failure and causes deployment to fail closed.

## Software Bill of Materials (SBOM)

The file `sbom.json` complies with CycloneDX 1.5 JSON format:
- Lists all npm runtime and development packages with declared licenses and purls.
- Identifies the Go runtime and standard library.
- Pins upstream tools (Open Policy Agent v1.2.0, Keycloak 26.1.3, OIDC Core 1.0).
- Encodes component hashes, supplier metadata, and licensing.

## Zero-network build recipe

The included `policyhelix-source.tar.gz` can be built completely offline without external network calls once standard toolchains are present:

```bash
tar -xzf policyhelix-source.tar.gz
cd policyhelix-*
# Standard toolchain: Go 1.23+ and Node 24+
go build -o dist/engine/policyhelix ./cmd/policyhelix
npm run build
bash scripts/package.sh
```
