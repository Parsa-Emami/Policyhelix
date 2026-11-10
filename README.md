# PolicyHelix

[![Source](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/contracts.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/contracts.yml?query=branch%3Amain) [![Plan](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/plan.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/plan.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/web.yml?query=branch%3Amain)

[User Guide](docs/release/USER_GUIDE.md) · [Clone & Run Guide](docs/engineering/CLONE_TO_RUN.md) · [Security Policy](SECURITY.md) · [Open Source Contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [CI Source Integrity](docs/engineering/CI_SOURCE_INTEGRITY.md)

---

Open-source local-first authorization engine and browser workspace under [Apache-2.0](LICENSE). **C01–C40 are verified.** [Download v1.0.0 for Linux x86_64](https://github.com/Parsa-Emami/Policyhelix/releases/tag/v1.0.0).

No paid accounts, compulsory cloud services, external databases, or proprietary dependencies are required.

## Quickstart: Clone and Run the Workspace

Prerequisites: Git, Node 24.19+ within Node 24 (npm included), and Go 1.26+.

```sh
git clone https://github.com/Parsa-Emami/Policyhelix.git
cd Policyhelix
npm run setup
npm start
```

Open http://127.0.0.1:4173 and select **Reference Workflow**.

- `npm run setup` validates the toolchain, installs locked dependencies with lifecycle scripts disabled, compiles the Go engine binary (`dist/engine/policyhelix`), and builds the web client.
- `npm start` supervises the Go engine on loopback (`127.0.0.1:4174`), opens the durable local manifest and object store in `.local-data/`, and runs the owned synthetic upstream.
- For complete step-by-step instructions, see the **[User Guide](docs/release/USER_GUIDE.md)** and **[Clone Guide](docs/engineering/CLONE_TO_RUN.md)**.

## Independent Source Builds

PolicyHelix can be compiled and verified directly from source without pre-built binaries:

```sh
# Compile Go engine binary
npm run build:engine

# Compile React web client
npm run build

# Package offline source archive
npm run package:source

# Generate full distributable release with SBOM and checksums
npm run package
```

All build and test steps are offline-capable once initial dependencies are cached.

## 6-Stage Reference Workflow

PolicyHelix provides a complete reference authorization lifecycle:
1. **Simulator Fixture:** Deterministic policy decision evaluation against Rego rules.
2. **Sign & Verify Bundle:** Ed25519 cryptographic bundle signing and monotonic revision checking.
3. **Protect Owned Upstream:** Authenticated reverse proxy routing to private upstream service.
4. **Spoofed Header / Direct Origin Rejection:** Strip unauthenticated ingress headers and reject direct origin bypass.
5. **Session Revocation:** Epoch-based revocation enforcing fail-closed boundaries within <= 30s.
6. **Outage & Expired Policy Fail-Closed:** Safe fallback denial (`allow: false`) during evaluator outage or bundle expiration.

Available as interactive cards or an accessible semantic table equivalent, supporting full sequential keyboard navigation and report export/import.

## Privacy, Limits & Local Durability

- **Strict Loopback Privacy:** Binds exclusively to `127.0.0.1` and `[::1]`. Transmits zero analytics or telemetry to third parties.
- **Durable Local Storage:** All sessions, bundles, and redacted audit logs are persisted locally in `.local-data/`.
- **Resource Envelope:** Verified baseline target: 2 vCPU / 4096 MiB RAM / 10240 MiB disk. Decision latency deadline <= 200ms.
- **Fail-Closed Guarantees:** Private resources default to deny on unauthenticated, malformed, or interrupted requests.

## Roadmap & Development Governance

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C34
npm run check
```

Each [work card](plans/COMMIT_ROADMAP.md) specifies paths, actions, resources, fixtures, acceptance, negative tests, command availability and rollback. [AGENTS.md](AGENTS.md) and [execution contract](docs/agents/EXECUTION_CONTRACT.md) let an agent resume from this repository alone. [فارسی](docs/ROADMAP_FA.md).

[User Guide](docs/release/USER_GUIDE.md) · [Open-Source Contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [Third-Party Inventory](THIRD_PARTY_NOTICES.md) · [Definition of Done](docs/release/DEFINITION_OF_DONE.md) · [Security](SECURITY.md). Permanent owner restrictions: No DB schema, migration, .env or Dockerfile changes are authorized.
