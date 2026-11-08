# PolicyHelix

[![Source](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/contracts.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/contracts.yml?query=branch%3Amain) [![Plan](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/plan.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/plan.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Policyhelix/actions/workflows/web.yml?query=branch%3Amain)

[CI source integrity and dependency updates](docs/engineering/CI_SOURCE_INTEGRITY.md)


Open-source local-first web application under [Apache-2.0](LICENSE). **Current implementation: the complete local reference workflow is verified at [C30](plans/commits/C30.md); the full published OSS v1 remains the [C40](plans/commits/C40.md) evidence gate.**

## Clone and run the workspace

Prerequisites: Git, Node 24.19+ within Node 24 (npm included) and Go 1.26+.

```sh
git clone https://github.com/Parsa-Emami/Policyhelix.git
cd Policyhelix
npm run setup
npm start
```

Open http://127.0.0.1:4173 and select **Reference Workflow**. Setup installs the locked web dependencies, builds the web workspace and compiles the Go engine. The supervised engine runs on loopback with durable local storage, a signed Ed25519 policy bundle evaluator and an owned synthetic upstream. No paid/cloud account, public domain, database server or sibling clone is needed. The local-demo identity provider issues fingerprint-bound, revocable sessions; this is not a production security certification. [Clone guide](docs/engineering/CLONE_TO_RUN.md).

## Full product endpoint

Simulator fixture -> sign/verify bundle -> protect owned upstream -> test spoofed header/direct origin -> revoke -> simulate decision/IdP outage and expired policy.

[C30](plans/commits/C30.md) proved the first locally usable supported product from a real clean clone, including negative cases, restart and restore (`docs/evidence/C30.json`). [C40](plans/commits/C40.md) remains the evidence gate for complete published OSS v1. [Runtime resources](ops/runtime-requirements.json).

## Implement the next commit

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C07
npm run check
```

Each [work card](plans/COMMIT_ROADMAP.md) specifies paths, actions, resources, fixtures, acceptance, negative tests, command availability and rollback. [AGENTS.md](AGENTS.md) and [execution contract](docs/agents/EXECUTION_CONTRACT.md) let an agent resume from this repository alone. [فارسی](docs/ROADMAP_FA.md).

[Open-source contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [Third-party inventory](THIRD_PARTY_NOTICES.md) · [Definition of done](docs/release/DEFINITION_OF_DONE.md) · [Security](SECURITY.md). No DB schema, migration, .env or Dockerfile changes are authorized.
