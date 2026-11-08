# Contributing to PolicyHelix

Thank you for your interest in contributing to PolicyHelix! We welcome contributions that maintain our commitments to local-first architecture, fail-closed security, and reproducible open-source software.

---

## 1. Prerequisites & Toolchain

Before contributing, ensure your environment meets the project toolchain baseline:
- **Operating System:** Linux x86_64 (officially verified baseline; macOS and Linux via WSL2 supported for development).
- **Node.js:** Node `>= 24.19.0 < 25` (npm bundled with Node 24).
- **Go:** Go `>= 1.26`.
- **Git:** Standard git client.

Run the repository setup command:
```sh
npm run setup
```
This verifies your toolchain, installs locked dependencies with scripts disabled, compiles the Go engine binary, and builds the web client.

---

## 2. Planning & Roadmap Governance

PolicyHelix development is governed by the sequential task roadmap (tasks C01 through C40).
To find the active task or check progress:

```sh
# View current roadmap progress
npm run plan -- status

# Inspect the next active task
npm run plan -- next

# Validate planning contracts and dependencies
npm run validate:plan
```

Read the returned task card (e.g. `plans/commits/Cxx.md`) in full. Every contribution should address an unmet dependency-ready task with complete positive and negative test fixtures and source-bound evidence.

---

## 3. Implementation Standards

- **Vertical Slices:** Implement real functionality rather than placeholders, static mocks, or empty endpoints.
- **Architecture Boundaries:** Keep domain rules, validation logic, storage/provider adapters, and web UI cleanly separated.
- **Fail-Closed by Default:** All authorization decisions, network boundaries, and state evaluations must fail closed (`allow: false` / `403` / `401`) on unexpected input, outage, or missing credentials.
- **No External Network Dependencies:** The core product must never require live cloud accounts, compulsory telemetry, or third-party proprietary services to build, test, or run.
- **Inert Sentinels:** All user inputs, policy payloads, and documentation strings must treat HTML/script sentinels as inert text to prevent XSS.

---

## 4. Verification & Testing

Every code change must pass all automated verification gates:

```sh
# 1. Full standard check (plan validation, build, engine build, web tests, engine tests)
npm run check

# 2. Browser integration tests (Playwright)
npm run test:browser

# 3. Clean-clone integration smoke test
npm run test:clone

# 4. Doctor diagnostic check
npm run doctor
```

Never disable checks, skip tests, or add broad analysis ignores to bypass CI failures.

---

## 5. Permanent Owner Restrictions

To protect repository invariants, the following permanent owner restrictions must be respected:
- **DO NOT** modify database schemas, migrations, `.env` files, or Dockerfiles.
- If a protected file change appears unavoidable, record a precise blocker and continue independent authorized work.
- Use compatible adapters and local configuration as defined in `docs/architecture/ADR-0003-open-source-local-first.md`.

---

## 6. Commit & Pull Request Guidelines

- **Conventional Commits:** Format commit messages matching task cards, e.g., `docs(oss): complete installation usage contribution and support guides`.
- **Developer Certificate of Origin (DCO):** All commits must include a valid DCO sign-off line (`git commit -s`):
  ```
  Signed-off-by: Your Name <your.email@example.com>
  ```
- **Source-Bound Evidence:** Complete roadmap tasks require machine-readable evidence in `docs/evidence/Cxx.json` containing commands, toolchain versions, fixture hashes, and execution results.

---

## 7. Security Disclosures

Do **not** report security vulnerabilities or sensitive incidents via public issues or pull requests.
Follow the confirmed private reporting route in **[SECURITY.md](SECURITY.md)** (GitHub Private Vulnerability Reporting or `security@policyhelix.org`).

---

## 8. Helpful Links

- **[User Guide](docs/release/USER_GUIDE.md)**
- **[Clone & Run Guide](docs/engineering/CLONE_TO_RUN.md)**
- **[Open-Source Contract](OPEN_SOURCE.md)**
- **[Third-Party Notices](THIRD_PARTY_NOTICES.md)**
- **[Execution Contract](docs/agents/EXECUTION_CONTRACT.md)**
