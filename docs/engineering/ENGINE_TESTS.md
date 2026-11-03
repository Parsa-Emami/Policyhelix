# PolicyHelix Engine Testing & Clean-Checkout Verification

Commit: `C06` — `ci(engine): verify the actual engine from a clean checkout`  
Requirement: `N06`  

---

## 1. Overview & Architecture

The PolicyHelix Engine verification architecture establishes automated, repeatable, source-bound testing from a clean repository checkout. Shell-only tests or static mocks cannot certify engine readiness; verification requires the compilation of the Go engine binary, validation of versioned domain contracts, and proof of crash-consistent authoritative storage.

### Testing Layers & Discovery

```
PolicyHelix Test Topology
├── cmd/policyhelix/        → Engine binary CLI, loopback HTTP server, health/status probes, supervisor lifecycle
├── internal/contracts/     → Type boundaries, schema v1 validation, 200ms SLO deadline, tamper-detection, fail-closed security
├── internal/storage/       → ADR-0003 single-writer file port, atomic manifest fsync, staged objects, startup reconciliation
└── tests/                  → Integration test suites:
    ├── runtime_ci_test.go  → C06 clean-checkout verification, negative security invariants, domain test discovery assertion
    ├── storage_test.go     → C05 crash consistency, lock contention, idempotency replays, interrupted recovery
    └── fixtures/policyhelix/C06/ → Synthetic positive and negative JSON inputs (Apache-2.0 licensed)
```

---

## 2. Local Reproduction Commands

To replicate clean-checkout verification locally on an isolated workspace or development host:

```bash
# 1. Validate planning metadata and repository contracts
npm run validate:plan
python3 scripts/validate_repo.py

# 2. Build the engine binary to dist/engine/policyhelix
npm run build:engine

# 3. Verify engine executable
./dist/engine/policyhelix --version
./dist/engine/policyhelix --help

# 4. Run all engine tests with race detection
go test -v -race ./...

# 5. Run specific C06 verification suites
go test -v -race ./tests -run "TestC06FixturesAndCleanCheckoutGuarantees|TestDomainTestCollectionInvariant|TestTamperedByteFailsClosed"

# 6. Run web & node contract tests
npm test
```

---

## 3. Continuous Integration: `.github/workflows/runtime.yml`

Continuous verification runs in an isolated runner on every pull request and push to `main`:

- **Job**: `verify-engine-clean-checkout` on `ubuntu-latest`.
- **Pinned Actions**:
  - `actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803`
  - `actions/setup-go@f111f3307d8850f501ac008e886eec1fd1932a34`
  - `actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38`
- **Domain Test Collection Invariant**: The workflow explicitly asserts that all test packages (`cmd/policyhelix`, `internal/contracts`, `internal/storage`, and `tests`) are discovered and collected. Absence of collected domain tests fails the build.

---

## 4. Negative Invariants & Security Guarantees

Every engine test suite enforces three fundamental negative properties:
1. **Tamper Detection (Single Modified Byte)**: Any alteration in an object file or bundle digest invalidates the cryptographic checksum, causing `ReadRecord` and evaluation to fail closed.
2. **Untrusted Signer / Unverified Signature**: Policy bundles with unverified signatures or forged identities are rejected before side effects or evaluation occur (`STALE_OR_UNSIGNED_BUNDLE`).
3. **Private Resource Fail-Closed**: Requests accessing private resources (`classification: private`) without an authenticated subject identity are rejected immediately with `UNAUTHENTICATED_IDENTITY`.
4. **Stale/Replayed Epoch Protection**: Older session epochs or bundle revisions cannot replace current authoritative state or produce allow decisions.
