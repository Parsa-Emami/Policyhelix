# PolicyHelix — Task C08: Evaluate Bounded Local Policy Bundles

This plan details the implementation of Task C08 (`feat(opa): evaluate bounded local policy bundles`, Requirement `F02`), providing a bounded, fail-closed local policy bundle evaluator that enforces strict decision deadlines ($\le 200\text{ms}$), cryptographic signature/digest integrity, monotonic bundle revisions, and explicit deny/error outcomes on invalid policies or timeouts without any silent fallback permit.

## User Review & Critical Decisions

> [!IMPORTANT]
> **Requirement F02 & Fail-Closed Contract**: Any invalid policy bundle, untrusted/missing signature, single-byte payload tampering, expired or stale/replayed bundle revision, or exceeded evaluation deadline must produce an explicit `allow: false` decision and typed error—never a silent fallback permit.
> **Zero Protected File Modifications**: In compliance with `AGENTS.md` and `ADR-0003`, no database schemas, migrations, `.env` files, or Dockerfiles will be modified.

- **Bounded Local Bundle Evaluator (`internal/policy`)**: Extends the existing `internal/policy` domain package (`RouteRegistry`, `ResourceClass`, `SubjectIdentity`) with a deterministic, thread-safe local OPA-compatible policy bundle evaluator (`BundleEvaluator`) that retains the last valid accepted bundle revision and rejects stale/downgraded or tampered bundles.
- **Strict Context & Deadline Enforcement**: Every evaluation runs under a bounded `context.Context` deadline (`<= 200ms` max SLO). Exceeding the deadline or encountering context cancellation immediately aborts evaluation and returns `allow: false` with a typed `DECISION_TIMEOUT` or `REQUEST_CANCELLED` error.

---

## 1. Overview & Core Concept

- **What It Does**: Evaluates authorization requests against signed, versioned local policy bundles with strict size, syntax/schema, signature, freshness, monotonic revision, and execution-time bounds.
- **Target Audience / Persona**: The PolicyHelix local Go engine, offline decision simulator (upcoming in C09), and local operators verifying policy bundle behavior before gateway enforcement.
- **Key Value**: Guarantees that policy syntax errors, corrupted bytes, untrusted signers, replayed revisions, or slow evaluations fail closed deterministically while preserving the last valid accepted authority in memory.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Bundle Activation & Monotonic Authority Check**: An operator or engine loads a signed policy bundle containing explicit route rules, role policies, revision number, cryptographic digest/signature, and validity window (`not_before` / `expires_at`). If valid and strictly newer than the active revision, it becomes the active authority; if tampered, unsigned, expired, or stale/replayed, activation is rejected and the prior valid authority remains intact.
  2. **Bounded Policy Decision Evaluation**: When a request arrives, the evaluator validates the active bundle's freshness, checks the execution deadline, resolves route classification via `RouteRegistry` (default-private for unspecified routes per F01), evaluates subject authentication and role rules, and returns a structured decision with `allow`, `policy_digest`, `revision`, `reasons`, `obligations`, and `error`.
  3. **Timeout & Invalid Policy Fail-Closed Handling**: If a policy bundle has invalid rules/syntax or evaluation exceeds the configured deadline, the engine returns `allow: false` with explicit reason codes (`INVALID_POLICY_BUNDLE`, `DECISION_DEADLINE_EXCEEDED`, etc.) and never falls back to permitting access.
- **Visual Identity & Theme**:
  - Preserves the existing local-first web workspace (`apps/web`), updating generated project state metadata only after full engine verification.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Self-Contained Deterministic Policy Bundle Evaluator Integrated with C07 `RouteRegistry`**
  - *Chosen Approach*: Build the bounded policy bundle evaluator directly on top of C07's `RouteRegistry` and `ResourceClass` primitives inside the `internal/policy` package, supporting declarative JSON/Rego-compatible bundle rules, Ed25519/SHA-256 verification, and deterministic simulated evaluation delay hooks for deadline testing.
  - *Why*: Eliminates external daemon race conditions during unit/integration tests while remaining 100% compatible with C09 (`feat(simulator): run expected decision fixtures offline`), C10 (`feat(bundles): build deterministic signed policy bundle`), and C11 (`feat(verification): require bundle trust and freshness`).
- **Decision 2: Last-Valid-Authority Preservation on Rejected Bundle Updates**
  - *Chosen Approach*: Maintain thread-safe state (`sync.RWMutex`) tracking the highest accepted monotonic revision and active bundle; if a candidate bundle fails byte-integrity, signer verification, freshness, or revision monotonicity, reject the candidate error-first while keeping the previously accepted valid bundle active.
  - *Why*: Directly satisfies the required negative case: *"An expired/stale/replayed revision cannot replace the last valid accepted authority."*

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Evaluation Lifecycle Diagram

```
[ Evaluation Request + Context Deadline ]   [ Signed Policy Bundle Candidate ]
                    │                                       │
                    │                                       ▼
                    │                        ┌──────────────────────────────┐
                    │                        │ 1. Bundle Integrity & Trust  │
                    │                        │  • Syntax & rule validation  │
                    │                        │  • SHA-256 digest & signer   │
                    │                        │  • Freshness (NotBefore/Exp) │
                    │                        │  • Monotonic revision > last │
                    │                        └──────────────┬───────────────┘
                    │                                       │ (Reject keeps last valid)
                    ▼                                       ▼
     ┌──────────────────────────────────────────────────────────────┐
     │ 2. Bounded Local Policy Evaluator (internal/policy)          │
     │  • Enforce DeadlineMS (<= 200ms) & context cancellation      │
     │  • Verify active bundle exists & is not expired at eval time │
     │  • Evaluate F01 route class (unspecified -> default private) │
     │  • Evaluate authenticated subject identity & role rules      │
     │  • Never fallback-permit on error, timeout, or invalid rule  │
     └──────────────────────────────┬───────────────────────────────┘
                                    │
                                    ▼
     ┌──────────────────────────────────────────────────────────────┐
     │ 3. Typed Decision Outcome                                    │
     │  • Allow: bool (strictly false on any error/timeout)         │
     │  • PolicyDigest, Revision, Reasons, Obligations, TypedError  │
     └──────────────────────────────────────────────────────────────┘
```

### Data Model & Fixtures (`tests/fixtures/policyhelix/C08/`)

- **`PolicyBundle`**: Encapsulates `bundle_id`, `issuer`, `revision` (monotonic `int64`), `digest` (`sha256:...`), `signer` / `signature_verified`, `not_before`, `expires_at`, `routes` (`[]RouteRule`), and `rules` (role/action/resource permissions and obligations).
- **`BundleEvalRequest` & `BundleEvalResult`**: Strongly typed input/output structs carrying subject identity, resource/path, action, evaluation timestamp, `deadline_ms`, simulated execution duration (for deterministic timeout verification), decision reasons, policy digest, and typed error codes.
- **Synthetic Licensed Fixtures (`Apache-2.0`)**:
  - `positive-bounded-bundle-allow.json`: Valid signed bundle, fresh validity window, authenticated `operator` role within deadline -> `allow: true`.
  - `negative-invalid-policy-deny.json`: Malformed/invalid policy rule definition -> `allow: false`, explicit `INVALID_POLICY_BUNDLE` error, no silent fallback permit.
  - `negative-deadline-exceeded-deny.json`: Evaluation exceeding deadline bound -> `allow: false`, explicit `DECISION_DEADLINE_EXCEEDED` error.
  - `negative-tampered-or-untrusted-signer.json`: Single modified byte / digest mismatch or untrusted signer -> rejected (`allow: false`, `UNTRUSTED_OR_TAMPERED_BUNDLE`).
  - `negative-stale-replayed-revision.json`: Expired bundle or stale/replayed revision attempting to replace higher accepted revision -> rejected while retaining last valid authority.
  - `negative-private-resource-fail-closed.json`: Unauthenticated or unauthorized request to private/unspecified resource -> `allow: false` (`PRIVATE_RESOURCE_FAIL_CLOSED`).

### Acceptance Criteria & Verification Method

1. **Acceptance Criteria**:
   - [ ] Invalid policy syntax/schema and exceeded deadlines produce explicit `allow: false` and typed error codes; zero silent fallback permits exist.
   - [ ] One modified byte, missing evidence, or wrong/untrusted signer is rejected and never produces trusted success.
   - [ ] An expired, stale, or replayed revision is rejected and cannot replace the last valid accepted authority.
   - [ ] Private and unspecified resources strictly fail closed.
2. **Verification Commands**:
   - `npm run validate:plan` — Validate roadmap, progress, requirements, and fixture metadata.
   - `go test -v -race ./...` — Execute all unit and integration tests across `internal/policy` and `tests` (including C08 acceptance and negative suites).
   - `npm test` & `npm run build` — Verify web application build, TypeScript typecheck, and contract regressions.
   - `python3 scripts/validate_repo.py` & `python3 scripts/source_identity.py` — Verify repository integrity, protected file hashes, and compute `source_identity` for `docs/evidence/C08.json`.
