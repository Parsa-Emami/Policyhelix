# PolicyHelix — Task C05: Recoverable Local Authoritative Writes

This plan details the implementation of an ADR-0003 compliant local authoritative storage port for PolicyHelix in Go (`internal/storage/adapter.go`), proving crash-consistent atomic writes, stable operation IDs, idempotency replay, lock-guarded single-writer semantics, and interrupted/disk-full recovery without modifying database schemas, migrations, `.env`, or Dockerfiles.

## User Review & Critical Decisions

> [!IMPORTANT]
> **Confirmed Direction**: Keep this implementation plan for Task C05.
> **Zero Database Schema Change Contract**: Per `AGENTS.md`, `C05.md`, and `ADR-0003`, no database schemas, migrations, `.env` files, or Dockerfiles may be edited or added. In accordance with ADR-0003, local service state is persisted via a bounded, content-addressed, versioned manifest file port (`internal/storage/adapter.go`).

- **Storage Port Architecture (ADR-0003)**: A single-writer file-based transactional repository managing immutable content-addressed payloads (`objects/<sha256>`) and an atomically published versioned manifest (`manifest.json` via atomic rename and directory `fsync`).
- **Stable Operation IDs & Idempotency Key Guard**: Operation IDs are checked atomically before side effects. Replay of an existing operation ID with identical payload returns the previous committed acknowledgment (`replayed: true`), whereas reusing an operation ID with a different payload fails loudly with `OPERATION_ID_CONFLICT` (`409`).
- **Crash Recovery & Orphan Reconciler**: Automatic startup reconciliation cleans uncommitted staged files (`.staging/`), detects missing object references, and recovers to the last valid published manifest state.
- **Fail-Closed Boundary**: Unauthenticated requests or expired/forged identities targeting sensitive state mutations are rejected before any disk write or staging allocation occurs.

---

## 1. Overview & Core Concept

- **What It Does**: Provides the durable storage foundation for PolicyHelix session epochs, policy bundle metadata, and evaluation audit records using a crash-safe local single-writer file repository.
- **Target Audience / Persona**: PolicyHelix engine runtime and local operators requiring tamper-evident, durable, restart-safe state without requiring external SQL databases or cloud storage.
- **Key Value**: Proves atomic visible state, zero partial writes, deterministic replay recovery, and strict fail-closed security under disk-full, crash, and concurrency scenarios.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Authoritative State Write**: When an authorized operator or engine component records an epoch update, signed bundle record, or audit batch, the request passes schema and identity verification first, claims the operation ID, writes immutable bytes to staging, flushes, atomically updates the manifest, and returns a verified storage receipt.
  2. **Idempotency Replay**: If network timeouts or retries resubmit an identical request, the storage engine returns the exact historical receipt without duplicating writes or advancing manifest revision.
  3. **Crash & Restart Recovery**: Upon process startup, the adapter inspects the manifest directory, purges incomplete staging files, and confirms digest integrity before accepting new writes.
- **Visual Identity & Theme**:
  - The local web shell remains a fast, local-first inspection workspace. Engine status reflects the presence of the verified storage port once wired.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Content-Addressed File Port with Atomic Manifest over SQLite Schema**
  - *Chosen Approach*: Implement the file-backed repository port outlined in ADR-0003 (`internal/storage/adapter.go`) with file locking (`syscall.Flock`), staging directory, and atomic `rename` of `manifest.json`.
  - *Why*: Satisfies repository owner constraint prohibiting database schema and migration edits while providing formal crash consistency and portability.
- **Decision 2: Strict Pre-Allocation Identity Gate**
  - *Chosen Approach*: Validate identity and resource permissions *before* opening staging file descriptors or acquiring write locks.
  - *Why*: Satisfies the negative security requirement ("Missing/expired/replayed identity and an unrelated owner/object scope fail before sensitive side effects").

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Write Lifecycle Diagram

```
[ Client / Evaluator Request ]
              │
              ▼
   ┌────────────────────────────────────────────────────────┐
   │ 1. Identity & Scope Guard (Fail-Closed Check)         │
   │    • Rejects unauthenticated, expired, or forged token │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ 2. Storage Port Lock & Idempotency Check               │
   │    • syscall.Flock (exclusive writer lock)             │
   │    • Check operation_id in manifest index              │
   │    • If exists with same hash -> Return Replay Receipt │
   │    • If exists with different hash -> Reject 409       │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │ 3. Staged Durable Write & Directory Sync               │
   │    • Write to .staging/<op_id>.<tmp>                   │
   │    • Check payload hash matches content SHA-256        │
   │    • Move to objects/<sha256> (immutable payload)      │
   │    • Write manifest.tmp -> Rename to manifest.json     │
   │    • Parent directory fsync                            │
   └──────────────────────────┬─────────────────────────────┘
                              │
                              ▼
                  [ Acknowledgment & Receipt ]
```

### Verification Plan

1. **Go Unit & Integration Tests**:
   - `go test -v ./internal/storage/...`
   - `go test -v ./tests/...`
   - `go test -v ./...`
2. **Web & Contract Regressions**:
   - `npm test`
   - `npm run test:browser` (Playwright)
   - `npm run test:clone` (clean git clone smoke test)
3. **Repository Integrity & Plan Validation**:
   - `npm run validate:plan`
   - `python3 scripts/validate_repo.py`
   - `python3 -m unittest discover -s tests/engineering -p 'test_*.py' -v`
4. **Evidence & State Update**:
   - Generate `docs/evidence/C05.json` with exact execution logs, toolchain probe, and fixture digests.
   - Update `plans/progress.json`, `plans/project-state.json`, and `docs/agents/SESSION_HANDOFF.json`.
