# PolicyHelix: Authoritative Local Storage Proof (C05)

This document records the architecture, crash-consistency protocol, security gates, and verification proofs for the PolicyHelix local authoritative storage port implemented in `internal/storage/adapter.go` per `ADR-0003`.

## 1. Architectural Compliance (`ADR-0003`)

In compliance with permanent repository restrictions (`AGENTS.md`, `ADR-0003`), PolicyHelix does not modify database schemas, SQL migrations, `.env` files, or Dockerfiles. Instead, local authoritative service state (session epochs, signed policy bundle metadata, and idempotency ledger records) uses a **bounded, content-addressed, versioned manifest file port**:

```
<storage-root>/
  ├── .lock                      # Exclusive advisory file lock (syscall.Flock LOCK_EX | LOCK_NB)
  ├── .staging/                  # Uncommitted write staging area (purged on startup reconciliation)
  │     └── <operation_id>.tmp
  ├── objects/                   # Content-addressed immutable payloads (<sha256-hex>)
  │     └── 4a5c88e5d263...
  └── manifest.json              # Atomically published versioned authority index
```

## 2. Single-Writer & Atomic Publication Protocol

Every state mutation (`Adapter.WriteRecord`) executes the following six-phase protocol:

1. **Pre-Allocation Security & Scope Gate (`ValidateIdentityAndScope`)**:
   - Before acquiring locks or allocating file descriptors, the adapter verifies:
     - `identity.provider_state != "unavailable"` (`PROVIDER_UNAVAILABLE`)
     - `identity.untrusted_headers_stripped == true` (`FORGED_HEADER_REJECTED`)
     - `identity.authenticated == true` with non-empty `subject_id` and `issuer` (`UNAUTHENTICATED_IDENTITY`)
     - `identity.session_epoch >= identity.min_required_epoch` (`EXPIRED_OR_REVOKED_IDENTITY`)
     - Caller possesses `operator` or `admin` role (`PRIVATE_RESOURCE_FAIL_CLOSED`)
     - `record_id` strictly matches the declared `owner_scope:` prefix (`OWNER_SCOPE_VIOLATION`)
   - Any violation fails closed immediately with **zero disk side effects**.

2. **Exclusive Process Lock & Idempotency Guard**:
   - `Open(rootDir)` acquires an exclusive non-blocking OS lock (`syscall.Flock(..., LOCK_EX|LOCK_NB)`) on `.lock`. Concurrent writers fail fast with `SINGLE_WRITER_LOCK_BUSY`.
   - Under the writer lock, `WriteRecord` computes a canonical request hash (`operation_id | record_id | owner_scope | classification | payload`) and checks `manifest.operations[operation_id]`:
     - **Exact match**: Returns the committed historical `WriteReceipt` with `replayed: true` without duplicating writes or advancing `revision`.
     - **Payload/target mismatch**: Rejects with `OPERATION_ID_CONFLICT` (`409`).

3. **Bounded Repository Check**:
   - Enforces `MaxPayloadBytes` (64 KiB) per payload and `MaxTotalRecords` (1024) across the repository.

4. **Staged Content-Addressed Write & Verification**:
   - Writes payload bytes to `.staging/<operation_id>.tmp` and calls `fsync()`.
   - Re-reads staged bytes and verifies their SHA-256 digest before promotion.
   - Atomically renames `.staging/<operation_id>.tmp` to `objects/<sha256-hex>` and syncs the `objects/` directory.

5. **Atomic Manifest Publication**:
   - Increments monotonic `manifest.revision`, records the `RecordEntry` and `OperationRecord`, writes to `manifest.json.tmp`, calls `fsync()`, atomically renames `manifest.json.tmp` -> `manifest.json`, and flushes the parent directory descriptor (`syncDir`).

6. **Post-Commit Acknowledgment**:
   - Returns `WriteReceipt` only after directory sync completes.

## 3. Crash, Disk-Full & Tamper Recovery

- **Interrupted Staging / Crash Recovery (`ReconcileStartup`)**:
  - On startup, `ReconcileStartup` sweeps `.staging/` and removes any uncommitted `.tmp` files left by an interrupted process or power loss.
  - Because `manifest.json` is updated last via atomic `rename`, an interrupted write leaves the previous `manifest.json` intact. Retrying the interrupted `operation_id` after recovery succeeds cleanly.
- **Disk-Full (`ENOSPC`) Handling**:
  - Any write or `fsync` error during staging or manifest creation aborts the transaction, unlinks temporary files, and preserves the prior committed revision.
- **Tamper & Missing Reference Detection**:
  - Both `ReconcileStartup` and `ReadRecord` recompute the SHA-256 digest of every referenced file in `objects/`. Any missing object or modified byte fails closed with `CORRUPT_OR_MISSING_OBJECT`.

## 4. Verification Commands

```bash
go test -v ./tests/...
go test -v ./...
npm test
```
