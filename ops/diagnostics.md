# PolicyHelix — Operations & Diagnostics Architecture

## 1. Overview and Operational Philosophy

In accordance with requirement **N29** and **ADR-0003** (Open Source & Local-First), PolicyHelix establishes strict operational observability and failure isolation prior to clean-host deployment (C30).

Key operational principles:
1. **Liveness vs. Readiness Separation**:
   - `/healthz` tests process liveness only (i.e. is the web-shell or engine process running and listening).
   - `/readyz` and `/api/v1/runtime/readiness` test deep operational capability: authoritative storage readability/lock status and required provider health (`local_opa`, `self_hosted_keycloak`, `owned_synthetic_upstream`).
2. **Explicit Failures Over Placeholder Success**:
   - If authoritative storage is uninitialized, corrupted, or locked by another process, or if required providers are offline, the system returns an explicit HTTP 503 Service Unavailable with a machine-readable error code.
   - Placeholder 200 OK responses during outages are forbidden.
3. **Fail-Closed Security Invariant**:
   - Private resources and diagnostic logs fail closed. Diagnostics endpoints (`/api/v1/runtime/diagnostics`) require valid authentication or loopback internal verification.
4. **Bounded Telemetry and Sentinel Redaction**:
   - Diagnostic event buffers are strictly bounded (100 events, max 4096 bytes per message) to prevent denial-of-service and memory exhaustion.
   - Synthetic secrets, Bearer tokens, JWT strings, session cookies, and `*_SENTINEL` tokens are automatically stripped and replaced with `[REDACTED]` or `[REDACTED_SENTINEL]`.

---

## 2. Readiness Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                              PolicyHelix                               │
├──────────────────────────┬─────────────────────────────────────────────┤
│ Endpoint                 │ Behavior                                    │
├──────────────────────────┼─────────────────────────────────────────────┤
│ GET /healthz             │ 200 OK: Process alive & listening           │
│ GET /readyz              │ 200 OK / 503 Unavailable: Component health  │
│ GET /v1/runtime/readiness│ Deep engine, storage, and provider status   │
│ GET /v1/runtime/diagnostics│ Bounded ring buffer of scrubbed log events│
└──────────────────────────┴─────────────────────────────────────────────┘
```

---

## 3. Storage and Provider Health Criteria

- **Authoritative Storage (`internal/storage`)**:
  - Root directory exists and is a directory.
  - Manifest (`manifest.json`) is present and valid JSON (or cleanly uninitialized at revision 0).
  - Single-writer exclusive file lock (`.lock`) is acquirable without contention (`syscall.LOCK_EX | syscall.LOCK_NB`).
- **Required Providers**:
  - `local_opa`: Evaluates Rego policy bundles. Returns `OPA_PROVIDER_UNAVAILABLE` on outage.
  - `self_hosted_keycloak`: Evaluates OIDC tokens and ID token verification. Returns `IDP_PROVIDER_UNAVAILABLE` on outage.
  - `owned_synthetic_upstream`: Target upstream service. Returns `UPSTREAM_PROVIDER_UNAVAILABLE` on outage.

---

## 4. Diagnostics Redaction and Bounded Buffers

- **Redaction Rules**:
  - `Bearer <token>` → `Bearer [REDACTED]`
  - `eyJ...` (JWT) → `[REDACTED_JWT]`
  - `policyhelix_session=<token>` → `policyhelix_session=[REDACTED]`
  - `(?i)[a-z0-9_-]*sentinel[a-z0-9_-]*` → `[REDACTED_SENTINEL]`
- **Buffer Capacity**:
  - Ring buffer capacity: 100 events.
  - Max message length: 4096 bytes (truncated with `...[TRUNCATED]`).
  - Memory consumption: <= 512 KiB guaranteed.

---

## 5. Verification Commands

```bash
# Verify plan and task status
npm run validate:plan

# Run Go engine readiness and diagnostics test suite
go test -v -run TestC29 ./tests

# Run Node web readiness test suite
node --test tests/web/engine-readiness.test.mjs
```
