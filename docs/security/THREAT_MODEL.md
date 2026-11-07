# PolicyHelix Threat Model (STRIDE & Authorization Boundaries)

## 1. Scope & Architecture Overview

PolicyHelix is a local-first, open-source identity-aware policy enforcement gateway, simulator, and audit plane (`ADR-0003`). It mediates untrusted client requests before they reach an allowlisted upstream service, enforces Ed25519-signed OPA/Rego policy bundles with monotonic anti-rollback revision floors, manages revocable server-side sessions bound to an external OIDC Identity Provider (Keycloak), and records pseudonymized, token-free audit logs in a single-writer durable local store.

This threat model governs **Task C27 (`Requirement N27`)** and defines the trust boundaries, protected assets, STRIDE threat analysis, abuse cases, and automated verification suites across every enabled web, HTTP proxy, policy engine, and durable storage surface.

---

## 2. Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ TB1: Untrusted Client / Browser DOM / Uploaded JSON Files                    │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │ HTTP (Loopback 127.0.0.1:4173)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ TB2: Node Loopback Web Server & Proxy (scripts/serve-web.mjs)                │
│      • Host authority allowlist (localhost / 127.0.0.1 / [::1])              │
│      • Path normalization, dot-segment & null-byte rejection                 │
│      • Strict CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff    │
│      • Bounded client JSON preview (<=64 KiB, <=32 depth, no __proto__)      │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │ HTTP Loopback Proxy (/api/v1/*)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ TB3: Go PolicyHelix Engine & Gateway Proxy (cmd/policyhelix, internal/*)     │
│      • Gate 1: Direct origin bypass proof verification (HMAC-SHA256)         │
│      • Gate 2: Single allowlisted upstream & SSRF host/header blocking       │
│      • Gate 3: Path traversal (.., //, @) & prefix allowlist enforcement     │
│      • Gate 4: Prohibited header stripping (X-PolicyHelix-*, X-Roles, etc.)  │
│      • Gate 5: Session lookup, 30s revocation bound & replay rejection       │
│      • Gate 6: Owner/Object scope isolation (IDOR prevention)                │
│      • Gate 7: Signed policy bundle evaluation & fail-closed outage handling │
└─────────────────┬───────────────────────────────────────────┬────────────────┘
                  │                                           │
                  ▼                                           ▼
┌───────────────────────────────────────┐   ┌──────────────────────────────────┐
│ TB4: Durable Local Storage            │   │ TB5: Allowlisted Upstream & IdP  │
│      (internal/storage/adapter.go)    │   │      • Self-hosted Keycloak/OIDC │
│      • Exclusive flock (.lock)        │   │      • Synthetic Demo Upstream   │
│      • CallerIdentity & OwnerScope    │   │        (service:analytics)       │
│      • SHA-256 object manifest        │   └──────────────────────────────────┘
└───────────────────────────────────────┘
```

---

## 3. Protected Assets

1. **Signing & Trust Material:** Ed25519 public/private trust keys, active policy bundle state (`policyhelix:trust-keyring-state`), and monotonic `HighestRevision` floor.
2. **Session & Authentication Credentials:** OIDC authorization codes, access/refresh tokens, and session cookies (`policyhelix_session`). Raw credentials must never be written to audit logs, DOM state, or error responses.
3. **Tenant & Object Data (`OwnerScope` / `ObjectScope`):** Scoped storage records (`policyhelix:session:*`, `policyhelix:revocation:*`, tenant-scoped objects) and upstream analytics resources (`tenant:default`).
4. **Gateway Origin Proof Secret:** Shared HMAC key (`X-PolicyHelix-Gateway-Proof`) proving to the upstream service that traffic traversed the PolicyHelix enforcement pipeline.
5. **Browser DOM & Operator Workspace Integrity:** Operator UI (`/#overview`, `/#simulator`, `/#gateway`, `/#roadmap`) protected against DOM XSS, prototype pollution, and UI redressing (clickjacking).

---

## 4. STRIDE Threat Analysis & Mitigations

| Threat Category | Attack Vector / Abuse Case | Affected Boundary | Implemented Mitigation | Verification Coverage |
|---|---|---|---|---|
| **S — Spoofing** | Client injects `X-PolicyHelix-Subject`, `X-PolicyHelix-Roles`, `X-User-Id`, or `X-Roles` to impersonate an operator or admin. | TB2 → TB3 (`internal/gateway/identity.go`) | `NormalizeSubjectContext` rejects any request with `UntrustedHeadersStripped: false` or `ForgedHeaders` / prohibited headers with `403 FORGED_HEADER_REJECTED` before upstream forwarding or storage mutation. | `negative-forged-header-privilege-escalation.json`, `tests/security_suite_test.go`, `tests/browser/security.spec.ts` |
| **S — Spoofing** | Attacker replays a superseded, rotated, or expired session ID, or omits identity credentials on a private route. | TB3 (`internal/gateway/proxy.go`, `internal/auth/session.go`) | `NormalizeSubjectContext` and `EvaluateProxyRequest` reject missing identity (`403 PRIVATE_RESOURCE_FAIL_CLOSED`), expired sessions (`403 EXPIRED_SESSION`), revoked sessions (`403 REVOKED_SESSION_DENIED`), and superseded sessions (`403 REPLAYED_IDENTITY_DENIED`). | `negative-missing-identity-denied.json`, `negative-expired-replayed-identity-denied.json` |
| **T — Tampering** | Client uploads JSON containing `__proto__`, `constructor`, or `prototype` keys, or `<script>` / `onerror=` XSS sentinels into Overview, Simulator, or Gateway file inputs. | TB1 → TB2 (`apps/web/src/lib/preview.mjs`, `internal/gateway/security.go`) | `inspectJson` and engine import validation reject prototype-pollution keys (`Unsafe document key` / `UNSAFE_IMPORT_PAYLOAD_REJECTED`), enforce `<=64 KiB` and `<=32` nesting depth, and React + CSP (`default-src 'none'; script-src 'self'`) render all strings inertly. | `negative-xss-import-prototype-pollution-rejected.json`, `tests/browser/security.spec.ts` |
| **T — Tampering** | Attacker modifies 1 byte of a signed policy bundle or replays an older signed revision. | TB3 → TB4 (`internal/bundles/keys.go`) | Ed25519 signature verification and SHA-256 digest checks fail with `TAMPERED_BUNDLE_DIGEST`; monotonic `HighestRevision` rejects stale revisions with `STALE_OR_REPLAYED_REVISION` while retaining prior valid authority. | `tests/enforcement_matrix_test.go`, `tests/key_rotation_test.go` |
| **R — Repudiation** | Unauthorized caller attempts cross-tenant mutation or policy override without audit visibility. | TB3 → TB4 (`internal/audit/logger.go`) | All allow/deny decisions and security rejections produce structured, pseudonymized audit events with `side_effects_executed: false` on denial. | `tests/redaction_test.go`, `tests/security_suite_test.go` |
| **I — Information Disclosure** | Cross-tenant / cross-owner Insecure Direct Object Reference (IDOR): authenticated user in `tenant:alpha` requests or mutates an object/resource owned by `tenant:default` or `tenant:bravo`. | TB3 & TB4 (`internal/gateway/identity.go`, `internal/storage/adapter.go`) | Gateway checks `TargetOwnerScope` and `ObjectScope` against session `OwnerScope` (`403 UNRELATED_OWNER_SCOPE`), and `storage.Adapter.WriteRecord` enforces `ValidateIdentityAndScope` (`OWNER_SCOPE_VIOLATION`) before any bytes are staged or written. | `negative-idor-unrelated-owner-scope.json`, `tests/security_suite_test.go`, `tests/browser/security.spec.ts` |
| **I — Information Disclosure** | Leakage of raw OIDC Bearer tokens, JWTs (`eyJ...`), or session cookies (`policyhelix_session=`) in DOM, API responses, or logs. | TB2 & TB3 (`internal/audit/logger.go`, `apps/web/src/pages/Gateway.tsx`) | Token redaction filters strip sensitive headers/fields; UI displays only pseudonymized subject digests and boolean credential presence flags. | `apps/web/tests/gateway.spec.ts`, `tests/browser/security.spec.ts` |
| **D — Denial of Service** | Oversized payloads (`>64 KiB`), deeply nested JSON (`>32` levels), or Identity/Policy Provider outage. | TB1, TB2, TB3, TB5 | `MaxAllowedPayload = 65536` and `inspectJson` cap memory/CPU; when IdP or OPA provider is unavailable, private routes fail closed (`403 PROVIDER_UNAVAILABLE` / `503 DECISION_LOSS_SENSITIVE_DENY`) while explicit public health routes (`/health`) remain bounded. | `negative-idp-unavailable-sensitive-deny.json`, `tests/browser/security.spec.ts` |
| **E — Elevation of Privilege** | Widened path traversal (`/api/v1/analytics/../../admin`, `/.env`) or widened upstream provider redirection (`target_upstream_id: "service:internal-db"`, `X-Forwarded-Host: evil.example`). | TB2 & TB3 (`scripts/serve-web.mjs`, `internal/gateway/proxy.go`) | Web server blocks dot-segments, backslashes, and non-loopback `Host` headers (`400`/`403`); gateway proxy blocks path traversal and non-allowlisted paths (`403 WIDENED_PERMISSION_DENIED`), non-allowlisted upstreams (`400 UPSTREAM_NOT_ALLOWLISTED`), and missing required roles (`403 WIDENED_PERMISSION_DENIED`). | `negative-widened-path-traversal-denied.json`, `negative-widened-provider-upstream-denied.json` |

---

## 5. Invariant Security Rules

1. **Fail-Closed Private Posture:** Any unauthenticated request, expired/revoked/replayed session, or provider outage targeting a `private`, `internal`, or `restricted` resource is denied (`Allow: false`, `ForwardedToUpstream: false`, `SideEffectsExecuted: false`).
2. **Pre-Execution Scope & Permission Gate:** Owner/object scope (`OwnerScope` / `ObjectScope`) and role permissions are verified prior to executing any storage write, session revocation, or upstream request forwarding.
3. **Zero Script Execution & Prototype Safety on Untrusted Imports:** All JSON files imported through the browser or submitted to engine verification endpoints are parsed as data only, checked against prototype-pollution keys (`__proto__`, `prototype`, `constructor`), and rendered as escaped text under a strict `Content-Security-Policy`.
