# PolicyHelix Release Security Matrix (C27 / Requirement N27)

This release security matrix catalogs the negative UAT, XSS/import, and object/provider authorization (IDOR) verification vectors across every enabled surface of the PolicyHelix local-first profile.

---

## 1. Enabled Surface Inventory

| Surface ID | Surface Name | Entry Point / Route | Security Gate / Enforcer |
|---|---|---|---|
| **S1** | Overview Workspace & Local JSON Preview | `/#overview` (`apps/web/src/lib/preview.mjs`) | Client-side `inspectJson` (`<=64 KiB`, `<=32` depth, `<=20,000` nodes, blocks `__proto__`/`prototype`/`constructor`), React text escaping, strict CSP |
| **S2** | Policy Simulator & Decision Diff UI | `/#simulator` (`apps/web/src/pages/Simulator.tsx`, `POST /api/v1/runtime/simulate`) | Schema validation (`fixture_id` required), HTML/script sentinel inert rendering, 503 fail-closed alert on engine/provider outage |
| **S3** | Gateway Health & Session Revocation UI | `/#gateway` (`apps/web/src/pages/Gateway.tsx`, `POST /api/v1/runtime/auth/revoke-check`) | Zero-token DOM invariant (no `Bearer`, `eyJ...`, or `policyhelix_session=`), XSS sentinel inertness, bounded `<=30s` revocation stop |
| **S4** | Loopback Web HTTP Server | `http://127.0.0.1:4173/*` (`scripts/serve-web.mjs`) | Loopback `Host` validation (`403 invalid_host`), dot-segment/backslash/null-byte path rejection (`400 invalid_path`), method allowlist (`405`), CSP & framing headers |
| **S5** | Gateway Upstream Proxy & Identity Normalizer | `internal/gateway/proxy.go`, `internal/gateway/identity.go` | Origin proof verification, single upstream allowlist (`service:analytics`), prohibited header stripping (`X-PolicyHelix-*`, `X-Roles`), session/revocation/replay enforcement, owner/object scope & role checks |
| **S6** | Durable Local Object & Bundle Storage | `internal/storage/adapter.go`, `internal/bundles/keys.go` | `ValidateIdentityAndScope` (`OWNER_SCOPE_VIOLATION`, `UNAUTHENTICATED_IDENTITY`, `FORGED_HEADER_REJECTED`), Ed25519 signature & monotonic revision floor |
| **S7** | Unified Security Boundary Verifier | `POST /api/v1/security/verify`, `-verify-security` (`internal/gateway/security.go`) | End-to-end verification of identity, IDOR owner/object scope, forged headers, widened path/provider permissions, IdP outage, and import safety with zero side effects |

---

## 2. C27 Fixture & Abuse Case Verification Matrix

All fixtures reside under `tests/fixtures/policyhelix/C27/` with `Apache-2.0` license provenance and pinned SHA-256 digests in `tests/fixtures/policyhelix/C27/manifest.json`.

| Fixture ID | Vector | Surface(s) | Input Summary | Expected Status | Expected Error Code | Side Effects Executed |
|---|---|---|---|---|---|---|
| `positive-authorized-owner-scope-access` | `authorized_owner_scope` | S5, S6, S7 | Authenticated `operator` in `tenant:default` accesses `/api/v1/analytics/reports` and writes scoped record in `tenant:default` | `200 OK` | *(none)* | `true` (authorized) |
| `negative-missing-identity-denied` | `missing_identity` | S5, S6, S7 | Unauthenticated caller (`session_id: ""`) requests private resource `/api/v1/analytics/reports` and attempts private storage write | `403 Forbidden` | `PRIVATE_RESOURCE_FAIL_CLOSED` | `false` |
| `negative-expired-replayed-identity-denied` | `expired_replayed_identity` | S5, S6, S7 | Caller presents superseded/replayed session (`sess-c27-replayed`) with stale epoch after session rotation | `403 Forbidden` | `REPLAYED_IDENTITY_DENIED` | `false` |
| `negative-idor-unrelated-owner-scope` | `idor_unrelated_owner_scope` | S5, S6, S7 | Authenticated subject in `tenant:alpha` attempts to access `tenant:default` upstream resource and write to `tenant:default` storage record | `403 Forbidden` | `UNRELATED_OWNER_SCOPE` (Storage: `OWNER_SCOPE_VIOLATION`) | `false` |
| `negative-forged-header-privilege-escalation` | `forged_header` | S5, S6, S7 | Client injects `X-PolicyHelix-Roles: admin` and `X-User-Id: root-admin` to escalate privileges | `403 Forbidden` | `FORGED_HEADER_REJECTED` | `false` |
| `negative-widened-path-traversal-denied` | `widened_path_permission` | S4, S5, S7 | Authenticated caller attempts path traversal `/api/v1/analytics/../../internal/secrets` outside allowlisted prefixes | `403 Forbidden` | `WIDENED_PERMISSION_DENIED` | `false` |
| `negative-widened-provider-upstream-denied` | `widened_provider_permission` | S5, S7 | Authenticated caller attempts to route to non-allowlisted upstream `service:internal-admin` / `http://169.254.169.254/latest/meta-data` | `400 Bad Request` | `UPSTREAM_NOT_ALLOWLISTED` | `false` |
| `negative-idp-unavailable-sensitive-deny` | `idp_unavailable` | S2, S3, S5, S7 | Identity Provider (`self_hosted_keycloak`) is in `unavailable` state during private resource access | `403 Forbidden` | `PROVIDER_UNAVAILABLE` | `false` |
| `negative-xss-import-prototype-pollution-rejected` | `xss_import_abuse` | S1, S2, S3, S7 | Untrusted import payload contains `__proto__` prototype pollution key and `<script>alert('xss-c27')</script><img src=x onerror=alert(1)>` sentinel | `422 Unprocessable Entity` | `UNSAFE_IMPORT_PAYLOAD_REJECTED` | `false` |
| `negative-private-resource-fail-closed` | `private_resource_fail_closed` | S5, S6, S7 | Authenticated `viewer` role lacking required `admin` role attempts sensitive action on restricted resource `/api/v1/analytics/exports` | `403 Forbidden` | `WIDENED_PERMISSION_DENIED` | `false` |

---

## 3. Browser Negative UAT, XSS & Import Test Matrix (`tests/browser/security.spec.ts`)

1. **HTTP Security Headers & Path/Host Hardening:**
   - Verifies `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Permissions-Policy`.
   - Verifies dot-segment traversal (`/.env`, `/..%2fpackage.json`) returns `400 {"error":"invalid_path"}` and disallowed HTTP methods (`DELETE /healthz`, `PUT /api/v1/runtime/simulate`) return `405 {"error":"method_not_allowed"}`.
2. **Overview JSON Import Abuse (`/#overview`):**
   - Rejects prototype-pollution JSON (`{"__proto__":{"polluted":true}}` and `{"constructor":{"prototype":{"isAdmin":true}}}`) with `Unsafe document key.` alert and verifies `Object.prototype.polluted === undefined`.
   - Rejects non-object JSON roots (`[1,2,3]`) and oversized files (`>64 KiB`) with explicit accessible error alerts.
   - Renders XSS sentinel keys/values (`{"<script>alert('xss')</script>":"<img src=x onerror=alert(1)>"}`) as inert text without script execution or dialog popups.
3. **Simulator & Gateway Negative UAT & XSS Inertness (`/#simulator`, `/#gateway`):**
   - Verifies script/HTML sentinels in Simulator and Gateway fixtures and custom uploads remain inert (`dialogs.length === 0`, no injected `<script>` tags).
   - Verifies zero credential/token leakage (`Bearer`, `eyJ...`, `policyhelix_session=`, `Set-Cookie`) across all Gateway scenarios.
4. **End-to-End Object/Provider Authorization (IDOR) via Loopback Engine (`POST /api/v1/security/verify`):**
   - Executes C27 positive and negative security fixtures directly from Playwright through the loopback web proxy to the Go engine and asserts `passed: true`, `side_effects_executed: false` on all negative vectors, and exact error codes.

---

## 4. Verification Commands

```bash
npm run validate:plan
go test -v -run TestC27 ./tests
go test -count=1 ./...
npm test
npm run test:browser
python3 scripts/validate_repo.py
```
