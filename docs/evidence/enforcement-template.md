# PolicyHelix Enforcement Verification Matrix (C26 — Requirement F20)

This document defines the unified end-to-end enforcement verification matrix for **Task C26** (`test(enforcement): verify origin bypass outage and replay`), certifying **Requirement F20**:

> **Requirement F20:** Direct origin, forged header, revoked session, expired bundle and policy outage all fail as specified.

All enforcement vectors execute against the actual Go runtime components (`internal/gateway`, `internal/auth`, `internal/bundles`, `internal/policy`, and `internal/storage`) using repository-authored Apache-2.0 synthetic fixtures under `tests/fixtures/policyhelix/C26/`.

---

## 1. Core Security Invariants Verified

1. **Direct Origin Isolation (`F11` / `F20`):** Any request attempting to reach the upstream origin directly (`direct_origin_access: true`) without a valid cryptographic `X-PolicyHelix-Gateway-Proof` HMAC token is rejected with `403 Forbidden` (`DIRECT_ORIGIN_BYPASS_DENIED`) before any upstream forwarding or side effects occur.
2. **Client Header Stripping & Forged Header Rejection (`F10` / `F20`):** Any request carrying unstripped client identity headers (`X-PolicyHelix-*`, `X-User-Id`, `X-Roles`, etc.) is rejected with `403 Forbidden` (`FORGED_HEADER_REJECTED`).
3. **Bounded Session Revocation Enforcement (`F09` / `F20`):** Any request presenting a revoked session ID or a session epoch older than the subject/scope revocation floor is rejected with `403 Forbidden` (`REVOKED_SESSION_DENIED`).
4. **Expired Policy Bundle Rejection (`F05` / `F20`):** Any bundle whose validity window (`expires_at`) has elapsed at evaluation time is rejected with `EXPIRED_POLICY_BUNDLE`; private routes fail closed (`allow: false`).
5. **Policy Outage & Decision Loss Fail-Closed (`F13` / `F20`):** When the policy decision engine is in an outage, timeout, or decision-loss state, private/sensitive routes fail closed with `503 Service Unavailable` (`DECISION_LOSS_SENSITIVE_DENY`), while explicitly configured public health routes remain intentionally testable (`INTENTIONAL_PUBLIC_BYPASS`).
6. **Tampered Byte & Untrusted Signer Rejection (`F04` / `F05` / `C26 Negative`):** Modifying a single byte of a signed bundle or signing with an untrusted/missing key rejects the candidate (`TAMPERED_BUNDLE_DIGEST` / `UNTRUSTED_OR_MISSING_SIGNER`) while preserving the last valid accepted bundle authority.
7. **Stale / Replayed Revision Authority Retention (`F06` / `C26 Negative`):** Submitting an expired, stale, or replayed bundle revision (`<= HighestRevision`) is rejected with `STALE_OR_REPLAYED_REVISION` and never replaces the last valid accepted bundle authority.
8. **Private Resources Fail Closed (`F01` / `C26 Negative`):** Unauthenticated requests to private or unspecified routes strictly fail closed (`allow: false`, `UNAUTHENTICATED` / `PRIVATE_RESOURCE_FAIL_CLOSED`).

---

## 2. Enforcement Verification Matrix

| Vector ID | Fixture Path | Attack / Failure Condition | Expected Outcome (`allow` / HTTP Status) | Expected Error / Disposition Code | Authority Retention Invariant |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `positive_authenticated_gateway` | `tests/fixtures/policyhelix/C26/positive-authenticated-gateway-enforcement.json` | Valid signed bundle (rev 2), active operator session, stripped headers, allowlisted upstream | `allow: true` (`200 OK`) | *(none)* | Active bundle rev 2 enforced |
| `positive_public_outage_bypass` | `tests/fixtures/policyhelix/C26/positive-public-route-outage-bypass.json` | Policy engine outage on explicit public route `/health` with `allow_public_bypass: true` | `allow: true` (`200 OK`) | `INTENTIONAL_PUBLIC_BYPASS` | Active bundle rev 2 retained |
| `direct_origin_bypass` | `tests/fixtures/policyhelix/C26/negative-direct-origin-bypass.json` | `direct_origin_access: true` without valid gateway HMAC proof | `allow: false` (`403 Forbidden`) | `DIRECT_ORIGIN_BYPASS_DENIED` | Active bundle rev 2 retained |
| `forged_header` | `tests/fixtures/policyhelix/C26/negative-forged-identity-header.json` | Forged `X-PolicyHelix-Subject` / `X-Roles` with `untrusted_headers_stripped: false` | `allow: false` (`403 Forbidden`) | `FORGED_HEADER_REJECTED` | Active bundle rev 2 retained |
| `revoked_session` | `tests/fixtures/policyhelix/C26/negative-revoked-session-denied.json` | Session ID present in durable `RevocationStore` | `allow: false` (`403 Forbidden`) | `REVOKED_SESSION_DENIED` | Active bundle rev 2 retained |
| `expired_bundle` | `tests/fixtures/policyhelix/C26/negative-expired-bundle-denied.json` | Candidate bundle `expires_at` is prior to evaluation time | `allow: false` (`403 Forbidden`) | `EXPIRED_POLICY_BUNDLE` | No untrusted/expired authority active |
| `policy_outage_private` | `tests/fixtures/policyhelix/C26/negative-policy-outage-private-deny.json` | `decision_loss: true` / `decision_engine_state: "outage"` on private route | `allow: false` (`503 Service Unavailable`) | `DECISION_LOSS_SENSITIVE_DENY` | Active bundle rev 2 retained |
| `tampered_byte` | `tests/fixtures/policyhelix/C26/negative-tampered-byte-rejected.json` | 1 modified byte in candidate bundle Rego module (rev 3) | Candidate `rejected`; valid authority retained | `TAMPERED_BUNDLE_DIGEST` | Last valid bundle rev 2 retained |
| `untrusted_signer` | `tests/fixtures/policyhelix/C26/negative-untrusted-signer-rejected.json` | Candidate bundle signed by untrusted key (rev 3) | Candidate `rejected`; valid authority retained | `UNTRUSTED_OR_MISSING_SIGNER` | Last valid bundle rev 2 retained |
| `stale_replayed_revision` | `tests/fixtures/policyhelix/C26/negative-stale-replayed-revision-retained.json` | Candidate bundle with stale revision 2 submitted when rev 3 is active | Candidate `rejected`; valid authority retained | `STALE_OR_REPLAYED_REVISION` | Last valid bundle rev 3 retained |
| `private_fail_closed` | `tests/fixtures/policyhelix/C26/negative-private-resource-fail-closed.json` | Unauthenticated request to private route `/api/v1/analytics/reports` | `allow: false` (`403 Forbidden`) | `PRIVATE_RESOURCE_FAIL_CLOSED` | Active bundle rev 2 retained |

---

## 3. Reproducible Verification Commands

```sh
# 1. Validate roadmap and evidence contract metadata
npm run validate:plan

# 2. Execute the C26 enforcement matrix test suite
go test -v -run TestC26 ./tests

# 3. Execute a single enforcement fixture via the Go engine CLI
go run ./cmd/policyhelix -verify-enforcement tests/fixtures/policyhelix/C26/positive-authenticated-gateway-enforcement.json

# 4. Run full repository test suite
go test -count=1 ./...
npm test
```
