# PolicyHelix — Definitive Sequential Roadmap v7

**Portfolio order:** 6 / 10
**Complexity:** Very high
**Planning estimate:** 12–18 focused weeks (not a promise; recalibrate after Phase 1)

**Why this order:** Authorization infrastructure has severe failure consequences; worthwhile after simpler deterministic engines are already shipped.

## First executable proof
OIDC login → compile/sign OPA bundle → Envoy ext_authz → strip spoofable identity headers → stale bundle rejected → decision service loss fails closed.

## Rules for this repository
- One phase at a time; no implementation work for phase N+1 before phase N exit evidence is merged.
- Contract/schema changes precede dependent implementation.
- Every retryable operation is idempotent.
- Every derived store/projection has a rebuild path.
- Negative and failure tests are part of the feature, not post-release hardening.
- Status claims must be evidence-backed.

## Phase 0 — App/resource model

**Implementation deliverables**
- Define tenants/apps/resources/actions/subjects
- Canonical resource identifiers
- Deny-by-default semantics
- Policy version/revision model

**Required verification**
- model invariants
- cross-tenant tests
- canonical ID tests

**Definition of Done**
- No authorization decision is possible without explicit resource/action/subject context.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 1 — OIDC AuthN gateway

**Implementation deliverables**
- Go gateway OIDC code flow
- Issuer/audience/nonce/state/PKCE validation
- Session/cookie hardening
- Strip inbound spoofable identity headers

**Required verification**
- OIDC negative tests
- header spoof tests
- session security tests

**Definition of Done**
- Only validated identity context is forwarded and all client-supplied identity headers are removed.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 2 — Policy model/compiler

**Implementation deliverables**
- Versioned high-level policy model
- Compile to Rego/OPA input contract
- Static validation and unreachable/conflict diagnostics
- Deterministic bundle contents

**Required verification**
- compiler golden tests
- conflict fixtures
- deterministic bundle hash

**Definition of Done**
- Same policy revision compiles to identical normalized bundle contents and invalid policies cannot publish.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 3 — Signed OPA bundles

**Implementation deliverables**
- Bundle manifest/version/digest
- Signing and verification
- Monotonic activation rules
- Reject stale/expired/untrusted bundle

**Required verification**
- signature tests
- rollback/freeze tests

**Definition of Done**
- Decision tier will not load a bundle that is unsigned, expired, stale or for the wrong application.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 4 — Go decision service

**Implementation deliverables**
- Embed/host OPA evaluation
- Strict timeout and input limits
- Decision reason/audit metadata
- Fail closed on evaluator errors for protected paths

**Required verification**
- policy decision matrix
- timeout tests
- malformed input tests

**Definition of Done**
- Every decision is bounded, attributable to bundle digest, and evaluator failure follows explicit deny behavior.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 5 — Envoy ext_authz

**Implementation deliverables**
- Wire ext_authz
- Header allowlist/identity injection
- Route/action mapping
- Caching only where semantics prove safe

**Required verification**
- integration tests
- header smuggling/spoof tests
- cache invalidation tests

**Definition of Done**
- Protected upstream cannot be reached when ext_authz denies or the decision service is unavailable.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 6 — Session/revocation

**Implementation deliverables**
- Session index/revocation
- OIDC logout/back-channel where supported
- Policy-change effect policy
- Emergency subject/app disable

**Required verification**
- revocation propagation tests
- race tests

**Definition of Done**
- Revocation/disable reaches enforcement within documented maximum staleness.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 7 — Failure/degraded modes

**Implementation deliverables**
- Decision service outage
- DB/Valkey/control-plane outage behavior
- Last-known-good bundle policy
- Clock skew and signing key rotation

**Required verification**
- fault injection matrix
- key rotation tests

**Definition of Done**
- Each dependency failure has a documented safe state; protected traffic never silently flips to allow.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 8 — SPIFFE/load/public v1

**Implementation deliverables**
- Optional workload identity adapter
- Latency/throughput benchmark
- Threat model closure
- Signed release/SBOM

**Required verification**
- load tests
- clean deployment
- release verifier

**Definition of Done**
- Public v1 reports measured p50/p95/p99 decision latency and passes fail-closed and rollback-attack tests.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Public v1 invariant
The project is not called production-ready merely because all phases are coded. `PUBLIC-V1-GO` requires the repository release gate, clean-install proof, security/recovery evidence and signed/verifiable release artifacts.
