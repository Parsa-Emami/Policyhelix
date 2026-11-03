# PolicyHelix: reference workflow

Status: planned domain acceptance; the current JSON structure preview does not implement this workflow.

Simulator fixture -> sign/verify bundle -> protect owned upstream -> test spoofed header/direct origin -> revoke -> simulate decision/IdP outage and expired policy.

## Required Invariants

1. **Private resources fail closed**:
   - Any failure in policy lookup, signature check, IdP reachability, or evaluation runtime results in immediate access denial (`allow: false`).
   - Default deny is enforced across proxy ingress and simulator evaluation.
2. **Only authenticated normalized identity enters policy**:
   - User identity must be authenticated via validated OIDC tokens issued by the configured identity provider.
   - Raw untrusted client headers (such as `X-Remote-User` or `X-Forwarded-User`) are stripped at the gateway boundary and rejected if unauthenticated.
3. **Bundle signature plus freshness and monotonic revision**:
   - Policy bundles are signed cryptographically (Ed25519) and verified prior to ingestion.
   - Bundles carry monotonic revision counters and timestamped freshness windows; stale or downgraded bundles are rejected.

## Required UAT (Acceptance Scenarios)

1. **Simulator fixture with expected outcome and explicit deny reason**:
   - Evaluating policy fixtures produces unambiguous decisions matching the domain schema (`subject`, `resource`, `action`, `policy_digest`, `allow`, `reasons`, `obligations`).
2. **Direct origin and spoofed header rejection**:
   - Requests attempting to bypass the gateway or supply forged identity headers must fail closed without reaching the upstream application.
3. **Outage and revocation fail-closed enforcement**:
   - Simulated IdP outage, decision engine outage, expired policy bundle, or revoked session epoch must enforce documented fail-closed behavior within defined latency and time bounds (decision deadline <= 200ms; revocation bound <= 30s).

## Reference Architecture & Components

- **Synthetic Demo Upstream**: Single owned private service (`service:analytics`) requiring authenticated role-based access.
- **Local Engine (OPA & Go Gateway)**: Policy evaluation engine evaluating signed bundles and producing explainable authorization decisions.
- **Identity Provider (OIDC)**: Self-hosted Keycloak or synthetic OIDC provider supplying standard ID/access tokens.
- **Session & Epoch Store (SQLite)**: Monotonic bundle revisions and session revocation epoch tracking.
- **PolicyHelix Browser Workspace**: Local web user interface for inspecting policy decisions, visualizing workflows, and reviewing rollout diffs.

## Bounded 6-Stage Reference Workflow

| Stage | Action | Inputs & Fixture | Expected State & Output | Invariants Verified |
|---|---|---|---|---|
| **1** | **Simulator Fixture** | `tests/fixtures/policyhelix/C01/positive-decision.json` | Explicit decision with `allow: true` and `reasons: ["policy_allow_role_operator"]` | Fail-closed default, Normalized identity |
| **2** | **Sign & Verify Bundle** | Policy source + Ed25519 keypair | Signed bundle digest verified; monotonic revision monotonically incremented | Bundle signature, Freshness, Monotonic revision |
| **3** | **Protect Owned Upstream** | Authenticated OIDC request via gateway | Reverse proxy forwards valid request to private upstream; response returned | Private resources fail closed, Normalized identity |
| **4** | **Spoofed Header / Direct Origin** | `tests/fixtures/policyhelix/C01/invalid-spoofed-header.json` | Gateway strips unauthenticated headers, rejects direct origin bypass; `allow: false` | Private resources fail closed, Normalized identity |
| **5** | **Session Revocation** | `tests/fixtures/policyhelix/C01/invalid-revoked-session.json` | Revocation epoch updated; subsequent requests fail closed within 30s bound | Private resources fail closed |
| **6** | **Outage & Expired Policy** | `tests/fixtures/policyhelix/C01/invalid-stale-bundle.json` | Engine outage / expired bundle triggers fallback fail-closed denial and audit telemetry | Private resources fail closed, Bundle freshness |

## Machine Contract & Verification

- Machine contract definition: [`tests/scenarios/clone-to-value.json`](file:///home/amirreza/Desktop/Projects/Policyhelix/tests/scenarios/clone-to-value.json).
- Synthetic test fixtures: [`tests/fixtures/policyhelix/C01/`](file:///home/amirreza/Desktop/Projects/Policyhelix/tests/fixtures/policyhelix/C01/).
- Self-contained contract validator: [`scripts/verify-reference.mjs`](file:///home/amirreza/Desktop/Projects/Policyhelix/scripts/verify-reference.mjs).

C01 and C04 freeze the synthetic positive and negative fixture formats. No real secrets, user source/traffic data, or unlicensed third-party corpuses are permitted.

A clean source clone must reproduce the entire workflow with restart and restore at C30:
```bash
git clone https://github.com/Parsa-Emami/Policyhelix.git
cd Policyhelix
npm run setup
npm start
```
