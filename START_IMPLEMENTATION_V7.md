# PolicyHelix — Start Implementation v7.0

**Decision:** GO for source implementation after repository owner tokens and GitHub settings are finalized.

**Current maturity:** architecture frozen enough for Sprint Zero; contracts are machine-readable; repository controls are present; application source is intentionally not represented as completed.

## First vertical slice
OIDC login → compile/sign OPA bundle → Envoy ext_authz → strip spoofable identity headers → stale bundle rejected → decision service loss fails closed.

## Required order
1. Read `FINAL_ENGINE_DECISIONS_V7.md`, ADRs, `spec/01..18`, and contracts.
2. Verify the prefilled GitHub namespace in CODEOWNERS/module paths.
3. Run `make validate`.
4. Run `make bootstrap`; review generated source and lockfiles.
5. Implement the first vertical slice before broad UI or secondary features.
6. Add executable tests, telemetry assertions and a failure/recovery proof before claiming S-tier readiness.
