# PolicyHelix — Final Engine Decisions v7

These are accepted v1 decisions, not open blockers. Alternatives require a future ADR and must preserve public/domain contracts.

1. Architecture has four explicit boundaries: Laravel Control Plane, Go Authentication Gateway, Go/OPA Decision Plane, Envoy Enforcement Plane.
2. Management PostgreSQL is never on the hot authorization request path. Data-plane nodes consume versioned signed bundles and last-known-good state.
3. Envoy ext_authz contract strips all user-controlled trusted identity headers before injecting verified identity/decision headers.
4. OPA bundle signature verification is mandatory in production. Bundle revision is monotonic; stale/rollback bundles are rejected according to freshness policy.
5. Failure mode is resource-class based: sensitive/admin/default private routes fail closed; explicitly public routes bypass auth by configuration rather than fail-open accident.
6. OIDC authentication issues short-lived server-side/revocable sessions. Revocation feed + TTL bounds maximum stale authorization window.
7. SPIFFE/SPIRE is the production workload-identity adapter for high-assurance distributed deployment; local development uses ephemeral local service certificates.
8. AuthorizationDecision v1 includes subject/resource/action/context, policy revision, result, reasons, obligations and decision timestamp; decisions are auditable without storing tokens.
