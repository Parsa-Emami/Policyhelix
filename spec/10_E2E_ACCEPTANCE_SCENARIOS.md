# PolicyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Golden E2E scenarios
1. OIDC session -> protected request -> ext_authz allow
2. Spoof identity header stripped
3. Signed bundle publish/apply
4. Stale/invalid bundle rejected
5. Decision plane outage fails closed protected route
6. Session revoke propagates and blocks

For every golden scenario record expected authoritative state, emitted event IDs/types, audit action, projection state, critical metrics and cleanup state. Run from a clean environment with deterministic synthetic fixtures. At least one scenario must fail mid-flight and then converge after restart/retry/reconciliation.
