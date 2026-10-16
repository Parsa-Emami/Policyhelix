# PolicyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Domain objects
- `Application`
- `ProtectedRoute`
- `IdentityProvider`
- `Session`
- `DeviceContext`
- `Policy`
- `PolicyBundle`
- `BundleRevision`
- `Decision`
- `GatewayNode`
- `Revocation`
- `StepUpChallenge`

## Aggregate rules
- Aggregate mutations occur through application commands, never controller/model convenience writes.
- Aggregate version is checked on conflicting writes.
- Invariants are tested with illegal-transition/negative cases.
- Domain objects do not import Laravel/Eloquent/vendor SDKs.

## Frozen v1 invariants
1. Only signed monotonic policy bundles become active.
2. Authorization decision includes subject/resource/action/policy revision/reasons and expiry.
3. Client-controlled identity headers never pass through untrusted.
4. Route fail behavior is explicit by resource class; protected defaults fail closed.
5. Revoked server-side session cannot be reauthorized solely from stale browser state.
