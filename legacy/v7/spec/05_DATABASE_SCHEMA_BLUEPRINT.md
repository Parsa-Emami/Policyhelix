# PolicyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Authoritative relational tables
- `applications`
- `protected_routes`
- `identity_providers`
- `sessions`
- `devices`
- `policies`
- `policy_revisions`
- `policy_bundles`
- `gateway_nodes`
- `revocations`
- `stepup_challenges`
- `audit_events`
- `outbox_messages`

## Universal columns
Where applicable: opaque primary ID, owning scope ID, aggregate/version number, created/updated instant, creator/updater actor where meaningful. Sensitive fields are explicit rather than hidden in generic JSON blobs. JSONB is reserved for versioned documents/extensible metadata with JSON Schema and migration plan.

## Constraints
Use database unique/foreign/check constraints for correctness that must survive concurrency. Soft deletion is not a substitute for retention/legal-hold semantics. Outbox rows are inserted in the same transaction as authoritative state changes.

## Index proof
Every nontrivial index is linked to a measured query plan/workload. CI integration tests use real PostgreSQL; production query regressions are captured with representative fixtures before v1.
