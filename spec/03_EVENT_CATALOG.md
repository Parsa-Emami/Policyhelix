# PolicyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Versioned domain/integration events
- `policy.revision_created.v1`
- `bundle.published.v1`
- `gateway.bundle_applied.v1`
- `authorization.decision.v1`
- `session.revoked.v1`
- `stepup.required.v1`
- `bundle.rollback_rejected.v1`

## Envelope
Every message carries `specversion`, `id`, `source`, `type`, `subject`, `time`, `datacontenttype`, `correlation_id`, `causation_id`, `tenant/workspace scope`, aggregate ID/version and payload schema version.

## Delivery semantics
At-least-once delivery is assumed. Consumers deduplicate by event/command identity and verify aggregate/projection checkpoint. Ordering is guaranteed only within an explicitly versioned stream. Consumers tolerate duplicates and documented reordering; correctness never assumes exactly-once transport.
