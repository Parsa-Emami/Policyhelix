# PolicyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## HTTP conventions
- Prefix `/api/v1`; JSON UTF-8; explicit content type.
- Resource IDs are opaque UUID/ULID-style identifiers and authorization is re-evaluated after lookup.
- Cursor pagination for unbounded collections.
- Mutation request/response schemas are versioned in OpenAPI; unknown security-sensitive fields are rejected where ambiguity is dangerous.
- Stable error codes follow the common error standard.

| Method | Route | Purpose | Gate |
|---|---|---|---|
| `POST` | `/applications` | Register protected application | auth + validation + idempotency where side-effecting |
| `POST` | `/policies` | Create policy revision | auth + validation + idempotency where side-effecting |
| `POST` | `/bundles/publish` | Compile/sign monotonic bundle | auth + validation + idempotency where side-effecting |
| `POST` | `/simulator/decide` | Explain policy decision without enforcement side effect | auth + validation + idempotency where side-effecting |
| `POST` | `/sessions/{id}/revoke` | Revoke server-side session | auth + validation + idempotency where side-effecting |
| `GET` | `/gateways` | Gateway health/bundle revision | auth + validation + idempotency where side-effecting |

## Compatibility
Additive compatible changes may ship in v1. Removing/renaming/changing semantics requires deprecation + migration and normally a new API major. Golden request/response fixtures run in CI.
