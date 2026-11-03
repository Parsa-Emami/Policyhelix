# PolicyHelix Domain Contracts — v1

This directory defines the machine-enforced contracts for PolicyHelix authorization inputs and evaluation results.

## Schemas

- **`input.schema.json`**: Strict JSON Schema (draft 2020-12) for domain evaluation requests.
  - Requires `schema_version: "1"`, explicit typed subject (`id`, `issuer`, `roles`, `authenticated`, `session_epoch`), resource (`id`, `type`, `classification`), action, request context, cryptographic policy bundle reference, and bounded execution limits (`max_payload_bytes: 1..65536`, `deadline_ms: 1..200`).
  - Prohibits unknown fields (`additionalProperties: false`).
- **`result.schema.json`**: Strict JSON Schema (draft 2020-12) for evaluation outcomes.
  - Returns `schema_version: "1"`, `request_id`, status (`complete`, `failed`, `cancelled`), deterministic SHA-256 `input_digest`, `engine_version`, typed `decision` with explicit reasons and obligations, typed `error` taxonomy, and execution `metrics`.
  - Prohibits unknown fields (`additionalProperties: false`).

## Typed Error Codes

| Error Code | HTTP Status | Retryable | Description |
|---|---|---|---|
| `INVALID_JSON` | 400 | False | Payload is not valid JSON. |
| `PAYLOAD_TOO_LARGE` | 413 | False | Payload exceeds configured size limit (maximum 64 KiB). |
| `UNSUPPORTED_VERSION` | 400 | False | Payload `schema_version` is not `"1"`. |
| `SCHEMA_VALIDATION_FAILED` | 422 | False | Missing required fields or schema constraint violated. |
| `UNAUTHENTICATED_IDENTITY` | 200 | False | Subject is unauthenticated while accessing private/internal resource. |
| `PRIVATE_RESOURCE_FAIL_CLOSED` | 200 | False | Subject lacks authorization for private/restricted classification. |
| `STALE_OR_UNSIGNED_BUNDLE` | 200 | False | Policy bundle signature is invalid or bundle revision is stale. |
| `PROVIDER_UNAVAILABLE` | 200 | True | Required authorization provider (e.g., local OPA, Keycloak) is unreachable. |
| `DECISION_TIMEOUT` | 504 | True | Evaluation exceeded configured deadline (SLO bound: <= 200ms). |
| `REQUEST_CANCELLED` | 499 | True | Request context was cancelled before evaluation completed. |

## Invariants & Security Guarantees

1. **Private resources fail closed**: If identity verification fails, providers are unavailable, or bundle signature is invalid, `allow` is strictly `false`.
2. **Hyrum's Law Protection**: Exact schema validation at the engine boundary prevents consumers from depending on incidental implementation details.
3. **No database schema modifications**: These contracts govern in-memory evaluation and network interfaces without altering database tables or migrations.
