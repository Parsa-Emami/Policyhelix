# PolicyHelix — Configuration Reference v1

Canonical machine-readable source: `../contracts/config.schema.json`. Safe local template: `../.env.example`.

| Variable | Requirement | Rule |
|---|---|---|
| `APP_ENV` | required | Non-secret runtime setting; see schema for constraints. |
| `SERVICE_NAME` | required | Non-secret runtime setting; see schema for constraints. |
| `DATABASE_DSN_REF` | required | Secret/reference URI; never embed production credentials in config. |
| `VALKEY_DSN_REF` | required | Secret/reference URI; never embed production credentials in config. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | required | Non-secret runtime setting; see schema for constraints. |
| `LOG_LEVEL` | optional | Non-secret runtime setting; see schema for constraints. |
| `OIDC_ISSUER` | optional | Non-secret runtime setting; see schema for constraints. |
| `OIDC_CLIENT_ID` | optional | Non-secret runtime setting; see schema for constraints. |
| `OIDC_CLIENT_SECRET_REF` | optional | Secret/reference URI. Do not commit secret material. |
| `OPA_BUNDLE_SIGNING_KEY_REF` | optional | Secret/reference URI. Do not commit secret material. |
| `ENVOY_EXT_AUTHZ_TIMEOUT_MS` | optional | Non-secret runtime setting; see schema for constraints. |
| `FAIL_CLOSED` | optional | Non-secret runtime setting; see schema for constraints. |

Production secrets must be indirect references or injected by the deployment secret store. `.env` is gitignored; `.env.example` contains no live credential. Unknown configuration keys are rejected by the JSON Schema.
