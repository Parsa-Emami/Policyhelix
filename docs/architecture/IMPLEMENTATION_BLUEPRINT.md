> Current OSS delivery/resources/storage/release policy is ADR-0003-open-source-local-first.md and DEFINITION_OF_DONE.md. The older planning context below is superseded where it conflicts; business invariants remain applicable.

# Current web entry point

The browser shell is implemented at apps/web/src/main.tsx, with root package.json/package-lock.json and apps/web/vite.config.ts. Read ADR-0002-web-application.md and WEB_RUNBOOK.md for runnable web commands. The domain blueprint below describes remaining engine work, not completed web status.

# PolicyHelix implementation blueprint v0

Planning detail; the file paths, commands and endpoints below are future targets, not installed capabilities.

## Executable proof and concrete layout

Entry point: `cmd/policyhelix/main.go`.

Module map: `internal/{policy,bundles,auth,gateway,audit,rollout}; apps/web/src/pages`.

First vertical slice: Simulator fixture -> sign/verify bundle -> protect owned upstream -> test spoofed header/direct origin -> revoke -> simulate decision/IdP outage and expired policy.

For Go repositories use a single root module; add cmd/agent, cmd/sensor or cmd/verify only where selected. For web assets add separate apps/web package.json/package-lock.json at C03; domain engine remains outside page components. Rust workspace and Python package names follow the paths in the commit plan. Versions must be verified/pinned at C02. No inferred 'latest' install command in documentation constitutes a lockfile.

## Persistence model

SQLite: sessions(fingerprint,subject_ref,expiry,revocation_epoch), active_bundle(digest,highest_accepted_revision), trust_keys metadata, decision_audit metadata. Confidential session credentials if stored are encrypted at rest with separately injected key; tokens never logged. Bundles are immutable files; CAS activation and DB high-watermark reconcile.

Plan constraints with actual types at C05: opaque ID, owner/scope where relevant, schema version, optimistic entity version, UTC creation/update times. Use unique indexes for idempotency and stable identity, foreign/check constraints where supported. Add indexes only for measured UI/engine queries. Where no DB is selected, explicitly test portable file integrity and failed write/import behavior instead of adding migrations.

## State and transport

DRAFT -> VALIDATED -> SIGNED -> VERIFIED -> ACTIVE -> SUPERSEDED|REVOKED; ACTIVE session -> EXPIRED|REVOKED.

CLI offline simulator first; one private gateway upstream. API for operator bundle preview/publish/session revoke. IdP remains upstream system. Planned request/decision schema must bind method/resource/context/policy version.

Status queries are authoritative on actual operation state. Async 202 means accepted durable operation with status reference, not completed success. Errors distinguish validation, authorization, stale write, quota, cancellation, unavailable dependency and corrupted data. C04 replaces v0 generic nested schemas with typed domain shapes and bounded fixtures before first public format.

## Authentication and authorization

OIDC issuer/audience/state/nonce/PKCE validation, server session, CSRF for operator mutations, anti-spoof normalized identity headers. Upstream origin must not bypass gateway. App still performs resource-level authorization.

If an embedded API is enabled, identity must be established before commands and resource scope checked in the application layer; put foundational identity adapter/permission tests in C03/C06 and complete object-level negative cases alongside each API feature. Don't postpone all auth to C27. Cookie-auth mutations require CSRF; non-browser agent paths have a distinct authenticated channel. Static viewers do not need a user account just to read a local report.

## Configuration without env edits

Read a validated runtime JSON/config path plus platform-injected secret references. Precedence: explicitly passed config -> documented project config -> safe development defaults. Production rejects missing required trust/auth/durable path values. Do not silently invent production secrets. Common typed settings: mode, listen address, input limits, data directory (where needed), task deadline, retention, public-demo switch, log level. Existing input env examples remain archival.

Secrets: secret reference identifies independently injected credential/key; never real value in JSON. Demo uses synthetic fixtures and has dangerous write/runtime admission disabled. Target quotas in product/project.json must be validated; negative/zero TTL and unlimited quotas are rejected where safety-sensitive.

## Development verification workflow

At C03 add real developer commands for build/dev and tests for this toolchain. At C06 run them in clean CI. Go: go test ./... and go vet ./...; Rust: cargo test --workspace and cargo clippy --workspace; Python: actual pytest suite plus declared formatter/type checks; TS: typecheck/build and domain/UI tests with chosen test dependencies pinned. These are planned commands until code/manifests exist. Do not report them as executed in v0.

For each feature run its named target test plus relevant existing regression suite. Use real selected storage/provider in integration tests; no mock-only evidence for durability, authorization, cryptography or isolation. Fuzz hostile parser inputs, inject interrupt/failure and measure overload at release gates. Example fixture data must be synthetic or explicitly authorized.

## Clean install and recovery

Deliver single versioned CLI/static/container artifact appropriate to selected mode. Stateful profile mounts local persistent disk and runs one controlled owner. Fresh install proves first slice, failure behavior and export/recovery; update fixtures prove previous exported schema can be read or migrated without silent loss. Maintenance window is acceptable for personal single-host mode. Restore and forward repair are documented with real measured evidence before sensitive use.

Full release policy and hardware targets are in sibling docs. Native mobile-store packaging and shared multi-user cloud hosting are not implicitly part of this blueprint.
