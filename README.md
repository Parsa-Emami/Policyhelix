# PolicyHelix

> v7.0 status: **ARCHITECTURE-GO / BOOTSTRAP-GO / SOURCE-NOT-IMPLEMENTED**

This directory is a standalone GitHub repository starting point for PolicyHelix. It contains the frozen architecture/specification, valid HTTP/event/configuration contracts, GitHub governance/security controls, and project-specific source bootstrap commands.

## Runtime boundary
- Laravel 13 policy/control plane
- Go 1.27 AuthN gateway
- Go 1.27 decision service embedding OPA
- Envoy enforcement proxy
- PostgreSQL 18.6
- Valkey
- OIDC
- OpenTelemetry

## First executable proof
OIDC login → compile/sign OPA bundle → Envoy ext_authz → strip spoofable identity headers → stale bundle rejected → decision service loss fails closed.

## Start
```bash
make validate
# verify the GitHub owner/module namespace first
make bootstrap
```

Read `ROADMAP_V7.md`, `PROJECT_START_CHECKLIST_V7.md`, `ACCEPTANCE_GATES_V7.md`, and `GITHUB_REPOSITORY_SETUP_V7.md` before the first code commit.

## Evidence rule
Architecture readiness is not production readiness. “S-tier”, “secure”, “resilient”, or performance claims require executable test/observability/failure/recovery/benchmark/release evidence.

## v7 portfolio position
Recommended implementation order: **6 / 10**. Authorization infrastructure has severe failure consequences; worthwhile after simpler deterministic engines are already shipped.
