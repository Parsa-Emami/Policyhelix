# ADR 0001 — PolicyHelix reference decision

**Status:** Accepted for v1

## Decision
Architecture has four explicit boundaries: Laravel Control Plane, Go Authentication Gateway, Go/OPA Decision Plane, Envoy Enforcement Plane.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
