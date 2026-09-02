# PolicyHelix — Failure & Recovery Proof v7

## Mandatory injected failures
- IdP outage
- bad/stale bundle
- rollback attempt
- decision service outage
- header spoof
- revocation race
- clock skew
- cache poisoning
- control plane offline

## Pass criteria
For every failure: no invariant violation; no unauthorized bypass; no unbounded retry storm; orphan resources are reconciled; user-visible state becomes correct; telemetry identifies cause; retry/cancel/manual recovery is documented; recovery test is automated where feasible.
