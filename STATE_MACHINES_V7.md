# PolicyHelix — State Machines v7

- **Bundle:** `DRAFT -> SIGNED -> ACTIVE -> SUPERSEDED | REVOKED`
- **Session:** `CREATED -> ACTIVE -> EXPIRED | REVOKED`
- **GatewayNode:** `BOOTSTRAPPING -> READY -> DEGRADED -> DRAINING -> OFFLINE`

Transitions are domain commands with authorization, optimistic version check where applicable, audit event and invariant tests. Illegal transitions fail closed and are observable.
