# PolicyHelix Engine Launch & Supervision

Task C03 establishes the PolicyHelix Go runtime engine (`cmd/policyhelix`) and unified single-terminal supervision with the web workspace.

## Architecture Overview

```
                                  Single Terminal
                                     npm start
                                (scripts/start-local.mjs)
                                     /             \
                       (spawns & monitors)     (starts HTTP server)
                                   /                 \
                                  v                   v
              ┌───────────────────────────┐   ┌───────────────────────────┐
              │    Go Engine Runtime      │   │     Node Web Server       │
              │   dist/engine/policyhelix │   │     scripts/serve-web.mjs │
              │   127.0.0.1:4174 (loopback) │◄──┤     127.0.0.1:4173        │
              └─────────────┬─────────────┘   └─────────────┬─────────────┘
                            │                               │
                            │                               v
                            │                  React Workspace Browser
                            │                  (apps/web/src/main.tsx)
                            v
                   Domain Evaluation
                (Awaiting C04-C30 features)
```

## Go Engine Command-Line Interface (`cmd/policyhelix`)

```sh
go run ./cmd/policyhelix [flags]
```

Supported flags:
- `--host <ip>`: Bind host address. Strictly restricted to loopback (`127.0.0.1`, `::1`, `localhost`). External IP addresses fail closed immediately. Default: `127.0.0.1`.
- `--port <number>`: Loopback port to listen on. Fails if port is already bound. Default: `4174`.
- `--version`: Prints JSON metadata and exits:
  ```json
  {"project":"PolicyHelix","engine":"policyhelix-engine","version":"0.0.1","status":"ok","loopback":true,"coreReady":false,"businessFeaturesCompleted":false,"invariants":["..."]}
  ```
- `--smoke-test`: Executes self-contained loopback bind verification and outputs engine health status.
- `--fixture <path>`: Evaluates a synthetic authorization fixture directly and prints the decision JSON.

## Loopback HTTP Endpoints

| Method | Endpoint | Response / Purpose |
|---|---|---|
| `GET` | `/healthz` | Loopback engine health (`status: "ok"`, `engine: "policyhelix-engine"`, `version: "0.0.1"`). |
| `GET` | `/readyz` | Engine readiness contract (`engineReady: false` minimal health boundary). |
| `GET` | `/v1/runtime/status` | Comprehensive engine state, provider connection map, and invariant list. |
| `POST` | `/v1/runtime/evaluate-fixture` | Evaluates synthetic fixture requests. Unauthenticated requests targeting private resources fail closed (`allow: false`). Missing providers fail closed. |

## Supervisor Error & Signal Handling

1. **Port Collisions**:
   - The supervisor tests port availability for both the web server and Go engine before spawning. If either port is occupied, it aborts with an explicit error and exits with code 1.
2. **Child Process Failure**:
   - If the Go engine exits prematurely or crashes during startup, the supervisor kills any remaining listeners, reports the exit code/signal, and shuts down immediately.
3. **Graceful Coordinated Shutdown**:
   - Upon receiving `SIGINT` (Ctrl+C) or `SIGTERM`, the supervisor stops accepting web connections, closes active sockets, sends `SIGTERM` to the Go engine child process, and waits for its exit before exiting 0. If the engine does not terminate within 4 seconds, `SIGKILL` is sent as a safeguard.
4. **Repeat After Restart**:
   - Restarting the supervisor repeatedly maintains deterministic port bindings, zero leaked sockets, and identical fail-closed invariant enforcement.

## Automated Verification

- Engine unit and integration tests: `go test -v ./...`
- Web launch and supervisor regression tests: `node --test tests/web/local-launch.test.mjs`
- End-to-end browser verification via Playwright: `npm run test:browser`
