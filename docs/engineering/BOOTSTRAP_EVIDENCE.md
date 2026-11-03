# PolicyHelix Bootstrap Evidence

Verified for task C03: unified local engine setup and single-terminal process supervision.

## 1. Verified Toolchain Environment

- **Node.js**: `v24.19.0` (official LTS release)
- **npm**: `11.17.0` (lockfile version 3)
- **Go compiler**: `go version go1.23.6 linux/amd64`
- **Operating System**: Linux (amd64)

## 2. Setup Lifecycle (`npm run setup`)

Running `npm run setup` prepares both the web workspace assets and compiles the PolicyHelix Go engine binary in a single reproducible flow:

```sh
npm run setup
```

The setup script (`scripts/oss-bootstrap.mjs`):
1. Validates that the active Node.js version is supported (Node 24.19+).
2. Executes `npm ci --ignore-scripts --no-fund` against locked dependencies.
3. Builds web client assets (`dist/web/`).
4. Compiles the Go engine binary to `dist/engine/policyhelix` (`go build -o dist/engine/policyhelix ./cmd/policyhelix`).

Flags supported:
- `--check`: validates prerequisites and planned execution steps without mutating disk state.
- `--skip-install`: skips `npm ci` and proceeds directly to building web and engine targets.

Verification:
```sh
npm run doctor
```
Outputs JSON recording `nodeSupported: true`, `webAssetsBuilt: true`, `engineBinaryBuilt: true`, `engineReady: false`.

## 3. Single-Terminal Supervision (`npm start`)

`npm start` executes `scripts/start-local.mjs`:
- Spawns the loopback engine (`dist/engine/policyhelix --host 127.0.0.1 --port 4174`).
- Polls loopback engine `/healthz` until healthy (or fails within timeout).
- Mounts loopback web server on `127.0.0.1:4173`.
- Proxies `/api/v1/runtime/status` to the loopback engine.
- All other `/api/*` routes continue returning fail-closed `503 {"error":"engine_not_integrated"}`.
- Traps `SIGINT` and `SIGTERM` to gracefully stop the web server and send `SIGTERM` to the Go engine child process, ensuring no orphaned background processes remain.

## 4. Invariant Guarantees

1. **Private resources fail closed**:
   - Any unauthenticated request targeting private resources produces `allow: false` with reason `fail_closed_private_resource`.
2. **Missing/unavailable provider fails closed**:
   - Missing required provider (`local_opa`, `self_hosted_keycloak`) returns `allow: false` with error `provider_unavailable`.
3. **Loopback isolation**:
   - Both the web server and engine listener reject non-loopback bindings (`0.0.0.0` or external addresses).
4. **Minimal health boundary**:
   - Engine minimal health (`status: "ok"`) does not imply completed domain evaluation features (`core_ready: false`, `businessFeaturesCompleted: false`). Full domain acceptance is achieved across C04–C30.
