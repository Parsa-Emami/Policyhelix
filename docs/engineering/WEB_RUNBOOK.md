# PolicyHelix web runbook

## Local checkout

Use Node 24.19.0, npm 11.17.0, and Go 1.23+ from the tested toolchain. From the repository root:

```sh
npm run setup
npm run check
go test -v ./...
npx --no-install playwright install chromium
npm run test:browser
npm start
```

Browser checks may use an operator-provided Chromium executable through the `WEB_TEST_CHROMIUM` process variable. CI uses the Playwright-managed browser. This test override never changes application configuration.

Development URL: http://127.0.0.1:5173. The unified local supervisor (`npm start`) builds and launches both the web workspace (port 4173) and the loopback Go engine (port 4174) in a single terminal with coordinated graceful shutdown:

```sh
npm run setup
npm start
```

Custom port binding:
```sh
npm start -- --port 4309 --engine-port 4310
```

Built URL: http://127.0.0.1:4173 (or configured port). Browser routing uses hashes and hosting at the origin root. There is no subpath deployment in this release. Change the public nonsecret configuration in `ops/web/runtime-config.json`; `apps/web/public/runtime-config.json` must mirror it for static hosts/development. The Node server validates its config at startup and the browser validates its own project identity. Do not put credentials in either file.

## What is runnable

The responsive React workspace, forty-step product roadmap, local bounded JSON structure preview, loopback Go engine (`policyhelix-engine` v0.0.1), and unified process supervisor (`scripts/start-local.mjs`) are implemented. Preview uses tab memory, does not persist files and does not send them to the server. Reload clears the preview.

`GET /healthz` covers the web shell process; loopback engine health is monitored at `/healthz` on the engine port. `GET /readyz` covers web assets and valid startup configuration (`engineReady: false` minimal health boundary). `GET /api/v1/runtime/status` proxies to the loopback Go engine and displays supervised runtime status in the workspace. All other unintegrated domain `/api/*` routes return 503 fail-closed. No arbitrary upload endpoint or unauthenticated access is permitted. Private resources fail closed.

## Build an artifact

```sh
npm run package:web
cd dist/release
sha256sum -c SHA256SUMS.txt
node scripts/serve-web.mjs --root web --port 4309 --config ops/web/runtime-config.json
```

Package after build. `release.json` records the source commit and whether the working tree was dirty; build from a clean commit for a releasable provenance record. Node production serving needs no installed npm dependencies. CI uploads the web package; it does not publish a host or modify repository settings. Copy the complete `dist/release` tree to the chosen immutable release directory.

## Private Linux host

Prerequisites: operator-owned domain/DNS, valid TLS certificate/key, installed Node 24.19.0, Nginx, systemd, and an unprivileged `policyhelix-web` account. Reserve port 4309 for this project. Keep certificates outside the artifact and never commit a private key. Install releases under `/srv/policyhelix/releases/<source-commit>` and point `/srv/policyhelix/current` to the selected verified release. Ensure the service user has read/execute access to artifact directories. Match the actual Node binary path in the service file.

Use `ops/web/service.systemd` and render `ops/web/nginx.conf.template` with the real owned domain, TLS paths and reviewed operator network ranges. The proxy passes the trusted local upstream authority in the `Host` header (`$proxy_host`), not an arbitrary external authority. The Node server rejects untrusted `Host` values, including on health endpoints, to reduce DNS-rebinding exposure. Keep the upstream on loopback; do not replace this with `$host` or publish its port. The proxy initially denies external traffic. Keep the deny-all default until private admission is configured and tested; do not treat an IP range as per-user authentication. Runtime APIs remain blocked until W06/W07. Validate the rendered Nginx configuration with `nginx -t` before reload. Install the service under `/etc/systemd/system/policyhelix-web.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now policyhelix-web
curl --fail http://127.0.0.1:4309/healthz
curl --fail http://127.0.0.1:4309/readyz
sudo journalctl -u policyhelix-web --since '10 minutes ago'
```

Test HTTPS access from an allowed operator and rejection from a disallowed network. Test that `/api/v1/not-implemented` stays unavailable. No domain, certificate, host or credentials were provisioned by the source commit.

## Update and rollback

Build/test/package from a clean source commit; verify SHA256SUMS before switching the current symlink. Retain the previous artifact; switch the symlink and restart the service in a maintenance window. Check both web probes and browser navigation. If either fails, restore the previous symlink and restart. The shell has no durable user data, so it has no data restore operation. Once domain storage/providers are integrated, add backup/restore and schema-compatibility evidence before updates; a frontend rollback does not roll back engine data.

## Engine integration and operations still required

Profile: `private-web`. Retained engine choices: Go gateway and simulator, OPA evaluation, Existing OIDC IdP, SQLite sessions/audit, Reverse proxy TLS ingress. Implement the first vertical slice in IMPLEMENTATION_BLUEPRINT.md and W06, then authenticated negative tests in W07. Route only explicitly supported endpoints through a same-origin authenticated service. Keep secrets exclusively on the server/provider. Add real engine readiness, bounded jobs, cancellation, redacted audit, operational metrics, alerts and retention/restore proof alongside the domain implementation. Public marketing/static demonstrations must use synthetic data; they cannot admit arbitrary runtime work.

For KeyHelix, no plaintext secrets may enter browser file preview; import only synthetic nonsecret metadata. For RiftRange/MirageMesh, orchestration/sensors stay on isolated private hosts. Existing RiskWeft Laravel source is preserved and has not been connected to this shell or certified by web tests.

## Reproduce source evidence

Run `python3 scripts/source_identity.py --check` against the committed checkout. The digest covers tracked and deliverable untracked files, excluding only the self-referential evidence JSON and SHA256SUMS.txt. Build/test output directories are ignored. Verification evidence records web-only checks and the exact tested runtime; it does not certify the domain engine.
