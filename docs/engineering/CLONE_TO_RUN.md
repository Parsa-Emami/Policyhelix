# PolicyHelix: clone to run

## Runnable today

Install Git, Node 24.19+ within Node 24 (npm bundled) and Go 1.26+, then:

```sh
git clone https://github.com/Parsa-Emami/Policyhelix.git
cd Policyhelix
npm run setup
npm start
```

Open http://127.0.0.1:4173 and select **Reference Workflow**. Setup installs the committed web lockfile with lifecycle scripts disabled, stops on errors, builds the web workspace and compiles `dist/engine/policyhelix`. `npm start` supervises the loopback Go engine, durable local storage under `.local-data` and an owned synthetic upstream; no second terminal, database server, cloud account or public domain is needed. The browser runs the six-stage reference workflow: simulator fixture, signed bundle activation, protected upstream, spoofed-header/direct-origin rejection, revocation, and outage/expired-policy fail-closed behavior.

`npm run setup -- --check` shows preparation without changes. `--skip-install` builds using already installed dependencies. `npm run doctor` reports actual web/core state. `npm run release:check` deliberately exits 2 until full evidence is ready. Ctrl+C stops the current web process. Ports can be selected with `npm start -- --port 4301` when running multiple projects.

## Verified local-demo scope

The same clone/setup/start sequence prepares and supervises the Go engine and its local resources, as verified by `npm run test:clone` and `docs/evidence/C30.json`. No second undocumented terminal, paid account, sibling clone or owned public domain is used. C31 supplies convenience artifacts plus a documented source-build alternative; downloads may be needed to prepare resources, and user payloads are not sent to a compulsory proprietary service. No global runtime install, system trust change or user data deletion occurs implicitly.

Local resources: embedded signed-bundle policy evaluator, a store-round-trip identity/session provider and the owned synthetic demo upstream. Hardware target: 2 vCPU / 4096 MiB RAM / 10240 MiB free disk plus real dataset/provider/backup space. The C30 verification host exceeded that target; C28 measured the bounded workload separately. Full engine support initially targets Linux x86_64; other hosts require their own actual C30/C33 evidence. Rootless workloads need Linux or a tested Linux/WSL2 host.

`local-demo` uses synthetic fixtures and isolated development providers; the identity provider issues engine-local, fingerprint-bound, revocable sessions instead of running Keycloak. `local-private` requires real identity/permission, provider durability, revocation and restore evidence before sensitive use. A development provider mode never becomes a production vault/gateway by relabeling it.

## Checks

```sh
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run test:clone
npm run doctor
```

`npm run test:clone` performs a real local Git transport clone of the staged/committed source, runs `npm run setup`, starts the supervised engine, verifies real storage/provider readiness, executes every step of `tests/scenarios/clone-to-value.json` (six workflow stages plus seven negative fixtures), restarts the supervisor against the same durable storage and proves the revoked session stays denied while a valid session still reaches the upstream. `tests/browser/clone-to-value.spec.ts` runs the same six stages through the browser workspace. C30 evidence is recorded in `docs/evidence/C30.json`; C40 still requires authorized published-source and installed full-workflow proof.

## Network boundaries & private hosting

Per Task C32 (Requirement N32), local operation has **zero public domain or public DNS requirements**. The web workspace and loopback Go engine bind strictly to `127.0.0.1` and `::1`.

- **Host validation:** Rejects external or untrusted `Host` headers (`403 {"error":"invalid_host"}`) to defend against DNS-rebinding.
- **Cross-origin defense:** Cross-origin API requests from untrusted origins are rejected with `403 {"error":"invalid_origin"}`.
- **Cache boundaries:** All dynamic and API responses strictly return `Cache-Control: no-store`; only fingerprinted static assets in `/assets/` are cached immutably.
- **Optional private hosting:** For intranet, VPN, or private subnet deployments behind an Nginx TLS reverse proxy, consult [infra/deployment.md](../../infra/deployment.md) and [WEB_RUNBOOK.md](WEB_RUNBOOK.md). Stripped ingress headers (`X-Remote-User`, `X-Forwarded-User`) ensure untrusted identities cannot be injected.
