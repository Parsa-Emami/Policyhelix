# PolicyHelix: Network Architecture, Local Launch & Private Hosting

Requirement: N32 | Commit: C32

This document defines PolicyHelix's local-first network architecture, loopback isolation, boundary controls, and deployment patterns for optional private ingress.

---

## 1. Local-First Zero Public Domain Guarantee

PolicyHelix operates **100% locally on loopback interfaces (`127.0.0.1`, `[::1]`, `localhost`)**. 

- **No Public Domain Required:** Operating the complete application (web UI, policy engine, supervisor, durable storage, audit logging) requires no registered domain name, public DNS record, or external network reachability.
- **No Paid or Cloud Accounts:** The core features require no third-party cloud tenant, SaaS token, or compulsory telemetry services.
- **Loopback Binding by Default:** All daemon processes (the Node.js web shell on port `4173` or `4309`, and the Go engine on port `4174` or `4310`) strictly bind to loopback addresses (`127.0.0.1` and `::1`).

---

## 2. Network Boundary Controls

### 2.1 Host Header Validation & DNS-Rebinding Defense
To protect operators from DNS-rebinding and unauthorized network routing, `scripts/serve-web.mjs` validates every request's `Host` header against trusted loopback authorities:
- Valid loopback hosts: `localhost`, `127.0.0.1`, `[::1]` (with valid port numbers `1–65535`).
- Rejection behavior: Any external or untrusted host (such as `attacker.invalid`, `192.168.1.100`, or `127.0.0.1.attacker.com`) is immediately rejected with `403 {"error":"invalid_host"}`.

### 2.2 Cross-Origin & Origin Header Protection
When an incoming HTTP request contains an `Origin` header (such as from browser `fetch` or cross-origin form submissions):
- The server checks whether the origin's host matches a trusted loopback authority or configured allowed host.
- Untrusted cross-origin requests targeting `/api/*` or dynamic endpoints fail closed with `403 {"error":"invalid_origin"}`.
- Content Security Policy (CSP) headers strictly enforce `default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'`.

### 2.3 Strict Cache Boundaries
- **Dynamic & Sensitive Routes:** All runtime routes (`/`, `/api/*`, `/healthz`, `/readyz`, `/runtime-config.json`) strictly emit `Cache-Control: no-store` and `Pragma: no-cache`. This ensures tokens, session states, decision outputs, and health status are never stored in intermediary or browser disk caches.
- **Static Assets:** Only fingerprinted immutable JavaScript and CSS files in `/assets/*` receive `Cache-Control: public, max-age=31536000, immutable`.

### 2.4 Loopback Engine Isolation
- The loopback Go engine daemon (`policyhelix`) listens strictly on `127.0.0.1` or `::1`.
- Raw engine ports (`4174`, `4310`) must never be exposed or forwarded to external or non-loopback network interfaces.
- The web shell proxies only supported domain API endpoints (`/api/v1/runtime/*`, `/api/v1/reference/*`) with timeout bounds (5–10s) and fails closed with `503 {"error":"engine_unavailable"}` if the engine is unreachable.
- Unmapped routes return `503 {"error":"engine_not_integrated"}` or `404 {"error":"not_found"}`.

---

## 3. Optional Private Hosting & Ingress Patterns

For organizations deploying PolicyHelix in an enterprise intranet, private VPC subnet, or VPN (e.g., Wireguard, Tailscale), traffic should ingress through a hardened reverse proxy with TLS termination.

### 3.1 Nginx Ingress Architecture

```text
Operator Browser
       │ (HTTPS on port 443 with Client TLS)
       ▼
┌────────────────────────────────────────────────────────┐
│  Nginx Reverse Proxy Ingress (Private Host)            │
│  - TLS Termination (TLSv1.2 / TLSv1.3 only)            │
│  - CIDR Whitelist (allow 10.0.0.0/8, deny all)         │
│  - Strip Untrusted Identity Headers                    │
│  - Proxy Pass to http://127.0.0.1:4309                 │
└────────────────────────────────────────────────────────┘
       │ (HTTP Loopback)
       ▼
┌────────────────────────────────────────────────────────┐
│  PolicyHelix Web Shell & Unified Supervisor (Node.js)  │
│  - Host: policyhelix.internal (configured allowed host)│
│  - Origin verification & Cache-Control: no-store       │
└────────────────────────────────────────────────────────┘
       │ (HTTP Loopback)
       ▼
┌────────────────────────────────────────────────────────┐
│  PolicyHelix Go Engine Gateway (Port 4310)             │
│  - Evaluates Ed25519-signed policy bundles             │
│  - Authenticated OIDC token validation                 │
│  - Durable SQLite session & revocation store           │
└────────────────────────────────────────────────────────┘
```

### 3.2 Ingress Configuration Template (`ops/web/nginx.conf.template`)

The template located at `ops/web/nginx.conf.template` provides production-ready private ingress:

```nginx
server {
    listen 443 ssl;
    server_name __OWNED_DOMAIN__; # e.g. policyhelix.internal
    ssl_certificate __TLS_CERTIFICATE_PATH__;
    ssl_certificate_key __TLS_PRIVATE_KEY_PATH__;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;

    allow 127.0.0.1;
    allow ::1;
    # allow __TRUSTED_OPERATOR_CIDR__; # e.g. 10.0.0.0/16
    deny all;
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:4309;
        proxy_set_header Host $proxy_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;

        # Strip unauthenticated/untrusted identity headers to enforce normalized subject context
        proxy_set_header X-Remote-User "";
        proxy_set_header X-Forwarded-User "";
        proxy_set_header X-Forwarded-Email "";
        proxy_set_header X-Authenticated-Subject "";

        proxy_read_timeout 20s;
    }
}
```

### 3.3 Allowing Custom Private Hosts
When hosting behind a private intranet domain, specify the allowed host via:
1. Configuration in `ops/web/runtime-config.json`:
   ```json
   {
     "allowedHosts": ["policyhelix.internal"]
   }
   ```
2. Or CLI parameter:
   ```bash
   node scripts/serve-web.mjs --port 4309 --allowed-hosts policyhelix.internal
   ```

---

## 4. Verification & Testing

The network posture is continuously verified by automated regression test suites:
- `tests/web/network-boundaries.test.mjs`: Tests loopback authority, external Host rejection, cross-origin blocking, and cache header isolation.
- `tests/web/foundation.test.mjs`: Tests path traversal rejection, symlink containment, and static asset immutable caching.
- `tests/gateway_ui_test.go` and `tests/header_test.go`: Verify client identity header stripping and normalized subject context enforcement.
