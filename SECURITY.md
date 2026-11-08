# Security Policy

PolicyHelix takes the security of our local-first authorization engine and browser workspace seriously. We appreciate the responsible disclosure of security issues by researchers and contributors.

---

## 1. Confirmed Vulnerability Reporting Route

Please **do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

To report a vulnerability privately, use one of the following confirmed routes:

1. **GitHub Private Vulnerability Reporting (Recommended):**
   - Go to the repository's [Security Advisories](https://github.com/Parsa-Emami/Policyhelix/security/advisories) tab.
   - Click **Report a vulnerability** to submit advisory details privately to the maintainers.
2. **Dedicated Security Contact Email:**
   - Email: **`security@policyhelix.org`**
   - Include a detailed description of the vulnerability, reproduction steps, proof of concept, and impacted components.
   - If desired, encrypt sensitive data using the maintainer's public PGP key.

---

## 2. Response Commitments & SLAs

- **Initial Acknowledgment:** Within **48 hours** of receiving your report.
- **Triage & Assessment:** Within **5 business days**, detailing validity, severity, and intended remediation timeline.
- **Coordinated Disclosure:** We adhere to responsible coordinated disclosure. Public advisories and CVE requests (if applicable) are published only after a fix has been verified and released.

---

## 3. Supported Versions

Security updates and patches are provided for the following versions:

| Version | Supported | Notes |
|---|---|---|
| `main` / `v0.0.1` | Yes | Current active development branch & local release |
| `< 0.0.1` | No | Historical planning baselines |

---

## 4. Security Architecture & Threat Boundaries

PolicyHelix is engineered around strict fail-closed, local-first boundaries:

- **Loopback Isolation:** The web server and Go engine bind exclusively to loopback addresses (`127.0.0.1` and `[::1]`). No public port is opened by default.
- **Host Header Validation:** Ingress requests must match loopback authority. External or unrecognized host headers are rejected with `403 {"error":"invalid_host"}` to mitigate DNS-rebinding attacks.
- **Cross-Origin Protection:** Cross-origin API calls from untrusted web origins are rejected with `403 {"error":"invalid_origin"}`.
- **Ingress Header Sanitization:** Untrusted upstream headers such as `X-Remote-User` and `X-Forwarded-User` are stripped at the gateway proxy boundary to prevent forged identity injection.
- **Cryptographic Bundle Signatures:** Policy bundles require valid Ed25519 digital signatures, monotonic revision counters, and active freshness windows. Tampered or expired bundles are rejected.
- **Fail-Closed Default:** If the policy evaluator, identity provider, or session store encounters an outage or unexpected error, access is unconditionally denied (`allow: false`).
- **Audit Masking:** Audit logs write redacted operational events to `.local-data/audit.log`, ensuring credentials, tokens, and private keys are never leaked to logs.

---

## 5. Out of Scope

The following items are outside the threat model of PolicyHelix and should not be submitted as security vulnerabilities:

- Compromise of the local operating system or root privileges on the user's host machine.
- Direct physical or filesystem manipulation of files located within `.local-data/` by an authorized local user.
- Denial of Service caused by exhausting local machine memory or disk when intentionally configured with excessive workloads.
- The `local-demo` synthetic identity provider issuing test tokens (as documented, this is a local development simulation and not an enterprise IdP).
