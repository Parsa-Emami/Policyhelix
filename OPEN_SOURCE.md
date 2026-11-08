# PolicyHelix: Open-Source Contract

PolicyHelix is committed to delivering a fully autonomous, local-first policy engine and authorization workflow workspace that is completely open source under the **[Apache-2.0](LICENSE)** license.

---

## 1. Core Open-Source Commitments

- **No Compulsory Cloud or Paid Accounts:** The entire local core—including the policy evaluation engine, web user interface, cryptographic bundle signing, session revocation store, synthetic upstream services, and test suites—operates 100% locally on standard hardware without requiring any commercial account, cloud subscription, or paid entitlement.
- **Zero Sibling Repositories or Proprietary Modules:** Everything needed to build, run, test, package, and verify PolicyHelix is self-contained within this public repository. No external private libraries or sibling repositories are required.
- **`private: true` in `package.json`:** The `private: true` flag in `package.json` exists solely to prevent accidental publishing to public npm registries. The repository itself and all its source files are completely open and distributable under Apache-2.0.

---

## 2. Upstream Dependencies & License Inventory

PolicyHelix respects and strictly adheres to upstream open-source licenses:
- All upstream libraries, Go packages, and npm dependencies are pinned with explicit version locks (`go.mod`, `go.sum`, `package-lock.json`).
- Shipped dependencies utilize compatible, permissive open-source licenses (Apache-2.0, MIT, BSD-3-Clause).
- Complete license texts, copyright notices, and third-party attributions are maintained in **[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)** and included in release distribution packages (`dist/release/THIRD_PARTY_NOTICES.md`).
- No restricted, non-commercial, copyleft-incompatible, or proprietary licenses are permitted in the core product.

---

## 3. Independent Source Builds

Open source requires that users can build the software independently from source:
- **Engine Binary:** Can be compiled directly with `go build -o dist/engine/policyhelix ./cmd/policyhelix` or `npm run build:engine`.
- **Web Workspace:** Can be compiled with `npm run build` using standard Vite and TypeScript compilers.
- **Source Distributions:** Standalone source archives are generated via `npm run package:source`.
- **Reproducibility:** Once dependencies are cached, source builds run entirely offline without network access.

---

## 4. Current Status & Verification Gates

- **Local Core Usability:** The complete local reference workflow, process supervisor, and restart/restore capabilities were verified from a real clean clone at **[C30](plans/commits/C30.md)** (`docs/evidence/C30.json`).
- **Complete OSS v1 Release:** Full release publication, independent package distribution, and final artifact verification remain the milestone gate at **[C40](plans/commits/C40.md)**.
- **Documentation & User Guides:** See **[User Guide](docs/release/USER_GUIDE.md)** and **[Clone Guide](docs/engineering/CLONE_TO_RUN.md)**.
- **Vulnerability Reporting:** See **[SECURITY.md](SECURITY.md)** for confidential security reporting instructions.
- **Contributing:** See **[CONTRIBUTING.md](CONTRIBUTING.md)** for contributor guidelines.
