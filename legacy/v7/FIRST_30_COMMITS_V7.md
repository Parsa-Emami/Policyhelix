# PolicyHelix — First 30 Commit Plan v7

These are atomic intent boundaries, not mandatory commit-message text. Do not combine unrelated items merely to hit a number.

1. chore: initialize toolchain manifests and lockfiles
2. ci: make repository validation executable
3. chore: add local development environment/health checks
4. test: add clean-bootstrap smoke test
5. docs: freeze Phase 0 invariants and ADR index
6. phase0: define tenants/apps/resources/actions/subjects
7. phase0: canonical resource identifiers
8. phase0: deny-by-default semantics
9. phase0: policy version/revision model
10. test(phase0): add model invariants
11. docs(phase0): record exit evidence and ADR updates
12. phase1: go gateway OIDC code flow
13. phase1: issuer/audience/nonce/state/PKCE validation
14. phase1: session/cookie hardening
15. phase1: strip inbound spoofable identity headers
16. test(phase1): add OIDC negative tests
17. docs(phase1): record exit evidence and ADR updates
18. phase2: versioned high-level policy model
19. phase2: compile to Rego/OPA input contract
20. phase2: static validation and unreachable/conflict diagnostics
21. phase2: deterministic bundle contents
22. test(phase2): add compiler golden tests
23. docs(phase2): record exit evidence and ADR updates
24. phase3: bundle manifest/version/digest
25. phase3: signing and verification
26. phase3: monotonic activation rules
27. phase3: reject stale/expired/untrusted bundle
28. test(phase3): add signature tests
29. docs(phase3): record exit evidence and ADR updates
30. test: close Phase 0/1 regression or failure-proof gap before scope expansion
