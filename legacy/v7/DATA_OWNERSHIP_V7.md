# PolicyHelix — Data Ownership v7

- **PostgreSQL:** apps/idps/policies/bundle metadata/audit
- **Data plane local:** signed bundle + bounded caches only
- **Valkey:** revocation/session coordination, not policy authority

## Universal rules
- cache is never authority
- derived projections have checkpoint + rebuild + staleness metric
- secrets/evidence follow project-specific retention and redaction
- deletion does not rewrite immutable audit/custody history
