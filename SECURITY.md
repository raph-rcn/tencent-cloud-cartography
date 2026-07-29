# Security

AWS Cartography Landscape is intended to run locally with read-only AWS
credentials.

Security-sensitive invariants:

- No AWS create, update, delete, invoke, upload, or secret-value API call is
  permitted by the runtime botocore guard.
- SSM parameter values and CloudTrail management-event payloads are excluded
  from the default sync.
- Secrets Manager secret values are never retrieved.
- Neo4j and the landscape HTTP server bind to loopback by default.
- The browser-facing API may execute only its fixed read-only Cypher queries.
- Credentials and discovered secrets must never be committed.

When reporting a security issue, open a private GitHub security advisory on the
fork. Include the affected commit, reproduction steps, and whether the issue can
cause an AWS write, credential disclosure, or non-loopback exposure. Do not put
live AWS credentials or account data in the report.
