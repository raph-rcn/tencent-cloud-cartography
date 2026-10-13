# Tencent Cloud Cartography contributor guide

This derivative implements Tencent Cloud inventory and local architecture diagrams.
The user explicitly requested adapting the AWS-only source into this separate project.

- Cloud collection is metadata-only. Allowlist exact API operations; never retrieve
  object bodies, function source, secret values, passwords, or workload payloads.
- Keep the UI and Neo4j bound to loopback. Preserve all collected relationships in
  the full graph and make partial coverage visible.
- Account, region, VPC, zone, and subnet placement must follow collected resource IDs.
- Every registered resource type must map to an existing Tencent icon. Bundle the
  full official icon archive, with source URL, checksums, and attribution.
- Retain Apache-2.0 attribution to Cartography and the AWS Landscape fork.
- Use uv and npm ci. Run pytest, pre-commit, frontend tests/build, npm audit, and
  a browser smoke test for behavior changes. Sign commits with git commit -s.
