# Validation — 2026-10-13

## Completed

- 36 Python tests: pagination and count controls, operation allowlist, CLI JSON/error handling, retries, COS parser, identity stability, account/region separation, baseline/native reconciliation, secret-field exclusion, full collection with synthetic API responses, graph containment, icon mapping, editable export geometry, private snapshot writes, and HTTP boundaries.
- 5 frontend tests: relationship highlighting, reset, endpoint filtering, empty-boundary filtering, and export hierarchy/icon retention.
- All **896 official SVGs** verified against the pinned archive hashes and XML checks. All registered native services resolve to bundled official assets.
- All 36 native/child collector request and response field layouts inspected against TCCLI 3.1.181.1's installed Tencent SDK, using pinned API versions. This verifies schema compatibility, not account permission or live behavior.
- Browser smoke check using the built UI and synthetic Frankfurt snapshot:
  - Architecture view renders official Tencent icons and VPC/AZ/subnet boundaries.
  - Full graph shows 13 resources and 13 relationships in the fixture.
  - Searching `ins-web` returns one resource.
  - Global-region filter returns one CAM role.
  - Collection coverage shows the deliberate denied Secrets Manager scope.
  - Collapse/expand and fit operate.
  - Full graph draw.io download parsed successfully: 18 editable nodes (including grouping containers), 13 edges, 10 embedded SVGs.
  - PNG download succeeded, 4096 × 2909 pixels in that layout.
  - Icon gallery lists 896 assets; CVM search displays the official product icon.
  - No browser console errors in the inspected run.
- Python lint/format and repository pre-commit checks pass.
- Clean `npm ci`, frontend tests, production build, and `npm audit --audit-level=high` pass. Audit reports zero vulnerabilities after updating the inherited Vitest and transitive packages.

## Remaining external checks

- **Live Tencent sync not run:** the default TCCLI credential was absent. Sign in and run `./landscape/local.sh sync --profile default --regions eu-frankfurt`. Inspect the coverage table for account-specific denials, availability and baseline-only products. Do not treat synthetic tests as a live account validation.
- **Neo4j integration not run:** neither the selected Colima daemon nor Docker Desktop daemon was available. JSON collection/viewer/export behavior was tested without Docker. The optional mirror should be integration-tested once Docker is running.

## Sources used for API behavior

- [Tencent Cloud Resource Center SearchResources](https://cloud.tencent.com/document/api/1791/136441)
- [Resource coverage and latency limits](https://cloud.tencent.com/document/product/1791/115771)
- [CLB DescribeLoadBalancersDetail](https://cloud.tencent.com/document/api/214/46916): relationship fields must be supplied explicitly in `Fields`.
- [Official icon download page](https://cloud.tencent.com/act/event/icons); exact archive and SHA-256 are recorded in the bundled manifest.

## Parity extension — 2026-10-13

- The source audit now enumerates all **66 enabled AWS collector slots**. Full parity is explicitly incomplete; see [PARITY.md](PARITY.md).
- Added 12 native inventory operations plus 2 child operations for compute/network depth. All **50 native/child request and response envelopes** now match the installed pinned-version Tencent SDK models.
- **48 backend tests + 5 frontend tests** pass. New negative controls cover cross-account UIN vs AppId, ambiguous subnet-to-VPC placement, IP/sentinel route next hops, IPv6 route IDs, key/payload omission, launch version identity, ACL direction/order and all new icon mappings.
- Browser validation: unresolved inventory is hidden initially (10 architecture resources), enabling it and full graph shows 13 resources and all 13 relationships. Service components render, and the grouped draw.io download parses with valid parent references and all 13 edges. No browser console errors observed.
- Official icon archive remains **896 verified assets**, with explicit mappings for CCN, Private Link, peering, Auto Scaling and ENIs.
- Previous live Tencent and Neo4j validation limitations remain. Contract checks and synthetic tests do not establish account-specific behavior or full AWS parity.
