# AWS Cartography Landscape contributor guide

This fork is AWS-only. Do not add non-AWS providers, generic compliance
products, or integrations unrelated to AWS discovery and diagramming.

## Product invariants

- AWS access is metadata-only and read-only.
- Never add an AWS API call that retrieves a secret value or workload payload.
- Keep Neo4j and the HTTP server loopback-bound by default.
- Every AWS model label must resolve to an intentional service family and an
  existing official saturated icon.
- Architecture containment must be factual: account → region → VPC →
  availability zone → subnet.
- Preserve every collected edge in the full relationship graph even when the
  presentation-focused architecture view suppresses low-level detail.
- draw.io and PNG exports must remain local.

## Changes

- Use `uv` for Python dependencies and `npm ci` for the web application.
- Add Arrange/Act/Assert tests for behavior changes.
- Run `uv run pytest tests/unit`, `uv run pre-commit run --all-files`, frontend
  tests/build, and `npm audit --audit-level=high`.
- Sign commits with `git commit -s`.
- Retain Apache-2.0 attribution to upstream Cartography.
