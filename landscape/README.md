# Cartography Landscape

Cartography Landscape is a local-only, editable AWS architecture view on top of
Cartography's Neo4j graph. It borrows the architecture-diagram approach from
AWS Workload Discovery on AWS—Cytoscape compound nodes, fCoSE/Cola layouts,
AWS resource icons, and draw.io export—without deploying the Workload
Discovery backend.

## Safety model

- AWS collection runs with `CARTOGRAPHY_AWS_READ_ONLY=true`. A botocore
  `before-call` handler blocks operations that are not read verbs before a
  request is sent.
- The provided sync enables every AWS collector in this Cartography version
  except the two payload-bearing streams: SSM parameter values and CloudTrail
  management-event payloads. Secrets Manager is inventory-only: it lists
  secret/version metadata and never calls `GetSecretValue`.
- Neo4j and the web UI bind only to `127.0.0.1`.
- Neo4j is unauthenticated only inside that loopback-only boundary.
- The UI API runs read-only Cypher and exposes a small property allowlist.
- draw.io and PNG files are generated and downloaded locally.

The guard is a hard safety net, not a substitute for an AWS IAM policy. A
dedicated principal with AWS managed `ReadOnlyAccess` (or a tighter equivalent)
is still the recommended credential boundary.

## Install

Requirements: Docker Desktop, Node.js 20+, npm, and `uv`.

```bash
cd cartography
./landscape/local.sh install
./landscape/local.sh start
```

The Docker Compose file stores Neo4j data in the local
`cartography-landscape-data` volume. It does not create any AWS resource.

## Collect AWS architecture data

Use the AWS profile already selected by your shell:

```bash
AWS_PROFILE=default \
  CARTOGRAPHY_AWS_REGIONS=eu-central-1 \
  ./landscape/local.sh sync
```

`CARTOGRAPHY_AWS_REGIONS` is optional. Omitting it lets Cartography inspect all
enabled regions. By default, the command discovers the current Cartography AWS
collector registry and runs every non-payload collector, so safe new collectors
do not require an account-specific list. To override that metadata module set:

```bash
CARTOGRAPHY_AWS_REQUESTED_SYNCS="ec2:vpc,ec2:subnet,ec2:instance" \
  ./landscape/local.sh sync
```

## Open the local diagram

```bash
./landscape/local.sh serve
```

Then visit <http://127.0.0.1:8765>.

The UI supports:

- Account, service, and resource filtering
- A Workload Discovery-style white architecture canvas with official AWS
  service icons, named functional components, directional orthogonal
  connectors, VPC boundaries, and subnet fills
- Every AWS node type modeled by this Cartography version is assigned to an
  intentional AWS service family. CI scans the AWS model catalog and fails if
  an upstream resource type would silently fall back.
- The complete official Q2 2026 AWS Architecture Service Icon package is
  bundled: 305 saturated 64px service tiles, pinned by source URL and archive
  SHA-256 in `web/public/icons/aws/manifest.json`.
- Multi-subnet resources such as ALBs and NLBs are placed at VPC level with
  explicit dashed subnet-membership connectors rather than being incorrectly
  nested in one arbitrary subnet.
- A presentation-focused architecture view that omits low-level operational
  objects such as security groups, route tables, network ACLs, network
  interfaces, and key pairs
- An opt-in full relationship graph that retains those operational objects
- fCoSE architecture layout (the Workload Discovery default)
- Cola relationship layout and grid inventory layout
- Compound AWS Cloud → Region → VPC → Availability Zone → Subnet → functional
  component groups
- Expand/collapse, inspect, fit, search, and re-layout controls
- Local PNG export
- Editable `.drawio` export using draw.io's built-in AWS4 shapes

## Stop

```bash
./landscape/local.sh stop
```

This stops the local Neo4j container but preserves the local graph volume. To
remove that volume later, explicitly run:

```bash
docker volume rm cartography-landscape-data
```

## Open-source attribution

- Cartography is Apache-2.0 licensed.
- AWS Workload Discovery on AWS is Apache-2.0 licensed. Its diagram interaction
  and legacy service-icon variants informed this local view.
- Cytoscape.js, cytoscape-fcose, cytoscape-cola,
  cytoscape-expand-collapse, and FileSaver.js are MIT licensed.
- AWS service tiles come from the official AWS Architecture Icons package. The
  diagram uses the saturated 64px service-tile generation for every modeled
  resource family, including an AWS Resource Explorer fallback reserved for
  genuinely unknown future labels. Legacy transparent glyphs and mixed icon
  canvases are not used. These assets remain subject to the AWS Architecture
  Icons terms.

## Completeness boundary

“Complete” means every AWS resource and relationship that this Cartography
version can collect with the enabled read-only metadata collectors. AWS
services that Cartography does not model cannot be inferred from Resource
Explorer alone, and missing IAM permissions can still prevent a collector from
seeing a resource. The full relationship graph preserves all collected
resource-to-resource edges; the architecture view intentionally hides selected
low-level IAM and network-control objects while retaining their inventory in
the full view.
