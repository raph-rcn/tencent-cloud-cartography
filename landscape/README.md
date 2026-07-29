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
- The provided sync excludes Secrets Manager, SSM parameters, and CloudTrail
  event payload collection.
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
enabled regions. To override the curated architecture module set:

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
  diagram uses one current saturated 80×80 service-tile generation for every
  resource, including its fallback icon. Legacy transparent glyphs and mixed
  icon canvases are not used. These assets remain subject to the AWS
  Architecture Icons terms.
