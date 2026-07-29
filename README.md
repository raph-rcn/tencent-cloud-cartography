# AWS Cartography Landscape

An AWS-only, local-first fork of
[Cartography](https://github.com/cartography-cncf/cartography) that discovers
AWS resources and relationships and turns them into editable architecture
diagrams.

This repository is intentionally not the general-purpose upstream Cartography
project. Non-AWS collectors, models, rules, documentation, dependencies, and
tests have been removed. The remaining codebase has one job:

> Read AWS metadata, build a local relationship graph, and render a useful
> Workload Discovery-style AWS architecture landscape.

## What it provides

- Local AWS inventory and relationship collection backed by Neo4j
- Architecture and full-relationship views
- AWS Cloud → Region → VPC → Availability Zone → Subnet containment
- Correct VPC-level placement for resources spanning multiple subnets
- Click-to-highlight resource relationships
- Search, filtering, fit, layout, and expand/collapse controls
- Local PNG download
- Editable draw.io export
- 305 official saturated AWS Architecture service icons
- Automatic coverage checks for every AWS node type modeled by this fork

Examples include EC2, EBS, VPCs, subnets, internet and NAT gateways, ELB/ALB/NLB,
API Gateway, Lambda, ECS, EKS, ECR, S3, DynamoDB, RDS, EFS, ElastiCache,
OpenSearch, Redshift, SQS, SNS, EventBridge, CloudFront, IAM, KMS, Secrets
Manager, Route 53, and the other AWS collectors inherited from Cartography.

## Safety model

This fork is designed for metadata-only operation:

- The CLI always enables `CARTOGRAPHY_AWS_READ_ONLY=true`.
- A botocore `before-call` guard blocks non-read AWS API operations before they
  are sent.
- The default landscape sync enables 65 AWS metadata collectors.
- SSM parameter-value collection is excluded.
- Secrets Manager collection lists metadata and versions; it never retrieves a
  secret value.
- Neo4j and the web application bind to `127.0.0.1`.
- The web API executes read-only Cypher and exposes only allowlisted properties.
- PNG and draw.io files are generated locally.

Use an AWS principal with `ReadOnlyAccess`, `SecurityAudit`, or a tighter custom
policy. The application guard is defense in depth, not a replacement for IAM.

## Quick start

Requirements:

- macOS or Linux
- Docker
- Node.js 20+
- npm
- [uv](https://docs.astral.sh/uv/)
- working read-only AWS credentials or profile

```bash
git clone https://github.com/raph-rcn/aws-cartography.git
cd aws-cartography
git switch agent/local-aws-landscape

./landscape/local.sh install
./landscape/local.sh start
AWS_PROFILE=default ./landscape/local.sh sync
./landscape/local.sh serve
```

Open <http://127.0.0.1:8765>.

Limit collection to particular regions when needed:

```bash
AWS_PROFILE=default \
  CARTOGRAPHY_AWS_REGIONS=eu-central-1,eu-west-1 \
  ./landscape/local.sh sync
```

Stop Neo4j without deleting the graph:

```bash
./landscape/local.sh stop
```

The complete command reference, architecture behavior, icon update procedure,
and safety details are in [landscape/README.md](landscape/README.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `cartography/intel/aws/` | AWS API collection and graph loading |
| `cartography/models/aws/` | AWS graph schemas and relationships |
| `cartography/analysis/aws/` | AWS-specific relationship and exposure analysis |
| `cartography/landscape/` | Read-only topology API and exporters |
| `landscape/web/` | Local Cytoscape architecture interface |
| `landscape/compose.yaml` | Loopback-only Neo4j service |
| `tests/unit/cartography/intel/aws/` | AWS collector tests |
| `tests/integration/cartography/intel/aws/` | AWS/Neo4j integration tests |

The shared `client`, `graph`, `data`, and ontology-label code is retained only
because the AWS ingestion pipeline depends on it.

## What “complete” means

The landscape includes every resource and relationship that the AWS collectors
in this fork can retrieve with the supplied credentials. It is not an
account-specific allowlist: the service registry and tests scan the entire AWS
model catalog, and unfamiliar future labels receive a deliberate AWS Resource
Explorer fallback icon.

There is still an honest technical boundary: an AWS service with no Cartography
collector cannot acquire configuration or relationships merely from Resource
Explorer. Missing IAM permissions can also produce an incomplete account view.

## Development

```bash
uv sync
uv run pytest tests/unit
uv run pre-commit run --all-files

cd landscape/web
npm ci
npm test -- --run
npm run build
npm audit --audit-level=high
```

Update the pinned official AWS icon package with:

```bash
uv run python scripts/update_aws_architecture_icons.py
```

The script verifies the downloaded archive checksum and regenerates the icon
manifest.

## Origin and license

This is an opinionated fork, not an official Cartography CNCF release.
Cartography remains available at
[cartography-cncf/cartography](https://github.com/cartography-cncf/cartography).
The architecture interaction was influenced by
[Workload Discovery on AWS](https://github.com/aws-solutions/workload-discovery-on-aws).

Code remains licensed under Apache-2.0; see [LICENSE](LICENSE). AWS Architecture
Icons remain subject to the AWS Architecture Icons terms.
