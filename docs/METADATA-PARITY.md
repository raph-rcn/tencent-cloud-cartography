# Metadata implementation and remaining AWS parity gaps

Updated 2026-10-14. The operator explicitly retained metadata-only collection.
The requested permission/exposure, container, CLB/database and service-family
implementation is delivered within that restriction. **Full AWS parity is not
established.** The table below records the actual implementation and the remaining
differences; offline tests do not establish API availability in a live account.

## Permission and exposure analysis

| Capability | Implemented | Remaining difference |
|---|---|---|
| CAM identity policies | Direct/group attachments; explicit denies; conservative wildcard scopes; conditional/unsupported expressions; evidence-linked decisions | Request conditions, resource policies, trust, session constraints and cross-account authorization do not form a complete effective-permission engine |
| Permission boundaries | User/role boundary configuration and statement evidence; intersection when collected | Null/denied boundary responses are unknown, not evidence of no boundary. Identity-only decisions explicitly retain their narrower evaluation scope |
| Credential/protection metadata | Access-key identifiers/status/dates and login/action protection flags | No secret keys, contact details, credential use or authentication probes |
| Database administration | Selected documented CAM actions for MySQL, PostgreSQL, SQL Server, MariaDB and CDWPG | These are control-plane matches, not SQL authentication or AWS IAM database-connect/Redshift credential equivalence |
| Managed sessions | TAT StartSession/RunCommand decisions require a collected online agent on the exact CVM | No command/session is invoked; other service, session and local agent constraints remain unevaluated |
| Stack execution | TIC ApplyStack identity-policy decisions with explicit global-wildcard scope | Narrow stack QCS expressions are not guessed; runtime TIC availability is unverified |
| COS public configuration | Anonymous bucket policy and ACL analysis, deny precedence, conditions, object-prefix scopes, incomplete inputs | Bucket READ ACL establishes listing configuration; object read remains conditional on object ACL inheritance. No objects or object ACLs are retrieved |
| COS account controls | Account summary of collected selected-region bucket controls with completeness flags | No audited S3-style account-wide public-access-block equivalent; no global protection boolean is invented |
| CLB exposure | Configured paths through listeners/rules/target groups/bindings to corroborated CVM/ENI targets | EXPOSE is a configuration edge. No public reachability, firewall passage, HTTP success or exploit is proved; cross-VPC and unsupported backend types remain unresolved |
| Container execution | Current Kubernetes context SelfSubjectAccessReview for each collected pod's pods/exec create action; matching SelfSubjectReview before/after | This reviews authorization only. No exec occurs; no CAM identity is guessed, and token/session equality is not established by username/UID/groups equality |

Analyses run after collection. `analyze --input ... --output ...` reruns the
identity-policy, COS and CLB analyses offline, replacing only their generated
results. Kubernetes reviews require the explicit live context described below.

References: [CAM evaluation](https://intl.cloud.tencent.com/zh/document/product/598/10605),
[boundaries](https://cloud.tencent.com/document/product/598/48770),
[boundary response](https://cloud.tencent.com/document/product/598/66680),
[TAT resources](https://intl.cloud.tencent.com/zh/document/product/598/57156),
[COS ACLs](https://cloud.tencent.com/document/product/436/30752),
[COS resource roots](https://intl.cloud.tencent.com/document/product/436/30580?lang=en),
[Kubernetes authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/),
[Kubernetes identity reviews](https://kubernetes.io/docs/reference/access-authn-authz/authentication/).

## Containers

TKE inventory retains cluster network, version, runtime, lifecycle and capacity
metadata; selected endpoints, endpoint ACL/security groups, public CA metadata,
OIDC/service-account authentication configuration, control-plane logging and
documented subaccount/common-name mappings. Private keys and PEM bodies are not
saved. The common-name API's subaccount schema is not interpreted as role mapping.

Kubernetes collection requires an already configured context for an exact
collected account/region/cluster. Its HTTPS endpoint must match collected TKE
endpoint metadata; TLS verification is mandatory. No context or kubeconfig is
downloaded, and context configuration is not persisted or switched.

```bash
./landscape/local.sh sync --profile default --regions eu-frankfurt \
  --services tke,cam,tcr \
  --kube-context ACCOUNT_UIN/eu-frankfurt/cls-CLUSTER_ID=EXISTING_CONTEXT
```

Repeat `--kube-context` for additional clusters. The collector makes fixed Table
requests with `includeObject=None` for namespaces, nodes, pods, services,
deployments, ReplicaSets, StatefulSets, DaemonSets, jobs and CronJobs. Selected
scalar summary columns are retained. Full-object JSON and embedded row objects
are rejected, with no fallback to workload definitions. Unsupported Table
responses and missing contexts remain visible in collection coverage.

Pod scheduling links require the exact collected node name within the same
cluster. Container names/images come from summary columns, with exact collected
Enterprise TCR host/repository/tag matches. Table rows do not provide reliable
UIDs, owner references, full container definitions, environment, volumes,
service-account bindings, execution roles or complete network settings. Those
relationships are not reconstructed from names. ECS task-definition
equivalence and Kubernetes RBAC inventory for all principals remain gaps.

The virtual authentication/authorization reviews use fixed POST requests; they
do not create workloads or execute a container command. The collector saves only
identity fields and authorization booleans, not review reason/extra fields.

Reference: [Kubernetes Table response contracts](https://kubernetes.io/docs/reference/using-api/api-concepts/).

## CLB and database depth

Modern CLB collects target groups, frontend associations, target bindings,
selected health-check settings, independently corroborated reported target
health and rewrite relationships. Traditional CLBs (`Forward=0`) use their
separate listener/target/health APIs. Health reports do not prove current
connectivity. Custom health-check payload bodies are omitted.

MySQL, PostgreSQL, Redis, MongoDB, SQL Server, MariaDB and CDWPG collect typed
lifecycle/version/capacity/encryption and explicit network metadata, with
separately identified public/private endpoints. Supported independent metadata
checks cover MySQL/PostgreSQL SSL/security groups, MySQL encryption key references
and Redis SSL, replica groups, nodes, shards and security groups. KMS links need
explicit returned key identity/region. MySQL master/DR and PostgreSQL parent
relationships require explicit compatible identifiers and scope.

CVM and CBS now retain additional capacity, network, lifecycle, billing,
protection, disk and encryption metadata. Current shared-disk attachment IDs are
links; last-attachment history is not treated as current attachment. ES clusters
retain typed capacity/version/lifecycle, node configuration, access flags, ACLs,
separate selected endpoints and explicit VPC/subnet/security groups. Free-form
ES/Kibana config is not saved; OPEN/ACL configuration is not anonymous query
authorization. Tencent public egress is represented by public-address/EIP/NAT/
route metadata, without inventing AWS internet-gateway resources.

Remaining provider differences include AWS database IAM query access, some
cluster/parameter/option/backup/proxy fields, unsupported CLB backend types and
cross-VPC target resolution. No SQL query, password read, certificate download,
network probe, reboot or mutation is performed.

References: [ES inventory](https://intl.cloud.tencent.com/zh/document/product/845/32214),
[MySQL authorization](https://cloud.tencent.com/document/product/598/69878),
[PostgreSQL authorization](https://intl.cloud.tencent.com/zh/document/product/598/57145),
[SQL Server authorization](https://cloud.tencent.com/document/product/598/70015),
[MariaDB authorization](https://cloud.tencent.com/document/product/598/67483).

## Additional service families

| Source capability | Tencent implementation | Exact gap |
|---|---|---|
| Reserved instances | CVM reservation metadata through the official international SDK and fixed international endpoint | Mainland TCCLI lacks this action; regional/account availability remains unverified |
| CloudFormation | Legacy TIC stack/version/event metadata with fixed read-only adapter; no source/state/variables | The audited old SDK contract is implemented; current service availability and full source equivalence are unverified |
| DynamoDB | TcaplusDB table-group metadata scoped to numeric cluster IDs already found by CloudRC | Native cluster discovery includes Password; table detail includes IDL file contents. Both excluded, so table schemas/indexes/ownership depth is unavailable |
| Cognito | CIAM user-store metadata and counts | Full application/client/domain/identity-provider semantics and Cognito equivalence are not established; no user records or client secrets are read |
| IAM Identity Center | CIC space, groups, safe group-member identities, permission configurations, system/custom policy attachments, account assignments and selected external-SAML metadata; organization units/members; CAM SAML/OIDC configuration | Full user APIs include Password, leaving ungrouped users unenumerated. Provisioning state, managed policy bodies and full federation semantics remain gaps; member accounts are not automatically scanned |
| Inspector | CWP machine/package/vendor vulnerability metadata and TCSS cluster/image/vendor vulnerability metadata | Vendor reports are not independently reproduced findings. TCSS container list includes command content and is excluded |
| GuardDuty / Security Hub | CSIP configuration-check rules, license/service state and aggregate pending-alert counts, plus CWP/TCSS reported security status | Alert-detail response contains leaked credentials/payloads and is excluded. No detector-equivalent feature set or finding body is fabricated |
| SageMaker | TI Platform billing resource groups, notebook summaries and explicit CFS/network/resource-group metadata | Training/service/model-version responses contain env values or image secrets; detail APIs excluded |
| Bedrock | LKE/Agent Development Platform application summaries, scoped model catalog/configuration views and shared knowledge metadata | No Hunyuan account asset census, invocation, prompts, documents, agents/tools or model entitlement equivalence. Agent detail contains instructions/tools/plugins and is excluded |
| Glue | WeData project/workflow/task summaries and DLC engines across documented generation/type/execution scopes; explicit project/workflow/network links | No scripts, SQL execution, credential-bearing connections or full data catalog/crawler/job-definition equivalence |
| CodeBuild | Explicit unsupported CODING CI coverage | Audited list and detail responses include pipeline content and environment values, with no verified metadata projection; neither is called |
| ECR | Enterprise TCR registries/namespaces/repos/tag refs/digests, replication policies and image-acceleration state; Personal Edition owned repositories/tag platform summaries | Manifests/config/layers/attestations excluded. Personal ImageId/TagId is not assumed to be a digest |
| ECR pull-through cache | TCR replication and image-acceleration configuration represented with native semantics | Replication and CFS-based acceleration do not establish upstream pull-through cache-rule equivalence; upstream credentials are never read |
| S3 account block | COS selected-region account summary and per-bucket public decisions | No S3-style global account block is claimed |

The 896 official Tencent SVG assets remain bundled and hash-checked. Every
registered kind has a mapping. CIC uses the official Cloud Identity Governance
asset. The pinned archive contains no LKE/ADP product logo: those nodes explicitly
use the official generic Application Programming Interface asset. A generic
asset is not claimed to be a product-specific logo.

References: [reserved capacity](https://intl.cloud.tencent.com/zh/document/product/213/68457),
[audited legacy TIC SDK](https://github.com/TencentCloud/tencentcloud-sdk-go/tree/a4f4482974da37ac175aad3595b8d20429ef95eb/tencentcloud/tic),
[Tcaplus schemas](https://cloud.tencent.com/document/api/596/39686),
[CIC APIs](https://cloud.tencent.com/document/product/850/109943),
[CIAM user stores](https://cloud.tencent.com/document/product/1441/94458),
[LKE APIs](https://cloud.tencent.com/document/product/1759/105114),
[TCR replication schemas](https://cloud.tencent.com/document/api/1141/41603),
[TCR acceleration](https://cloud.tencent.com/document/product/1141/79575),
[Personal Edition repositories](https://cloud.tencent.cn/document/product/1141/41583),
[CODING OpenAPI](https://coding.net/help/openapi).

## Enforced exclusions and verification boundary

[`exclusions.py`](../tencent_cloud_cartography/exclusions.py) records each audited
unsafe response field in unsupported coverage. Exact-action guards are enforced
in both the runner and transports. This includes TKE node bootstrap scripts,
SCF environment/source, TCR manifests, CVM launch-template versions, AS launch
configuration user data, TAT command content, sensitive TI/TCSS/CSIP/Tcaplus/CIC
and CODING responses, and credential-bearing CDN configuration. TLS private-key
and secret-value operations remain outside the allowlist too.

Unknown missing-configuration responses remain errors. A denied request is not
an empty configuration or evidence of safety. Independent scopes preserve other
successful metadata when one scope fails.

All current validation is offline fixtures, local UI/export behavior and CI
Neo4j integration. No Tencent account, Kubernetes context, SQL query, object
read, exec session or live Frankfurt collection was used for this release.
[`aws-parity-audit.json`](aws-parity-audit.json) retains all 67 source registry
slots, including the source-excluded SSM value collector, and records remaining
source-field/provider differences. There is no assertion that every enabled
AWS capability is equivalent.
