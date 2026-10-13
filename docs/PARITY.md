# AWS capability parity audit

**Full parity is not achieved.** The initial Tencent implementation reproduced the main diagram UI and a useful subset of collection. It did not replace the complete AWS backend capability set. Passing its initial tests did not establish that broader requirement.

The authoritative comparison is the AWS checkout's collector registry, model/analysis code and Landscape implementation, including its current Resource Explorer changes. The original checkout is read-only throughout this work. [The audit](aws-parity-audit.json) records all 67 source collector slots, 66 enabled by its Landscape script, the source revision/file hash, current counterpart, and remaining work. Product counterparts labeled pending require further API research; they are not claims of equivalent behavior.

## Required work beyond listing resources

| Requirement | Current evidence | Remaining work |
|---|---|---|
| Preserve source history and publish Tencent repository | Original revision is an ancestor; `origin/main` published | Retain provenance as features are added |
| All official product assets | 896 SVGs, manifest hashes, gallery and native-service mappings tested | Keep mappings complete for added resource types |
| Broad mandatory inventory and native reconciliation | CloudRC baseline exists, per-scope errors retained | Canonical type aliases, baseline failure semantics and reconciliation audit |
| All 66 enabled collector capabilities | Per-collector audit linked above | Complete equivalent configuration/relationships; justify provider differences with evidence |
| Account/region/VPC/AZ/subnet hierarchy | Existing diagram and containment tests | Common VPC inference from unanimous subnet memberships added; broader graph cycles/scope audit remains |
| Full relationship graph | Collected edges preserved by current tests | Restore missing relationship collection and applicable analyses |
| Unresolved-inventory toggle | Toggle, count and inspector explanation implemented; browser validated | Keep native references visible and validate large inventories |
| Search, filters, selection, layout, collapse | Initial UI and browser smoke tests | Add regressions as graph semantics expand |
| Service component grouping | Per-location service components implemented and browser validated | Further large-graph/export validation |
| Direct Neo4j-backed viewer | Direct reads, complete metadata, auth/database options and refresh implemented; 5 real Neo4j integration tests passed in CI | Large-inventory performance validation remains; runtime results recorded in VALIDATION.md |
| PNG / editable draw.io | Initial browser downloads verified | Preserve grouping and assets across new graph types |
| Multi-account discovery and federation | Explicit TCCLI profiles supported | Compare organization hierarchy and assume-role/federation workflows |
| Metadata safeguards | Exact action allowlist and property filtering tested | Audit new APIs, preserve exclusions and avoid fetching object/secret values |
| Live validation | No authenticated default profile in prior check | Authenticate with a suitable read-only profile and reconcile results to native API evidence |

## Network and compute extension

Added native inventory for CVM images/key pairs/launch templates and versions, CBS snapshots, Auto Scaling groups/configurations/members, network ACLs, CCN/attachments, Private Link endpoints/services, and VPC peering. Typed relationships preserve ACL rule order, route destinations and next hops, cross-account UIN/region, and scaling/image/snapshot associations.

Route configuration is not a reachability finding. For `NORMAL_CVM` next hops, Tencent returns an IP rather than a CVM ID; `EIP` may return `0`. These remain route properties until they can be resolved with evidence. Missing remote UINs are not replaced with AppIds or the collecting account. Shared Private Link endpoints still need reconciliation against separately collected service identities.

Sources: [AS API catalog](https://cloud.tencent.com/document/api/377/20423), [image ownership filter](https://cloud.tencent.com/document/api/213/15715), [CCN attachments](https://cloud.tencent.com/document/api/215/19202), and the pinned-version models in TCCLI's Tencent SDK. Offline contract fixtures validate implementation semantics; live coverage remains unverified.

## Identity and encryption configuration

KMS now queries both `ListKeys` creator categories and describes each key. Aliases, origin, lifecycle and rotation metadata are retained, together with explicit CBS/Secrets Manager key configuration and exact CAM key-resource references. The Tencent API catalog exposes CAM-based authorization rather than the source's AWS `GetKeyPolicy`/`ListGrants` workflow. Configuration edges are not a replacement for that authorization analysis. Dedicated HSM discovery, additional encryption consumers and live verification remain gaps.

CAM now collects group membership, user/role/group attachments, local policies and attached preset policies, with parsed policy and role trust statements. Conditions, deny effects and exact principal expressions remain visible. Numeric UIN identities are resolved only when their owning UIN is explicit; AppIds and wildcards are not guessed. These configuration relationships do not establish effective permissions. Permission boundaries, federation inventory, credential metadata and applicable permission analyses remain gaps.

## DNS configuration

Owned DNSPod domains and Private DNS zones now include paginated records, assigned nameservers, configured subzones and explicit VPC bindings. Record types, values, TTL, weight, routing line and enabled state remain visible. Public names and each private zone view have separate identities. Private IP relationships require a matching VPC binding with an explicit region and owner; a shared address alone does not join unrelated networks.

DNSPod collection uses `Type=MINE` and its filtered `DomainTotal` count. Shared public-domain ownership is not inferred from the collecting account. Private zone ownership must match the profile owner. Nameserver/subzone and address links describe collected configuration, not effective DNS answers or reachability. Cross-zone private resolver precedence, additional managed-service endpoint aliases, shared public domains and authenticated runtime validation remain gaps.

## Container registry configuration

TCR Enterprise now collects namespaces, repositories, tag references and image digest metadata. Repositories use registry-scoped names; tags refer to separate content nodes. Digest equality is shared only within an account and region. Public/anonymous configuration is retained without inferring pull permission. Denied namespace metadata does not prevent repository discovery.

Image and repository pagination uses `Offset` as a one-based page number. Namespace collection requests `All=true` and checks the returned total; a truncated response remains explicitly incomplete. The source ECR collector also models multi-platform manifest members, architecture and attestations. These capabilities, image-layer analysis, Personal Edition, workload links, registry policy analysis, proxy/cache rules and authenticated runtime validation remain gaps.

## Serverless configuration

SCF now adds function versions, aliases, weighted and rule-based version routing, triggers and layer version inventory. Qualifiers distinguish versions and aliases, including unresolved references when a detail API is denied. Triggers retain selected configuration and enabled state. COS bucket hostnames, CKafka instance/topic names and explicit API Gateway service IDs link only to matching collected resources in the same account and region.

`GetFunction` remains excluded under the repository metadata policy: its response includes environment values and can include function source. Consequently execution-role, VPC, image and function-layer configuration still need an approved metadata collection design. Listing layers does not establish that a function uses them. Full event integration coverage, permissions/public invocation analysis and live runtime validation also remain incomplete. Trigger snapshots omit custom event arguments, CKafka credential fields and URL query/fragment values.

## API Gateway configuration

Classic API Gateway now includes service detail, APIs/method paths, selected backend configuration, environments, release versions and custom domains/certificate references. SCF, WebSocket role functions and COS backends link only to matching collected account/region identities. SCF namespaces must be explicit and unique. Backend VPC links are separate from service placement. API authentication type and authorizer references describe configuration, not effective access.

Published environment status controls release edges; API `Environments` is retained separately. Conflicting API/environment publication metadata is flagged. Current API detail does not establish the contents of an older deployed release. Upstream/TSF details, custom domain path mappings, certificate inventory, historical deployment API contents, broader policies/permissions, Cloud Native API Gateway equivalence and live validation remain gaps.

## COS bucket configuration extension

COS adds ACL grant nodes, validated policy statements with conditions and explicit denies, default encryption settings/KMS key references, versioning and configured logging destinations. All five detail checks run independently, preserving denials and malformed responses as partial coverage. AppId in bucket names/ACL identities is never treated as a CAM account UIN. Opaque encryption key references remain properties; only a bare UUID creates a key reference in the bucket account/region.

The official COS SDK is used for XML configuration; TCCLI remains the bucket-listing and other-service transport. Static profile credentials or unmixed environment credentials are supported. Dynamic credential refresh, notification configuration, ownership/public-access-block equivalents, effective public access and live account validation remain incomplete. Unknown missing-configuration error codes remain errors rather than being interpreted as disabled settings.

## Certificate and compute-role extension

SSL DescribeCertificates adds global metadata and reconciles previously unresolved API Gateway and CLB certificate references. CLB DescribeListeners retains listener and rule configuration, separate server/client-CA certificate links and additional server certificates. Flat CLB inventory now models routing rules separately from listeners while preserving forwarding relationships. Certificate detail/download operations remain excluded because they can return private keys. Signature algorithm, full consumer discovery, classic CLB coverage, target-group/rewrite/health-check depth and live verification remain gaps.

CVM CamRoleName now resolves to unique, collected CAM RoleName within the same account; missing/ambiguous names remain references. Tencent directly attaches a role rather than using an AWS instance-profile resource. Template/scaling role bindings and effective permission analysis remain incomplete.

## Audit and logging extension

CloudAudit tracks and detail selectors now retain read/write/resource/event filters, status and the organization-delivery flag. COS storage names omit AppId; destination links require matching collected owner, region and optional AppId suffix. Explicit CLS destinations retain account/region references even when destination inventory is denied. Neither the organization flag nor a delivery configuration proves successful event collection or delivery.

CLS adds log sets, separate log/metric topic inventory, retention/index/web-tracking metadata, custom KMS references and COS shippers. Shipper bucket names resolve to the unique collected bucket's actual account/region. Ambiguous or missing destinations remain visibly unresolved. AWS metric filters/alarms, legacy CloudAudit API equivalence, CKafka destination topic inventory, delivery-role/filter depth and live validation remain incomplete.

## Completion rule

A registered action, mapping row, green unit test, or icon does not on its own establish parity. Each audit item must have corresponding native collection, model/relationship behavior, tests for failure and negative controls, and runtime evidence appropriate to that capability. Keep this audit incomplete until those checks hold for the original scope.
