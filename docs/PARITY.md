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

### Cloud Monitor alarm configuration

Cloud Monitor now queries `DescribeAlarmPolicies` once per account using the
required `Module=monitor` and one-based page numbers. Policies remain at global
scope because their configured regions can span locations. Metric/event rules
retain thresholds, comparison operators, periods, repeat frequency, compound
condition expressions, rule filters and hierarchical threshold metadata. Enabled
and disabled policies are both collected. Notification IDs become graph nodes;
embedded templates retain selected identity/channel metadata and callback counts,
without callback URLs, validation codes, contact details or opaque task payloads.

`DescribeBindingPolicyObjectList` is paginated separately per policy, with explicit
zero `GroupId` and the actual `PolicyId`. The graph retains shielded objects and
instance-group configuration. CVM links require the documented `MT_QCE` /
`cvm_device` / `unInstanceId` tuple, an explicit recognized region, and an enriched
CVM in the same account and region. Known dimension-region aliases include
`de` → `eu-frankfurt`; unsupported aliases and namespaces remain unresolved.
No region is inferred from a policy's region list. Changed groups, duplicate
bindings, missing totals and truncated pages produce partial coverage.

These edges describe configured alarm objects, including disabled/shielded
configurations. They do not prove metric ingestion, active evaluation or successful
notification. Other namespaces, bind-all/tag expansion, legacy/template rules,
standalone notice enumeration, detailed scaling actions and CLS alarm/metric-filter
parity remain open. No live Tencent validation has been performed.

Schema references: [policies](https://cloud.tencent.com/document/product/248/51279),
[bound objects](https://cloud.tencent.com/document/api/248/40570),
[data types](https://cloud.tencent.com/document/api/248/30354), and
[dimension region aliases](https://cloud.tencent.com/document/product/248/50863).

### CLS alarms and notification configuration

Regional `DescribeAlarms` and `DescribeAlarmNotices` now collect enabled and disabled
configurations with total-count validation, duplicate detection and independent
coverage records. Alarm query nodes retain the configured query text, syntax and
time offsets, linking only to explicitly returned topic/logset IDs in the same
account and region. Queries are configuration; the collector never executes them.
Schedules, repeat/trigger periods, single/multiple conditions, grouping fields and
classification metadata are retained.

CLS notice references stay regional; `MonitorNotice` references target global
Cloud Monitor templates, with content-template IDs and severity bindings preserved.
Notification groups retain channel metadata, callback integration IDs/methods,
security switches, routing-rule text and bounded escalation configuration. Callback
URLs/headers/bodies, phone details, user-supplied notification payloads and raw
failure messages are excluded. Selected receiver metadata includes channel/time
settings and receiver counts, not recipient contact data. Generic recursive graph
inference is disabled for these payloads so callback fields cannot fabricate
compute/network relationships. Explicit delivery-topic regions are honored without
claiming that delivery succeeded; reported delivery flags are retained separately.

These additions do not close the CloudWatch parity audit: log-to-metric extraction,
current alarm-state equivalence, wider Cloud Monitor mappings, legacy/template
expansion and live account validation remain open. References:
[alarms](https://cloud.tencent.com/document/api/614/56461),
[notification groups](https://cloud.tencent.com/document/product/614/56462),
[data types](https://cloud.tencent.com/document/api/614/56471).

### CLS scheduled SQL and declared metric outputs

`DescribeScheduledSqlInfo` now collects regional scheduled SQL tasks with validated
pagination and duplicate task detection. Task properties retain query text, enable
and reported status, start/end/window/delay settings, syntax, service-log flags and
both schedule period and its unit (minutes or seconds). Queries are never executed.

Explicit source/destination topic IDs and regions create configuration edges;
missing or malformed region data fails visibly instead of using the CLI region.
Both log and metric destinations are supported. For metric outputs, nonempty
`MetricNames` takes precedence over legacy `MetricName`, following the SDK contract.
Metric nodes are keyed by account, destination region/topic and metric name.
Each producer retains its own metric labels, static labels and timestamp mapping,
so shared metric names do not overwrite different task configurations. These are
**declared metric outputs**, not evidence of samples or successful execution.

This provides the configured log-to-metric mapping counterpart to AWS log metric
filters. It does not claim equal runtime behavior, expand SQL into inferred metric
values, or close the entire CloudWatch audit. Current alarm-state equivalence,
legacy/template rules, broader Cloud Monitor resource mapping, action execution and
live Tencent validation remain open. Sources:
[task API](https://cloud.tencent.com/document/api/614/95519) and
[output schemas](https://cloud.tencent.com/document/api/614/56471).

### CFS mount targets and export permissions

CFS file-system collection now requires complete totals and retains lifecycle,
protocol/storage, capacity/throughput, encryption and snapshot-policy metadata.
Explicit UUID KMS IDs link within the collected account/region; a key returned for
an explicitly unencrypted file system is marked conflicting instead. Unsupported
key formats remain unresolved. `AppId` never becomes an account UIN.

`DescribeMountTargets` runs separately for each file system, verifies its total,
checks returned parent identity, and scopes mount IDs to that file system. Mount
metadata includes endpoint IP, root FSID, lifecycle, network type and the returned
server-IP list/truncation flag. VPC/subnet placement uses explicit VPC mount fields;
Turbo CCN mounts link to the global CCN reference without accepting stale VPC fields.
The schema's uppercase network values and API examples' lowercase values are
supported. Unknown network types remain visible without guessed placement.

`DescribeCfsPGroups` and `DescribeCfsRules` are non-paginated APIs. The default
`pgroupbasic` is supported. Rules are scoped to their group and retain the client
selector, read/write mode, UID/GID squash configuration and priority. Permission
failures on one mount/group do not prevent collection of the others. Neither rule
presence nor a configured endpoint proves that a share can be mounted or read.

The AWS source also collects access-point POSIX identity and root-directory
configuration. Equivalence for that behavior, KMS ARN resolution, deeper
lifecycle/snapshot configuration and live validation remain incomplete. Sources:
[mount targets](https://cloud.tencent.com/document/product/582/38169),
[groups](https://cloud.tencent.com/document/product/582/38157),
[rules](https://cloud.tencent.com/document/product/582/38156),
[data types](https://cloud.tencent.com/document/api/582/38175).

## CKafka configuration and integration links

CKafka instance details now retain version, lifecycle, capacity, topic defaults,
explicit VPC/subnet placement, endpoint metadata and an optional global SSL
certificate reference. Per-instance topic lists use the documented maximum of 50
items per page, require totals and reject duplicate IDs/names. Topic IDs are scoped
to the instance, account and region. Detail responses must echo the requested
instance ID or the listed topic ID before enrichment.

Topics retain retention/cleanup/replication configuration, IP allowlists, quota
configuration and selected preset ACL rule summaries. Partition nodes retain
leader state, ISR count and replica count; duplicate or truncated partition lists
make collection partial. These API fields do not identify individual brokers.
Opaque ACL entry strings are not treated as evaluated authorization; full ACL
entry collection, route/security-protocol configuration, consumer groups and
brokers remain gaps. No message contents or offsets are collected.

CloudAudit destination names and SCF trigger names now resolve to native topics
only through a matching collected instance/topic relationship in the same account
and region. Configured delivery/invocation does not establish successful delivery,
consumption or effective permissions. Live validation and full AWS parity remain
incomplete.

Sources: [topic attributes](https://cloud.tencent.com/document/product/597/40846),
[topic listing](https://cloud.tencent.com/document/product/597/40847),
[custom SSL certificate integration](https://intl.cloud.tencent.com/zh/document/product/597/81299),
and the installed Tencent SDK 2019-08-19 request/response models.
