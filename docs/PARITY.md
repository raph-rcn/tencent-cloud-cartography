# AWS capability parity audit

## Current implementation — 2026-10-14

See [the metadata depth extension](METADATA-DEPTH.md) for COS notifications,
database backup/proxy/replica depth, gateway backend mappings/bindings and federation
provider/provisioning configuration. Unsafe response fields remain explicitly excluded.

The permission/exposure, container, CLB/database and additional service-family
metadata implementation is delivered. The operator retained the metadata-only
restriction: APIs known to return workload or secret content stay excluded.
Read [the current capability and gap report](METADATA-PARITY.md) and
[the updated per-collector audit](aws-parity-audit.json). **Full AWS equivalence
and live Frankfurt behavior remain unverified.**

Named COS identity/resource/boundary composition and caller-policy/role-trust
paths are now implemented offline; see [authorization semantics](AUTHORIZATION.md).
Named project workspaces, an empty real-inventory setup flow, official Tencent
branding and portable UI-inclusive builds replace the example-first quick start.
Automatic per-service/account region discovery, explicit restrictions, organization
member/profile reconciliation, isolated account failures and a scope coverage
overview are implemented. [Collection guide](COLLECTION-COVERAGE.md) describes
failed-attempt tracking and the observed/planned scope universe. Environment-specific
permissions, credential support and service availability still govern coverage.

The sections below preserve earlier source comparison and implementation
history. Statements describing features as future work predate this extension;
the current report and per-collector audit supersede those status statements.

**Full parity is not achieved.** The initial Tencent implementation reproduced the main diagram UI and a useful subset of collection. It did not replace the complete AWS backend capability set. Passing its initial tests did not establish that broader requirement.

The authoritative comparison is the AWS checkout's collector registry, model/analysis code and Landscape implementation, including its current Resource Explorer changes. The original checkout is read-only throughout this work. [The audit](aws-parity-audit.json) records all 67 source collector slots, 66 enabled by its Landscape script, the source revision/file hash, current counterpart, and remaining work. Product counterparts labeled pending require further API research; they are not claims of equivalent behavior.

## Required work beyond listing resources

| Requirement | Current evidence | Remaining work |
|---|---|---|
| Preserve source history and publish Tencent repository | Original revision is an ancestor; `origin/main` published | Retain provenance as features are added |
| All official product assets | 896 SVGs, manifest hashes, gallery and native-service mappings tested | Keep mappings complete for added resource types |
| Broad mandatory inventory and native reconciliation | Documented CBS/CKafka/MySQL aliases, duplicate/error checks, scope validation and global identity reconciliation implemented | Composite resource IDs, remaining provider type ambiguities and live reconciliation |
| All 66 enabled collector capabilities | Per-collector audit linked above | Complete equivalent configuration/relationships; justify provider differences with evidence |
| Account/region/VPC/AZ/subnet hierarchy | Existing diagram and containment tests | Common VPC inference from unanimous subnet memberships added; broader graph cycles/scope audit remains |
| Full relationship graph | Collected edges preserved by current tests | Restore missing relationship collection and applicable analyses |
| Unresolved-inventory toggle | Toggle, count and inspector explanation implemented; browser validated | Keep native references visible and validate large inventories |
| Search, filters, selection, layout, collapse | Initial UI and browser smoke tests | Add regressions as graph semantics expand |
| Service component grouping | Per-location service components implemented and browser validated | Further large-graph/export validation |
| Direct Neo4j-backed viewer | Direct reads, complete metadata, auth/database options and refresh implemented; 5 real Neo4j integration tests passed in CI | Large-inventory performance validation remains; runtime results recorded in VALIDATION.md |
| PNG / editable draw.io | Initial browser downloads verified | Preserve grouping and assets across new graph types |
| Multi-account and region orchestration | Per-account/service RMS discovery, region restrictions, verified profile/member reconciliation, failure isolation and scope overview implemented | Runtime validation, unavailable RMS mappings and automatic federation/session acquisition remain gaps |
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

## CMQ queues and publish/subscribe configuration

The SQS/SNS counterparts now include TDMQ for CMQ queue/topic inventories and
per-resource details, with paginated subscriptions. All three list APIs use the
50-item maximum and require totals. Queue and topic detail IDs/names must match
inventory; subscriptions bind to the requested topic and retain topic-scoped IDs.
A changed subscription count is reported as partial collection. Use native service
filter `--services tdmq` for this collection.

Queues retain retention, visibility, polling, capacities, transaction and dead-letter
configuration. Dead-letter names resolve only to unique collected queues in the
same account/region; reverse source metadata must agree with explicit forward
configuration. Topics/subscriptions retain filters, retry strategy and content
format. Queue destinations use the same scoped matching; unresolved/ambiguous
names remain visible in properties. HTTP destinations retain origins and a
redaction marker; userinfo, paths, query strings and fragments are omitted because
webhook URLs can carry credentials. No request is made to these destinations.

`CreateUin` is creator metadata and `TopicOwner` is an AppId; neither replaces the
collecting account UIN. Tenant/namespace strings do not imply VPC or account
containment. Source AWS queue policy, KMS, FIFO/deduplication fields, SNS
confirmation/encryption/delivery-policy correspondence, wider messaging protocols,
and live API validation remain gaps. No messages are read, sent, cleared or rewound.

Sources: [CMQ queues](https://cloud.tencent.com/document/api/1179/55909),
[subscription API](https://cloud.tencent.com/document/product/1179/55908),
[control-flow SDK](https://cloud.tencent.com/document/product/1496/65108),
and installed Tencent SDK `tdmq.v20200217` metadata models. The API catalog lists
Frankfurt (`eu-frankfurt`); this does not establish availability for a particular
account.

## EventBridge rule and target configuration

EventBridge now collects all returned regional buses, bus details, per-bus rules,
rule details and per-rule targets. Required totals, duplicate detection and explicit
parent ID checks protect pagination and child scoping. Rule patterns are validated
as JSON objects and preserved as configuration; disabled rules remain visible.
Bus logging references retain regional CLS identities. Safe connection summaries
retain type/status without inventing connection IDs.

Target QCS resource strings preserve explicit UIN and region, including references
to another account. AppId alone cannot supply an owner. SCF targets require one
collected function matching namespace/name/account/region and preserve version or
alias qualifiers. Kafka targets and dead-letter routes require a matching collected
instance/topic association; contradictory nested UINs prevent linking. CLS and
Elasticsearch IDs produce explicit references, with AppId kept separate from UIN.
Batch settings, retry configuration, event delivery format and selected ES output
configuration remain metadata; no event is published or read.

AWS schedule expressions, role associations and managed-by correspondence still
need provider-specific evidence, and live validation is pending. `ListConnections`
is intentionally excluded: its `DTSParams` schema can return a password, violating
this project's metadata-only collection boundary. Source AWS EventBridge currently
collects rules and targets, not that Tencent connection detail operation. Event
search, transformation payloads and execution/permission claims remain excluded.

Sources: [EventBridge API catalog](https://cloud.tencent.com/document/product/1359/67713),
[bus listing](https://cloud.tencent.com/document/product/1359/67683),
[target/QCS schemas](https://cloud.tencent.com/document/api/1359/67704), and the
installed Tencent SDK `eb.v20210416` request/response models.

## CloudRC and native identity reconciliation

Documented CloudRC type codes `cvm::volume`, `ckafka::ckafkaId` and
`cdb::instanceId` now map to the existing CBS, CKafka and MySQL native kinds.
Resource IDs remain opaque and unchanged: a type alias cannot equate different IDs,
accounts or regions. PostgreSQL already shares its normalized machine type.
Original inventory type, ID, alias, tags and provenance survive native enrichment.

CloudRC documents `scf::namespace` as a function resource, whereas SCF
`ListNamespaces` enumerates actual namespaces. It now stays an explicitly ambiguous
inventory type instead of accidentally merging with a namespace. The public
Lighthouse table has inconsistent human labels; its distinct machine types are
preserved without inferring aliases. Composite/function resource-ID reconciliation
still requires authoritative format or live evidence.

Baseline pagination rejects duplicate canonical identities even with changing
continuation tokens, invalid token types and malformed owner/type/ID metadata.
Prior valid rows and request IDs survive a later denial/error. The account-wide
pass reports scanned versus retained counts and preserves only explicit globals or
records with missing regions. Missing regions remain `unknown`; a global native
API must provide a matching account/type/ID before merging. That merge preserves
incoming/outgoing edges and their provenance. Regional filters do not substitute
for a missing returned region. Unknown types stay visible through unresolved
inventory rather than being silently discarded.

Sources: [CloudRC type catalog](https://cloud.tencent.com/document/product/1791/115765),
[SearchResources](https://cloud.tencent.com/document/api/1791/136441), and installed
`cloudrc.v20240606` schemas. These rules apply to newly collected snapshots;
previously saved snapshots are not silently rewritten. Full live reconciliation,
remaining product aliases and broader AWS parity remain incomplete.


## SES sending-domain configuration

The AWS source `intel/aws/ses.py` lists email identities and collects sending,
verification and DKIM attributes. Tencent now lists sending domains with required
`Total` pagination, normalized domain identities, reputation/quota metadata,
configured sending IPs, tags and independent per-domain details. List/detail
verification changes remain visible. Denied or invalid detail responses retain the
listed domain and do not prevent other domains from being collected.

Tencent `DKIMOption` represents key size (1024, 2048 or both); it is not the AWS
`DkimSigningEnabled` or `DkimStatus` field. Provider-reported DNS checks preserve
record type/name, expected/current values and check status. The graph links exact
same-account public DNSPod record name/type/value matches, without inferring live
DNS resolution, successful signature generation or delivery. No email, recipient
list, template body, SMTP password or sending API is queried.

Mainland APIs document Guangzhou and Hong Kong; international APIs document
Singapore with `ses.intl.tencentcloudapi.com`. Transport selects the documented
endpoint from the explicit selected region. Frankfurt and other unsupported
regions produce a visible unsupported coverage record, with no SES request.
Domains and DNS checks use the bundled official Simple Email Service icon.

AWS individual email-address identity correspondence, exact DKIM signing-state
semantics and live account validation remain incomplete. Sender addresses are not
silently equated to independently verified identities. The API examples omit the
newer `Total` field although both current schemas and the installed SDK include it;
responses without it remain incomplete rather than being assumed exhaustive.

Sources: [domain list](https://cloud.tencent.com/document/api/1288/51045),
[domain details](https://cloud.tencent.com/document/api/1288/51046),
[international endpoint and region](https://www.tencentcloud.com/document/product/1084/39411),
[data types](https://cloud.tencent.com/document/api/1288/51053).


## CloudConfig recorder, delivery and rules

The source AWS Config collector models recorders, delivery channels and rule
configuration. Tencent now collects the account recorder, its selected resource
types, account delivery settings, and paginated rules with independent detail
checks. Current API pages make Region optional, and the product aggregates across
regions: nodes are account/global objects, while `RegionsScope` remains rule
configuration. Recorder/delivery IDs are explicit account-singleton graph IDs,
not invented provider IDs. Rule author/owner and account-group metadata do not
reassign account scope or infer cross-account permissions.

Resource types are definition nodes, not discovered resource instances. Rule
type/region/tag/exclusion scopes, conditions, input parameters and trigger periods
are retained. Detail changes replace rule type edges without changing recorder
scope. Provider compliance results and evaluation time remain reported metadata;
no independent evaluation is claimed. Numeric RiskLevel is retained without a
severity label because list-filter documentation and SDK descriptions disagree.

COS destination matching accepts documented QCS forms and requires a uniquely
collected full bucket name in the explicit region. AppId constrains the bucket
name and never becomes an account UIN. CLS references require an explicit UIN,
region and topic ID. Disabled delivery configuration stays visible. Unknown QCS
forms, mismatched product types and ambiguous buckets do not produce guessed links.
The public delivery example contains inconsistent type/QCS fields; it is not used
as a mapping contract. The exact documented missing-delivery error is empty;
other errors and unavailable recorder scope remain partial.

Recorder CAM-role bindings, delivery encryption/frequency correspondence,
organization aggregators, custom function binding semantics and live validation
remain incomplete. The collector never invokes resource-snapshot, evaluation-history or remediation
APIs. Returned rule annotations
are omitted; configuration queries do not prove recording, delivery or compliance.

Sources: [rule list](https://cloud.tencent.com/document/api/1579/101781),
[rule detail](https://cloud.tencent.com/document/api/1579/129718),
[recorder](https://cloud.tencent.com/document/api/1579/129700),
[delivery](https://cloud.tencent.com/document/api/1579/129733),
[cross-region product scope](https://cloud.tencent.com/product/config),
[COS identifiers](https://cloud.tencent.com/document/product/651/133239).


## EMR clusters and nodes

`DescribeInstancesList` collects both standard (`ClusterType=0`) and TKE (`2`)
clusters, using `DisplayStrategy=clusterList` to include creating and failed
clusters. The API excludes destroyed clusters. Both this operation and
`DescribeClusterNodes` use zero-based **page numbers** in `Offset`, not row
offsets. Required totals, duplicate detection and independent coverage records
prevent incomplete lists from being reported as exhaustive.

Node inventory covers `all` (excluding CDB), `db` (normal CDB nodes), and Tencent's
literal `recyle` value (isolated nodes, including CDB). Overlapping views merge
by cluster-scoped EMR node ID, with a documented serial-number fallback. Each
view retains its own coverage outcome. Conflicting metadata between overlapping
views is reported as partial before introducing incompatible links. Node identity, returned parent IDs,
AppId/region metadata and explicit zone codes are checked before graph mutation.
AppId never becomes the account UIN.

Selected metadata includes release, status, billing/project, tags, machine
specifications, deployed-service names and node-level API termination protection.
Only `UniqVpcId`/`UniqSubnetId` create network links; legacy numeric network IDs
remain properties. A multi-zone cluster's configured default subnet is a
configuration relationship, not single-subnet containment. Nodes use their own
returned subnet and zone. Explicit host instance IDs link to CVM and pod TKE IDs
link to TKE. Database names/IPs do not invent native CDB identities. All EMR nodes
use the bundled official Elastic MapReduce logo.

The AWS source models cluster roles, log/KMS settings, security configuration,
image versions, scale-down policy and termination behavior. These fields still
need safe Tencent equivalents and live validation. `DescribeInstances` is
explicitly excluded: its nested `CustomMetaDBInfo` schema contains `MetaDataPass`.
Filtering after retrieval would violate the repository's metadata-only policy.
No job data, script bodies, credentials or workload contents are requested.
Node protection does not establish cluster-level termination-policy equivalence.

Sources: [cluster list](https://cloud.tencent.com/document/api/589/74070),
[node inventory](https://cloud.tencent.com/document/product/589/41707),
[official SDK schemas](https://github.com/TencentCloud/tencentcloud-sdk-python/blob/master/tencentcloud/emr/v20190103/models.py).


## Resource tags

The AWS source's `resourcegroupstaggingapi` collector creates shared tag nodes
and `TAGGED` relationships to inventory resources, including a separate global
IAM path. Tencent now uses account-wide `tag.GetResources` with API version
2018-08-13, no tag/resource filters, and continuation-token pagination. Each
profile is queried once; returned regional bindings are retained only for the
selected regions, alongside global or unresolved-region bindings. Coverage
reports both scanned and retained resource counts. Missing/null tokens, repeated
tokens/resources and malformed arrays remain incomplete.

Tag keys and values are case-sensitive. Unicode and empty values are preserved;
duplicate keys and malformed fields are rejected before writing a binding.
Tag identity is a hash of the separate key/value strings, scoped to the account;
colon-containing keys cannot collide with colon-containing values. Sharing a tag
expresses metadata equality and does not imply permission or network access.

Documented QCS service/prefix pairs map to the actual native resource kinds.
Matching includes account UIN, region and full ID; names and ID suffixes are not
substituted. Global CAM roles/users, SSL, CCN and private DNS use documented
regionless identifiers. EMR node references need a unique returned EmrResourceId.
COS's three documented AppId forms resolve only to a full bucket name already
collected under the same account and region. AppId is never treated as a UIN;
object paths are rejected instead of silently tagging the containing bucket.

Unknown resource types, missing regional identity, missing collected resources,
ambiguous node IDs, and conflicting tag sets for equivalent QCS identifiers
remain `tag.resource` inventory-only nodes. They retain the tag relationships and
make the snapshot partial. Successfully matched bindings become direct
resource-to-tag edges; the temporary binding nodes are removed. Native and
CloudRC tag properties remain separate from `tag_api_tags`, preserving their
provenance. A new collection builds a new snapshot, so removed tags are not
silently carried forward from an earlier scan.

The full relationship graph includes tags; the architecture view hides these
metadata detail nodes. The bundled official archive has no Tag product logo:
this metadata service uses its generic **Application Programming Interface**
symbol, explicitly mapped in the icon catalog. All native product logos remain
unchanged. This is not presented as a dedicated Tag logo.

Remaining gaps include unsupported/composite resource identifiers, native API
fallback where the Tag API omits a product, and live account verification. An
empty successful tag response does not establish that every cloud resource is
untagged or supported by the Tag API.

Sources: [GetResources](https://cloud.tencent.com/document/product/651/72278),
[resource prefixes](https://cloud.tencent.com/document/product/651/89122),
[COS identifier forms](https://cloud.tencent.com/document/product/651/133239),
[CAM role identifiers](https://cloud.tencent.com/document/product/1312/48197),
[TKE resource identifiers](https://intl.cloud.tencent.com/zh/document/product/598/57168),
[international resource table](https://intl.cloud.tencent.com/zh/document/product/651/55662).


## Secrets Manager lifecycle, versions and rotation

The AWS collector lists secrets and all available version IDs, with lifecycle,
rotation, encryption and version-stage metadata. Tencent's `ListSecrets` defaults
to custom secrets and KMS encryption. Collection now explicitly queries the four
documented request categories (custom, cloud product, SSH and cloud API keys)
with both encryption modes (KMS and software-key), retaining all states. Each of
the eight combinations has independent required-total offset pagination and
coverage. Cloud-product responses can retain the separately reported Redis type.
Unexpected category/encryption fields and duplicate secret names remain partial.

Metadata includes description, creation/deletion/next-rotation times, state,
creator/target UINs, product IDs and rotation frequency. String UINs are validated
against returned integer forms; creators and target users never replace the
account proven by STS. SSH associations use explicit CVM IDs only for SSH secrets.
MySQL, Redis and cloud API user relationships require exact existing same-account
resources, in the explicit region (or global CAM scope). Other product names are
retained without guessed relationships. KMS references use the existing explicit
key configuration rules; software encryption does not imply a KMS relationship.

`ListSecretVersionIds` has no pagination parameters in Tencent's schema. Its
returned secret name must match the request; versions are validated as a complete
array before graph mutation, scoped by parent secret/account/region, and linked
with `VERSION_OF`. A version's KMS key and stage cannot be inferred from the
current secret, so neither is fabricated. Missing/deleted/denied detail requests
remain independent incomplete coverage while inventory survives.

`DescribeRotationDetail` supplies reported enablement, frequency and timestamps.
List and detail observations stay separate and enablement changes are flagged.
These fields do not prove a rotation completed or that a credential works.
Creator-qualified `secret/creatorUin/.../...` QCS tag bindings resolve using the
collected creator and full secret name. The Secrets Manager icon covers both
secrets and versions in the full graph and draw.io export.

AWS version-stage/historical-key, replication/primary-region, rotation-function,
last-access/change and broader database-product equivalence remain gaps. Current
metadata comes from list/version/rotation APIs; DescribeSecret is not required
and its opaque additional configuration is not collected. Neither secret values,
SSH key material, rotation mutation nor credential validation operations are
allowlisted. Live verification, including product-specific filtering and detail
API availability, remains pending.

Sources: [ListSecrets](https://cloud.tencent.com/document/product/1140/40519),
[version IDs](https://cloud.tencent.com/document/product/1140/40520),
[rotation metadata](https://cloud.tencent.com/document/product/1140/58264),
[data types](https://cloud.tencent.com/document/product/1140/40530),
[QCS identity](https://cloud.tencent.com/document/product/598/70019).

## CDN certificate deployment metadata

CDN selection now uses SSL `DescribeHostCdnInstanceList` with fresh, synchronous
requests, validated totals and offset pagination. Global domain nodes retain
provider status and the HTTPS billing flag; deployed `CertId` creates an explicit
`USES_CERTIFICATE` edge. Billing is not interpreted as HTTPS enablement, and
certificate name/SAN matches are not deployment evidence.

The previous CDN `DescribeDomains` operation is disabled: its response schema
includes `Origin.AdvanceHttps.CertInfo.PrivateKey`. `DescribeDomainsConfig` is
also outside the exact metadata allowlist. No sensitive response is fetched
for subsequent filtering. An unsupported CDN inventory scope stays visible even
when the SSL deployment view succeeds or is empty. API documentation permits
empty/zero values when unavailable, so those results cannot prove the absence
of CDN domains. Complete domain/origin inventory, CloudFront configuration
equivalence, EdgeOne and live selection semantics remain gaps.

Sources: [CDN schemas](https://cloud.tencent.com/document/api/228/30987),
[SSL CDN deployment inventory](https://cloud.tencent.com/document/product/400/91663),
[deployed certificate field](https://cloud.tencent.com/document/api/400/41679).

## Auto Scaling group settings and membership

Compared directly with the source `ec2/auto_scaling_groups.py`: it collects
groups, launch configurations, subnet memberships and instance memberships.
Scaling policy collection is not part of that source collector, so it is not
a required gap in this mapping.

Group metadata now retains cooldown, health checks and grace period, enabled and
activity status, desired/min/max capacity, rebalance and mixed-capacity settings,
termination order, placement choices and replacement-service settings. Explicit
subnet/VPC/configuration/load-balancer references preserve account and region;
forward CLB references honor their returned Region. Multiple zone choices do not
place a group into one invented availability zone.

Instance membership records retain lifecycle, health, warmup, version and
scale-in protection under `as_` properties. Existing CVM names/state remain intact.
Membership-only CVMs stay references, keeping denied or unavailable CVM inventory
visible. Group and membership pagination require totals and reject duplicate IDs.

`DescribeLaunchConfigurations` is now excluded: its response includes UserData
and its request has no metadata-only projection. Configuration ID/name references
remain available from group/member metadata. Full launch configuration properties,
AWS-specific lifetime/default-protection correspondence and live validation remain
incomplete. No launch payload or scaling mutation is requested.

Sources: [Tencent group API](https://intl.cloud.tencent.com/zh/document/product/377/31013),
[instance membership API](https://cloud.tencent.com/document/api/377/20437),
[launch configuration API](https://cloud.tencent.com/document/api/377/20445),
[response schemas](https://www-sg.tencentcloud.com/document/api/377/31018).

## Owned and in-use images/snapshots

Direct source comparison found that AWS image/snapshot collection includes both
owned inventory and metadata for referenced resources outside owned inventory.
Tencent now explicitly filters private image/snapshot lists, requires totals, and
looks up unresolved referenced IDs individually after native collectors finish.
An unavailable ID cannot erase another lookup's result; a wrong/empty response
leaves the reference unresolved. Referenced inventory-only rows are eligible too.

Public/shared resources retain provider type and selected lifecycle, architecture,
license, retention, encryption and size fields. Their account field identifies
the query context; `owned_by_collected_account=false` explicitly distinguishes
external resources. The API does not supply authoritative foreign owner UINs.
Foreign image backing snapshot IDs and shared snapshot source disk IDs are kept
as metadata without fabricated current-account ownership edges.

Owned resources independently query `DescribeImageSharePermission` or
`DescribeSnapshotSharePermission`. Sharing nodes preserve recipient root-account
ID and timestamp, with `HAS_SHARE` and `SHARE_RECIPIENT` relationships. These are
provider-reported sharing configuration, not proven effective access. Empty
sharing lists do not establish the AWS snapshot `Public=false` predicate. No
image/snapshot contents are retrieved and no sharing mutation is allowed.

Remaining differences include AWS public-permission semantics, snapshot KMS and
source-disk creation provenance absent from these collected schemas, broader
image boot/hardware fields and live verification.

Sources: [image sharing](https://intl.cloud.tencent.com/zh/document/product/213/33273),
[snapshot sharing](https://intl.cloud.tencent.com/document/api/362/33300),
[recipient identity](https://cloud.tencent.com/document/product/362/40469),
[image API](https://cloud.tencent.com/document/api/213/15715),
[snapshot schema](https://cloud.tencent.com/document/product/362/15669).

## ENI addresses, EIP bindings and CLB target resolution

Network interfaces now retain typed lifecycle/MAC/primary/QoS and attachment
metadata, explicit VPC/subnet/security groups, and separate interface-scoped IPv4
and IPv6 address nodes. The address carries its primary/blocked/state flags and
reported public-IP/EIP association. IPv6 is canonicalized; duplicate or
contradictory alias rows fail before adding that page. Nullable IPv6 metadata is
marked unavailable. The official ENI icon covers both interface and address nodes.

EIP collection retains selected lifecycle/billing/blocking/direct-connection
metadata. Instance type and ID determine CVM/NAT/ENI/CLB references; unsupported
types remain raw identifiers. Binding to an address requires the explicit ENI ID
and private address within the same account/region. Contradictory EIP ID or
public-IP reports prevent reconciliation and remain visible as a conflict.

CLB IP targets resolve only against a unique address in the parent CLB's account,
region and VPC. The graph retains both the original target and its address match.
A CVM edge additionally requires the ENI attachment instance ID to match collected
CVM inventory in that account/region/VPC. Opaque `InstanceAccountId` is preserved
as metadata without treating it as a UIN. Non-CVM attachments are not forced into
CVM nodes. No route, health-check, firewall or actual reachability conclusion is
inferred; cross-VPC targets remain unresolved under this matching rule.

Sources: [ENI inventory](https://cloud.tencent.com/document/api/215/15817),
[EIP inventory](https://intl.cloud.tencent.com/zh/document/product/215/16702),
[network schemas](https://cloud.tencent.com/document/product/215/15824).

## Cloud Connect Network ownership and attachments

Comparison with the AWS `ec2/tgw.py` collector confirmed that its scope is gateways
and attachments, including VPC/subnet associations and owner/shared-account links.
It does not collect transit-gateway route tables or routes. The audit no longer
counts those as a missing source capability.

CCN collection now retains selected lifecycle, billing/QoS, instance count and
routing-feature flags. Each attachment validates its CCN ID and explicit CCN
owner UIN against the parent scope. Target identity includes instance type, root
UIN, region and resource ID; a missing owner never defaults to the current account.
VPC, Direct Connect gateway and Blackstone VPC references keep their provider
namespace. Unrecognized types retain metadata without an invented target edge.

CIDRs, attachment state/time and returned route-table identifiers remain metadata.
Pending/deleted associations remain visible with their reported state;
`connectivity_verified=false` applies even when the provider reports ACTIVE.
Pagination requires totals, validates each page before mutation and isolates
failures by parent CCN. The existing official Cloud Connect Network SVG covers
both network and attachment nodes. No API permission was added.

Shared CCNs that are absent from the queried account's CCN inventory remain a
discovery gap. AWS owner/SHARED_WITH correspondence, provider-specific subnet
attachment semantics and live Tencent validation are also incomplete.

Sources: [CCN inventory](https://cloud.tencent.com/document/product/215/19199),
[attachment API](https://intl.cloud.tencent.com/zh/document/api/215/34789),
[network response schemas](https://cloud.tencent.com/document/product/215/15824),
[cross-account workflow](https://intl.cloud.tencent.com/zh/document/product/1003/31985).

## Private Link inventory and shared service relationships

Endpoint and service collection now explicitly queries IPv4, IPv6 and dual-stack
scopes. Dual-stack uses MaxResults/NextToken, preserving the request filters and
following nonempty tokens even after short pages. Totals, repeated tokens, duplicate
identities and malformed pages produce visible scope failures. Service inventory
queries CLB, CDB, CRS and GWLB independently because the API defaults to CLB.

Endpoints retain lifecycle, VIP, AppId, service identifiers and consumer VPC, subnet
and security-group links. ServiceVpcId is metadata about the remote service, never
consumer-account containment. Services retain selected creation, auto-accept,
backend and count metadata, plus explicit CLB/MySQL/Redis/GWLB references. Nested
consumer endpoint rows expose AppIds; their counts are retained without assigning
those consumers to the service owner's UIN. The official Private Link icon covers
endpoint/service nodes; GWLB references use the official Cloud Load Balancer icon.

Referenced services absent from owned inventory receive exact authorized-ID
lookups. These require a returned ServiceUin; ServiceOwner and EndPointOwner are
AppIds and are never converted into UINs. After all profiles finish, an endpoint
links to a unique collected service in the same region with the exact service ID,
provided its ServiceVpcId agrees. Missing, ambiguous or inconsistent matches stay
unresolved. Reported associations do not prove connectivity or authorization.

Source AWS endpoint policy, private-DNS, requester-managed, ENI and gateway route
table fields do not have established equivalents in these Tencent responses.
Those semantics, native GWLB enrichment and live account/API verification remain
incomplete. This change adds no API operation to the allowlist.

Sources: [endpoint API](https://cloud.tencent.com/document/api/215/54679),
[service API](https://cloud.tencent.com/document/product/215/54678),
[response schemas](https://cloud.tencent.com/document/product/215/15824),
[GWLB identifiers](https://cloud.tencent.com/document/product/1782/111701).

## VPC CIDR associations and subnet metadata

AWS VPC collection models primary/associated IPv4 and IPv6 ranges as graph nodes.
Tencent now preserves VPC-scoped CIDR nodes for primary IPv4, auxiliary IPv4,
legacy IPv6 and provider IPv6 arrays. Repeated legacy/provider IPv6 ranges merge
while retaining roles, ISP and address type. Auxiliary type and explicit subnet
references are retained; subnet parent IDs and CIDR membership must agree.
These nodes use the official VPC icon and appear in the full relationship graph.

VPC metadata now includes default, multicast, DHCP/DNS/domain, stack and route-
publication settings. DNS order and explicit false values are preserved. Subnets
retain IPv4/IPv6 ranges, default/broadcast/SNAT flags, available/total IPv4 counts,
CDC/stack fields and explicit VPC/AZ/route-table/ACL references. Nested subnet
records do not produce reverse VPC containment. Invalid pages, parent mismatches,
duplicate identities and missing pagination totals are visible failures.

AWS VPC tenancy/state and CIDR association IDs/state messages are absent from
these collected schemas. Subnet public/customer-owned-IP launch defaults, IPv6
auto-assignment and AWS default-for-AZ semantics have not been established as
equivalent. No such values are fabricated; live Tencent validation remains open.

Sources: [VPC inventory](https://cloud.tencent.com/document/product/215/15778),
[subnet inventory](https://cloud.tencent.com/document/product/215/15784),
[network response schemas](https://cloud.tencent.com/document/api/215/15824).

## Security-group selectors and reusable templates

The source AWS collector retains IPv4 range nodes and referenced security groups.
It does not collect prefix-list dependencies. Tencent rules now retain version,
index, priority, direction, action, descriptions and timestamps, with explicit
links to referenced groups, IPv4/IPv6 selectors and address/service templates.
A malformed or conflicting rule prevents that policy response from partially
updating the graph; independent group failures remain isolated.

Four metadata APIs collect address templates/groups and service templates/groups.
Members retain IP/CIDR/range identities or literal protocol/port selectors.
Canonical addresses coexist with original provider text. Member remarks remain
on their template so shared address nodes cannot overwrite each other's comments.
Group membership and template dependencies remain explicit graph edges. All new
kinds use the bundled official VPC SVG and appear in the full relationship graph.

Security-group metadata now preserves descriptions, project, default flag and
creation/update timestamps. Missing referenced groups/templates remain references.
Rule address groups are not expanded into a claim of effective access, and policy
version/index values describe the collected snapshot. The Tencent schemas provide
no foreign owner UIN for a referenced group; references use the query account and
region. AWS VPC-specific SG scoping and effective rule behavior require provider
semantics/live verification; no reachability or firewall mutation is performed.

Sources: [network response schemas](https://cloud.tencent.com/document/api/215/15824),
[address templates](https://intl.cloud.tencent.com/document/product/215/16717),
[service templates](https://intl.cloud.tencent.com/document/product/215/16719),
[service template groups](https://intl.cloud.tencent.com/document/api/215/16718).

## Route-table associations and next-hop reconciliation

Route tables retain Main, creation and local-CIDR publication metadata. Explicit
subnet associations now have table/subnet identity nodes, while the existing
subnet-to-table link remains. No provider association ID or state is invented.
Embedded routes are preserved and each table independently queries the paginated
DescribeRouteList API with explicit table/VPC filters and required totals.
Conflicting, disappearing or duplicate route rows leave visible incomplete scopes.
A denied listing cannot erase embedded inventory.

Routes retain descriptions, type, enabled/publication flags and creation/CDC
metadata. RouteItemId is preferred; the fallback includes destination and next
hop rather than using the nonunique IPv6 RouteId zero. Local gateways and GWLB
endpoints now have typed references. EIP sentinel zero, unrecognized gateway
identifiers and INTRANAT identifiers without an established mapping remain
metadata. CCN route responses lack an owner UIN, so owner links require a unique
collected global CCN with the exact identifier, including foreign-account CCNs.

NORMAL_CVM next hops contain IP addresses. They match only a unique collected ENI
address in the route's account, region and VPC. A CVM link additionally requires a
collected ENI attachment and a collected instance in the same scope. Disabled
routes remain configuration records; these relationships do not establish packet
forwarding or effective reachability.

AWS association state/IDs, route origin and blackhole-state equivalents, broader
private-NAT identity mapping and effective path evaluation remain incomplete.
Live Tencent API behavior, including IPv6 coverage, is not yet verified.

Sources: [route tables](https://cloud.tencent.com/document/product/215/15763),
[paginated route list](https://cloud.tencent.com/document/product/215/115754),
[route and gateway schemas](https://cloud.tencent.com/document/api/215/15824).

### Network ACL rule formats and subnet placement

The ACL collector selects typed metadata from `DescribeNetworkAcls`, requires
pagination totals, validates explicit VPC/subnet associations, and keeps ACLs and
rules in their collected VPC. Three-field ingress/egress rules retain provider
entry IDs, action, protocol, ports, IPv4/IPv6 selectors, description, modification
time and priority. Older responses without entry IDs or priority use a labeled
response-position identity/order; no provider priority is invented. Missing type
is labeled `legacy_triple`, and unknown types produce unsupported coverage.

Five-field ACLs use the separately allowlisted, paginated
`DescribeNetworkAclQuintupleEntries` API scoped by exact `NetworkAclId`. Both
returned directions are collected, with source/destination ports and IPv4/IPv6
selectors, provider IDs, creation time and priority. Denials are isolated per ACL;
missing totals, malformed families, duplicate IDs/priorities and mismatched
parent associations retain partial coverage. Whole pages are validated before
new nodes or edges are added. No rule is evaluated as proof of reachability.

The AWS source stores default/owner/association IDs and numbered rules. Tencent's
listed ACL schema has no corresponding default flag or association identifier:
account ownership is the queried account and subnet association edges use explicit
returned IDs. Those source semantics and live Frankfurt behavior remain unverified.
Provider documentation:
[ACL list](https://cloud.tencent.com/document/product/215/42160),
[five-field rule list](https://cloud.tencent.com/document/product/215/77634),
[data types](https://cloud.tencent.com/document/api/215/15824).

### Peering endpoint identity and collected CIDRs

A dedicated peering collector retains state, creation time, bandwidth, controller,
QoS and billing metadata. It requires pagination totals, validates whole pages,
reconciles DestinationVpcId/PeerVpcId aliases, and preserves UINs separately from
AppIds. Original region strings are retained; documented abbreviations such as
`de`, `sg` and `gz` normalize to canonical region codes using the existing Monitor
region map. Unknown regions and missing owners remain unresolved and partial.

`VPC_PEER` produces explicitly scoped endpoint VPC references. Bare-metal or
unknown type records (including the official example's `VPC0`) require unique
collected VPC/BMVPC inventory to establish network kind. No side is assumed to be
bare metal merely from `VPC_BM_PEER`. Unresolved types retain unsupported coverage.
Endpoint CIDR links require enriched CIDR nodes belonging to the exact collected
VPC, owner and region. These edges describe VPC address inventory, not advertised
routes or effective connectivity; isolated/rejected peerings remain configuration.

The source AWS collector stores peering status messages, remote DNS/ClassicLink
options, and peer-returned CIDR association state. Tencent's PeerConnection schema
does not expose those fields. CIDRs available only from an inaccessible remote
account remain uncollected, and exact provider equivalence/live behavior remain
open. References: [peering API](https://cloud.tencent.com/document/api/215/96023),
[region abbreviations](https://cloud.tencent.com/document/product/248/50863).

### Identity policy analysis foundation

`permissions.py` runs automatically after collection and through the offline
`analyze --input ... --output ...` command. It evaluates collected direct and
inherited group policies for COS GetObject/PutObject, Secrets Manager
GetSecretValue and CAM PassRole. Actions normalize the documented optional
`name/` prefix. Explicit denies take precedence across policies; conditions and
principal clauses remain conditional without supplied request context. Unexpanded
function-set actions, uncertain case variants, project semantics and unsupported
expressions cannot produce unconditional allows.

Each `cam.permissiondecision` links its principal, target and supporting
statements. It retains exact action/resource scope, decision and conditions.
Role name/ARN aliases are evaluated together so a deny through one alias is not
bypassed through another. Secret identities require returned creator UIN;
COS uses the bucket's AppId namespace, without converting it into a UIN. COS
object-prefix grants retain their actual scope; overlapping subset denies remain
conditional. Missing inventory, attachment/group detail or policy reads suppress
allow conclusions. Reanalysis replaces generated decisions and preserves source
inventory. No forbidden cloud action is requested by this analyzer.

These results describe collected identity-policy matches. Resource policies/ACLs,
permission boundaries, session constraints, role trust and cross-account access
are not included in an effective-access conclusion. Root-principal default access
is not inferred. Remaining AWS permission-map targets include database query/admin,
container command execution, stack operations and managed-session preconditions.
Exposure/resource-policy analysis and complete Tencent policy syntax remain open.
References: [CAM evaluation](https://intl.cloud.tencent.com/zh/document/product/598/10605),
[COS object resources](https://cloud.tencent.com/document/product/436/112225),
[secret resources](https://intl.cloud.tencent.com/ind/document/product/598/57154),
[role passing](https://cloud.tencent.com/document/product/1242/49730).

### Configured load-balancer exposure links

The AWS source's ELBv2 exposure phase loads EXPOSE relationships to configured
instance/function/load-balancer/private-IP targets; it does not establish public
network reachability. Tencent now adds EXPOSE links from collected CLBs to explicit
CVM backends and uniquely corroborated ENI address/CVM targets. Each path also
retains its listener/rule, raw backend and target through `clb.exposurepath` nodes.
Distinct frontends remain separate paths even when their direct EXPOSE edge merges.

All nodes must share account/region; current resolution requires an explicit,
unambiguous common VPC. IP targets must agree with the reported target address;
instance resolution additionally requires a unique collected ENI attachment.
Foreign/intermediate frontend scope, conflicting IPs, duplicate matches and
uncollected backends cannot produce exposure links. Unresolved configured backends
mark analysis partial while preserving other confirmed paths. Reanalysis removes
stale generated paths/edges, and graph cycles terminate.

This runs after collection and in offline analyze. It does not probe or infer
public access, firewall passage, application success or health. Cross-VPC targets,
additional Tencent target types, target-group depth and COS public/resource-policy
analysis remain open. Source evidence: read-only checkout
`cartography/intel/aws/ec2/load_balancer_v2s.py`, including the separate IP-target
phase and non-IP MatchLinks.
