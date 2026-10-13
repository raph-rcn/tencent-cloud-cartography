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

## Completion rule

CAM now collects group membership, user/role/group attachments, local policies and attached preset policies, with parsed policy and role trust statements. Conditions, deny effects and exact principal expressions remain visible. Numeric UIN identities are resolved only when their owning UIN is explicit; AppIds and wildcards are not guessed. These configuration relationships do not establish effective permissions. Permission boundaries, federation inventory, credential metadata and applicable permission analyses remain gaps.

A registered action, mapping row, green unit test, or icon does not on its own establish parity. Each audit item must have corresponding native collection, model/relationship behavior, tests for failure and negative controls, and runtime evidence appropriate to that capability. Keep this audit incomplete until those checks hold for the original scope.
