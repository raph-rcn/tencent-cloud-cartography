# Platform, security and authorization metadata parity

Version **0.8.0**, 2026-10-15. This release adds **46 exact metadata reads**, for
**316 allowlisted cloud operations**. The asset checker verifies **896 official
SVGs, the official wordmark and 322 kind mappings**. Collection remains read-only
and metadata-only. No cloud mutation, token issuance, role assumption, workload
execution, object content, SQL query or secret retrieval is added.

This report supersedes the older broad gap descriptions for the **15 requested
platform areas**. It records implemented metadata separately from excluded
responses, provider differences and remaining unverified semantics. It does
**not** claim complete AWS parity. A live account can still deny a read, lack an
entitlement or expose a different supported API version; coverage records retain
those failures. No authenticated Tencent validation was performed for this release.

## Requested capabilities and disposition

| Area | Implemented configuration and analysis | Exact remaining boundary |
|---|---|---|
| CAM / COS / Kubernetes analysis | Nonsecret numeric/string COS request conditions, explicit absent-header semantics, qualified tag equality, collected resource-tag evidence; declared session restrictions now constrain CAM permissions, caller AssumeRole and supported role-path permission decisions. Fixed GET lists collect Roles, ClusterRoles, RoleBindings and ClusterRoleBindings; graph rules, subjects, namespace-scoped configured grants, aggregation selectors and exact reviewed-principal matches are rebuilt offline | Unknown keys/operators, unreviewed service/tag applicability, policy variables, empty tag-set semantics and joint condition satisfiability remain unknown. Collected tags cannot be overridden through operator context. Federation/service/workload principals do not become named CAM callers. Declared policies are hypothetical restrictions, not observed STS sessions; policies are never automatically carried across role hops. RBAC grants do not cover other authorizers, admission, authenticators or actual execution |
| DNSPod / Private DNS | DNSPod aliases/share grants and separately paginated shared domains; shared ownership requires matching native domain ID/name and explicit owner UIN. Private DNS forwarding rules, inbound services, explicit regional VPC/subnet relationships and outbound endpoint references; exact collected managed endpoint-host matches | A share listing/account label is not ownership evidence. Missing/denied owner detail leaves a query view. Outbound detail has no usable public response schema in the audited SDK. Cross-zone/forwarding precedence, routing-line/client/caching behavior and actual resolver answers are unverified; no longest-match or AWS Route 53 resolver ordering is invented |
| SSL Certificates | Additional list-time lifecycle, hosting, issuer/SAN and renewal metadata; deployed resource IDs/domains from `DescribeDeployedResources`; unique same-account consumers resolve to collected resources | Private-key-bearing certificate detail calls remain blocked. Unsupported consumer types and identities ambiguous across collected regions remain metadata without guessed edges. Deployment does not prove a successful TLS handshake or complete consumer inventory |
| CWP / TCSS assessment coverage | Vendor asset/image/compliance coverage counters, scan timestamps/settings, image/vulnerability/malware scan scope, four native TCSS compliance asset classes and policy-item summaries | Container list/detail return `Cmd` and remain blocked. Vendor counters are not independently reconciled assessments, proof of protection, or an AWS Inspector coverage denominator |
| CSIP / CWP / TCSS findings and controls | CSIP rule definitions/compliance standards, TCSS compliance results and public CWP CVE/CVSS descriptions/repair guidance; existing finding summaries and asset links remain available | CSIP alert bodies can contain leaked bytes, secrets and payloads. They remain blocked. A public vulnerability definition is not a host finding body. Integrations/control meanings retain Tencent semantics; AWS Security Hub control equivalence is not asserted |
| CSIP / CWP / TCSS detector features | Vulnerability/image/virus scan settings and scope, CSIP scheduled/incremental scan settings, posture/coverage summaries and rule catalog | Settings/counters do not establish detection efficacy or a complete GuardDuty-like detector-feature census. Unsafe alert bodies stay excluded; product-specific licensing and live scan success remain unverified |
| CloudConfig | Aggregator lists, explicit owner-scoped aggregator details/accounts, aggregate delivery and account-member links; configured destination identity and exact canonical custom SCF references | Audited recorder/delivery/aggregator schemas expose no execution-role or encryption-settings equivalent. Native custom-function identity does not establish Lambda invocation/runtime semantics. Delivery and compliance remain unverified; resource snapshots/function source are not fetched |
| CIC / Organizations / CAM | Existing groups/memberships, assignments, role configurations, managed/inline policy bodies and provisioning; additional user-sync detail, public SAML service-provider identity/ACS URL and IdP certificate metadata | CIC `ListUsers`/`GetUser` return passwords and remain blocked, so ungrouped users are not a complete census. Assignment/provisioning configuration is not successful federation or an observed issued session. Public IdP metadata cannot establish complete federation authorization |
| CloudAudit | Regional legacy `ListAudits`/`DescribeAudit` configuration alongside modern trails; destination, encryption-key and notification names retained; exact collected COS destination links | No log bodies, event delivery probe or cloud write is performed. Configured status and destination existence are not validated delivery. Legacy and modern APIs keep their native region/account scope |
| Cloud Monitor / CLS | Product namespace and metric/dimension-definition inventory; 19 documented instance/product dimension mappings for exact resource identities, with owner/region checks and parent-instance labels for node dimensions; existing CLS/Monitor alarm/action/metric configuration | Unsupported/multi-resource dimensions stay unresolved. `DescribeAlarmHistories.Content` may contain workload text and is blocked. Definition/Enable flags are not current ALARM/OK state, action delivery or successful metric evaluation; no samples/log queries are added |
| EventBridge | Existing buses/rules/targets, event patterns, target settings and exact resource references; explicit connection exclusion | `ListConnections` includes DTS passwords and stays blocked. Audited rule/target schemas do not establish AWS scheduler/execution-role correspondence. No schedule/role field is inferred from a rule name, and no connection credentials are requested |
| TI Platform | Billing resource pools now expand to native resource instances/capacity and current running-job identities; exact collected CVM links, notebook/resource metadata retained | Pool jobs are not a complete training/model/service census: serverless/completed/other-pool jobs are outside that query. Native training/service/model-version detail returns environment values, image secrets or auth tokens and remains blocked. Creator SubUin is not an execution role |
| LKE / ADP / TI | Existing applications/shared knowledge/model catalogs plus provider-reported knowledge quota; model availability/catalog/entitlement views explicitly distinguish available models from owned Hunyuan assets | Agent/tool/app detail contains prompts/configuration or application keys and remains blocked. Quota/catalog availability does not prove runtime entitlement or a Hunyuan asset census. No safe owned-asset enumeration was established in the audited Hunyuan SDK |
| WeData / DLC | WeData catalogs, databases, schemas, tables and typed columns; resource-group/project/network relationships alongside existing task/workflow summaries. DLC users/workgroups/grants remain configured metadata | Task source/SQL and credential/query APIs stay excluded. Crawler and Glue job/permission correspondence is not established by catalog listing. Column schemas are metadata; row values are never read. Native DLC grants do not prove query authorization |
| CODING CI | Exact list/detail exclusions and visible unsupported coverage; existing CloudRC references remain references | Audited list/detail responses contain Jenkinsfile content and environment values. No metadata-only projection was established. The tool cannot obtain full pipeline parity under the retained restriction |

A blocked response is **never requested**, including when it could be filtered
in memory afterwards. Provider differences and missing runtime evidence are not
closed by fabricated AWS-shaped nodes or a percentage derived from API counts.
The per-collector [AWS audit](aws-parity-audit.json) retains unverified parity.

## Use the new collectors

Existing named project/profile/region settings continue to work. The new reads
run automatically when their services are selected; denied scopes are isolated.
For example, to restrict collection to Frankfurt and the selected global APIs:

```bash
./landscape/local.sh sync --profile default --regions eu-frankfurt \
  --services cam,dnspod,privatedns,ssl,cwp,tcss,csip,config,organization,cloudaudit,monitor,cls,eb,tione,lke,wedata,dlc \
  --output inventory.json
```

Global services use their global scope. Regional services honor the selected
region or the saved project's discovery configuration. The mandatory CloudRC
baseline remains enabled. The [API inventory](api-actions.json) lists the complete
permission-review surface; it is not a deployable CAM policy.

For Kubernetes RBAC, explicitly bind an existing context to an already collected
TKE cluster. The endpoint must match collected metadata and TLS is verified:

```bash
./landscape/local.sh sync --profile default --regions eu-frankfurt \
  --services tke,cam \
  --kube-context ACCOUNT_UIN/eu-frankfurt/cls-CLUSTER_ID=EXISTING_CONTEXT \
  --analysis-limit 25000 --output inventory.json
```

Only the four RBAC list endpoints return RBAC objects. Workloads still use fixed
Table requests with `includeObject=None`; secrets, pod bodies and manifests are
not requested. RBAC metadata retains policy rules/subjects/selected labels and
ignores annotations. Stable resourceVersion, cursor/duplicate checks and exact
cluster/namespace identities protect collection. Missing roles retain reference
edges and partial coverage. Aggregation selector edges record configuration;
the collector uses the API's actual role rules and never synthesizes additional
controller permissions. Configured grants retain `effective_access_verified=false`.

`analyze` rebuilds these graph links and authorization results offline:

```bash
./landscape/local.sh analyze --input inventory.json --output analyzed.json \
  --context request-context.json --session-policies sessions.json
```

See [authorization](AUTHORIZATION.md) for context and declared-session semantics.
No credentials should be placed in either file. The default grant/decision budget
is 25,000 per phase; exhaustion remains partial and source metadata is preserved.

## Additional storage/database closure

The earlier [nine-area guide](STORAGE-DATABASE-PARITY.md) remains applicable.
This release additionally reads MySQL parameter-template descriptors, proxy
capabilities/custom resource sizing, SSM's supported-product catalog and TcaplusDB
tags for already identified cluster/group/table identities. These do not retrieve
parameter SQL, passwords, secret values, IDL or database rows. TcaplusDB snapshot
references still do not constitute a complete table census.

## Evidence and limits

Response projections and request scopes are tested against explicit provider
fixtures; recursive field types are checked against the isolated native SDK.
Tests include denied/foreign scopes, duplicate and changing inventories, malformed
RBAC, unresolved/ambiguous ownership, namespace limits, session denies and offline
idempotence. See [validation](VALIDATION.md) for final test/build/browser/CI evidence.

Native response contracts were audited with **TCCLI 3.1.181.1 / SDK 3.1.188**.
The native transport supports audited APIs absent from the older international
SDK. This is an implementation contract check, not an authenticated API test.

Primary references:

- [CAM condition types](https://cloud.tencent.com/document/product/598/10608),
  [COS conditions](https://cloud.tencent.com/document/product/436/71306) and
  [COS tag-set examples](https://cloud.tencent.com/document/product/436/71307).
- [SCF canonical resource syntax](https://cloud.tencent.com/document/product/583/47934).
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
- [Private DNS forwarding](https://cloud.tencent.com/document/product/1338/127647)
  and [native Private DNS schema](https://intl.cloud.tencent.com/zh/document/product/1097/42124).
- [Monitor policy dimensions](https://intl.cloud.tencent.com/ko/document/product/248/39565).
- [WeData API catalog](https://cloud.tencent.com/document/product/1267/123653)
  and [native metadata schemas](https://cloud.tencent.com/document/api/1267/123643).
- [Official native SDK source](https://github.com/TencentCloud/tencentcloud-sdk-python).
