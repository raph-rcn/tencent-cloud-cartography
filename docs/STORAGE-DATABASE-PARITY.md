# Storage, database and secret metadata parity

Version **0.7.0**, 2026-10-15. All cloud operations remain **read-only** and
**metadata-only**. This extension adds **37 exact reads**, for **270 allowlisted
operations**. All **265 registered kinds** resolve to bundled official Tencent
assets. It does not retrieve object contents, database rows, credentials, query
results, secret values or TcaplusDB schema files.

## Requested capabilities and disposition

| Tencent counterpart | Implemented metadata | Remaining boundary or provider difference |
|---|---|---|
| COS | Existing V2 SCF/CKafka notifications and renewable verified authentication; new bounded named-object ACL reads, current-object named and anonymous analysis, explicit/default/directory inheritance, version-specific anonymous ACL analysis and offline declared session-policy restrictions | Unselected objects and missing directory ACLs remain unknown. Selected keys are not a complete object inventory. Resource-only grants interacting with implicit permission-boundary denial remain unknown. Actual STS policies and dynamic effective authorization are not inferred from temporary credentials. Notification delivery and runtime access remain unverified |
| COS account summary | Selected-region bucket controls, completeness flags and selected object ACL/decision counts | No audited global account-block API equivalent is established. `global_block_state_verified=false`; an unsupported-equivalence coverage record remains. A bucket summary is not a global protection switch |
| TcaplusDB | Existing CloudRC-scoped table groups plus paginated backup metadata and native snapshot metadata for discovered numeric cluster IDs; snapshot-to-table references use explicit cluster/group/table identities | `DescribeClusters` returns passwords; `DescribeTables` returns IDL contents. Both stay blocked. Artifact-derived table references do not establish a complete table/index/schema inventory or DynamoDB model equivalence |
| MySQL / PostgreSQL / SQL Server / MariaDB | Existing instance/SSL/SG/backup/HA/replica depth plus MySQL cloud-disk cluster nodes/addresses, backup encryption and summaries for all three product variants, binlog retention and backup-download restrictions; PostgreSQL proxies/nodes/addresses/routes and independent proxy SSL configuration; SQL Server configured parameters, regional backup summary and read-only group/member configuration; MariaDB backup schedules/retention | Unrestricted MySQL/MariaDB parameter APIs can return SQL workload configuration; credential-bearing backup listings stay blocked. AWS option-group and IAM database-connect semantics are not invented. Native parameter/cluster/replica fields retain their product meanings |
| TencentDB Redis | Known parameter settings; native replication group/member configuration and per-instance membership; automatic backup configuration, retained backup metadata, password-policy requirements, existing SSL/shards/nodes/SG data | Numeric AppId/region/VPC fields are not translated into UIN/canonical region/VPC identities. Group members alone do not assert cross-account ownership. Unknown parameter names are excluded and counted. Backup reads explicitly include in-progress and successful states, retain the provider's default time window, and do not claim all historical backups |
| CDWPG / DLC | CDWPG database account privileges, ordered HBA selectors/methods and native nodes; DLC users in TencentAccount and EntraAccount namespaces, workgroups, fully paginated data/engine grants and memberships, catalog VPC access, third-party user identity and current third-party-platform subuser policy; exact collected engine/member references | These are configured grants, not successful query authorization. No database credential/token acquisition, role assumption or query is performed. DLC row-filter expression/runtime semantics, Redshift credentials and identical warehouse semantics are not asserted |
| Elasticsearch Service | Existing native endpoints/IP ACL/security flags plus HTTP request-path policy, automatic COS backup strategies and all-time manual/automatic snapshot metadata | Request paths are not AWS principal access policies. Free-form ES/Kibana config and log contents are not collected by the new APIs. No safe equivalent is established for the remaining AWS logging/policy fields; raw config stays unretained |
| CFS | Existing filesystem/mount/export permissions plus paginated snapshots, automatic snapshot policies and lifecycle rules/path associations, with explicit same-account/region filesystem references | Native export squash modes and lifecycle paths are not EFS access-point POSIX UID/GID/root enforcement. Missing or deleted filesystems remain references. KMS ARN translation and effective client behavior remain unverified |
| Secrets Manager | Rotation history version IDs and database-account status/host/time metadata, visible truncation, existing version ID/time/current KMS data and broader exact product/resource links for collected PostgreSQL, SQL Server, MariaDB and MongoDB alongside MySQL/Redis/CAM associations | Account `Version` is a native account-status label, not an AWS version stage or a secret version ID. No historical KMS, replication/primary region or rotation-function fields are exposed by the audited version/history schemas. Supported product linkage is only resolved when matching native product and exact collected identity are present; no support is inferred from a display name |

**These nine areas have feasible implementation additions and explicit limits. Full
AWS equivalence and live-account behavior remain unverified.** Unsafe retrieval
restrictions and absent provider equivalents cannot be closed by assigning guessed
fields or treating an API response as proof of access.

## Collect selected object ACLs

Ordinary sync collects bucket configuration only. Supply literal object names to
add bounded ACL metadata reads; the tool never lists objects to discover targets.
A maximum of 256 selections is accepted, with duplicate identities rejected.
Leading-slash/dot-segment keys and policy wildcard characters are rejected to avoid
ambiguous scope. Missing/denied/nonexistent ACL reads remain visible failures.

Create `object-acls.json` with your verified account UIN and real bucket/key names:

```json
[
  {"account":"100000000001","region":"eu-frankfurt","bucket":"assets-1250000000","key":"docs/"},
  {"account":"100000000001","region":"eu-frankfurt","bucket":"assets-1250000000","key":"docs/report.pdf"},
  {"account":"100000000001","region":"eu-frankfurt","bucket":"assets-1250000000","key":"archive.pdf","version_id":"VERSION_ID"}
]
```

```sh
tencent-cloud-cartography sync --project my-environment \
  --cos-object-acls object-acls.json
```

Each selection must belong to an enriched bucket in the verified profile's
selected region scope. Entries without a verified matching account are reported
as not queried. File/directory ACLs, their grants and analysis stay in the full
graph. A provider `x-cos-acl: default` header is authoritative for inheritance;
otherwise an explicit ACL document overrides bucket ACL grants. An empty default
ACL on a nested object requires every intervening directory's metadata before
falling back to bucket configuration. Missing evidence is unknown, including 404s.

Versioned reads use a fixed signed `GET ?acl&versionId=...` query. The SDK's object
ACL helper maps `VersionId` into a header, so this adapter constructs the fixed
query through the official signing transport. ACL XML parsing rejects DTDs,
entities, unexpected namespaces, malformed singleton fields and oversized bodies.
Object ACL `FULL_CONTROL` maps to read/ACL operations; it never grants object
upload or deletion. Bucket policy explicit denies retain precedence.

Analyses apply to the default COS endpoint configuration. CDN/custom-domain
behavior is not established. A private object ACL is not an explicit CAM-policy
deny. Named current-object analysis composes the collected identity, resource,
boundary and supplied session restrictions. Version-specific selected ACL
analysis is anonymous; general named prefix decisions remain conservative where
object overrides are unknown. `effective_access_verified=false` throughout.

## Declare an offline session policy

The CLI does not obtain a temporary key to discover its restrictions. You can
provide an existing nonsecret policy document for a collected CAM principal:

```json
[
  {
    "account":"100000000001",
    "kind":"cam.role",
    "principal_id":"12345678",
    "policy": {
      "version":"2.0",
      "statement":[{
        "effect":"allow",
        "action":["name/cos:GetObject"],
        "resource":["qcs::cos:eu-frankfurt:uid/1250000000:assets-1250000000/docs/*"]
      }]
    }
  }
]
```

```sh
tencent-cloud-cartography analyze \
  --input .local/projects/my-environment/inventory.json \
  --output .local/analysis.json --session-policies session-policies.json
```

The manifest must contain one policy per exact collected principal. It contains
no keys, tokens or login state. A supplied session policy intersects the signed
COS decision: it can restrict access and cannot create a base permission. Explicit
deny wins, missing allow denies, and unresolved conditions remain conditional or
unknown. An unsigned route is evaluated independently. The graph labels the
policy `operator_declared_hypothetical_session`; it is not evidence that the actual
live session carries that policy. Declarations persist for offline re-analysis; an explicit empty manifest `[]`
clears prior declarations.
`--context` remains an optional allowlisted nonsecret request-attribute file.

## Collection and identity guarantees

Every new operation has its own coverage record. Denied, unsupported, malformed,
changing-total, duplicate-page and identity-mismatch responses remain partial;
independent operations continue. Pages validate selected rows before publication.
Single-response APIs validate totals where the native contract supplies them.
Elasticsearch snapshots explicitly request `Duration=0` and all creation methods.
SSM history exposes at most ten provider-visible versions; a larger advertised
total is preserved as a truncation error, never silently completed.

Graph reconstruction is deterministic. Derived links are rebuilt after collection
and offline import, with exact account/region scoping. DLC native identities are
separate from CAM principals. Membership namespace matters; a shared user name
across TencentAccount and EntraAccount does not merge users. Ambiguous engine names
remain unresolved. AppIds are never promoted into owner UINs. No new secret value,
workload-valued parameter, schema-content or log-content operation is allowlisted.

## Primary contracts

- [COS ACL operation sets, default inheritance and endpoint caveat](https://cloud.tencent.com/document/product/436/30752)
- [GET Object ACL response](https://intl.cloud.tencent.com/document/product/436/7744)
- [COS Python ACL SDK](https://cloud.tencent.com/document/product/436/44355)
- [MySQL backup summary product scopes](https://cloud.tencent.com/document/product/236/41228)
- [Redis parameter metadata](https://cloud.tencent.com/document/product/239/34448)
- [SQL Server parameters](https://cloud.tencent.com/document/api/238/59108)
- [CFS lifecycle policies](https://cloud.tencent.com/document/product/582/122046)
- [DLC subuser access policy](https://cloud.tencent.com/document/product/1342/107092)
- [SSM rotation-history ceiling](https://intl.cloud.tencent.com/document/product/1078/41516)

The isolated native TCCLI SDK contracts are checked recursively for every field in
all declarative reads, including nested arrays. APIs absent from the older
international SDK still use the native signed transport and exact allowlist.
See [API permission inventory](api-actions.json), [implementation evidence](VALIDATION.md)
and [per-source-collector audit](aws-parity-audit.json).
