# Metadata depth: implemented contracts and retained exclusions

The current [storage/database/secret metadata extension](STORAGE-DATABASE-PARITY.md)
(version 0.7.0) adds bounded COS object ACL/inheritance and declared session
analysis, database proxy/cluster/backup/parameter depth, DLC/CDWPG grants,
CFS snapshots/lifecycle and secret rotation history. Its nine-row disposition
supersedes older gap descriptions for these areas. The read-only metadata
restriction, provider differences and unverified live behavior remain explicit.

Updated 2026-10-14. This extension implements the feasible audited contracts for
COS notifications, relational database depth, API Gateway backends and federation
metadata. It adds 23 exact read operations (216 total). It does not establish full
AWS equivalence or live provider behavior. The operator retained metadata-only
collection; server responses containing secrets or workload content remain blocked.

## COS notifications

`cos.get_bucket_notification` uses the official Python SDK's verified HTTPS,
signing and timeout transport with a fixed `GET /?notification&notify-type=2`.
The SDK has no notification convenience method, so a bounded XML parser handles
this fixed response without evaluating text, DTDs, external entities or arbitrary
URLs. V2 includes both SCF and CKafka rules; the older default query omits Kafka.

Rules retain ID, events, prefix/suffix filters and configured destination/role
identifiers. A whole response is validated before adding rules. Empty successful
configuration is explicit; denied or unknown missing-configuration errors are not
absence. SCF links require an exact unique collected function, namespace, region
and matching bucket AppId. AppId is never converted into account UIN. Legacy or
opaque function addresses stay unresolved. Qualifiers remain declared metadata;
a base function link does not resolve its alias/version routing. CKafka links
require exact instance/topic names in the same account/region. Explicit same-account
role names link only to unique collected CAM roles. No objects, messages or
notification destinations are requested; delivery is unverified.

Reference: [COS V2 notification contract](https://cloud.tencent.com/document/product/436/131249).

## Database depth

| Engine | Additional implemented configuration |
|---|---|
| MySQL | Backup windows and retention/archive/standby settings; remote backup region lists; primary/standby replication/deployment configuration; proxy groups, nodes, addresses and network settings; read-only groups and explicit regional member references |
| PostgreSQL | Backup plans; primary/standby HA thresholds; read-only groups and members; twelve fixed named parameter checks; paginated base/log backup metadata with retention, state, size and time fields |
| SQL Server | Independent security groups; instance attributes including archive-backup retention/strategy, TLS and TDE status, replica-read endpoint settings and explicitly historical old addresses |
| MariaDB | Independent security groups, log retention and DCN peer/status/encryption flags |

These supplement existing native instance/network/encryption inventory and Redis
SSL, security-group, shard and replica checks. Proxy/replica metadata does not
invent cluster ownership, KMS identity or effective connectivity. Read-only members
outside selected regions remain references; no extra region is queried to enrich
them. Malformed or denied detail scopes remain visible and do not stop independent
checks. SQL Server TDE certificate ownership is not a KMS-key identifier.

PostgreSQL parameter requests must name one of `max_connections`, `shared_buffers`,
`work_mem`, `maintenance_work_mem`, `statement_timeout`,
`idle_in_transaction_session_timeout`, `wal_level`, `max_wal_senders`,
`synchronous_commit`, `log_statement`, `log_min_duration_statement`, or `ssl`.
The transport rejects unrestricted requests and other parameter names. Returned
names and counts must agree with the query. Missing parameters remain unavailable.
This is a selected parameter inventory, not complete parameter-group equivalence.

PostgreSQL backup metadata is obtained separately from download URLs. The default
seven-day lower time bound is overridden with `1970-01-01 00:00:00`; the provider's
current-time upper bound applies. Totals, duplicates and instance identity are
checked. These are metadata for returned retained backups, not downloaded backups
or independently verified recoverability. API rejection of the wider interval is
visible failure; there is no silently narrower fallback.

Retained exclusions:

- MySQL `DescribeInstanceParams` and MariaDB `DescribeDBParameters` expose
  unrestricted values, including `init_connect` SQL configuration, without an
  audited server-side field projection.
- MariaDB `DescribeDBEncryptAttributes.CipherText` returns a DEK.
- MySQL/SQL Server backup listing responses contain download capabilities;
  PostgreSQL `DescribeBackupDownloadURL` is also blocked. No URL is followed.
- AWS IAM database-connect, query authorization and provider-specific option-group
  semantics are not recreated by these configuration checks.

References: [MySQL configuration](https://cloud.tencent.cn/document/product/236/17491),
[PostgreSQL selected parameter contract](https://cloud.tencent.com/document/api/409/63344),
[PostgreSQL backup contract](https://cloud.tencent.com/document/api/409/89022),
[SQL Server attributes](https://cloud.tencent.com/document/product/238/90299).

## Gateway backends

Domain mappings use `DescribeServiceSubDomainMappings`: the default-mapping flag
is explicit, and custom path/environment rows create scoped mapping relationships.
Paths are unique per domain and environments are restricted to documented values.
Default mapping does not fabricate custom rows or prove deployment.

Existing HTTP integration metadata now resolves CVM/CLB backends only by declared
product, exact literal IP, one collected backend, account, region and matching VPC.
DNS names, duplicate addresses, missing VPC evidence and foreign scopes remain
unresolved. No DNS lookup or HTTP probe is performed.

Explicit upstream IDs create reference nodes. The separate safe
`DescribeUpstreamBindApis` operation collects paginated binding metadata with
service/API composite identity, preserving bind time and provenance. It does not
claim that upstream node configuration was collected. `DescribeUpstreams` remains
blocked: `HealthChecker.ActiveRequestHeader.Value` can contain credentials and the
schema provides no server-side field projection. TSF microservice cluster/namespace/
name references, load-balancing and health-check scalar settings are retained from
the existing API detail response; no TSF cluster or workload is inferred.

References: [Gateway API overview](https://intl.cloud.tencent.com/ko/document/product/628/36595),
[official SDK response models](https://github.com/TencentCloud/tencentcloud-sdk-python-intl-en/blob/master/tencentcloud/apigateway/v20180808/models.py).

## Federation metadata

CAM SAML provider details and CIC public encoded SAML metadata are parsed into
entity IDs, declared validity, sanitized SSO endpoints, public certificate SHA-256
fingerprints and certificate validity dates. Raw XML, encoded documents and PEM
bodies are not saved. Parsing is bounded and rejects DTDs/entities, invalid
certificates, unexpected roots and contradictory CIC entity identity. URL queries,
fragments and embedded credentials are excluded. Existing user-OIDC configuration
also retains scope and sanitizes its identity/authorization endpoint URLs; key
material is omitted.

Exact declared `federated` SAML provider QCS expressions link to collected provider
identities, including references in deny statements. These links do not grant
access or demonstrate successful federation.

CIC adds permission-configuration details (including session duration and sanitized
relay state), paginated deployment status (`Deployed`, `DeployedRequired`,
`DeployFailed`) and user/group synchronization settings. Explicit target UINs and
principal IDs link to reference identities/accounts without collecting or assuming
a role in those accounts. Documented `rc-` and `up-` configuration IDs are supported.

System policy documents are queried through CAM `GetPolicy` using returned numeric
policy IDs and exact policy-name matching. Missing IDs or a service selection that
excludes CAM leave documents unavailable. Counts/cursors/duplicates and configuration
identity are checked before each page is published. Previously collected valid
pages survive a later failure with incomplete coverage.

Full user APIs that return passwords and SCIM credential APIs stay blocked. No SSO
session, assertion, token or federation login is requested. Authentication-provider
refresh and full effective federation/session semantics remain separate work.

References: [SAML provider management](https://cloud.tencent.com/document/product/598/30291),
[declared federation principal](https://cloud.tencent.com/document/product/598/19381),
[CIC provisioning](https://intl.cloud.tencent.com/pt/document/product/1031/63598),
[CIC response structures](https://intl.cloud.tencent.com/zh/document/product/1031/52067).

## Verification

Unit tests exercise fixed signed COS V2 requests and actual XML parsing without
network access, destination identity controls, atomic malformed-response rejection,
database configuration/parameter/backup scope, federation certificates and public
metadata, provisioning pagination, gateway binding identity, ambiguous addresses,
secret-field omission and blocked operations. Added Cloud API actions are checked
against installed official SDK models and TCCLI's offline CLI skeleton generator.

The normal viewer still starts empty without login or synthetic inventory. Browser
checks use an explicit private offline fixture. Live account validation, runtime
service availability, delivery, database access and successful federation remain
unverified. `api-actions.json` remains a permission review inventory, not a deployable
CAM policy.
