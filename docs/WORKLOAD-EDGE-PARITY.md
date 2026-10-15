# Container, serverless, gateway and edge metadata — v0.9.0

The collector remains **read-only and metadata-only**. This release adds **34
audited read operations**, bringing the exact allowlist to **350 operations**.
All **356 registered resource kinds** resolve to bundled official Tencent assets.
Collection runs against each configured project, account and selected service
scope. Account-specific API permission and availability remain visible in coverage.

## Disposition of the 13 requested areas

| Tencent counterpart | Implemented metadata and relationships | Remaining boundary |
|---|---|---|
| TCR Enterprise / Personal | Existing owned namespaces/repositories/tags/digest summaries; new immutable-tag rules, namespace retention filters/schedules, retention execution/task counts and registry CIDR access policies. Enterprise image summaries retain the returned KMS signature, without validating it. Personal Edition keeps its native tag identity | `DescribeImageManifests` returns image configuration alongside the manifest. It is never requested. Platform/index membership and a complete supply-chain graph cannot be established from tag/digest summaries; Enterprise controls are not invented for Personal Edition |
| TCR image summaries | Explicit flags state that manifest membership, layers, configuration and attestations were not collected. A returned signature is evidence of a provider field, not verified signing, provenance or attestation | No layer/configuration downloads, registry token acquisition or artifact-body reads. No safe attestation or platform-membership census was established in the audited API surface |
| TCR replication / acceleration | Existing replication policies/configured endpoints and acceleration settings; new replica-instance identities, policy execution and task status/count/source/destination metadata. Requests use collected registry/policy/execution IDs | Provider-reported successful tasks are not independently verified replication. Native replication/acceleration do not establish AWS pull-through-cache rules; the capability gap remains visible |
| TKE / TCSS | Existing workload Table summaries and TCSS posture; new virtual-node pools, labels/taints, subnet allocation, virtual-node phase/subnet, cluster routes, controller enablement and encryption status | Workload definitions, owner references, volumes, service accounts and full per-workload networking remain unavailable. Raw workload and TCSS container responses contain command/environment data; metadata responses containing last-applied workload annotations are not a safe workaround |
| TKE | Existing four-kind paginated Kubernetes RBAC inventory and cloud common-name/authentication mappings; new `DescribeUserPermissions` for individually collected CAM user UINs, retaining native cluster/role/namespace/custom-role settings | User permission results do not prove effective RBAC or a complete principal census. Role IDs are not substituted for role UINs. Ordinary node/node-pool APIs include user scripts and remain blocked. Missing CAM or Kubernetes permissions remain gaps |
| SCF | Existing functions/versions/aliases/triggers/layer inventory; new async retry/TTL settings, reserved/provisioned concurrency and trigger schedules, custom-domain path rewrites, certificate/WAF references and exact function/version/alias joins. Offline CAM analysis now evaluates `scf:InvokeFunction` against native namespace/function QCS identities | `GetFunction` includes environment/source; `GetLayerVersion` returns a code download capability. Function execution role/VPC/image and layer usage remain unavailable from safe summaries. Identity-policy decisions do not prove invocation access, resource-policy equivalence or successful execution; no function is invoked |
| API Gateway | Existing services/APIs/backends/releases/environments/domain mappings; new service/API environment quotas, dedicated-instance inventory and instance placement. Existing WebSocket register/cleanup/transport SCF integrations remain distinct | Upstream detail includes authentication headers; application summaries include application secrets. Neither is requested. Backend references, quota and deployment configuration do not prove reachability or authorization |
| API Gateway / Cloud Native gateway | New TSE Cloud Native gateway inventory, groups, nodes, typed protocol/port lists and lightweight services with upstream targets/SCF references. Exact collected CVM/function and VPC/subnet relationships; native HTTP/WebSocket fields preserved | Full Kong route lists include header/query match values that can contain credentials; certificates contain private keys and service sources contain passwords/tokens. These reads remain blocked. Lightweight service metadata is not a complete route/authentication policy census or AWS API Gateway v2 equivalence |
| CDN / EdgeOne | Existing limited CDN certificate-deployment view. New global EdgeOne sites, alias domains, default certificate metadata, site-level cache/TTL/cache-key/compression, HTTPS redirect/HSTS/TLS/HTTP2/QUIC/WebSocket settings and DDoS configuration | Traditional CDN full listing includes credential/private-key-bearing origin configuration. EdgeOne acceleration-domain/origin-group lists include private authentication parameters. They remain blocked. Site-level settings do not cover every per-domain/per-rule cache override, full WAF policy, origin or distribution; alias configuration is not a verified DNS answer |
| CIAM | Existing user-store summaries; a separate unsupported capability record now makes missing application/federation depth visible | No safe application/client/provider/federation census was established in the audited CIAM public API/SDK. User-store `AppNum` is a count, not application inventory. No console scraping, user/profile data or token acquisition substitutes for this missing interface |
| Simple Email Service | Existing sending-domain identities/DKIM DNS checks; new individual sender addresses, display names, creation time and SMTP password **type**, with exact collected sending-domain links | Sender listing does not expose an individual DKIM verification state. Native domain DKIM checks are not AWS identity/selector semantics. SES runs only in Guangzhou, Hong Kong or Singapore through its existing region-specific endpoints; Frankfurt remains explicitly unsupported |
| TDMQ CMQ topics | Existing topic/subscription detail, native protocol, notification strategy/content format, filter keys and configured HTTP/queue destinations; explicit unknown resource-policy/encryption/confirmation fields and capability coverage | No established AWS encryption, confirmation or delivery-policy correspondence is asserted. Configured notification settings do not demonstrate successful delivery; no messages are published or received |
| TDMQ CMQ queues | Existing retention/visibility/transaction/dead-letter/backlog configuration and exact same-owner queue links; explicit unknown encryption/resource-policy state and unestablished FIFO/deduplication correspondence | Missing fields are not interpreted as disabled encryption or unrestricted policy. Queue names and native transaction settings do not establish AWS FIFO or deduplication semantics |

All feasible additions identified in this API audit are implemented. The boundaries
above are retained gaps, **not completed AWS parity**. Live Tencent collection and
effective authorization/delivery remain unverified. API counts are not a parity
percentage. The [machine-readable source comparison](aws-parity-audit.json) keeps
every affected AWS collector unverified.

## Use across projects

The new reads run automatically with their selected services. TSE is regional;
EdgeOne uses its global site scope. Existing project/profile/account isolation,
region discovery, atomic snapshots and partial-coverage handling apply.

```bash
./landscape/local.sh sync --project YOUR_PROJECT \
  --services cam,tcr,tke,tcss,scf,apigateway,tse,cdn,teo,ciam,ses,tdmq,ssl
```

For an explicit Frankfurt collection, SES will report unsupported rather than
silently querying another region. Use a separate project/region restriction for
SES in `ap-guangzhou`, `ap-hongkong` or `ap-singapore`. Global EdgeOne inventory is
still global when Frankfurt is selected.

TKE user-permission expansion requires collected CAM users; a missing principal
inventory is not replaced by guessed UINs. Existing `--kube-context` bindings are
still required for Kubernetes RBAC and workload Table summaries. SCF invocation
analysis works offline with collected CAM policies using `analyze`; it never
calls `Invoke`, `InvokeFunction`, creates a token or changes a cloud resource.

The [exact operation manifest](api-actions.json) is the permission-review surface,
not a ready-to-deploy CAM policy. Capability records prefixed `capability:` are
local coverage explanations and never API calls.

## Audited interfaces and sources

Request/response projections are checked recursively against the native SDK from
the isolated TCCLI runtime. Known mixed responses are denied by the exact
allowlist before any request is sent; post-response filtering is not used to
justify requesting a blocked API.

- [TCR native data structures](https://cloud.tencent.com/document/api/1141/41603): immutable/retention/replication metadata; [replication execution inputs](https://cloud.tencent.cn/document/api/1141/137093).
- [TKE virtual-node metadata](https://cloud.tencent.cn/document/product/457/85351) and [native types](https://cloud.tencent.cn/document/api/457/31866).
- [SCF policy syntax and function QCS identity](https://cloud.tencent.com/document/product/583/47934).
- [TSE gateway types](https://cloud.tencent.com/document/api/1364/54942) and [gateway node query](https://intl.cloud.tencent.com/ind/document/product/1290/79262).
- [EdgeOne API catalog](https://cloud.tencent.com/document/product/1552/80731), [site acceleration settings](https://intl.cloud.tencent.com/ind/document/product/1145/68149?has_map=1) and [response types](https://cloud.tencent.com/document/api/1552/80721).
- [CIAM public API introduction](https://cloud.tencent.com/document/api/1441/75533); audited `ciam.v20220331` client exposes user-store/user/group/job/log operations, not an application/client/provider census.
- [SES sender listing, Guangzhou/Hong Kong](https://cloud.tencent.com/document/product/1288/51050) and [Singapore](https://intl.cloud.tencent.com/document/api/1084/39404).

Validation evidence and retained live checks are recorded in [VALIDATION.md](VALIDATION.md).
