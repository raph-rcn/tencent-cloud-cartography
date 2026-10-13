# Validation — 2026-10-13

## Completed

- 36 Python tests: pagination and count controls, operation allowlist, CLI JSON/error handling, retries, COS parser, identity stability, account/region separation, baseline/native reconciliation, secret-field exclusion, full collection with synthetic API responses, graph containment, icon mapping, editable export geometry, private snapshot writes, and HTTP boundaries.
- 5 frontend tests: relationship highlighting, reset, endpoint filtering, empty-boundary filtering, and export hierarchy/icon retention.
- All **896 official SVGs** verified against the pinned archive hashes and XML checks. All registered native services resolve to bundled official assets.
- All 36 native/child collector request and response field layouts inspected against TCCLI 3.1.181.1's installed Tencent SDK, using pinned API versions. This verifies schema compatibility, not account permission or live behavior.
- Browser smoke check using the built UI and synthetic Frankfurt snapshot:
  - Architecture view renders official Tencent icons and VPC/AZ/subnet boundaries.
  - Full graph shows 13 resources and 13 relationships in the fixture.
  - Searching `ins-web` returns one resource.
  - Global-region filter returns one CAM role.
  - Collection coverage shows the deliberate denied Secrets Manager scope.
  - Collapse/expand and fit operate.
  - Full graph draw.io download parsed successfully: 18 editable nodes (including grouping containers), 13 edges, 10 embedded SVGs.
  - PNG download succeeded, 4096 × 2909 pixels in that layout.
  - Icon gallery lists 896 assets; CVM search displays the official product icon.
  - No browser console errors in the inspected run.
- Python lint/format and repository pre-commit checks pass.
- Clean `npm ci`, frontend tests, production build, and `npm audit --audit-level=high` pass. Audit reports zero vulnerabilities after updating the inherited Vitest and transitive packages.

## Remaining external checks

- **Live Tencent sync not run:** the default TCCLI credential was absent. Sign in and run `./landscape/local.sh sync --profile default --regions eu-frankfurt`. Inspect the coverage table for account-specific denials, availability and baseline-only products. Do not treat synthetic tests as a live account validation.
- **Local Neo4j daemon not available:** neither the selected Colima daemon nor Docker Desktop daemon was available. The real database integration is now verified in GitHub CI, as recorded below; no local live-database browser session is claimed.

## Sources used for API behavior

- [Tencent Cloud Resource Center SearchResources](https://cloud.tencent.com/document/api/1791/136441)
- [Resource coverage and latency limits](https://cloud.tencent.com/document/product/1791/115771)
- [CLB DescribeLoadBalancersDetail](https://cloud.tencent.com/document/api/214/46916): relationship fields must be supplied explicitly in `Fields`.
- [Official icon download page](https://cloud.tencent.com/act/event/icons); exact archive and SHA-256 are recorded in the bundled manifest.

## Parity extension — 2026-10-13

- The source audit now enumerates all **66 enabled AWS collector slots**. Full parity is explicitly incomplete; see [PARITY.md](PARITY.md).
- Added 12 native inventory operations plus 2 child operations for compute/network depth. All **50 native/child request and response envelopes** now match the installed pinned-version Tencent SDK models.
- **48 backend tests + 5 frontend tests** pass. New negative controls cover cross-account UIN vs AppId, ambiguous subnet-to-VPC placement, IP/sentinel route next hops, IPv6 route IDs, key/payload omission, launch version identity, ACL direction/order and all new icon mappings.
- Browser validation: unresolved inventory is hidden initially (10 architecture resources), enabling it and full graph shows 13 resources and all 13 relationships. Service components render, and the grouped draw.io download parses with valid parent references and all 13 edges. No browser console errors observed.
- Official icon archive remains **896 verified assets**, with explicit mappings for CCN, Private Link, peering, Auto Scaling and ENIs.
- Live Tencent validation remains outstanding. Contract checks and synthetic tests do not establish account-specific behavior or full AWS parity.

## Neo4j source and refresh — 2026-10-13

- [CI run for `3d839589`](https://github.com/raph-rcn/tencent-cloud-cartography/actions/runs/38386506037) passed all verification jobs, including **5 integration tests against Neo4j 5.26 Community**. No database integration tests were skipped in that job.
- Verified snapshot round-trip with coverage/accounts, preservation of unrelated graph nodes, repeated publication without duplicates, rollback after a forced transaction failure, and a reader retry during concurrent graph replacement. A deliberately corrupted generation is rejected.
- Real HTTP integration verifies an unpublished graph returns 503 and subsequent imports become visible without restarting the viewer. The reader issues only its fixed read queries.
- Browser check of the file-backed viewer: Refresh picked up an atomically replaced synthetic account label without duplicate filter options. Temporarily removing the fixture produced an explicit disconnected/data-unavailable state. Restoring it and refreshing recovered the graph with its original account label and counts. Only the synthetic demo fixture was used and it was restored.

## CAM configuration depth — 2026-10-13

- Added `GetGroup`, `GetRole`, `GetPolicy` and `ListAttachedGroupPolicies`. Request fields and response shapes were checked against the installed CAM 2019-01-16 SDK and official API documentation.
- **75 backend tests** pass. CAM tests cover exact UIN membership identity, shared-policy deduplication, local versus preset policy scope, conditions and deny retention, malformed/duplicate JSON rejection, unsupported syntax, mismatched role IDs, incomplete membership counts, denied detail APIs, and foreign-principal isolation.
- Full graph preserves statement and principal edges with official CAM icons. The architecture view omits these detail nodes. No effective access or role-assumption edges are inferred.
- Browser fixture verified 5 CAM resources and 4 trust/principal relationships in global full graph view, while architecture counts stayed at 10 resources and 3 relationships. Original synthetic snapshot restored afterward. Recovery also clears the accessible status message; the previous hidden toast retained stale error text.
- Full AWS IAM parity and authenticated Tencent runtime validation remain outstanding.

Sources: [GetGroup](https://intl.cloud.tencent.com/document/api/598/32260), [GetPolicy](https://cloud.tencent.com/document/api/598/34574), [role structures](https://cloud.tencent.com/document/product/598/33167), [group attachments](https://cloud.tencent.com/document/api/598/34573), and [CAM policy syntax](https://cloud.tencent.com.cn/document/product/598/10604).

## KMS metadata and encryption configuration — 2026-10-13

- The source KMS collector was inspected directly: it collects described keys, aliases, key policies and grants. Tencent authorization analysis is still incomplete; configuration links do not substitute for it.
- `ListKeys` now queries `Role=0` and `Role=1` independently. Its default previously omitted service-created keys. Each discovered key is described once per region; one denied list category does not suppress the other.
- DescribeKey request/response and retained fields were checked against the installed KMS 2019-01-18 SDK. CBS `Disk.KmsKeyId` and SSM `SecretMetadata.KmsKeyId` field semantics were checked against their SDK models. Snapshot encryption flags do not supply a key ID.
- **88 backend tests** pass, including owner/region separation, creator UIN versus owner UIN, duplicate alias names, false/zero rotation values, mismatched IDs, denied detail calls, explicit versus absent/contradictory encryption metadata, exact CAM resource matching, and blocked plaintext/ciphertext key retrieval calls.
- Keys are resolved only from explicit supported IDs. Unknown formats remain visible as unresolved reference properties. Exact CAM resource references include deny/conditional statements and never create access or decrypt permissions.
- Browser check of a separate synthetic KMS fixture rendered 6 resources, 5 relationships and 4 services with official icons. Architecture view retained only the disk. The draw.io download parsed with 13 editable nodes (including groups), all 5 edges and valid endpoints/parents. The original demo fixture was restored. Frontend tests, build, dependency audit and all 896 icon integrity checks passed.
- Dedicated HSM discovery, broader encrypted-resource coverage and authenticated Tencent runtime validation remain outstanding.

Sources: [ListKeys](https://www.tencentcloud.com/document/api/1030/32184), [DescribeKey](https://www.tencentcloud.com/document/api/1030/32197), [KMS API catalog](https://intl.cloud.tencent.com/document/product/1030/32172), [KMS CAM resources](https://intl.cloud.tencent.com/ind/document/product/598/57129), and [CBS disk fields](https://cloud.tencent.com/document/product/362/15669).

## DNS records and network scope — 2026-10-13

- Compared the source Route53 collector and DNS record models with DNSPod 2021-03-23 and Private DNS 2020-10-28 SDK schemas and official documentation. Added both record-list actions to the metadata API allowlist.
- DNSPod domain inventory explicitly requests owned domains and uses the filtered count. Private zone ownership is checked before insertion. VPC bindings use explicit owner UIN and region; deleted bindings and ownerless shared bindings do not create active associations.
- **106 backend tests** pass. DNS controls cover pagination and duplicate IDs, partial/denied responses, malformed names/records, failed zone enrichment, IDNA, all retained record types, null MX/SRV targets, zero weight, disabled records, subzone nameserver checks, and public/private/account/region/VPC isolation.
- Synthetic browser fixture: **14 resources, 16 relationships, 4 services** in the full graph; **5 resources and 2 relationships** in architecture view. Official DNSPod and Private DNS icons render. The local draw.io export parses with **20 editable nodes including containers and 16 edges**, with valid parent and endpoint references.
- Frontend tests, production build, dependency audit and all 896 icon integrity checks pass. The original demo fixture was restored after browser validation.
- Cross-zone private resolver precedence, additional managed-service aliases, shared public-domain collection and live Tencent verification remain incomplete. No external DNS queries or authenticated cloud calls were used for this validation.

Sources: [DNSPod domain list](https://cloud.tencent.com/document/product/1427/56172), [DNSPod records](https://cloud.tencent.com/document/api/1427/56166), [DNSPod models](https://cloud.tencent.com/document/product/1427/56185), [Private DNS records](https://cloud.tencent.com/document/api/1338/55938), and [Private DNS models](https://cloud.tencent.com/document/product/1338/55947).

## TCR repository and image metadata — 2026-10-13

- Compared the source ECR collector with the installed TCR 2019-09-24 SDK and official namespace/repository/image APIs. Added `DescribeNamespaces`, `DescribeRepositories` and `DescribeImages` to the metadata allowlist.
- Repository and image `Offset` is a page number. The current image parameter description explicitly starts at 1, although its older example sends 0; implementation follows the explicit parameter description. Namespace collection uses `All=true` and a required total to avoid ambiguous namespace pagination semantics. Missing, invalid, changing, truncated and duplicate inventory cannot be reported as complete.
- **122 backend tests** pass. TCR cases cover account/region/registry isolation, shared digests with separate tags, untagged references, repository namespace validation, malformed digests/tags, nested repository paths, page 1 to page 2 progression, denied namespace access with continuing repositories, duplicate-tag partial coverage and forbidden token/manifest/deletion APIs. Selected metadata excludes image config and raw signature material.
- Registry anonymous-access configuration, namespace/repository public flags and scan/blocking configuration are retained as configuration. No effective anonymous pull or vulnerability claim is inferred.
- Browser fixture rendered **9 resources and 11 relationships**, with only the registry in architecture view. Export parsed with **12 editable nodes including containers, 11 edges and 9 embedded official SVGs**; all parent and endpoint references were valid. Full digests remain in resource IDs/properties while labels use a short digest. Original demo restored afterward.
- `npm ci`, 5 frontend tests, production build, dependency audit and pre-commit checks pass; audit reports zero vulnerabilities and all 896 official assets pass integrity checks.
- Multi-platform manifests, attestations, image-layer analysis, Personal Edition, workload-image relationships, policies/proxy-cache rules and authenticated Tencent validation remain incomplete. No live cloud calls were used in this verification.

Sources: [Namespaces](https://cloud.tencent.com/document/product/1141/42765), [repositories](https://cloud.tencent.com/document/product/1141/42722), [images and page numbering](https://cloud.tencent.com/document/product/1141/42723), [manifest response](https://cloud.tencent.com/document/api/1141/43525), and [TCR CAM actions](https://intl.cloud.tencent.com/document/product/598/57160).
