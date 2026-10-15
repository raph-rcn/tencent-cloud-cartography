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

## SCF versions, aliases, triggers and layers — 2026-10-13

- Compared the AWS Lambda collector with SCF 2018-04-16 SDK models and official trigger/alias documentation. Added `ListVersionByFunction`, `ListAliases`, `ListTriggers`, `ListLayers` and `ListLayerVersions` to the action allowlist. `GetFunction`, invocation and code-download APIs remain excluded.
- **138 backend tests** pass. SCF controls cover namespace/account/region isolation, weighted and rule-based aliases, zero weights, invalid/nonfinite weights, qualifier identity, disabled triggers, duplicate JSON fields and resources, denied aliases with continuing trigger collection, partial pagination, layer identity and cross-scope event-source matching.
- Tests verify exclusion of custom event payloads, CKafka credential fields, unfiltered environment data and URL query/fragment values. HTTP authentication/network fields remain configuration; no effective public access is inferred. Unknown trigger types retain identity with `configuration_supported=false` and discard opaque configuration.
- Browser fixture: **11 resources, 13 relationships, 2 services** in the full graph; **3 resources and 1 relationship** in architecture view. Draw.io export has **15 editable nodes including containers, 13 edges and 11 embedded official SVGs**, with valid endpoints and parents. The original synthetic Frankfurt demo was restored afterward.
- Five frontend tests, production build, dependency audit and pre-commit checks pass. All 896 official icon assets remain verified.
- `GetFunction` exposes environment values and optionally source, so execution-role, VPC, image and function-layer usage remain outside the current metadata collection design. Layer inventory is not proof of function use. Broader event integrations, permission/public invocation analyses and authenticated Tencent validation remain incomplete.

Sources: [ListTriggers](https://cloud.tencent.com/document/product/583/44268), [trigger configuration formats](https://cloud.tencent.com/document/product/583/39901), [ListAliases](https://intl.cloud.tencent.com/ind/document/product/583/36322), [alias routing](https://cloud.tencent.com/document/api/583/44164), and [SCF data structures](https://cloud.tencent.com/document/product/583/17244).

## API Gateway configuration and deployment metadata — 2026-10-13

- Compared AWS API Gateway/v2 collectors with the installed Tencent API Gateway 2018-08-08 SDK and official API/model documentation. Added service/API detail, API lists, environments, release versions and custom domains through six read operations.
- **149 backend tests** pass. Gateway controls cover service-scoped API IDs, parent/detail ID mismatches, independent denied scopes, SCF account/region/namespace isolation, ambiguous function names, separate WebSocket backend roles/qualifiers, COS bucket identity, backend VPC versus service placement, publication conflicts and SSL icon mapping.
- Frontend method/path and backend method/path remain separate. URL credentials are rejected and query/fragment values are omitted; OAuth config, constant parameter values and mock response bodies are not stored. Authentication flags do not create effective-access claims.
- Only published environments link to running release versions. Current API detail is not presented as the contents of a historical deployment. Contradictory API/environment publication fields are flagged.
- Browser fixture: **10 resources and 12 relationships** in full graph; **2 resources and 0 relationships** in architecture view. One alias remains an explicit unresolved reference. Export parsed with **14 editable nodes including containers, 12 edges and 10 embedded official SVGs**, with valid parents/endpoints. Original Frankfurt demo restored afterward.
- Five frontend tests, production build, dependency audit and pre-commit checks pass; all 896 official assets pass integrity checks.
- Upstream/TSF details, custom domain path mappings, certificate inventory, historical deployment API contents, broader policy/permission analysis, Cloud Native API Gateway equivalence and authenticated runtime validation remain incomplete.

Sources: [DescribeApi](https://intl.cloud.tencent.com/document/product/628/36659), [environments](https://cloud.tencent.com/document/api/628/45198), [API Gateway data structures](https://cloud.tencent.com/document/api/628/45244), and [API catalog](https://intl.cloud.tencent.com/zh/document/product/628/36595).

## COS configuration extension (2026-10-13)

- Adds 22 tests for five independently scoped metadata checks, ACL group identity, AppId/UIN separation, policy deny/condition preservation, malformed detail rejection, safe KMS references, logging destinations and COS encryption enums.
- Exercises the real official SDK XML parser and request construction against mocked transport responses, including empty versioning/logging XML. No cloud request is made by these tests.
- Credential tests use isolated temporary fixture profiles: mixed sources, incomplete environment pairs and dynamic credential types fail explicitly. SDK dispatch tests verify HTTPS, exact method/parameter scope and exclusion of raw error messages.
- COS successful request IDs are unavailable through these SDK methods; missing configuration error codes are not silently treated as disabled controls. No live account collection, public-access probe or dynamic credential refresh is claimed.
- Sources: [official SDK](https://github.com/tencentyun/cos-python-sdk-v5), [bucket operations](https://cloud.tencent.com/document/product/436/35150), [encryption](https://cloud.tencent.com/document/product/436/40137), [versioning](https://cloud.tencent.com/document/api/436/19888), [logging](https://cloud.tencent.com/document/product/436/17053).

- Verification: 171 backend tests, 5 frontend tests, production build, all 896 icon hashes and pre-commit checks passed; npm audit reports zero vulnerabilities. Browser fixture displayed 7 resources / 6 relationships with COS, CAM and KMS icons. The downloaded draw.io file contained 13 vertices, 6 edges and 7 embedded SVGs. Synthetic preview: `.local/cos-preview.png`; fixture: `.local/cos-demo.json`.

## SSL / CLB / CVM role extension (2026-10-13)

- 184 backend tests pass, including SSL pagination and required totals, owner-UIN rejection, selected metadata retention/private-key exclusion, reference reconciliation, listener/rule/target identity, server-versus-client CA certificate links, per-load-balancer denials, count and identity negative controls, exact same-account CVM role matching and unresolved/ambiguous role references.
- SSL DescribeCertificates uses pinned API version 2019-12-05 and no region. DescribeCertificateDetail and DownloadCertificate are explicitly blocked by operation tests because they can expose private keys. Configured certificate/role relationships do not establish effective access or successful TLS/role use.
- Frontend tests (5), build, npm audit (zero vulnerabilities), pre-commit and all 896 icon hashes passed. Browser fixture showed 4 resources / 3 forwarding relationships in architecture view and 9 resources / 8 relationships in full view. Export contained 9 embedded SVG icons and all 8 edges. Preview `.local/certificates-preview.png`; synthetic fixture `.local/certificates-demo.json`.
- Schema verification used the installed official Tencent SDK and primary documentation: [certificate list](https://cloud.tencent.com/document/api/400/41671), [certificate detail](https://cloud.tencent.com/document/product/400/41673), [CLB output structures](https://cloud.tencent.com/document/api/214/30694), [CVM instances](https://cloud.tencent.com/document/product/213/15728). Live Tencent collection remains unverified.

## CloudAudit and CLS extension (2026-10-13)

- 207 backend tests pass. New controls cover PageNumber/PageSize pagination, independent detail denials, list/detail name changes, event selectors, AppId/UIN separation, cross-account/region destinations, ambiguous buckets, separate log/metric topic requests, invalid topic categories/track IDs, CLS retention/KMS/shipper relationships, scoped CKafka membership and payload exclusion. Audit-event and log-content actions are explicitly blocked.
- Five frontend tests, build, npm audit (zero vulnerabilities), pre-commit and all 896 icon hashes passed. Browser fixture displayed 5 resources / 4 relationships in architecture view and 6 / 5 in full view. Export preserved 6 embedded SVGs and all 5 edges. A stale browser viewport initially prevented activation; viewport reset/reload resolved the export check without application changes. Preview `.local/observability-preview.png`; fixture `.local/observability-demo.json`.
- CloudAudit details do not echo TrackId; list/detail Name agreement is checked. Status and organization-delivery flags are configuration, not proof of successful delivery or organization inventory. Missing destination resources remain references/unresolved properties. Live account collection remains unverified.
- Primary sources: [CloudAudit tracks](https://cloud.tencent.com/document/product/629/69204), [track detail](https://cloud.tencent.com/document/api/629/83247), [storage identifiers](https://cloud.tencent.com/document/api/629/35353), [CLS topics](https://cloud.tencent.com/document/api/614/56454), [COS shipping configuration](https://cloud.tencent.com/document/api/614/58744), [CLS structures](https://cloud.tencent.com/document/product/614/56471).

## 2026-10-13 — Cloud Monitor policy and binding configuration

- `uv run pytest -q`: **229 passed**, including 20 new alarm tests and two
  additional metadata-only API denial tests. Fixtures cover compound metric/event
  rules, embedded notice filtering, 11-policy pagination, independent binding
  permission failures, 101-binding pagination, group changes, duplicates, null
  empty arrays, malformed dimensions and account/region/namespace isolation.
- `uv run pre-commit run --all-files`: passed Ruff and all **896 icon** checks.
- `npm ci`, frontend tests (**5 passed**), production build and high-level npm
  audit passed (**0 vulnerabilities**). The existing bundle-size warning remains.
- Browser fixture `.local/monitor-demo.json` on loopback port 8789 rendered
  **5 nodes / 4 edges** with official Cloud Monitor and CVM icons. It demonstrates
  the account-scoped policy/rule/notice/binding and an explicit Frankfurt CVM link.
  This is synthetic data, not a live account result.
- Browser export produced `tencent-cloud-cartography (10).drawio`: **10 vertices,
  4 edges, 5 embedded SVGs**. The default 897px viewport exposed a toolbar clipping
  defect; wrapping toolbar groups and an automatic toolbar grid row fixed it.
  Readback placed the complete export button inside the viewport and the browser
  confirmed the successful local export. Preview: `.local/monitor-preview.png`.
- Live Tencent permissions, API availability, metric evaluation, notification
  delivery and complete AWS CloudWatch parity remain unverified/incomplete.

## 2026-10-13 — CLS alarm queries and notification groups

- `uv run pytest -q`: **246 passed**. Fifteen new CLS tests cover query/schedule
  fields, reference enrichment, receiver/callback filtering, recursive escalation,
  cross-account/region controls, distinct global Monitor references, 101-item
  pagination for both APIs, duplicates, malformed identities/configuration and
  independent regional access denial. Two additional tests block alarm log/history
  operations at the exact API allowlist.
- `uv run pre-commit run --all-files`: Ruff and all **896 official icon** checks
  passed. `npm ci`, frontend tests (**5 passed**), build and npm audit passed with
  **0 vulnerabilities**; the existing bundle-size warning remains.
- Browser smoke fixture `.local/cls-alarms-demo.json` on loopback 8790 rendered
  **7 nodes / 6 edges** in the full graph. Left-to-right layout visibly retained the
  Frankfurt alarm → query → topic path, notification group/rule and cross-region
  delivery-topic configuration. Preview: `.local/cls-alarms-preview.png`.
- Browser export `tencent-cloud-cartography (11).drawio` was read back as **12
  vertices, 6 edges and 7 embedded SVG icons**. No frontend changes were needed.
- All data above is synthetic. No live Tencent API calls, query execution or
  notification delivery were performed; complete AWS parity remains incomplete.

## 2026-10-13 — CLS scheduled SQL metric mappings

- `uv run pytest -q`: **262 passed**. Sixteen new tests cover multi-metric
  precedence, legacy single-metric and log destinations, producer-specific labels,
  explicit source/destination regions, account isolation, disabled/error status,
  schedule units, pagination/duplicates/truncation, malformed configuration and
  independent regional denial. Unrecognized payload fields cannot fabricate
  network relationships or persist arbitrary nested data.
- Ruff and **896 official icon** integrity checks passed. `npm ci`, **5 frontend
  tests**, production build and npm audit passed with **0 vulnerabilities**. The
  existing bundle-size warning remains.
- `.local/cls-metrics-demo.json` rendered **5 resources / 6 relationships** in the
  browser full graph with official CLS icons. The prior observability fixture
  server on loopback 8788 was verified by process identity and stopped; that port
  now serves this metric fixture. Its prior snapshot/preview files remain intact.
- Browser draw.io export `tencent-cloud-cartography (12).drawio` read back as
  **8 vertices, 6 edges, 5 embedded SVGs**. Preview:
  `.local/cls-metrics-preview.png`.
- These checks use synthetic metadata. No SQL query was executed, no metric
  samples were retrieved, and no successful task execution is claimed. Live
  Tencent validation and complete AWS parity remain incomplete.

## 2026-10-13 — CFS mount and permission configuration

- `uv run pytest -q`: **280 passed**, including 18 CFS cases covering file-system
  pagination, parent-scoped mount/rule IDs, independent child denials, totals and
  duplicate controls, rule semantics, VPC/CCN separation, truncated IP lists,
  encryption conflicts, `pgroupbasic` and lowercase network types.
- Ruff and all **896 official icon** integrity checks passed. `npm ci`, **5 frontend
  tests**, production build and npm audit passed with **0 vulnerabilities**. The
  existing bundle-size warning remains.
- Synthetic `.local/cfs-demo.json` on loopback 8788 rendered **7 resources / 7
  relationships**. The mount appears inside its explicit VPC/subnet while the file
  system, permission group/rule and key remain at their collected scopes.
- Browser review identified a floating duplicate Tencent label covering the account
  title. Removing that overlay preserved header branding and service icons; browser
  readback confirmed the account title is visible. Preview: `.local/cfs-preview.png`.
- Browser export `tencent-cloud-cartography (13).drawio` read back as **13 vertices,
  7 edges and 5 embedded service SVGs**, with VPC/subnet represented as containers.
- No live Tencent request, share mount or file access occurred. AWS access-point
  equivalence and other documented parity/validation gaps remain incomplete.

## 2026-10-13 — CKafka topics, partitions and integration links

- `uv run pytest -q`: **303 passed**. Twenty-three new Kafka cases cover
  51-topic pagination at the 50-item API maximum, scoped identities and duplicate
  names, instance/topic detail identity checks, missing/truncated/duplicate
  partitions, independent access denials, selected configuration boundaries,
  cross-account/region link controls, and excluded message/credential APIs.
- Ruff and all **896 official icon** integrity checks passed. `npm ci`, **5
  frontend tests**, production build and npm audit passed with **0 vulnerabilities**.
  The existing bundle-size warning remains.
- Synthetic `.local/ckafka-demo.json` on loopback 8788 rendered **8 resources / 9
  relationships** in the full graph. The instance is contained in its explicit
  VPC/subnet, with topic/partition, global SSL certificate, CloudAudit delivery and
  SCF trigger relationships preserved. Preview: `.local/ckafka-preview.png`.
- Browser export `tencent-cloud-cartography (14).drawio` read back as **16 vertices,
  9 edges and 6 embedded service SVGs**. VPC/subnet remain containers.
- These are synthetic checks; no live Tencent request or Kafka message access was
  performed. Effective ACL evaluation, fuller Kafka configuration and the broader
  AWS capability comparison remain incomplete as detailed in PARITY.md.

## 2026-10-13 — CMQ queues, topics and subscriptions

- `uv run pytest -q`: **335 passed**. Thirty-two CMQ cases cover 50-item
  pagination for all list operations, required totals, topic-scoped subscription
  IDs, conflicting parent/detail IDs, independent access denials, subscription
  count changes, dead-letter policy thresholds and forward/reverse conflicts,
  cross-account/region/ambiguous queue names, endpoint redaction and excluded
  message/mutation APIs. The full synthetic collection now checks 68 coverage rows.
- Ruff and all **896 official icon** integrity checks passed. `npm ci`, **5
  frontend tests**, production build and npm audit passed with **0 vulnerabilities**;
  the existing bundle-size warning remains.
- `.local/cmq-demo.json` rendered **6 resources / 5 relationships** on loopback
  8788, with official CMQ icons, topic/subscription routing, the configured queue
  destination and dead-letter queue. Preview: `.local/cmq-preview.png`.
- Browser export `tencent-cloud-cartography (15).drawio` read back as **9 vertices,
  5 edges and 6 embedded SVGs**. No frontend code changes were needed.
- This was synthetic metadata. No live Tencent request, message operation or HTTP
  callback occurred. Full AWS parity and live validation remain incomplete.

## 2026-10-13 — EventBridge buses, rules and targets

- `uv run pytest -q`: **369 passed**. Thirty-four EventBridge cases cover bus,
  rule and target pagination; required totals; scoped and duplicate identities;
  detail/parent mismatches; pattern validation; independent access denials; QCS
  owner/region controls; SCF versions/aliases; explicit CLS/ES references; Kafka
  and dead-letter links; disabled/drop behavior; selected configuration fields;
  and excluded secret-bearing connection/event/payload operations. The full
  synthetic collection now checks 69 coverage rows.
- Ruff and all **896 official icon** integrity checks passed. `npm ci`, **5
  frontend tests**, production build and npm audit passed with **0 vulnerabilities**;
  the existing bundle-size warning remains.
- Synthetic `.local/eventbridge-demo.json` rendered **8 resources / 8 relationships**
  on loopback 8788, including an SCF version target and a Kafka dead-letter topic.
  Preview: `.local/eventbridge-preview.png`.
- Browser export `tencent-cloud-cartography (16).drawio` read back as **13 vertices,
  8 edges and 8 embedded official SVGs**. No frontend changes were needed.
- No live Tencent call, event read/publication or invocation occurred. Full AWS
  parity, provider-specific schedule/role correspondence and live validation remain
  incomplete; see PARITY.md for the documented connection-secret exclusion.


## 2026-10-13 — CloudRC identity reconciliation and compound Grid layout

- `uv run pytest -q`: **399 passed**. Thirty new inventory cases cover documented
  CBS/CKafka/MySQL type aliases, ambiguous SCF codes, required ownership, malformed
  identities and metadata, duplicate resources and token failures, partial results,
  explicit versus missing region evidence, and native global reconciliation with
  incoming/outgoing edges and provenance preserved. No API allowlist expansion.
- CloudRC records with missing region remain unresolved until the same account,
  kind and ID are confirmed by a global native collector. Ambiguous `scf::namespace`
  records remain inventory-only; they cannot overwrite native namespaces.
- Browser review exposed overlapping region/service boxes in the flat Grid layout.
  Grid now arranges siblings recursively within their containers. The new frontend
  regression verifies sibling separation, containment, stable rearrangement and
  relationship preservation; **6 frontend tests** passed.
- Ruff and **896 official icon** integrity checks passed. `npm ci`, production build
  and npm audit passed with **0 vulnerabilities**; the existing bundle-size warning
  remains.
- Synthetic `.local/inventory-demo.json` rendered **7 resources / 1 relationship**,
  including separate unresolved SCF inventory and native namespace, and global
  Private DNS outside Frankfurt. Preview: `.local/inventory-preview.png`.
- Browser export `tencent-cloud-cartography (17).drawio` read back as **16 vertices,
  1 edge and 7 embedded official SVGs**. No live Tencent request occurred. Full AWS
  parity and live validation remain incomplete, as recorded in PARITY.md.

## 2026-10-13 — SES domain verification and layout cancellation

- `uv run pytest -q`: **434 passed**. Thirty-five SES cases cover 101-domain
  pagination, required totals, normalized duplicate identities, selected metadata,
  malformed list/detail responses, independent denials, account isolation, exact
  public DNS links, the three documented regional endpoints, unsupported Frankfurt
  and the exclusion of sending/template/recipient/credential APIs.
- Native collection coverage now counts each successfully retained row even if a
  later row in the same page is invalid. The complete synthetic collection checks
  **70 coverage rows**, including explicit unsupported SES coverage for Frankfurt.
- Ruff and all **896 official icon** integrity checks passed. `npm ci`, **7 frontend
  tests**, production build and npm audit passed with **0 vulnerabilities**. The
  existing bundle-size warning remains.
- `.local/ses-demo.json` rendered **5 resources / 4 relationships**, including
  domain verification, two DNS checks, and an exact collected DNSPod record match.
  The coverage dialog displayed Frankfurt as unsupported with the supported regions.
  Preview: `.local/ses-preview.png`.
- Rapid Auto-to-Grid switching exposed an unfinished animation overwriting the new
  positions. Layout changes now stop the preceding layout and queued animations.
  A delayed-layout regression and browser review after the prior animation duration
  both confirmed stable Grid positions.
- Browser export `tencent-cloud-cartography (18).drawio` read back as **10 vertices,
  4 edges and 5 embedded official SVGs**.
- This was synthetic metadata. No live Tencent request, DNS lookup, email access or
  send operation occurred. Full AWS parity and live validation remain incomplete;
  see PARITY.md for the domain/address and DKIM semantic distinctions.

## 2026-10-13 — CloudConfig recorder, delivery and rule definitions

- `uv run pytest -q`: **475 passed**. Forty-one new CloudConfig cases cover
  required totals, 101-rule pagination, duplicate IDs, multi-account/global scope,
  rule detail identity/owner changes, exact scope-edge replacement, malformed
  definitions, unavailable recorder scope, independent denials and missing delivery,
  disabled settings, COS AppId/region/ambiguity controls and explicit CLS references.
- The full synthetic collector now checks **73 coverage rows**. CloudConfig
  recorder, delivery and rule discovery run once per account across selected regions.
  Rule annotations and unexpected nested fields are excluded from persisted data;
  only the four audited configuration actions are allowed.
- Ruff and all **896 official icon** integrity checks passed. `npm ci`, **7 frontend
  tests**, production build and npm audit passed with **0 vulnerabilities**; the
  existing bundle-size warning remains.
- `.local/cloudconfig-demo.json` rendered **5 resources / 3 relationships** on
  loopback 8788. Recorder, delivery, rule and resource-type definition stay global;
  the configured COS archive stays in Frankfurt. The rule inspector showed disabled
  state, region/tag/exclusion scope, parameters, condition/trigger fields and the
  explicit `compliance_independently_verified: false` property.
- Preview: `.local/cloudconfig-preview.png`. Browser export
  `tencent-cloud-cartography (19).drawio` read back as **10 vertices, 3 edges and
  5 embedded official SVGs**. No frontend changes were needed.
- These were synthetic checks. No live Tencent query, resource snapshot retrieval,
  evaluation, remediation, log or object read occurred. Full AWS parity and live
  validation remain incomplete; provider-specific limitations are in PARITY.md.


## 2026-10-13 — EMR cluster and node inventory

- `uv run pytest -q`: **506 passed**. Thirty-one EMR cases cover standard/TKE
  inventories, zero-based page-number pagination across 101 records, node views,
  identity and scope mismatches, duplicate detection, changing overlapping views,
  invalid metadata, missing totals, denied scopes and exact API allowlisting.
- The synthetic full collector now checks **75 coverage rows**. The two EMR
  cluster-type passes remain independent; each discovered cluster adds separate
  all/database/isolated-node coverage records.
- `uv run pre-commit run --all-files`: lint, formatting and all **896 official
  icon checksums** passed. EMR clusters and nodes resolve the official EMR SVG.
- Frontend: **7 tests passed**, production build succeeded, `npm audit
  --audit-level=high` reported **0 vulnerabilities**. The existing large-bundle
  advisory remains.
- Browser fixture `.local/emr-demo.json`: **8 resources / 13 relationships**,
  synthetic Frankfurt metadata. Full-graph Grid view shows the multi-zone cluster
  outside its default subnet, worker nodes in their explicit subnet and CVM/TKE
  links. Inspector verifies node protection, host ID, memory and service metadata.
- Export `Downloads/tencent-cloud-cartography (20).drawio`: **16 vertices,
  13 edges, 5 embedded SVGs**; network resources use the export's container shapes.
  Screenshot: `.local/emr-preview.png`.
- No live Tencent collection was performed. Cluster role/log/security/image
  fields and AWS termination-policy equivalence remain gaps; the password-bearing
  `DescribeInstances` API remains disallowed.


## 2026-10-13 — Shared resource-tag graph

- `uv run pytest -q`: **540 passed**, including **34** new tag cases for
  continuation tokens and page bounds, empty intermediate pages, account/region
  isolation, case-sensitive key/value identity, Unicode/empty values, malformed
  data, CAM global IDs, CBS aliases, COS AppId forms, ambiguous EMR node IDs,
  unresolved inventory and conflicting equivalent resource identifiers.
- Full synthetic collection now checks **76 coverage rows**, including the
  independent account-wide `tag.GetResources` pass. API mutation actions remain
  outside the allowlist.
- Pre-commit lint/format and **896 icon checksum checks passed**. The icon catalog
  explicitly identifies the generic official Cloud API symbol used for tagging;
  the archive has no dedicated Tag product logo.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**. The existing large-bundle advisory remains.
- `.local/tags-demo.json` rendered **5 resources / 4 relationships** with the
  Frankfurt region filter. Global tag nodes remained visible. The inspector for
  `team=analytics` showed incoming links from the CVM worker, COS bucket and CAM
  role, with `tag.GetResources` provenance.
- Browser export `Downloads/tencent-cloud-cartography (21).drawio` preserved
  **12 vertices / 4 edges / 5 embedded SVGs**. Preview: `.local/tags-preview.png`.
- Validation uses synthetic metadata; no live Tencent collection was performed.
  Unknown/composite resource mappings and product-specific fallback remain gaps.


## 2026-10-13 — Secrets Manager inventory, versions and rotation

- Backend: **570 tests passed**, including **30** new Secrets Manager cases for
  all eight type/encryption combinations, offset pagination, metadata validation,
  creator/owner separation, SSH associations, exact database/user matching,
  version identity/time/duplicate checks, independent detail failures, rotation
  changes and creator-qualified QCS tag matching.
- Full synthetic collector: **83 coverage rows**. The prior single default
  ListSecrets request is replaced by eight explicit independent inventory scopes.
- Pre-commit lint/format and **896 official icon checksum checks passed**.
  Secret/version nodes use the existing official Secrets Manager SVG.
- Frontend: **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- `.local/secrets-demo.json` rendered **5 resources / 4 relationships** with the
  Frankfurt secret, two versions, configured KMS key and MySQL association.
  Inspector verified lifecycle/rotation fields, both incoming version edges,
  metadata provenance and `secret_value_collected=false`.
- Browser export `Downloads/tencent-cloud-cartography (22).drawio` preserved
  **10 vertices / 4 edges / 5 embedded SVGs**. Screenshot: `.local/secrets-preview.png`.
- No secret contents or key material APIs were allowed or called. Validation is
  synthetic; live API availability/filter behavior, version stages and historical
  per-version encryption metadata remain unverified or unsupported by the
  collected schema.

## 2026-10-13 — CDN deployment metadata and sensitive API exclusion

- Backend: **589 tests passed**, including **19** new checks covering CDN domain
  normalization, deployed certificate references, global scope, billing semantics,
  offset pagination, duplicates, invalid responses, denial, sensitive API blocking
  before subprocess execution and permission inventory consistency.
- Full synthetic collector: **84 coverage rows**. CDN has an explicit unsupported
  complete-inventory scope and a separate SSL deployment metadata scope.
- Frontend: **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Synthetic `.local/cdn-demo.json`: **3 resources / 2 relationships** in the full
  graph. Inspector showed the exact deployed certificate edge and provider source;
  the coverage dialog displayed the inventory/origin limitation.
- Browser export `Downloads/tencent-cloud-cartography (23).drawio` and screenshot
  `.local/cdn-preview.png` verified the official CDN and SSL icons.
- The permission inventory now matches the exact action allowlist, including
  recently added services; existing COS API/CAM mappings are retained.
- No live Tencent collection occurred. Complete domain inventory, origin/cache/TLS
  configuration, EdgeOne and account-specific SSL API behavior remain unverified.

## 2026-10-13 — Auto Scaling source comparison and metadata depth

- Backend **609 tests passed**, including **20** new cases for group settings,
  multi-subnet placement, explicit CLB regions, zero/false metadata, membership
  isolation, CVM state preservation, pagination, invalid/duplicate identities,
  independent denied scopes and launch user-data API blocking before execution.
- Source comparison confirmed that `ec2/auto_scaling_groups.py` collects group,
  launch configuration, subnet and instance metadata, not scaling policies.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- Synthetic `.local/autoscaling-demo.json` rendered **6 resources / 9 relationships**.
  The group sits in the VPC with both subnet associations; the worker sits in its
  explicit subnet/AZ. The launch configuration remains an unresolved reference.
  Inspector showed cooldown, min/max/desired capacity, health-check grace period,
  rebalance flag, replacement settings and all five outgoing group relationships.
- Browser export `Downloads/tencent-cloud-cartography (24).drawio` and screenshot
  `.local/autoscaling-preview.png` preserve official Auto Scaling/CVM/network icons.
- Validation is synthetic; no live Tencent collection or scaling action occurred.
  Launch configuration details remain excluded because the API includes UserData.

## 2026-10-13 — Image/snapshot ownership, in-use lookup and sharing

- Backend **631 tests passed**, including **22** new cases covering owned filters,
  typed metadata, share recipients/timestamps, reference upgrades, wrong/empty
  lookup responses, pagination, independent failures, ownership and account/region
  boundaries, duplicate/invalid data and exact read-only API selection.
- In-use public/shared resources are explicitly marked not owned by the query
  account. Their foreign backing disks/snapshots are not assigned guessed owners.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- Synthetic `.local/image-snapshot-demo.json` rendered **6 resources / 6 relationships**
  across the owner and recipient accounts. The inspector showed the snapshot share,
  incoming snapshot edge, recipient identity, timestamp and `access_verified=false`.
- Browser export `Downloads/tencent-cloud-cartography (25).drawio` and screenshot
  `.local/image-snapshot-preview.png` verified the official CVM/CBS/CAM icon mappings.
- No live API calls, snapshot/image contents, sharing mutations or access attempts
  occurred. AWS public-permission semantics and broader source metadata parity
  remain incomplete and are tracked in the parity audit.

## 2026-10-13 — Interface addresses, EIP binding and CLB IP targets

- Backend **653 tests passed**, including **22** new cases for canonical IPv4/IPv6,
  ENI-scoped identity, explicit EIP bindings, IPv6 alias/availability handling,
  metadata validation/pagination, account/region/VPC isolation, overlapping IPs,
  non-CVM attachments and conflicting EIP associations.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Synthetic `.local/network-addresses-demo.json` rendered **9 resources / 18 relationships**.
  Interface/address/CVM placement followed explicit subnet and VPC references.
  The target inspector showed both address and instance resolution edges and
  `reachability_verified=false`.
- Browser export `Downloads/tencent-cloud-cartography (26).drawio` preserved the
  full relationship set; screenshot `.local/network-addresses-preview.png`.
  Address nodes use the official ENI SVG, alongside EIP, CVM and CLB assets.
- No live Tencent collection, connectivity probes or configuration mutations were
  performed. Cross-VPC target mappings, effective reachability, undocumented owner
  identifier semantics and non-CVM attachment counterparts remain gaps.

## 2026-10-13 — CCN ownership, state and network references

- Backend **680 tests passed**, including **27** new cases for explicit owner/region
  identity, mismatched/missing UINs, parent mismatch, CIDR validation, lifecycle
  flags, unknown types, duplicate pages, pagination totals and independent denial.
- Source review corrected the audit: AWS transit-gateway collection includes
  gateways and attachments, but does not include route tables or routes.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Synthetic `.local/ccn-demo.json` rendered **5 resources / 4 relationships** across
  three accounts and global/Frankfurt/Guangzhou scopes. Two network references
  remain unresolved, so the fixture correctly reports partial coverage.
- Inspector verified PENDING state, both UINs, target region/CIDR and explicit
  `active_reported=false` / `connectivity_verified=false` on the partner attachment.
- Browser export `Downloads/tencent-cloud-cartography (27).drawio` retained all
  four edges and the official CCN SVG; preview `.local/ccn-preview.png`.
- No live Tencent collection occurred. Discovery of shared CCNs absent from the
  queried inventory, source ownership/SHARED_WITH correspondence and provider
  subnet semantics remain open gaps. No additional API operation was allowed.

## 2026-10-13 — Private Link family/type coverage and shared services

- Backend **713 tests passed**, including **33** new cases covering authorized
  foreign-owner resolution, AppId preservation, typed CLB/CDB/CRS/GWLB references,
  IPv4/dual-stack pagination, short pages with continuation tokens, malformed
  pages, duplicates, incorrect lookup results, owner mismatch and denied scopes.
- Tests verify that consumer resources are not placed in the provider account,
  remote ServiceVpcId does not become local containment, and ambiguous, wrong-
  region or contradictory-VPC service matches do not produce a connection edge.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Synthetic `.local/privatelink-demo.json` rendered **7 resources / 8 relationships**
  across consumer/provider accounts in Frankfurt. Supporting VPC/subnet/CLB
  inventory is explicitly synthetic; this is not a live API collection.
- Inspector showed consumer containment, security-group membership, the shared
  service edge, original AppId and `connectivity_verified=false`.
- Browser export `Downloads/tencent-cloud-cartography (28).drawio` retained all
  eight edges and official Private Link/network/CLB SVGs; preview saved to
  `.local/privatelink-preview.png`. All 896 official assets remain bundled.
- Live Tencent validation, AWS-specific endpoint policy/DNS/ENI/route semantics
  and native GWLB backend enrichment remain incomplete.

## 2026-10-13 — VPC address-space associations and subnet metadata

- Backend **738 tests passed**, including **25** new cases for CIDR family/host-bit
  validation, legacy/provider IPv6 reconciliation, overlapping ranges in separate
  VPCs, auxiliary subnet membership, malformed parents, pagination/duplicates,
  invalid zones and independent denied scopes.
- Full/architecture graph tests verify CIDR detail visibility and retention of
  every relationship. Default false flags, zero available addresses and DNS
  resolver order survive collection.
- Frontend **7 tests passed**, production build succeeded, dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- Synthetic `.local/vpc-cidr-demo.json` rendered **7 resources / 10 relationships**.
  The subnet appears in Frankfurt zone 1, inside the VPC; all three CIDR nodes
  remain inside the VPC without placing the VPC inside its nested subnet.
- Inspector confirmed canonical IPv6, BGP/ULA and both primary/provider roles.
  Two route/ACL references remain unresolved, correctly making the fixture partial.
- Browser export `Downloads/tencent-cloud-cartography (29).drawio` preserved all
  ten edges and the official VPC SVGs; preview `.local/vpc-cidr-preview.png`.
- No live Tencent collection occurred. Provider-specific source-field equivalence
  gaps remain documented in the parity audit. No API permission was added.

## 2026-10-13 — Security-group references and reusable selectors

- Backend **763 tests passed**, including **25** new cases for direct IPv4/IPv6
  selectors, referenced groups, address/service template dependencies, group
  membership, ranges, policy versions/priorities, malformed selectors, duplicates,
  pagination totals, independent denial and template-scoped member remarks.
- Invalid ingress/egress data prevents partial application of that policy response.
  Unsupported/denied template reads retain unresolved references. A source review
  confirmed that AWS security_groups.py does not collect prefix-list dependencies.
- Frontend **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- Synthetic `.local/security-templates-demo.json` rendered **12 resources / 11
  relationships** in the full graph. Inspector confirmed two template dependency
  edges plus policy version 7, priority 0 and `reachability_verified=false`.
- Browser export `Downloads/tencent-cloud-cartography (30).drawio` retained all
  eleven edges and embedded official VPC SVGs; preview saved to
  `.local/security-templates-preview.png`. The peer group remains an unresolved
  reference, making the synthetic fixture partial.
- Four metadata API actions were added to the permission inventory. All 896
  bundled official icons remain intact. No cloud mutation or live collection
  occurred; source/provider scoping and effective-access semantics remain open.

## 2026-10-13 — Route pagination, association identities and next hops

- Backend **792 tests passed**, including **29** new cases covering route metadata,
  disabled routes, association parents, IPv6 fallback identity, typed gateways,
  pagination, missing totals, independent denial, inventory changes and scoped
  IP next-hop resolution. CCN tests cover foreign and ambiguous owners.
- Embedded route inventory survives denied paginated listing. Conflicting gateway
  changes cannot silently add a second stale next-hop edge.
- Frontend **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- Synthetic `.local/routes-demo.json` rendered **10 resources / 18 relationships**.
  Inspector confirmed an appliance route's address/instance matches, source APIs,
  enabled/publication metadata and `reachability_verified=false`. Supporting ENI,
  address, CVM and subnet inventory is synthetic.
- Browser export `Downloads/tencent-cloud-cartography (31).drawio` preserved all
  eighteen edges with official VPC/ENI/NAT/CVM SVGs; preview `.local/routes-preview.png`.
  The unresolved NAT reference correctly leaves the fixture partial.
- DescribeRouteList was added to the metadata permission inventory. No cloud
  mutation, probe or live collection occurred. Source-state/provider equivalence
  and live IPv6 route coverage remain explicit gaps.

## 2026-10-13 — Network ACL metadata and five-field rule pagination

- Backend **824 tests passed**, including **32** new cases covering both rule
  formats, IPv4/IPv6, exact subnet/VPC associations, provider versus positional
  identities, priorities, ports, malformed pages, pagination totals, duplicate
  parents/rules, independent denied scopes and preservation of partial inventory.
- Frontend **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Synthetic `.local/network-acls-demo.json` rendered **8 resources / 12
  relationships**. Inspector confirmed an IPv6 EGRESS DROP rule's source and
  destination selectors, ports, priority, parent ACL and reachability=false.
- Browser export `Downloads/tencent-cloud-cartography (32).drawio` retained all
  twelve edges and embedded five official VPC SVGs. The preview is
  `.local/network-acls-preview.png`; supporting VPC/subnet inventory is synthetic.
- Added DescribeNetworkAclQuintupleEntries to the exact metadata API allowlist and
  permission inventory. All 896 official bundled icons remain available. No cloud
  mutation or live collection occurred. AWS default/association identity semantics
  and live Frankfurt behavior remain explicit gaps.

## 2026-10-14 — Peering endpoint ownership, regions and CIDRs

- Backend **848 tests passed**, including **24** new tests for typed metadata,
  abbreviated regions, UIN/AppId separation, alias mismatches, missing owners,
  unknown types, bare-metal corroboration, duplicate/denied/paginated reads and
  negative controls for CIDR account/region/VPC scope.
- Frontend **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**; the existing bundle-size advisory remains.
- Synthetic `.local/peering-demo.json` rendered **5 resources / 8 relationships**
  across Frankfurt/account 100 and Singapore/account 200. Inspector confirmed
  ISOLATED state, exact owners, original and normalized regions, scoped CIDR
  inventory and reachability=false. VPC/CIDR support inventory is synthetic.
- Browser export `Downloads/tencent-cloud-cartography (34).drawio` retained all
  eight relationships with three embedded official VPC/Peering SVGs. Preview:
  `.local/peering-preview.png`. All 896 official bundled icons remain intact.
- No additional API permission or cloud mutation was introduced. Source DNS,
  ClassicLink/status-message/CIDR association semantics and live Frankfurt
  behavior remain explicit gaps.

## 2026-10-14 — Initial identity policy analysis and offline command

- Backend **878 tests passed**, including **30** new cases for explicit deny across
  direct/group policies, conditions, action/resource scopes, missing policy and
  attachment/membership reads, role aliases, COS object-prefix subset/disjoint
  denies, UIN/AppId/creator isolation, unsupported syntax, stale decisions and
  idempotent reanalysis. Offline CLI verification forbids any cloud call and
  confirms input snapshot preservation.
- Frontend **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Offline analyze generated synthetic `.local/permissions-demo.json`: **10
  resources / 13 relationships**. Browser inspector confirmed a conditional COS
  read, exact docs/* prefix, IP condition, source statement and effective-access
  verified=false. Secret allow and COS write deny are separate decision nodes.
- Browser draw.io export `(35)` retained all thirteen relationships and embedded
  ten official CAM/COS/Secrets Manager SVGs. Previews are
  `.local/permissions-preview.png` and `.local/permissions-inspector.png`.
- No API was added to the collection allowlist. All 896 bundled official icons
  remain available. This closes the initial analysis foundation only; complete
  permission/resource-policy/exposure semantics and further source permission
  mappings remain incomplete, as do containers and the other requested families.

## 2026-10-14 — Configured CLB exposure graph

- Backend **893 tests passed**, including **15** new tests for direct CVM and
  corroborated address/attachment paths, account/region/VPC/status controls,
  conflicting/invalid IPs, ambiguous matches, foreign intermediates, distinct
  frontends, cycles, stale links and idempotent reanalysis. The full collector
  test now verifies unresolved CLB backends add an explicit partial-analysis scope.
- Frontend **7 tests passed**, production build succeeded and dependency audit
  reported **0 vulnerabilities**. The existing bundle-size advisory remains.
- Synthetic `.local/exposure-demo.json` rendered **10 resources / 20 relationships**.
  Inspector verified the frontend rule, IP backend, CVM target, corroborated ENI
  attachment and reachability=false. Input/supporting topology is synthetic.
- Browser draw.io export `(36)` retained all twenty edges and nine official
  CLB/VPC/ENI/CVM SVGs; previews `.local/exposure-preview.png` and
  `.local/exposure-inspector.png`. All 896 bundled official icons remain intact.
- No cloud API permission, probe or mutation was introduced. Complete permission
  analysis, public/resource-policy exposure, containers, CLB/database depth and
  missing service-family implementation remain incomplete.

## 2026-10-14 — Metadata permission/container/depth/family extension

- Backend **1,046 tests passed**. New cases cover COS policy casing/ACL/public
  decisions, boundaries, TKE endpoint/CA/auth/logging metadata, Kubernetes Table
  projections/pagination/context checks and current-context authorization reviews,
  CLB groups/traditional targets/health/rewrite configuration, typed database/ES/
  compute metadata, identity-center memberships/policies/assignments, vendor
  security metadata, new data/AI/identity families, legacy TIC/international
  reservations, Personal Edition TCR scope checks and exact API exclusions.
- Frontend **7 tests passed**, production build succeeded, npm audit reported
  **0 vulnerabilities**, and pre-commit/lint/icon integrity passed. The existing
  714 kB bundle advisory remains. The exact API manifest contains 191 actions;
  all 186 registered kinds map to existing assets and all 896 official SVG hashes
  remain intact. LKE/ADP uses the documented official generic API fallback.
- Synthetic `.local/metadata-demo.json` renders **59 nodes / 65 relationships /
  43 kinds / 21 services** in the full graph. Browser inspector confirms pod
  exec authorization review scope, identity controls and execution=false;
  coverage explicitly shows metadata-only exclusions and account-block
  non-equivalence. Service filtering and refresh were verified. Browser warning/
  error logs were empty. No live cloud or Kubernetes account was used.
- Browser export `Downloads/tencent-cloud-cartography (38).drawio` retains all
  59 resource labels and 65 relationships. It embeds 58 official SVGs; the VPC
  resource is a grouping container. PNG exported at **3,510 × 3,419**. Preview:
  `.local/metadata-preview.png`; inspector: `.local/metadata-authorization-inspector.png`.
- Current implementation and remaining differences are in METADATA-PARITY.md
  and the reconciled 67-slot aws-parity-audit.json. Workload/secret response APIs
  remain excluded, with no opt-in override. Live Frankfurt behavior, provider
  equivalence and complete effective authorization remain unverified.
- CI also runs the separate actual Neo4j transaction/isolation/viewer integration
  suite; the exact published-head result is reported after publication.

## 2026-10-14 — Named authorization and reusable product

- Backend **1,132 tests passed**, including 86 new cases for named COS composition,
  signed/unsigned separation, explicit/implicit/conditional denies, boundary and
  object-ACL uncertainty, cross-account namespaces, request conditions, role trust,
  role chains/cycles, non-COS permission endpoints, budget coverage, private project
  settings and independent HTTP project selection. Empty setup cannot replace a
  Neo4j mirror or contain fabricated inventory.
- Frontend **7 tests passed**, production build succeeded and npm audit reported
  **0 vulnerabilities**. The existing 717 kB bundle-size advisory remains. No
  cloud API was added: 191 exact allowlisted actions remain. All 195 cataloged
  kinds map to official assets; all 896 product SVGs and the official wordmark
  are hash-checked. Brand source/attribution is in the bundled brand manifest.
- The normal viewer was restarted without a demo input. Browser proof shows the
  official wordmark, an empty setup screen, zero resources and disabled diagram
  exports; no cloud authentication or collection was needed. Public preview is
  `docs/product-preview.png`. Two separate empty verification projects switched
  independently, including an explicit return to the default snapshot from a
  server started with a selected project. Browser warnings/errors were empty.
- Explicit offline authorization fixture `.local/authorization-demo.json` contains
  **46 nodes / 110 relationships**. The browser inspector verified caller IAM,
  boundary and role trust evidence, evaluated IP context, and effective assumption
  verified=false. Browser draw.io export `(39)` retained all **110** relationships.
  These are synthetic test inputs only; the normal product never loads them.
- Portable **0.2.0 wheel and source archive** include the compiled UI, complete
  official asset library and attribution. The wheel was installed in a new virtual
  environment and exercised away from the checkout: private project configuration,
  distinct region/profile settings, empty project views, static UI and logo/icon
  integrity all passed without Tencent credentials or API calls. This build/install
  smoke check also runs in CI, which uploads the distribution artifacts.
- Live service behavior and effective access remain unverified. Unknown session,
  object-ACL, unsupported policy and joint-condition semantics are documented in
  AUTHORIZATION.md. These are configuration decisions, not proven findings.

## 2026-10-14 — Environment-wide collection orchestration

- **1,178 backend tests passed**, including 46 new cases for independent per-service/
  per-account discovery, returned-product aliases, unavailable/unknown/malformed
  regions, explicit bounds and empty-bound rejection, actual collector dispatch,
  retained CloudRC assets outside RMS discovery, expired/denied/changed identities,
  account exceptions, backup/duplicate profiles, organization matching/partial
  enumeration, failed-attempt retention, HTTP overview and plan schema controls.
- **11 frontend tests passed**, including coverage classification/filter/count
  checks beyond a visible page. Production build and npm audit passed with zero
  vulnerabilities; the existing 725 kB bundle advisory remains. The exact metadata
  allowlist now contains **193** actions, adding only RMS DescribeProducts and
  DescribeRegions. Installed TCCLI's offline skeleton confirms Product/Scene inputs.
- Browser verification used explicit `.local/fleet-demo.json` only: **466** scope
  rows (10 scanned, 8 failed, 441 excluded, 7 unscanned). Cards reconcile to the
  stored plan; outcome filtering and 100-row paging work. Member 200 matched a
  collected profile, 404 matched a discarded attempt, and 303 remained unscanned
  without a verified profile. Failed scopes retain success/failure counts and
  show zero resources for discarded identity attempts. Browser warning/error logs
  were empty. Screenshot: `.local/fleet-coverage-overview.png` (offline example).
- Normal product viewing remains an empty setup state without cloud login or
  example inventory. Failed-attempt tracking is tested separately from the fixture;
  it retains previous JSON inventory and presents the newer attempt's coverage.
- A sixth actual Neo4j integration test now verifies collection-plan metadata
  roundtrip, generation fingerprint and HTTP overview counts. Exact-head CI runs
  this with the existing transaction/isolation/concurrent-refresh tests and the
  portable 0.3.0 wheel installation check.
- No Tencent account authentication, live regional/organization collection,
  credential acquisition or role assumption was performed. Runtime support and
  availability remain visible provider gaps rather than a full-parity assertion.

## 2026-10-14 — COS, database, gateway and federation metadata depth

- **1,273 backend tests passed**, including 87 focused metadata-depth cases,
  notification transport/real XML fixtures and expanded exclusion cases. Negative
  controls cover malformed/count/duplicate responses, contradictory parent/region/
  account identity, ambiguous backend addresses, restricted parameter queries,
  SAML entity/root/certificate checks and provisioning pagination failures.
- **23 added read operations / 216 total** are reconciled to `api-actions.json`.
  All **22 added Cloud API actions** are recognized by installed TCCLI's offline
  `--generate-cli-skeleton`; notification uses a fixed signed COS V2 GET because
  the Python SDK has no notification helper. No cloud request was sent by these
  contract checks. Evidence: `.local/depth-cli-contracts.json`.
- **11 frontend tests**, npm audit (zero vulnerabilities), production build,
  lint/format and icon integrity passed. All **896 original SVGs**, official
  wordmark and **211 registered kind mappings** were checked. The existing
  approximately 724 kB frontend bundle advisory remains.
- The full graph browser check used an explicit private **offline fixture** with
  **21 resources and 18 relationships** across nine services. New notification,
  proxy, backup-plan, mapping and provisioning nodes render with official icons;
  coverage preserves the excluded upstream detail operation. No JavaScript errors
  were observed; Cytoscape reported two transient edge-overlap warnings during
  layout. Snapshot/export evidence: `.local/metadata-depth-fixture.json`,
  `.local/metadata-depth.drawio`, `.local/metadata-depth-browser.png`.
- Native CLB VIPs are retained in graph address metadata. A test constructs the
  actual `clb.clb` collector output and verifies product/account/region/VPC/address
  corroboration; it does not substitute an invented backend kind or probe HTTP.
- **0.4.0** wheel and source archive bundle the compiled viewer, official assets
  and new collectors. Isolated wheel installation away from the checkout verifies
  assets, project isolation and empty unauthenticated setup; no cloud login occurs.
- Metadata-only exclusions remain enforced for header-bearing upstream details,
  unrestricted workload-valued database parameters, DEK material, download
  capabilities and earlier workload/secret APIs. These gaps, remaining provider
  differences and the exact implementation scope are in `METADATA-DEPTH.md`.
- Live Tencent account/API availability, delivery, database access and federation
  login remain unverified. Authentication-provider refresh is separate work.


## 2026-10-15 — shared authentication and renewable scan sessions

- Unified explicit profile precedence across Cloud API/COS/international CVM/TIC;
  no named-profile fallback, source merging or implicit instance metadata lookup.
- Native TCCLI 3.1.181.1 OAuth/SSO helpers, forced renewal, SSO expiry, configured
  role exchange (including OAuth source token), CVM credentials and TKE web identity
  are exercised offline in TCCLI's own interpreter. HTTP fixtures check real SDK
  signing, token use, pinned API version, region, verified TLS and no redirects;
  socket connections are blocked. Cache schema, `0600` modes, atomic cleanup and
  absence of TCCLI request log creation are asserted.
- New-generation caller checks bind account, source principal, ARN, identity type
  and user/role ID. Tests distinguish rotating role-session names from a changed
  role or federated user; a failed identity check stays failed after a reversion.
- Expired-token replay is bounded to one forced refresh. Permission denials never
  select another identity. Session/refresh failures have safe structured status
  and local remediation; healthy account inventory survives other profile failures.
- Coverage now displays provider, auth state, renewal count and login guidance.
  Prior snapshots explicitly show when authentication status was not recorded.
- COS listing uses official structured SDK metadata with continuation markers;
  the historical table parser is retained only for compatibility tests. The exact
  **216-operation inventory allowlist is unchanged**; session issuance is isolated
  authentication, and no resource mutation or workload/secret API is enabled.
- **1,320 backend tests and 13 frontend tests passed**. Native fixtures ran in
  both the installed Homebrew Python 3.10 CLI and a fresh isolated Python 3.13
  TCCLI environment. All generic signing names/endpoints are reconciled against
  official SDK clients; Auto Scaling retains its native `as` API name.
- Pre-commit/lint, the production web build, icon checks (**896 SVGs and 211 kind
  mappings**) and npm audit (zero vulnerabilities) passed. The existing roughly
  725 kB frontend bundle advisory remains.
- An explicit temporary offline browser fixture showed a healthy OAuth profile
  with one renewal alongside an expired SSO profile and its local login command.
  The healthy resource remained visible; no JavaScript errors were observed.
  The temporary tab/server were closed; the normal viewer's data was untouched.
- **0.5.0** wheel/source archive include the compiled viewer, official assets and
  authentication bridge. Isolated wheel installation verifies the UI, asset
  hashes and independent project setup without cloud calls. A regression test
  ensures the installed bridge cannot expose the application's conflicting SDK
  directory to TCCLI's interpreter.
- **No live Tencent authentication or Frankfurt collection was performed.**

## Networking metadata closure — 2026-10-15 (0.6.0)

- Implemented the feasible metadata work in all 14 requested networking rows;
  [NETWORK-PARITY.md](NETWORK-PARITY.md) records the closure matrix, audited
  provider differences and evidence limits. The AWS source checkout was read only.
- Added **17 exact read operations / 233 total**. Native SDK request/response
  contracts were inspected for cross targets, SCF bindings, IPv6 variants,
  endpoint-service allowlists, shared CCN attachments, gateway identities and
  GWLB target groups/bindings/reported health. No live cloud API call was made.
- **1,390 backend tests** pass, including **70 new tests** covering cross-account,
  cross-region, VPC/ENI/IP and exact-rule contradictions, duplicate owners,
  legacy remote-region bindings, scoped SCF identity, stale offline evidence,
  ACL/default-subnet semantics, shared CCN owners, private NAT next hops,
  gateway denials, pagination and payload omission. The native TCCLI provider
  fixture ran in the isolated installed TCCLI interpreter, without network access.
- **13 frontend tests**, clean `npm ci`, production build and dependency audit
  passed; npm reports **zero vulnerabilities**. The existing bundle-size advisory
  remains. Pre-commit includes Python lint/format and official asset checks.
- Browser smoke used a separate, explicitly labeled local example fixture:
  **29 resources / 49 relationships / 5 services** in full graph view. New gateway
  and CLB/SCF metadata rendered with official assets. Grid layout and local
  draw.io export completed; the export contains **48 editable vertices including
  grouping containers and all 49 edges**, with valid parent/source/target IDs
  and embedded SVGs. No console errors were observed. Initial auto layout emitted
  one node-overlap edge warning. The test did not replace any project inventory.
- All **896 official SVGs**, the official wordmark and **222 registered kind
  mappings** passed integrity checks. VPN and Direct Connect have explicit official
  product mappings; GWLB uses the official CLB symbol because the pinned archive
  has no dedicated GWLB asset.
- The **0.6.0 wheel and source archive** bundle the viewer and official assets.
  The isolated installation smoke verifies project isolation and local HTTP/UI
  delivery away from the checkout. Artifacts are generated under `dist/`.
- Authenticated Tencent/Frankfurt validation remains outstanding. AWS tenancy,
  launch-time addressing, default ACL, endpoint IAM/private-DNS and other native
  schema differences are documented; offline tests do not establish full AWS
  equivalence, public reachability or effective authorization.


## Storage/database/secret metadata extension — 2026-10-15 (0.7.0)

- Implemented the feasible additions for all nine requested areas; see
  [the disposition and usage guide](STORAGE-DATABASE-PARITY.md).
- Added **37 exact read operations / 270 total**, with **265 registered kinds**.
  Recursive native TCCLI SDK schema checks cover every declarative projection,
  including nested response types. No new data/credential/log retrieval methods
  are allowed. The native SDK includes operations absent from the older
  international package; they use the native transport.
- **1490 Python tests passed**, including the isolated native TCCLI contracts.
  Controls cover wrong instance/account/namespace, malformed/duplicate/changing
  pagination, unsafe XML and method/parameter injection, empty/default versus
  explicit ACLs, missing directory metadata, current-object named and anonymous
  decisions, fixed signed version queries, session-policy intersections,
  replication ownership ambiguity and rotation-history truncation.
- **13 frontend tests passed**; `npm ci`, production build and production dependency
  audit passed with **0 vulnerabilities**. Vite retains its existing large-chunk
  advisory; this extension does not change the frontend bundle structure.
- Pre-commit Ruff checks/format and official asset integrity passed. All **896 SVGs**
  and the Tencent wordmark remain byte-verified.
- Separate loopback browser validation used an explicitly labeled **EXAMPLE DATA**
  fixture; the user's real project snapshots were not replaced. Full view showed
  **98 resources / 139 relationships / 14 services**. The editable draw.io export
  preserved every relationship: **119 editable vertices**, including **96 embedded
  official resource icons**, plus VPC/subnet and structural containers. Export:
  `.local/validation/data-metadata-export-20261015.drawio`.
- The **0.7.0 wheel and source archive** were built. The wheel was installed in a
  fresh environment away from the checkout; packaged UI, all official icons/logo,
  and isolated empty project workspaces were verified without cloud access.
- Local logs and temporary fixture: `.local/validation/data-metadata-*`.
  No live Tencent requests, database login/query, object contents, secret values,
  or TcaplusDB passwords/schema contents were used in validation.
- Full AWS parity remains unverified. The account-wide COS block equivalence,
  native-model differences, unsafe mixed responses and missing runtime evidence
  stay explicit in the nine-area report and per-collector audit.


## Platform/security/authorization extension — 2026-10-15 (0.8.0)

- Added **46 exact metadata reads / 316 total**. Implemented configuration,
  scoped relationships, condition/session evaluation and native Kubernetes RBAC
  metadata for the requested areas; the [15-area report](PLATFORM-PARITY.md)
  records the remaining excluded responses and unverified provider semantics.
- **1634 Python tests passed** with the isolated native TCCLI runtime, including
  recursive response contracts, explicit fixtures for all 42 new declarative
  reads, TcaplusDB tag scopes, wrong owner/region/catalog/certificate/zone/asset
  type controls, stable pagination, RBAC namespace/identity/reference controls,
  session deny propagation, finite numeric/wildcard/absent-attribute/tag conditions
  and offline reconciliation idempotence.
- **13 frontend tests passed**. `npm ci`, production build and dependency audit
  passed with **0 vulnerabilities**. The existing Vite large-chunk advisory remains.
- Pre-commit Ruff lint/format and the asset checker passed: **896 official SVGs**,
  the official wordmark and **322 kind mappings**. The kind-mapping count includes
  catalog collectors, child/detail kinds and explicit kind-icon entries.
- Separate browser validation used an explicitly labeled **EXAMPLE DATA** file on
  loopback port 8793. Full relationship view with unresolved inventory displayed
  **79 resources / 49 relationships / 23 services**; search located two configured
  RBAC grants. No browser console errors were observed. The initial DOM checkbox
  helper failed to toggle; the native accessible control succeeded and its checked
  state was verified. No production snapshot/project settings were replaced.
- Browser draw.io download preserved all **49 relationships**, **120 editable
  vertices** (including structural containers) and **75 embedded resource SVGs**.
  Export: `.local/validation/platform-metadata-export-20261015.drawio`. The fixture
  intentionally includes an unknown inventory kind to exercise unresolved visibility.
- Built the **0.8.0 wheel and source archive**. An isolated installation away from
  the checkout verified packaged UI, checksummed official assets/wordmark and
  separate empty project workspaces without cloud access.
- Final local evidence: `.local/validation/platform-final-tests.txt`,
  `platform-final-precommit.txt`, `platform-web-tests.txt`, `platform-web-build.txt`,
  `platform-npm-audit.txt`, `platform-package-build.txt`, `platform-package-check.txt`.
- No live Tencent/Kubernetes API requests, cloud writes, database login/query,
  workload execution or object/secret contents were used for validation. Configured
  access, vendor security counters and delivery settings remain configuration
  evidence. Full AWS parity, actual authorization and live Frankfurt behavior are
  **not established**.
