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
