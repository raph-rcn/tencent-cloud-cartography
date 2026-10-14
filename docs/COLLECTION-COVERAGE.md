# Environment-wide collection and coverage

Collection is read-only and metadata-only. Opening the viewer does not authenticate,
scan accounts or contact Tencent Cloud. `sync` uses the existing profiles explicitly
selected for a project/run. Organization membership does not grant collection access.

## Automatic regions and explicit restrictions

New projects and unprojected syncs default to `auto`. Each authenticated account
queries the Region Management System's paginated `DescribeProducts` catalog and
`DescribeRegions` for each selected regional service. Only returned `AVAILABLE`
regions are eligible. Service aliases must resolve uniquely to an observed product
name; unsupported/missing products and failed discovery remain visible gaps. No
universal CVM region list is substituted for another service's region list.

```bash
# Discover available regions independently for each selected account and service.
./landscape/local.sh projects init production --profile production --regions auto
./landscape/local.sh sync --project production

# Explicit region list: direct attempts only within those regions, without RMS.
./landscape/local.sh sync --project production --regions eu-frankfurt

# Discover per-service availability, still restricted to the named regions.
./landscape/local.sh sync --project production --discover-regions \
  --regions eu-frankfurt,ap-singapore

# Persist bounded discovery in a new project.
./landscape/local.sh projects init bounded --profile production \
  --regions eu-frankfurt,ap-singapore --discover-regions
```

Existing projects retain their saved region lists. Explicit sync flags override
settings for that run only. Invalid/empty restrictions fail before collection.
If discovery fails in bounded mode, direct attempts are limited to the explicitly
approved regions and availability remains unknown. Global APIs remain account-wide;
returned regional resources are filtered when a region restriction exists.

CloudRC regional queries cover the union of eligible regions, plus its global pass.
With unrestricted automatic discovery, the unfiltered account inventory also retains
resources from regions absent from RMS. Those assets retain their collected region,
and missing native scopes are shown as unscanned; their presence does not authorize
an unplanned native regional request. Unknown-region resources stay unresolved.
Discovery can be incomplete: the ledger describes the observed/planned scope universe,
not an assertion that all possible Tencent products and regions have been enumerated.

References: [DescribeRegions](https://cloud.tencent.com/document/api/1596/77930),
[international RMS API](https://intl.cloud.tencent.com/document/product/1271/71925).

## Organization coverage reconciliation

Organization member metadata is collected when that service is selected. Each
returned member UIN is matched to the account ID returned by `sts:GetCallerIdentity`
for configured profiles. Profile names, AppIds, organization permissions and role
names do not establish account identity or collection access. No member profile is
created, credential acquired or role assumed by this reconciliation.

- A matching, reverified profile with successful inventory operations is **scanned**;
  remaining scope failures and exclusions can make its collection partial.
- A member matched to an initially verified profile whose collection failed or was
  discarded is **failed**.
- A member without an identity-verified selected profile is **unscanned**. This means
  no collection access was established; it does not prove the account itself denies access.
- Failed/denied member enumeration remains incomplete even if some member pages were
  collected. Excluded organization discovery and a documented non-member response
  are distinguished from successful empty enumeration.

The member node's `member_inventory_collected` and collection status are reconciled
with the same ledger. The coverage view also shows which account discovered each
member and which profiles matched it.

Reference: [DescribeOrganizationMembers](https://intl.cloud.tencent.com/ind/document/product/1031/52062).

## Account failure isolation and publication

Each account is collected into a separate in-memory graph. Its identity is checked
before and after collection. A changed identity or failed final check discards that
attempt's resources and retains the failure evidence; other accounts continue.
Unexpected account errors are sanitized and isolated. Interrupting the command still
stops publication. Duplicate verified account profiles are reported as aliases and
are not collected twice; a backup profile can run after a discarded attempt.

A usable mixed-result run saves healthy/partial account metadata and returns **2**.
If no usable inventory was collected, `sync` returns **1**, preserves the previous
JSON snapshot and Neo4j generation, and saves a private coverage report alongside the
output: `inventory.json.attempt.json`. Normal project/default viewing reads a newer
failed-attempt report and shows its gaps while retaining the previous inventory.
The inventory timestamp and attempt timestamp are separate. A newer successful
snapshot supersedes an older failure report. Fixed `serve --input` sources read the
specified file; project/default viewing provides failed-attempt tracking.

A successfully queried empty inventory is publishable. Partial page results can
remain usable when identity is reverified. A denied request is not an empty inventory.
A mirror still represents the latest supplied snapshot, not accumulated account
history; accounts that failed during a mixed run are visibly missing from that run.

## Coverage overview

Open **Collection coverage** in the viewer. It provides:

- Counts and filters for **scanned, failed, excluded and unscanned** scopes.
- Account/profile, region and service combinations, successful/failed/excluded
  operation counts, enriched native resource counts and gap reasons.
- Profile identity/collection outcomes, duplicate aliases, member matching and
  organization-enumeration completeness.
- Paginated scope/member/API tables (100 rows per page), search and operation evidence.

Counts cover stored plan rows and failed-profile attempts; duplicate-account aliases
are listed separately. An unauthenticated profile has no known account ID. An
undiscovered regional universe is labeled `unknown`, rather than guessed. Service
selection, region restrictions, unavailable service regions and metadata exclusions
have different reasons. A failed scope can retain successfully collected metadata,
with `partial=true`. Operation counts are logical collection scopes, not individual
HTTP requests or pagination pages. Native resource counts exclude derived analysis
nodes and inventory-only/reference resources.

Older snapshots remain readable. Their overview is explicitly limited to recorded
API operations; omitted scopes are unknown. A fresh setup state has no collection
counts. The JSON snapshot stores the versioned `collection` plan; Neo4j preserves it
as generation metadata, and `/api/coverage` returns the same overview. Offline
`analyze` preserves the plan and does not rerun discovery or authentication.

Only `region.DescribeProducts` and `region.DescribeRegions` were added to the exact
metadata allowlist. Review [the updated permission inventory](api-actions.json)
when provisioning read access. Runtime availability still depends on region,
account, service and credential support; failed or unavailable discovery is a gap.
