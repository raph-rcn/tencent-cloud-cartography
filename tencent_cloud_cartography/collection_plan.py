"""Account-specific, service-specific collection scopes and honest discovery gaps."""

import re
from collections import Counter
from dataclasses import dataclass, field

from .catalog import COLLECTORS, EXTRA_COLLECTORS, SCF_FUNCTIONS, SCF_NAMESPACES, Collector
from .transport import CollectionError, pages

STATES = {"scanned", "failed", "excluded", "unscanned"}
REGION_CODE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
# API service aliases are resolved only against names actually returned by RMS.
PRODUCT_NAMES = {"autoscaling": ("autoscaling", "as"), "postgres": ("postgres", "postgresql")}


def service_modes():
    result = {}
    for spec in (*COLLECTORS, *EXTRA_COLLECTORS, SCF_NAMESPACES, SCF_FUNCTIONS):
        result.setdefault(spec.service, set()).add("regional" if spec.regional else "global")
    for service in ("cos",):
        result.setdefault(service, set()).update(("global", "regional"))
    result.setdefault("tag", set()).add("global")
    for service in ("lke", "tcaplusdb", "coding", "hunyuan"):
        result.setdefault(service, set()).add("regional")
    result["cloudrc"] = {"global", "regional"}
    return result


def region_restrictions(regions):
    if regions is None or regions == ["auto"]:
        return None
    if (
        not isinstance(regions, (list, tuple))
        or not regions
        or not all(isinstance(r, str) and REGION_CODE.fullmatch(r) for r in regions)
    ):
        raise ValueError("Use auto or one or more region codes, e.g. eu-frankfurt")
    return list(dict.fromkeys(regions))


def record(account, action, status="complete", **extra):
    return dict(
        account=account,
        region="global",
        service="region",
        action=action,
        status=status,
        count=0,
        request_ids=[],
        **extra,
    )


def discover(transport, account, selected, coverage, progress=lambda _: None):
    """No fallback to a universal CVM region list or a guessed product name."""
    catalog = record(account, "DescribeProducts")
    coverage.append(catalog)
    progress(f"{account} / global / region.DescribeProducts")
    names = {}
    spec = Collector("region", "DescribeProducts", "Products", "", ("Name",), require_total=True)
    try:
        for batch, request in pages(transport, spec, "global"):
            if request:
                catalog["request_ids"].append(request)
            for raw in batch:
                name = raw.get("Name") if isinstance(raw, dict) else None
                if not isinstance(name, str) or not re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_-]{0,63}", name
                ):
                    raise CollectionError("InvalidRegionProduct")
                if len(names) >= 1000:
                    raise CollectionError("RegionProductLimitExceeded")
                if name.casefold() in names:
                    raise CollectionError("DuplicateRegionProduct")
                names[name.casefold()] = name
                catalog["count"] += 1
        if not names:
            catalog["status"] = "empty"
    except CollectionError as exc:
        catalog.update(status="error", error=exc.code)
    except (ValueError, TypeError, KeyError, AttributeError):
        catalog.update(status="error", error="InvalidRegionCatalog")
    result, observations = {}, {}
    for service in sorted(selected):
        row = record(account, "DescribeRegions", detail=service, target_service=service)
        coverage.append(row)
        candidates = {
            names[name] for name in PRODUCT_NAMES.get(service, (service,)) if name in names
        }
        if len(candidates) != 1:
            row.update(
                status="error",
                error="RegionProductUnavailable" if not candidates else "AmbiguousRegionProduct",
            )
            result[service] = None
            continue
        product = next(iter(candidates))
        progress(f"{account} / global / region.DescribeRegions product={product}")
        row["product"] = product
        try:
            data = transport.call("region", "DescribeRegions", "global", Product=product)
            if data.get("RequestId"):
                row["request_ids"].append(data["RequestId"])
            values, total = data.get("RegionSet"), data.get("TotalCount")
            if (
                not isinstance(values, list)
                or type(total) is not int
                or total != len(values)
                or len(values) > 1000
            ):
                raise CollectionError("InvalidRegionList")
            validated = {}
            for value in values:
                code, state = value.get("Region"), value.get("RegionState")
                if (
                    not isinstance(code, str)
                    or not REGION_CODE.fullmatch(code)
                    or not isinstance(state, str)
                    or not re.fullmatch(r"[A-Z_]{1,64}", state)
                ):
                    raise CollectionError("InvalidRegionState")
                if code in validated:
                    raise CollectionError("DuplicateRegion")
                validated[code] = state
            observations[service] = validated
            result[service] = sorted(
                code for code, state in validated.items() if state == "AVAILABLE"
            )
            row.update(count=len(values), status="complete" if values else "empty")
        except CollectionError as exc:
            row.update(status="error", error=exc.code)
            result[service] = None
        except (ValueError, TypeError, KeyError, AttributeError):
            row.update(status="error", error="InvalidRegionList")
            result[service] = None
    return result, observations


@dataclass
class RegionPlan:
    account: str
    profile: str
    restrictions: list | None
    services: set | None
    automatic: bool = False
    regions: list = field(default_factory=list)
    by_service: dict = field(default_factory=dict)
    scopes: list = field(default_factory=list)
    observations: dict = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        transport,
        account,
        profile,
        regions,
        services,
        coverage,
        automatic=False,
        progress=lambda _: None,
    ):
        limits = region_restrictions(regions)
        plan = cls(account, profile, limits, services, automatic or limits is None)
        modes = service_modes()
        selected = set(services) if services else set(modes) - {"cloudrc"}
        regional = {s for s in selected if "regional" in modes.get(s, ())}
        discovered = {}
        if plan.automatic:
            discovered, plan.observations = discover(
                transport, account, regional, coverage, progress
            )
        for service in regional:
            values = discovered.get(service) if plan.automatic else limits
            # Explicit restrictions authorize direct attempts if discovery failed;
            # availability stays unknown, not guessed as supported or unsupported.
            allowed = values if values is not None else limits or []
            plan.by_service[service] = (
                [r for r in limits if r in allowed] if limits else list(allowed)
            )
        plan.regions = (
            list(limits) if limits else sorted({r for rs in plan.by_service.values() for r in rs})
        )
        observed_regions = {r for values in plan.observations.values() for r in values}
        universe = sorted(set(plan.regions) | observed_regions)
        for service, mode in sorted(modes.items()):
            if "global" in mode:
                plan.add(
                    service,
                    "global",
                    "unscanned" if service in selected or service == "cloudrc" else "excluded",
                    "awaiting_collection"
                    if service in selected or service == "cloudrc"
                    else "service_selection",
                )
            if "regional" not in mode:
                continue
            regions_for_rows = universe or ["unknown"]
            if (
                plan.automatic
                and service in regional
                and discovered.get(service) is None
                and not limits
                and "unknown" not in regions_for_rows
            ):
                regions_for_rows = [*regions_for_rows, "unknown"]
            for region in regions_for_rows:
                if service not in selected and service != "cloudrc":
                    state, reason = "excluded", "service_selection"
                elif region == "unknown":
                    state, reason = (
                        ("excluded", "no_available_regions")
                        if plan.automatic and service in regional and discovered.get(service) == []
                        else ("unscanned", "region_discovery_unresolved")
                    )
                elif limits and region not in limits:
                    state, reason = "excluded", "region_restriction"
                elif service == "cloudrc":
                    state, reason = "unscanned", "awaiting_collection"
                elif region in plan.by_service.get(service, []):
                    state, reason = "unscanned", "awaiting_collection"
                elif service in plan.observations:
                    availability = plan.observations[service].get(region)
                    if availability not in (None, "AVAILABLE", "UNAVAILABLE"):
                        state, reason = "unscanned", "region_state_unrecognized"
                    else:
                        state, reason = "excluded", "region_not_available_for_service"
                else:
                    state, reason = "unscanned", "region_discovery_unresolved"
                plan.add(service, region, state, reason)
        return plan

    def add(self, service, region, state, reason):
        self.scopes.append(
            dict(
                profile=self.profile,
                account=self.account,
                region=region,
                service=service,
                state=state,
                reason=reason,
                query_count=0,
                successful_queries=0,
                failed_queries=0,
                excluded_queries=0,
                resource_count=0,
                partial=False,
                errors=[],
            )
        )

    def regions_for(self, service):
        return self.regions if service == "cloudrc" else self.by_service.get(service, [])

    def permitted(self, service, region):
        return (service == "cloudrc" or not self.services or service in self.services) and (
            not region or region == "global" or region in self.regions_for(service)
        )

    def finish(self, graph, discarded=False):
        # Unfiltered automatic CloudRC inventory can reveal regions absent from RMS.
        # Retain those assets and record the missing native scope without guessing support.
        known = {(r["service"], r["region"]) for r in self.scopes}
        if self.automatic and self.restrictions is None:
            for node in graph.nodes.values():
                service, region = node["kind"].split(".")[0], node["region"]
                if (
                    node["account"] != self.account
                    or node["status"] == "reference"
                    or region in {"global", "unknown"}
                ):
                    continue
                if (service, region) not in known:
                    selected = not self.services or service in self.services
                    self.add(
                        service,
                        region,
                        "unscanned" if selected else "excluded",
                        "inventory_region_not_in_discovery" if selected else "service_selection",
                    )
                    known.add((service, region))
        records_by_scope = {}
        for record in graph.coverage:
            records_by_scope.setdefault((record.get("service"), record.get("region")), []).append(
                record
            )
        native_counts = Counter(
            (n["kind"].split(".")[0], n["region"])
            for n in graph.nodes.values()
            if n["account"] == self.account and n["status"] == "enriched"
        )
        for row in self.scopes:
            if row["state"] == "excluded" or row["region"] == "unknown":
                continue
            records = records_by_scope.get((row["service"], row["region"]), [])
            # Scope declarations and policy exclusions are not successful queries.
            actual = [
                r
                for r in records
                if r.get("action") != "*"
                and r.get("error") != "UnsupportedMetadataOnlyProjection"
                and r.get("status") != "not-queried"
            ]
            failed = [r for r in actual if r["status"] not in {"complete", "empty"}]
            excluded = [r for r in records if r.get("error") == "UnsupportedMetadataOnlyProjection"]
            row.update(
                query_count=len(actual),
                successful_queries=len(actual) - len(failed),
                failed_queries=len(failed),
                excluded_queries=len(excluded),
                errors=sorted({r.get("error", "CollectionFailed") for r in failed}),
                resource_count=0 if discarded else native_counts[(row["service"], row["region"])],
            )
            if discarded:
                row.update(
                    state="failed" if actual else "unscanned",
                    reason="account_identity_not_reverified",
                    partial=bool(actual),
                )
            elif failed:
                row.update(
                    state="failed", reason="query_failure", partial=row["successful_queries"] > 0
                )
            elif actual:
                row.update(
                    state="scanned", reason="metadata_queries_finished", partial=bool(excluded)
                )
            elif excluded:
                row.update(state="excluded", reason="metadata_only_restriction", partial=True)
        return self.scopes


def blank_scopes(profile, regions, services, error):
    """An unauthenticated profile has no known account ID or discovered region universe."""
    limits = region_restrictions(regions)
    rows = []
    for service, modes in sorted(service_modes().items()):
        for region in (["global"] if "global" in modes else []) + (
            (limits or ["unknown"]) if "regional" in modes else []
        ):
            selected = not services or service in services or service == "cloudrc"
            rows.append(
                dict(
                    profile=profile,
                    account=None,
                    region=region,
                    service=service,
                    state="unscanned" if selected else "excluded",
                    reason="profile_identity_unavailable" if selected else "service_selection",
                    query_count=0,
                    successful_queries=0,
                    failed_queries=0,
                    excluded_queries=0,
                    resource_count=0,
                    partial=False,
                    errors=[error] if selected else [],
                )
            )
    return rows
