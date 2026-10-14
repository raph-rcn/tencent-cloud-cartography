"""Reconcile organization roster against verified collection, without assuming access."""

from collections import Counter

from .collection_plan import STATES


def reconcile_organization(graph):
    collection = graph.collection
    if collection is None:
        return
    profiles = collection["profiles"]
    profiles_by_account, scopes_by_account = {}, {}
    for profile in profiles:
        if profile["identity_verified"]:
            profiles_by_account.setdefault(profile["account"], []).append(profile)
    for scope in collection["scopes"]:
        scopes_by_account.setdefault(scope["account"], []).append(scope)
    for member in sorted(graph.nodes.values(), key=lambda n: n["id"]):
        if member["kind"] != "organization.member" or member["status"] != "enriched":
            continue
        uin = member["resource_id"]
        if not uin.isdigit() or int(uin) <= 0:
            continue
        matched = profiles_by_account.get(uin, [])
        committed = [p for p in matched if p["committed"]]
        scopes = scopes_by_account.get(uin, [])
        successful = sum(s["successful_queries"] for s in scopes)
        if committed and successful:
            state = "scanned"
            partial = any(s["state"] in {"failed", "unscanned"} or s["partial"] for s in scopes)
            reason = "partial_metadata_collection" if partial else "verified_profile_collected"
        elif matched:
            state, partial, reason = "failed", False, "verified_profile_collection_failed"
        else:
            state, partial, reason = "unscanned", False, "no_identity_verified_profile"
        row = dict(
            collector_account=member["account"],
            member_account=uin,
            member_name=member["name"],
            matched_profiles=[p["profile"] for p in matched],
            state=state,
            partial=partial,
            reason=reason,
            inventory_collected=bool(committed and successful),
        )
        collection["organization"].append(row)
        member["properties"].update(
            member_inventory_collected=row["inventory_collected"],
            member_collection_status="partial" if partial else state,
            member_collection_reason=reason,
        )
        if state != "scanned" or partial:
            graph.coverage.append(
                dict(
                    account=uin,
                    region="all",
                    service="organization",
                    action="ReconcileMemberCoverage",
                    collector_account=member["account"],
                    status="not-queried" if state == "unscanned" else "error",
                    error=reason,
                    count=successful,
                    request_ids=[],
                )
            )
    for account in graph.accounts:
        rows = [
            r
            for r in graph.coverage
            if r.get("account") == account
            and r.get("service") == "organization"
            and r.get("action") == "DescribeOrganizationMembers"
        ]
        members = [r for r in collection["organization"] if r["collector_account"] == account]
        if not rows:
            requested = collection["requested_services"]
            excluded = requested is not None and "organization" not in requested
            state, reason = (
                ("excluded", "service_selection")
                if excluded
                else ("unscanned", "organization_enumeration_not_attempted")
            )
        elif all(r["status"] in {"complete", "empty"} for r in rows):
            state, reason = "scanned", "member_enumeration_finished"
        elif all(r.get("error") == "ResourceNotFound.OrganizationNotExist" for r in rows):
            state, reason = "excluded", "not_in_organization"
        else:
            state, reason = "failed", "member_enumeration_incomplete"
        collection["organization_discovery"].append(
            dict(
                collector_account=account,
                state=state,
                reason=reason,
                enumeration_complete=state == "scanned",
                discovered_members=len(members),
            )
        )


def overview(snapshot):
    """Stored plan, with a clearly labeled compatibility view for older snapshots."""
    attempt = snapshot.get("latest_attempt")
    source = attempt or snapshot
    collection = source.get("collection")
    if collection:
        scopes = collection["scopes"]
        basis = "collection_plan"
    else:
        groups = {}
        for r in source["coverage"]:
            if r.get("service") == "analysis":
                continue
            key = (r["account"], r["region"], r["service"])
            groups.setdefault(key, []).append(r)
        scopes = []
        for (account, region, service), records in sorted(groups.items()):
            failures = [
                r for r in records if r["status"] not in {"complete", "empty", "not-queried"}
            ]
            successful = sum(r["status"] in {"complete", "empty"} for r in records)
            state = "failed" if failures else "scanned" if successful else "excluded"
            scopes.append(
                dict(
                    profile="",
                    account=account,
                    region=region,
                    service=service,
                    state=state,
                    reason="legacy_recorded_operations",
                    query_count=len(records),
                    successful_queries=successful,
                    failed_queries=len(failures),
                    excluded_queries=0,
                    resource_count=None,
                    partial=bool(failures and successful),
                    errors=sorted({r.get("error", "CollectionFailed") for r in failures}),
                )
            )
        collection = dict(
            profiles=[],
            organization=[],
            organization_discovery=[],
            requested_regions=None,
            requested_services=None,
            region_mode="legacy",
        )
        basis = "no_collection" if source["mode"] == "setup" else "recorded_operations_only"
        if basis == "no_collection":
            collection["region_mode"] = "not_started"
    totals = Counter(r["state"] for r in scopes)
    return dict(
        basis=basis,
        created_at=None if basis == "no_collection" else source["created_at"],
        inventory_created_at=None if snapshot["mode"] == "setup" else snapshot["created_at"],
        latest_attempt_failed=bool(attempt),
        region_mode=collection["region_mode"],
        requested_regions=collection["requested_regions"],
        requested_services=collection["requested_services"],
        counts={s: totals[s] for s in sorted(STATES)},
        partial_scopes=sum(r["partial"] for r in scopes),
        scopes=scopes,
        profiles=collection["profiles"],
        organization=collection["organization"],
        organization_discovery=collection["organization_discovery"],
    )


def validate_collection(value, snapshot):
    """Reject malformed plan metadata before it can be presented as coverage proof."""
    required = {
        "version",
        "region_mode",
        "requested_profiles",
        "requested_regions",
        "requested_services",
        "profiles",
        "scopes",
        "organization",
        "organization_discovery",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["region_mode"] not in {"automatic", "explicit"}
    ):
        raise ValueError("Invalid collection plan")
    import re

    from .collection_plan import region_restrictions

    profiles = value["requested_profiles"]
    if (
        not isinstance(profiles, list)
        or not profiles
        or not all(
            isinstance(p, str) and p not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", p)
            for p in profiles
        )
        or len(profiles) != len(set(profiles))
    ):
        raise ValueError("Invalid collection profiles")
    region_restrictions(value["requested_regions"])
    services = value["requested_services"]
    if services is not None and (
        not isinstance(services, list)
        or not services
        or not all(isinstance(s, str) for s in services)
    ):
        raise ValueError("Invalid collection services")
    for key in ("profiles", "scopes", "organization", "organization_discovery"):
        if not isinstance(value[key], list) or not all(isinstance(r, dict) for r in value[key]):
            raise ValueError("Invalid collection rows")
    if [p.get("profile") for p in value["profiles"]] != profiles:
        raise ValueError("Collection profile outcomes are incomplete")
    accounts = {a["id"] for a in snapshot["accounts"]}
    for p in value["profiles"]:
        account = p.get("account")
        if account is not None and (
            not isinstance(account, str) or not re.fullmatch(r"[1-9][0-9]*", account)
        ):
            raise ValueError("Invalid collection account")
        if (
            p.get("status") not in {"failed", "discarded", "duplicate", "scanned", "partial"}
            or type(p.get("committed")) is not bool
            or type(p.get("identity_verified")) is not bool
        ):
            raise ValueError("Invalid collection profile outcome")
        if p["committed"] and (
            not p["identity_verified"]
            or account not in accounts
            or p["status"] not in {"scanned", "partial"}
        ):
            raise ValueError("Unverified account inventory")
    outcomes = {p["profile"]: p for p in value["profiles"]}
    for s in value["scopes"]:
        if (
            s.get("profile") not in outcomes
            or s.get("account") != outcomes[s["profile"]]["account"]
        ):
            raise ValueError("Collection scope identity mismatch")
        if (
            s.get("state") not in STATES
            or s.get("profile") not in profiles
            or not isinstance(s.get("service"), str)
            or not isinstance(s.get("region"), str)
            or type(s.get("partial")) is not bool
        ):
            raise ValueError("Invalid collection scope")
        for key in (
            "query_count",
            "successful_queries",
            "failed_queries",
            "excluded_queries",
            "resource_count",
        ):
            if type(s.get(key)) is not int or s[key] < 0:
                raise ValueError("Invalid collection scope counters")
        if s["successful_queries"] + s["failed_queries"] != s["query_count"]:
            raise ValueError("Collection scope counters disagree")
        if not isinstance(s.get("errors"), list) or not all(
            isinstance(e, str) for e in s["errors"]
        ):
            raise ValueError("Invalid collection scope errors")
    for r in value["organization"]:
        if (
            r.get("state") not in STATES
            or type(r.get("partial")) is not bool
            or type(r.get("inventory_collected")) is not bool
            or not isinstance(r.get("matched_profiles"), list)
        ):
            raise ValueError("Invalid organization coverage")
    if snapshot["status"] == "complete" and incomplete(value):
        raise ValueError("Incomplete collection cannot claim complete coverage")
    for r in value["organization_discovery"]:
        if (
            r.get("state") not in STATES
            or type(r.get("enumeration_complete")) is not bool
            or type(r.get("discovered_members")) is not int
            or r["discovered_members"] < 0
        ):
            raise ValueError("Invalid organization discovery coverage")


def incomplete(collection):
    return any(
        r["state"] in {"failed", "unscanned"} or r.get("partial", False)
        for key in ("scopes", "organization", "organization_discovery")
        for r in collection[key]
    )
