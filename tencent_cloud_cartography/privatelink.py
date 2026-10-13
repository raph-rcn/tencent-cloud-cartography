"""Private Link metadata and explicit service-owner reconciliation."""

import ipaddress
import re
from dataclasses import replace

from .transport import CollectionError, pages

FAMILIES = ("Ipv4", "Ipv6", "DualStack")
SERVICE_TYPES = ("CLB", "CDB", "CRS", "GWLB")


def identifier(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Za-z0-9]+", value):
        raise CollectionError("InvalidPrivateLinkIdentity")
    return value


def prepare(raw, kind, account, authorized=False):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidPrivateLinkMetadata")
    service = kind == "vpc.endpointservice"
    fields = (
        (
            "EndPointServiceId",
            "VpcId",
            "ServiceOwner",
            "ServiceName",
            "ServiceVip",
            "ServiceInstanceId",
            "CreateTime",
            "ServiceType",
            "CdcId",
            "ServiceUin",
        )
        if service
        else (
            "EndPointId",
            "VpcId",
            "SubnetId",
            "EndPointOwner",
            "EndPointName",
            "ServiceVpcId",
            "ServiceVip",
            "EndPointServiceId",
            "EndPointVip",
            "State",
            "CreateTime",
            "ServiceName",
            "CdcId",
        )
    )
    props = {}
    for field in fields:
        if raw.get(field) is not None:
            value = raw[field]
            if not isinstance(value, str) or any(ord(c) < 32 for c in value):
                raise CollectionError("InvalidPrivateLinkMetadata")
            props[field] = value
    for field in ("AutoAcceptFlag", "EndPointCount", "BusinessIpType") if service else ():
        if raw.get(field) is not None:
            typ = bool if field == "AutoAcceptFlag" else int
            if type(raw[field]) is not typ or (typ is int and raw[field] < 0):
                raise CollectionError("InvalidPrivateLinkMetadata")
            props[field] = raw[field]
    rid = identifier(
        props.get("EndPointServiceId" if service else "EndPointId"), "vpcsvc" if service else "vpce"
    )
    owner = account
    if service:
        if props.get("ServiceUin"):
            owner = props["ServiceUin"]
            if not re.fullmatch(r"[1-9][0-9]*", owner):
                raise CollectionError("InvalidPrivateLinkOwner")
            if not authorized and owner != account:
                raise CollectionError("PrivateLinkOwnerMismatch")
        elif authorized:
            raise CollectionError("MissingPrivateLinkOwner")
        props["owner_uin_source"] = "ServiceUin" if props.get("ServiceUin") else "queried-account"
        # Nested endpoints expose AppIds, not owner UINs. Do not turn them into
        # consumer nodes in the service owner's account.
        nested = raw.get("EndPointSet")
        if nested is not None:
            if not isinstance(nested, list) or any(not isinstance(r, dict) for r in nested):
                raise CollectionError("InvalidPrivateLinkMetadata")
            props["reported_endpoint_rows"] = len(nested)
            if "EndPointCount" in props:
                props["endpoint_rows_truncated"] = len(nested) < props["EndPointCount"]
    else:
        props["state"] = props.get("State", "")
        if props.get("EndPointServiceId"):
            identifier(props["EndPointServiceId"], "vpcsvc")
            props["endpoint_service_id"] = props["EndPointServiceId"]
    for field in ("ServiceOwner", "EndPointOwner"):
        if props.get(field) and not re.fullmatch(r"[1-9][0-9]*", props[field]):
            raise CollectionError("InvalidPrivateLinkAppId")
    for field in ("ServiceVip", "EndPointVip"):
        if props.get(field):
            try:
                if "%" in props[field]:
                    raise ValueError("Scoped address")
                props[field] = str(ipaddress.ip_address(props[field]))
            except ValueError as exc:
                raise CollectionError("InvalidPrivateLinkAddress") from exc
    links = []
    for field, target_kind, prefix, relation in (
        ("VpcId", "vpc.vpc", "vpc", "IN_VPC"),
        ("SubnetId", "vpc.subnet", "subnet", "IN_SUBNET"),
    ):
        if props.get(field):
            links.append((target_kind, identifier(props[field], prefix), relation))
    if props.get("ServiceVpcId"):
        identifier(props["ServiceVpcId"], "vpc")
    if not service:
        groups = raw.get("GroupSet")
        if groups is not None:
            if not isinstance(groups, list):
                raise CollectionError("InvalidPrivateLinkGroups")
            for group in groups:
                links.append(("vpc.securitygroup", identifier(group, "sg"), "USES_SECURITY_GROUP"))
    else:
        mapping = {
            "CLB": ("clb.clb", "lb", "SERVES_LOAD_BALANCER"),
            "CDB": ("cdb.instance", "cdb", "SERVES_DATABASE"),
            "CRS": ("redis.instance", "crs", "SERVES_DATABASE"),
            "GWLB": ("clb.gatewayloadbalancer", "gwlb", "SERVES_LOAD_BALANCER"),
        }
        backend = mapping.get(props.get("ServiceType"))
        if backend and props.get("ServiceInstanceId"):
            links.append(
                (backend[0], identifier(props["ServiceInstanceId"], backend[1]), backend[2])
            )
    props["connectivity_verified"] = False
    return owner, rid, props, links


def resource_pages(transport, spec, region, params):
    if params["IpAddressType"] != "DualStack":
        yield from pages(transport, replace(spec, require_total=True), region, params)
        return
    token, seen_tokens, count, expected = None, set(), 0, None
    for _ in range(10000):
        query = dict(params, MaxResults=100)
        if token:
            query["NextToken"] = token
        response = transport.call(spec.service, spec.action, region=region, **query)
        rows, total = response.get(spec.result), response.get("TotalCount")
        if not isinstance(rows, list) or type(total) is not int or total < 0:
            raise CollectionError("InvalidPrivateLinkPage")
        if expected is not None and total != expected:
            raise CollectionError("InventoryChanged")
        expected = total
        next_token = response.get("NextToken")
        if next_token is not None and not isinstance(next_token, str):
            raise CollectionError("InvalidPrivateLinkToken")
        if next_token and (next_token in seen_tokens or not rows):
            raise CollectionError("PaginationStalled")
        count += len(rows)
        if count > total or (not next_token and count != total):
            raise CollectionError("CountMismatch")
        yield rows, response.get("RequestId")
        if not next_token:
            return
        seen_tokens.add(next_token)
        token = next_token
    raise CollectionError("PageLimit")


def collect(runner, spec, region):
    service = spec.kind == "vpc.endpointservice"
    source = f"vpc.{spec.action}"

    def scope(params, detail, authorized=False, expected_id=None):
        def operation(record):
            seen = set()
            for rows, request in resource_pages(runner.transport, spec, region, params):
                if request:
                    record["request_ids"].append(request)
                prepared = [prepare(row, spec.kind, runner.account, authorized) for row in rows]
                identities = [(r[0], r[1]) for r in prepared]
                if len(set(identities)) != len(identities) or seen.intersection(identities):
                    raise CollectionError("DuplicatePrivateLinkResource")
                if expected_id and any(r[1] != expected_id for r in prepared):
                    raise CollectionError("PrivateLinkLookupMismatch")
                if (
                    not authorized
                    and service
                    and any(
                        r[2].get("ServiceType") != params["Filters"][0]["Values"][0]
                        for r in prepared
                    )
                ):
                    raise CollectionError("PrivateLinkTypeMismatch")
                seen.update(identities)
                for owner, rid, props, links in prepared:
                    nid = runner.graph.add(
                        owner,
                        region,
                        spec.kind,
                        rid,
                        props.get("ServiceName" if service else "EndPointName"),
                        source=source,
                    )
                    runner.graph.nodes[nid]["properties"].update(props)
                    saved = runner.graph.nodes[nid]["properties"]
                    families = set(filter(None, saved.get("queried_ip_families", "").split(",")))
                    saved["queried_ip_families"] = ",".join(
                        sorted(families | {params["IpAddressType"]})
                    )
                    ip = props.get("ServiceVip" if service else "EndPointVip")
                    if ip:
                        addresses = set(filter(None, saved.get("ip_addresses", "").split(", ")))
                        saved["ip_addresses"] = ", ".join(sorted(addresses | {ip}))
                    for target_kind, target_id, relation in links:
                        target = runner.graph.add(
                            owner, region, target_kind, target_id, source=source, status="reference"
                        )
                        runner.graph.edge(nid, target, relation, source)
                    record["count"] += 1

        runner.scope("vpc", spec.action, region, operation, detail)

    for family in FAMILIES:
        for typ in SERVICE_TYPES if service else (None,):
            params = dict(IpAddressType=family)
            if typ:
                params["Filters"] = [{"Name": "service-type", "Values": [typ]}]
            scope(params, f"{family}/{typ}" if typ else family)
    if service:
        # Exact authorized lookups can identify foreign owners without converting
        # APPIDs. No broad enumeration of another account is attempted.
        wanted = {
            n["properties"].get("endpoint_service_id")
            for n in runner.graph.nodes.values()
            if n["kind"] == "vpc.endpoint"
            and n["account"] == runner.account
            and n["region"] == region
        }
        owned = {
            n["resource_id"]
            for n in runner.graph.nodes.values()
            if n["kind"] == spec.kind
            and n["account"] == runner.account
            and n["region"] == region
            and n["status"] == "enriched"
        }
        for rid in sorted(wanted - owned - {None}):
            for family in FAMILIES:
                scope(
                    dict(
                        IpAddressType=family,
                        EndPointServiceIds=[rid],
                        IsListAuthorizedEndPointService=True,
                    ),
                    f"authorized/{rid}/{family}",
                    authorized=True,
                    expected_id=rid,
                )


def link(graph):
    services = {}
    for node in graph.nodes.values():
        if node["kind"] == "vpc.endpointservice" and node["status"] == "enriched":
            services.setdefault((node["region"], node["resource_id"]), []).append(node)
    for node in list(graph.nodes.values()):
        if node["kind"] != "vpc.endpoint" or node["status"] != "enriched":
            continue
        props = node["properties"]
        matches = services.get((node["region"], props.get("endpoint_service_id")), [])
        if not matches:
            props["service_resolution"] = "unresolved"
        elif len(matches) != 1:
            props["service_resolution"] = "ambiguous"
        elif props.get("ServiceVpcId") and props["ServiceVpcId"] != matches[0]["properties"].get(
            "VpcId"
        ):
            props["service_resolution"] = "conflicting-vpc"
        else:
            props["service_resolution"] = "matched"
            graph.edge(
                node["id"],
                matches[0]["id"],
                "CONNECTS_TO_SERVICE",
                "vpc.DescribeVpcEndPoint+vpc.DescribeVpcEndPointService",
            )
