"""Route-table metadata, independently paginated routes and scoped IP next hops."""

import ipaddress
import json
from dataclasses import replace

from .catalog import Collector
from .model import stable_id
from .transport import CollectionError, pages
from .vpc import cidr, fields, identity

ROUTES = Collector(
    "vpc", "DescribeRouteList", "RouteSet", "vpc.route", ("RouteItemId",), require_total=True
)
GATEWAYS = {
    "INTRANAT": ("vpc.privatenat", "intranat"),
    "NAT": ("vpc.nat", "nat"),
    "VPN": ("vpc.vpngateway", "vpngw"),
    "PEERCONNECTION": ("vpc.peeringconnection", "pcx"),
    "DIRECTCONNECT": ("vpc.directconnectgateway", "dcg"),
    "CVM": ("cvm.instance", "ins"),
    "HAVIP": ("vpc.havip", "havip"),
    "USER_CCN": ("vpc.ccn", "ccn"),
    "CCN": ("vpc.ccn", "ccn"),
    "LOCAL_GATEWAY": ("vpc.localgateway", "lgw"),
    "GWLB_ENDPOINT": ("vpc.endpoint", "vpce"),
}


def route(raw, table, vpc, scoped=False):
    props = fields(
        raw,
        (
            "GatewayType",
            "GatewayId",
            "RouteDescription",
            "RouteType",
            "RouteTableId",
            "RouteItemId",
            "CreatedTime",
            "CdcId",
        ),
        booleans=("Enabled", "PublishedToVbc"),
        integers=("RouteId",),
    )
    if (scoped or props.get("RouteTableId")) and props.get("RouteTableId") != table:
        raise CollectionError("RouteParentMismatch")
    destinations = []
    for key, version in (("DestinationCidrBlock", 4), ("DestinationIpv6CidrBlock", 6)):
        if raw.get(key) not in (None, ""):
            props[key] = cidr(raw[key], version)
            destinations.append(props[key])
    if len(destinations) != 1 or not props.get("GatewayType") or not props.get("GatewayId"):
        raise CollectionError("InvalidRoute")
    target = None
    gateway = props["GatewayId"]
    if props["GatewayType"] in GATEWAYS:
        kind, prefix = GATEWAYS[props["GatewayType"]]
        # System routes may use provider sentinel values. Preserve them, but do
        # not turn a non-resource value into a gateway reference.
        if gateway.startswith(prefix + "-"):
            target = (kind, identity(gateway, prefix))
    if props["GatewayType"] == "NORMAL_CVM":
        try:
            if "%" in gateway:
                raise ValueError("Scoped address")
            props["next_hop_ip"] = str(ipaddress.ip_address(gateway))
        except ValueError as exc:
            raise CollectionError("InvalidRouteNextHopIp") from exc
    rid = props.get("RouteItemId")
    if rid and any(ord(c) < 32 for c in rid):
        raise CollectionError("InvalidRouteIdentity")
    rid = rid or stable_id(destinations[0], props["GatewayType"], gateway)
    props.update(
        RouteTableId=table, VpcId=vpc, destination=destinations[0], reachability_verified=False
    )
    props["origin_resolution"] = {
        "USER": "user-configured",
        "NETD": "provider-network-probe",
        "CCN": "provider-ccn",
    }.get(props.get("RouteType"), "unreported-or-unsupported")
    props["route_state_resolution"] = (
        "enabled-reported"
        if props.get("Enabled") is True
        else "disabled-reported"
        if props.get("Enabled") is False
        else "unreported"
    )
    return f"{table}/{rid}", props, target


def table(raw):
    props = fields(raw, ("RouteTableName", "CreatedTime"), booleans=("Main",))
    rid = identity(raw.get("RouteTableId"), "rtb")
    vpc = identity(raw.get("VpcId"), "vpc")
    props.update(RouteTableId=rid, VpcId=vpc)
    associations = raw.get("AssociationSet")
    if not isinstance(associations, list):
        raise CollectionError("InvalidRouteAssociations")
    subnets = []
    for association in associations:
        if not isinstance(association, dict) or association.get("RouteTableId", rid) != rid:
            raise CollectionError("RouteAssociationParentMismatch")
        subnets.append(identity(association.get("SubnetId"), "subnet"))
    if len(set(subnets)) != len(subnets):
        raise CollectionError("DuplicateRouteAssociation")
    local = []
    local_rows = raw.get("LocalCidrForCcn")
    if local_rows is not None and not isinstance(local_rows, list):
        raise CollectionError("InvalidLocalRouteCidrs")
    for item in local_rows or []:
        entry = fields(item, ("Cidr",), booleans=("PublishedToVbc",))
        value = entry.get("Cidr")
        if not isinstance(value, str):
            raise CollectionError("InvalidLocalRouteCidr")
        entry["Cidr"] = cidr(value, 6 if ":" in value else 4)
        local.append(entry)
    props["LocalCidrForCcn"] = json.dumps(local)
    embedded = raw.get("RouteSet")
    props["embedded_routes_available"] = embedded is not None
    if embedded is not None and not isinstance(embedded, list):
        raise CollectionError("InvalidRouteSet")
    routes = [route(r, rid, vpc) for r in embedded or []]
    if len({r[0] for r in routes}) != len(routes):
        raise CollectionError("DuplicateRoute")
    return rid, props, subnets, routes


def add_route(runner, parent, prepared, source):
    rid, props, target = prepared
    nid = runner.graph.add(
        parent["account"], parent["region"], "vpc.route", rid, props["destination"], source=source
    )
    runner.graph.nodes[nid]["properties"].update(props)
    runner.graph.edge(parent["id"], nid, "HAS_ROUTE", source)
    vpc = runner.graph.add(
        parent["account"], parent["region"], "vpc.vpc", props["VpcId"], status="reference"
    )
    runner.graph.edge(nid, vpc, "IN_VPC", source)
    if target:
        kind, gateway = target
        if kind == "vpc.ccn":
            # Shared CCNs may belong to another root account. Route responses
            # identify the CCN, but do not identify its owner.
            runner.graph.nodes[nid]["properties"]["next_hop_resolution"] = "unresolved-owner"
            return
        other = runner.graph.add(
            parent["account"],
            "global" if kind == "vpc.ccn" else parent["region"],
            kind,
            gateway,
            source=source,
            status="reference",
        )
        runner.graph.edge(nid, other, "ROUTES_TO", source)


def collect(runner, spec, region):
    collected = []
    source = "vpc.DescribeRouteTables"

    def inventory(record):
        seen = set()
        for rows, request in pages(
            runner.transport, replace(spec, require_total=True), region, {"NeedRouterInfo": True}
        ):
            if request:
                record["request_ids"].append(request)
            prepared = [table(r) for r in rows]
            ids = [r[0] for r in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateRouteTable")
            seen.update(ids)
            for rid, props, subnets, routes in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    "vpc.routetable",
                    rid,
                    props.get("RouteTableName"),
                    source=source,
                )
                parent = runner.graph.nodes[nid]
                parent["properties"].update(props)
                vid = runner.graph.add(
                    runner.account, region, "vpc.vpc", props["VpcId"], status="reference"
                )
                runner.graph.edge(nid, vid, "IN_VPC", source)
                for sid in subnets:
                    subnet = runner.graph.add(
                        runner.account, region, "vpc.subnet", sid, source=source, status="reference"
                    )
                    aid = runner.graph.add(
                        runner.account,
                        region,
                        "vpc.routeassociation",
                        f"{rid}/{sid}",
                        sid,
                        source=source,
                    )
                    runner.graph.nodes[aid]["properties"].update(
                        RouteTableId=rid, SubnetId=sid, identity_source="table/subnet"
                    )
                    runner.graph.edge(nid, aid, "HAS_ASSOCIATION", source)
                    runner.graph.edge(aid, subnet, "ASSOCIATED_SUBNET", source)
                    runner.graph.edge(subnet, nid, "USES_ROUTE_TABLE", source)
                    runner.graph.edge(aid, vid, "IN_VPC", source)
                for prepared_route in routes:
                    add_route(runner, parent, prepared_route, source)
                collected.append((nid, {r[0]: r[1] for r in routes}))
                record["count"] += 1

    runner.scope("vpc", spec.action, region, inventory)
    for nid, embedded in collected:
        parent = runner.graph.nodes[nid]

        def entries(record, parent=parent, embedded=embedded):
            source = "vpc.DescribeRouteList"
            seen = set()
            params = {
                "Filters": [
                    {"Name": "route-table-id", "Values": [parent["resource_id"]]},
                    {"Name": "vpc-id", "Values": [parent["properties"]["VpcId"]]},
                ]
            }
            for rows, request in pages(runner.transport, ROUTES, region, params):
                if request:
                    record["request_ids"].append(request)
                prepared = [
                    route(r, parent["resource_id"], parent["properties"]["VpcId"], scoped=True)
                    for r in rows
                ]
                ids = [r[0] for r in prepared]
                if len(set(ids)) != len(ids) or seen.intersection(ids):
                    raise CollectionError("DuplicateRoute")
                for rid, props, _ in prepared:
                    previous = embedded.get(rid, {})
                    if any(previous[k] != v for k, v in props.items() if k in previous):
                        raise CollectionError("RouteInventoryChanged")
                seen.update(ids)
                for r in prepared:
                    add_route(runner, parent, r, source)
                    record["count"] += 1
            if set(embedded) - seen:
                raise CollectionError("RouteInventoryChanged")

        runner.scope("vpc", "DescribeRouteList", region, entries, parent["resource_id"])


def link_next_hops(graph):
    sources = {
        "Exact route CCN ID and collected CCN owner",
        "Collected route VPC and unique interface address",
        "Collected ENI attachment ID and route account/region/VPC",
    }
    graph.edges = {k: e for k, e in graph.edges.items() if e.get("provenance") not in sources}
    ccns = {}
    reported_owners = {
        (n["properties"].get("CcnUin"), n["properties"].get("CcnId"))
        for n in graph.nodes.values()
        if n["kind"] == "vpc.ccnattachment"
        and n["status"] == "enriched"
        and n["account"] == n["properties"].get("CcnUin")
    }
    for node in graph.nodes.values():
        if (
            node["kind"] == "vpc.ccn"
            and node["region"] == "global"
            and (
                node["status"] == "enriched"
                or (node["account"], node["resource_id"]) in reported_owners
            )
        ):
            ccns.setdefault(node["resource_id"], []).append(node["id"])
    vpcs = {}
    interfaces = {}
    instances = {}
    for edge in graph.edges.values():
        if edge["relationship"] == "IN_VPC":
            vpcs.setdefault(edge["source"], set()).add(edge["target"])
        if edge["relationship"] == "HAS_ADDRESS":
            interfaces[edge["target"]] = edge["source"]
        if (
            edge["relationship"] == "ATTACHED_TO"
            and graph.nodes[edge["target"]]["kind"] == "cvm.instance"
        ):
            instances.setdefault(edge["source"], set()).add(edge["target"])
    addresses = {}
    for n in graph.nodes.values():
        if (
            n["kind"] == "vpc.interfaceaddress"
            and n["status"] == "enriched"
            and len(vpcs.get(n["id"], set())) == 1
        ):
            addresses.setdefault(
                (
                    n["account"],
                    n["region"],
                    next(iter(vpcs[n["id"]])),
                    n["properties"].get("address"),
                ),
                [],
            ).append(n["id"])
    for n in list(graph.nodes.values()):
        props = n["properties"]
        if n["kind"] == "vpc.route" and props.get("GatewayType") in {"CCN", "USER_CCN"}:
            matches = ccns.get(props.get("GatewayId"), [])
            props["next_hop_resolution"] = (
                "ambiguous-owner" if len(matches) > 1 else "unresolved-owner"
            )
            if len(matches) == 1:
                graph.edge(
                    n["id"], matches[0], "ROUTES_TO", "Exact route CCN ID and collected CCN owner"
                )
                props["next_hop_resolution"] = "matched-collected-owner"
            continue
        if n["kind"] != "vpc.route" or props.get("GatewayType") != "NORMAL_CVM":
            continue
        scope = vpcs.get(n["id"], set())
        matches = (
            addresses.get(
                (n["account"], n["region"], next(iter(scope)), props.get("next_hop_ip")), []
            )
            if len(scope) == 1
            else []
        )
        props["next_hop_resolution"] = "ambiguous" if len(matches) > 1 else "unresolved"
        if len(matches) != 1:
            continue
        props["next_hop_resolution"] = "matched-address"
        address_id = matches[0]
        graph.edge(
            n["id"],
            address_id,
            "MATCHES_INTERFACE_ADDRESS",
            "Collected route VPC and unique interface address",
        )
        targets = instances.get(interfaces.get(address_id), set())
        if len(targets) == 1:
            target = next(iter(targets))
            instance = graph.nodes[target]
            if (
                instance["status"] == "enriched"
                and instance["account"] == n["account"]
                and instance["region"] == n["region"]
                and vpcs.get(target) == scope
            ):
                graph.edge(
                    n["id"],
                    target,
                    "ROUTES_TO",
                    "Collected ENI attachment ID and route account/region/VPC",
                )
                props["next_hop_resolution"] = "matched-instance"
