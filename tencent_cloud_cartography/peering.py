"""Owner-qualified peering endpoints and corroborated VPC address inventory."""

import re
from dataclasses import replace

from .monitor import REGIONS
from .transport import CollectionError, pages
from .vpc import fields, identity


def owner(value):
    if value in (None, ""):
        return None
    if type(value) is int:
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise CollectionError("InvalidPeeringOwner")
    return value


def location(value):
    if not value:
        return None
    # API 3.0's peering example still uses gz. Preserve original metadata and
    # normalize only documented Tencent region abbreviations, shared with Monitor.
    if value in REGIONS:
        return REGIONS[value]
    if re.fullmatch(r"(?:ap|na|eu|sa|me|af)-[a-z]+(?:-[a-z]+)*", value):
        return value
    return None


def prepare(raw):
    props = fields(
        raw,
        (
            "PeeringConnectionName",
            "SourceRegion",
            "DestinationRegion",
            "State",
            "Type",
            "CreateTime",
            "ChargeType",
            "QosLevel",
        ),
        ("IsNgw",),
        ("Bandwidth", "AppId", "PeerAppId"),
    )
    rid = identity(raw.get("PeeringConnectionId"), "pcx")
    props.update(PeeringConnectionId=rid, reachability_verified=False)
    endpoints = []
    for side, id_key, owner_key, region_key in (
        ("source", "SourceVpcId", "SourceUin", "SourceRegion"),
        ("peer", "DestinationVpcId", "DestinationUin", "DestinationRegion"),
    ):
        value = raw.get(id_key)
        if side == "peer":
            alias = raw.get("PeerVpcId")
            if value and alias and value != alias:
                raise CollectionError("PeeringVpcAliasMismatch")
            value = value or alias
            if alias:
                props["PeerVpcId"] = identity(alias, "vpc")
        vpc_id = identity(value, "vpc") if value not in (None, "") else None
        uin = owner(raw.get(owner_key))
        region = location(props.get(region_key))
        if vpc_id:
            props[id_key] = vpc_id
        if uin:
            props[owner_key] = uin
        if region:
            props[f"{side}_region"] = region
        # VPC_BM_PEER does not establish which side is bare metal. Unknown
        # types (including the documented VPC0 example) need collected inventory.
        kind = "vpc.vpc" if props.get("Type") == "VPC_PEER" else None
        resolution = (
            "missing-vpc"
            if not vpc_id
            else "missing-owner"
            if not uin
            else "unresolved-region"
            if not region
            else "unresolved-network-type"
            if not kind
            else "explicit"
        )
        props[f"{side}_resolution"] = resolution
        endpoints.append((side, vpc_id, uin, region, kind))
    return rid, props, endpoints


def collect(runner, spec, region):
    source = "vpc." + spec.action

    def operation(record):
        seen = set()
        incomplete = False
        for rows, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = [prepare(row) for row in rows]
            ids = [row[0] for row in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicatePeeringConnection")
            seen.update(ids)
            for rid, props, endpoints in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    rid,
                    props.get("PeeringConnectionName"),
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(props)
                for side, vpc_id, uin, target_region, kind in endpoints:
                    if not all((vpc_id, uin, target_region)):
                        incomplete = True
                        continue
                    if kind:
                        target = runner.graph.add(
                            uin, target_region, kind, vpc_id, source=source, status="reference"
                        )
                        runner.graph.edge(
                            nid, target, "SOURCE_VPC" if side == "source" else "PEER_VPC", source
                        )
                record["count"] += 1
        if incomplete:
            raise CollectionError("IncompletePeeringEndpoint")

    runner.scope("vpc", spec.action, region, operation)


def link(graph):
    """Link address inventories, without asserting which CIDRs are reachable."""
    networks = {}
    for node in graph.nodes.values():
        if node["kind"] in {"vpc.vpc", "bmvpc.vpc"} and node["status"] == "enriched":
            networks.setdefault((node["account"], node["region"], node["resource_id"]), []).append(
                node
            )
    for node in list(graph.nodes.values()):
        if node["kind"] != "vpc.peeringconnection" or node["status"] != "enriched":
            continue
        props = node["properties"]
        for side, id_key, owner_key, relation in (
            ("source", "SourceVpcId", "SourceUin", "SOURCE_VPC"),
            ("peer", "DestinationVpcId", "DestinationUin", "PEER_VPC"),
        ):
            key = (props.get(owner_key), props.get(f"{side}_region"), props.get(id_key))
            candidates = networks.get(key, [])
            if props.get("Type") == "VPC_PEER":
                candidates = [n for n in candidates if n["kind"] == "vpc.vpc"]
            if len(candidates) != 1:
                props[f"{side}_cidr_resolution"] = (
                    "ambiguous-network" if candidates else "uncollected-network"
                )
                continue
            target = candidates[0]
            graph.edge(node["id"], target["id"], relation, "peering.collected-network")
            props[f"{side}_resolution"] = "matched-collected-network"
            count = 0
            for edge in list(graph.edges.values()):
                if edge["source"] != target["id"] or edge["relationship"] != "HAS_CIDR":
                    continue
                block = graph.nodes[edge["target"]]
                if (
                    block["kind"] != "vpc.cidr"
                    or block["status"] != "enriched"
                    or block["account"] != target["account"]
                    or block["region"] != target["region"]
                    or block["properties"].get("VpcId") != target["resource_id"]
                ):
                    continue
                graph.edge(
                    node["id"],
                    block["id"],
                    f"{side.upper()}_VPC_CIDR",
                    "peering.collected-vpc-cidr",
                )
                count += 1
            props[f"{side}_cidr_resolution"] = (
                "collected-vpc-inventory" if count else "uncollected-cidrs"
            )
        if any(
            props.get(f"{side}_resolution") == "unresolved-network-type"
            for side in ("source", "peer")
        ):
            graph.coverage.append(
                dict(
                    account=node["account"],
                    region=node["region"],
                    service="vpc",
                    action="DescribeVpcPeeringConnections",
                    detail=node["resource_id"],
                    status="unsupported",
                    error="UnresolvedPeeringNetworkType",
                    count=0,
                    request_ids=[],
                )
            )
