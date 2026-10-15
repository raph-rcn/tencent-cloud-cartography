"""VPC address-space metadata with explicit subnet containment."""

import ipaddress
import json
import re
from dataclasses import replace

from .transport import CollectionError, pages


def identity(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Za-z0-9]+", value):
        raise CollectionError("InvalidVpcIdentity")
    return value


def fields(raw, strings=(), booleans=(), integers=()):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidVpcMetadata")
    result = {}
    for names, typ in ((strings, str), (booleans, bool), (integers, int)):
        for name in names:
            value = raw.get(name)
            if value is not None:
                if type(value) is not typ or (typ is int and value < 0):
                    raise CollectionError("InvalidVpcMetadata")
                result[name] = value
    return result


def cidr(value, version):
    try:
        if not isinstance(value, str) or "/" not in value or "%" in value:
            raise ValueError("Invalid network")
        network = ipaddress.ip_network(value, strict=True)
        if network.version != version:
            raise ValueError("Wrong family")
        return str(network)
    except ValueError as exc:
        raise CollectionError("InvalidVpcCidr") from exc


def array(raw, name):
    value = raw.get(name)
    if value is None:
        return []
    if not isinstance(value, list):
        raise CollectionError("InvalidVpcArray")
    return value


def prepare_vpc(raw, region):
    props = fields(
        raw,
        ("VpcName", "CreatedTime", "DomainName", "DhcpOptionsId", "StackType"),
        (
            "IsDefault",
            "EnableMulticast",
            "EnableDhcp",
            "EnableRouteVpcPublish",
            "EnableRouteVpcPublishIpv6",
        ),
    )
    rid = identity(raw.get("VpcId"), "vpc")
    props["VpcId"] = rid
    blocks = {}

    def block(value, version, role, extra=None):
        network = cidr(value, version)
        current = blocks.setdefault(
            network, dict(cidr=network, ip_version=version, roles=[], subnets=[])
        )
        current["roles"].append(role)
        for name, val in (extra or {}).items():
            if name in current and current[name] != val:
                raise CollectionError("ConflictingVpcCidrMetadata")
            current[name] = val
        return network, current

    for name, version, role in (
        ("CidrBlock", 4, "primary_ipv4"),
        ("Ipv6CidrBlock", 6, "primary_ipv6"),
    ):
        if raw.get(name) not in (None, ""):
            props[name], _ = block(raw[name], version, role)
    seen = set()
    for row in array(raw, "AssistantCidrSet"):
        meta = fields(row, integers=("AssistantType",))
        if row.get("VpcId") != rid:
            raise CollectionError("AssistantCidrParentMismatch")
        network, entry = block(row.get("CidrBlock"), 4, "assistant", meta)
        if network in seen:
            raise CollectionError("DuplicateAssistantCidr")
        seen.add(network)
        subnet_ids = set()
        for subnet in array(row, "SubnetSet"):
            if not isinstance(subnet, dict) or subnet.get("VpcId") != rid:
                raise CollectionError("AssistantSubnetParentMismatch")
            sid = identity(subnet.get("SubnetId"), "subnet")
            if sid in subnet_ids:
                raise CollectionError("DuplicateAssistantSubnet")
            if subnet.get("CidrBlock") and not ipaddress.ip_network(
                cidr(subnet["CidrBlock"], 4)
            ).subnet_of(ipaddress.ip_network(network)):
                raise CollectionError("AssistantSubnetCidrMismatch")
            subnet_ids.add(sid)
            entry["subnets"].append(sid)
    seen = set()
    for row in array(raw, "Ipv6CidrBlockSet"):
        meta = fields(row, ("ISPType", "AddressType"))
        network, _ = block(row.get("IPv6CidrBlock"), 6, "provider_ipv6", meta)
        if network in seen:
            raise CollectionError("DuplicateIpv6Cidr")
        seen.add(network)
    if raw.get("DnsServerSet") is not None:
        servers = []
        for server in array(raw, "DnsServerSet"):
            try:
                if not isinstance(server, str) or "%" in server:
                    raise ValueError("Invalid address")
                servers.append(str(ipaddress.ip_address(server)))
            except ValueError as exc:
                raise CollectionError("InvalidVpcDnsServer") from exc
        props["DnsServerSet"] = json.dumps(servers)
    return rid, props, blocks, []


def prepare_subnet(raw, region):
    props = fields(
        raw,
        ("SubnetName", "CreatedTime", "Zone", "CdcId", "StackType"),
        ("IsDefault", "EnableBroadcast", "IsRemoteVpcSnat"),
        ("AvailableIpAddressCount", "TotalIpAddressCount", "IsCdcSubnet"),
    )
    rid = identity(raw.get("SubnetId"), "subnet")
    props["SubnetId"] = rid
    props["network_acl_association"] = (
        "unavailable"
        if raw.get("NetworkAclId") is None
        else "explicit"
        if raw["NetworkAclId"]
        else "none"
    )
    props["route_table_association"] = (
        "unavailable"
        if raw.get("RouteTableId") is None
        else "explicit"
        if raw["RouteTableId"]
        else "none-reported"
    )
    vpc = identity(raw.get("VpcId"), "vpc")
    props["VpcId"] = vpc
    links = [("vpc.vpc", vpc, "IN_VPC")]
    for name, version in (("CidrBlock", 4), ("Ipv6CidrBlock", 6)):
        if raw.get(name) not in (None, ""):
            props[name] = cidr(raw[name], version)
    zone = props.get("Zone")
    if zone:
        if not re.fullmatch(re.escape(region) + r"-[0-9]+", zone):
            raise CollectionError("SubnetZoneMismatch")
        props["zone"] = zone
    for name, prefix, kind, relation in (
        ("RouteTableId", "rtb", "vpc.routetable", "USES_ROUTE_TABLE"),
        ("NetworkAclId", "acl", "vpc.networkacl", "USES_NETWORK_ACL"),
    ):
        if raw.get(name) not in (None, ""):
            props[name] = identity(raw[name], prefix)
            links.append((kind, props[name], relation))
    return rid, props, {}, links


def collect(runner, spec, region):
    source = f"vpc.{spec.action}"
    prepare = prepare_vpc if spec.kind == "vpc.vpc" else prepare_subnet

    def operation(record):
        seen = set()
        for rows, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = [prepare(row, region) for row in rows]
            ids = [row[0] for row in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateVpcResource")
            seen.update(ids)
            for rid, props, blocks, links in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    rid,
                    props.get("VpcName" if spec.kind == "vpc.vpc" else "SubnetName"),
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(props)
                for kind, target_id, relation in links:
                    target = runner.graph.add(
                        runner.account, region, kind, target_id, source=source, status="reference"
                    )
                    runner.graph.edge(nid, target, relation, source)
                for network, metadata in blocks.items():
                    block_id = runner.graph.add(
                        runner.account,
                        region,
                        "vpc.cidr",
                        f"{rid}/{network}",
                        network,
                        source=source,
                    )
                    saved = {k: v for k, v in metadata.items() if k not in {"roles", "subnets"}}
                    saved["roles"] = json.dumps(sorted(set(metadata["roles"])))
                    saved["VpcId"] = rid
                    runner.graph.nodes[block_id]["properties"].update(saved)
                    runner.graph.edge(nid, block_id, "HAS_CIDR", source)
                    runner.graph.edge(block_id, nid, "IN_VPC", source)
                    for subnet in metadata["subnets"]:
                        target = runner.graph.add(
                            runner.account,
                            region,
                            "vpc.subnet",
                            subnet,
                            source=source,
                            status="reference",
                        )
                        runner.graph.edge(block_id, target, "HAS_SUBNET", source)
                record["count"] += 1

    runner.scope("vpc", spec.action, region, operation)
