"""Explicit subnet ACL configuration; policy inventory is not reachability proof."""

import ipaddress
from dataclasses import replace

from .catalog import Collector
from .transport import CollectionError, pages
from .vpc import fields, identity

QUINTUPLE = Collector(
    "vpc",
    "DescribeNetworkAclQuintupleEntries",
    "NetworkAclQuintupleSet",
    "vpc.networkaclrule",
    ("NetworkAclQuintupleEntryId",),
    require_total=True,
)


def array(raw, name):
    value = raw.get(name)
    if not isinstance(value, list):
        raise CollectionError("MissingAclArray")
    return value


def address(value, version):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Invalid address")
        net = ipaddress.ip_network(value, strict=True)
        if net.version != version:
            raise ValueError("Wrong address family")
        return str(net)
    except ValueError as exc:
        raise CollectionError("InvalidAclAddress") from exc


def selector(raw, v4, v6):
    active = [(name, version) for name, version in ((v4, 4), (v6, 6)) if raw.get(name)]
    if len(active) != 1:
        raise CollectionError("InvalidAclAddressFamily")
    name, version = active[0]
    return name, address(raw[name], version), version


def port(value):
    if value.lower() == "all":
        return
    parts = value.split("-")
    if len(parts) not in (1, 2) or any(not p.isascii() or not p.isdigit() for p in parts):
        raise CollectionError("InvalidAclPort")
    numbers = [int(p) for p in parts]
    if any(p > 65535 for p in numbers) or numbers[0] > numbers[-1]:
        raise CollectionError("InvalidAclPort")


def rule(raw, parent, direction=None, index=None):
    quintuple = direction is None
    props = fields(
        raw,
        (
            "Protocol",
            "Action",
            "Description",
            "ModifyTime",
            "CreateTime",
            "Port",
            "SourcePort",
            "DestinationPort",
            "NetworkAclIpv4EntryId",
            "NetworkAclIpv6EntryId",
            "NetworkAclQuintupleEntryId",
            "NetworkAclDirection",
        ),
        integers=("Priority",),
    )
    if raw.get("NetworkAclId") not in (None, parent):
        raise CollectionError("AclRuleParentMismatch")
    if props.get("Action") not in {"ACCEPT", "DROP"} or props.get("Protocol") not in {
        "TCP",
        "UDP",
        "ICMP",
        "ALL",
    }:
        raise CollectionError("InvalidAclPolicy")
    for name in ("SourcePort", "DestinationPort") if quintuple else ("Port",):
        if props.get(name):
            port(props[name])
        elif props["Protocol"] in {"TCP", "UDP"}:
            raise CollectionError("MissingAclPort")
    if quintuple:
        direction = props.get("NetworkAclDirection")
        if direction not in {"INGRESS", "EGRESS"} or "Priority" not in props:
            raise CollectionError("MissingAclRuleOrder")
        key = identity(props.get("NetworkAclQuintupleEntryId"), "(?:acli45|acli65)")
        first = selector(raw, "SourceCidr", "SourceIPv6Cidr")
        second = selector(raw, "DestinationCidr", "DestinationIPv6Cidr")
        if first[2] != second[2]:
            raise CollectionError("AclMixedAddressFamilies")
        selectors = [first, second]
        props["identity_source"] = "provider"
    else:
        selectors = [selector(raw, "CidrBlock", "Ipv6CidrBlock")]
        version = selectors[0][2]
        name = f"NetworkAclIpv{version}EntryId"
        other = f"NetworkAclIpv{6 if version == 4 else 4}EntryId"
        if props.get(other):
            raise CollectionError("AclRuleIdentityFamilyMismatch")
        key = props.get(name)
        if key:
            identity(key, f"acli{version}3")
        else:
            key = f"ipv{version}/index-{index}"
        props["identity_source"] = "provider" if props.get(name) else "response_position"
        props["response_index"] = index
    for name, value, version in selectors:
        props[name] = value
    props.update(
        direction=direction,
        ip_version=selectors[0][2],
        NetworkAclId=parent,
        order_source="provider_priority" if "Priority" in props else "response_position",
        reachability_verified=False,
    )
    return f"{parent}/{direction}/{key}", props


def prepare(raw):
    props = fields(raw, ("NetworkAclName", "CreatedTime", "NetworkAclType"))
    rid = identity(raw.get("NetworkAclId"), "acl")
    vpc = identity(raw.get("VpcId"), "vpc")
    props.update(NetworkAclId=rid, VpcId=vpc)
    acl_type = props.get("NetworkAclType", "TRIPLE")
    if acl_type not in {"TRIPLE", "QUINTUPLE"}:
        raise CollectionError("UnsupportedAclType")
    props["acl_type_resolution"] = "provider" if "NetworkAclType" in props else "legacy_triple"
    subnets = []
    for row in array(raw, "SubnetSet"):
        fields(row)
        sid = identity(row.get("SubnetId"), "subnet")
        if row.get("VpcId") not in (None, vpc) or row.get("NetworkAclId") not in (None, rid):
            raise CollectionError("AclSubnetParentMismatch")
        if sid in subnets:
            raise CollectionError("DuplicateAclSubnet")
        subnets.append(sid)
    rules = []
    if acl_type == "TRIPLE":
        for direction in ("Ingress", "Egress"):
            entries = array(raw, direction + "Entries")
            rules.extend(rule(row, rid, direction.upper(), i) for i, row in enumerate(entries))
        validate_rules(rules, set(), set())
    return rid, props, subnets, rules, acl_type


def validate_rules(rows, seen, priorities):
    new_ids, new_priorities = set(), set()
    for rid, props in rows:
        key = (props["direction"], props["ip_version"], props.get("Priority"))
        if rid in seen or rid in new_ids:
            raise CollectionError("DuplicateAclRule")
        if "Priority" in props:
            if key in priorities or key in new_priorities:
                raise CollectionError("DuplicateAclPriority")
            new_priorities.add(key)
        new_ids.add(rid)
    seen.update(new_ids)
    priorities.update(new_priorities)


def add_rule(runner, region, parent, vpc, prepared, source):
    rid, props = prepared
    nid = runner.graph.add(
        runner.account,
        region,
        "vpc.networkaclrule",
        rid,
        f"{props['direction']} {props['Action']} {props['Protocol']}",
        source=source,
    )
    runner.graph.nodes[nid]["properties"].update(props)
    runner.graph.edge(parent, nid, "HAS_RULE", source)
    runner.graph.edge(nid, vpc, "IN_VPC", source)


def collect(runner, spec, region):
    selected = []
    source = "vpc." + spec.action

    def operation(record):
        seen = set()
        for rows, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = [prepare(raw) for raw in rows]
            ids = [row[0] for row in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateNetworkAcl")
            seen.update(ids)
            for rid, props, subnets, rules, acl_type in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    rid,
                    props.get("NetworkAclName"),
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(props)
                vpc = runner.graph.add(
                    runner.account,
                    region,
                    "vpc.vpc",
                    props["VpcId"],
                    source=source,
                    status="reference",
                )
                runner.graph.edge(nid, vpc, "IN_VPC", source)
                for sid in subnets:
                    subnet = runner.graph.add(
                        runner.account, region, "vpc.subnet", sid, source=source, status="reference"
                    )
                    runner.graph.edge(subnet, nid, "USES_NETWORK_ACL", source)
                    runner.graph.edge(subnet, vpc, "IN_VPC", source)
                for row in rules:
                    add_rule(runner, region, nid, vpc, row, source)
                if acl_type == "QUINTUPLE":
                    selected.append((rid, nid, vpc))
                record["count"] += 1

    runner.scope("vpc", spec.action, region, operation)
    for rid, nid, vpc in selected:
        collect_quintuple(runner, region, rid, nid, vpc)


def collect_quintuple(runner, region, rid, nid, vpc):
    def operation(record):
        seen, priorities = set(), set()
        for rows, request in pages(runner.transport, QUINTUPLE, region, {"NetworkAclId": rid}):
            if request:
                record["request_ids"].append(request)
            prepared = [rule(row, rid) for row in rows]
            validate_rules(prepared, seen, priorities)
            for row in prepared:
                add_rule(runner, region, nid, vpc, row, "vpc." + QUINTUPLE.action)
                record["count"] += 1

    runner.scope("vpc", QUINTUPLE.action, region, operation, rid)
