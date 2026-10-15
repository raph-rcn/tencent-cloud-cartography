"""Interface-scoped IPs and typed EIP associations; configuration is not reachability."""

import ipaddress
import re
from dataclasses import replace

from .model import stable_id
from .transport import CollectionError, pages


def rid(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Za-z0-9]+", value):
        raise CollectionError("InvalidNetworkIdentity")
    return value


def ip(value, version=None):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        result = ipaddress.ip_address(value)
        if version and result.version != version:
            raise ValueError
        return str(result)
    except ValueError as exc:
        raise CollectionError("InvalidNetworkAddress") from exc


def fields(raw, strings=(), integers=(), booleans=()):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidNetworkMetadata")
    out = {}
    for keys, typ in ((strings, str), (integers, int), (booleans, bool)):
        for key in keys:
            if raw.get(key) is not None:
                if type(raw[key]) is not typ or (typ is int and raw[key] < 0):
                    raise CollectionError("InvalidNetworkMetadata")
                out[key] = raw[key]
    return out


def interface(raw, region):
    props = fields(
        raw,
        (
            "NetworkInterfaceName",
            "NetworkInterfaceDescription",
            "MacAddress",
            "State",
            "NetworkInterfaceState",
            "CreatedTime",
            "Business",
            "Zone",
            "QosLevel",
            "CdcId",
            "ResourceId",
        ),
        ("EniType", "AttachType"),
        ("Primary",),
    )
    identity = rid(raw.get("NetworkInterfaceId"), "eni")
    refs = []
    for key, prefix, kind, relation in [
        ("VpcId", "vpc", "vpc.vpc", "IN_VPC"),
        ("SubnetId", "subnet", "vpc.subnet", "IN_SUBNET"),
    ]:
        if raw.get(key):
            props[key] = rid(raw[key], prefix)
            refs.append((kind, props[key], relation))
    if props.get("Zone") and not re.fullmatch(re.escape(region) + r"-\d+", props["Zone"]):
        raise CollectionError("NetworkRegionMismatch")
    groups = raw.get("GroupSet", [])
    if groups is None:
        groups = []
    if not isinstance(groups, list):
        raise CollectionError("InvalidNetworkSecurityGroups")
    refs += [("vpc.securitygroup", rid(s, "sg"), "USES_SECURITY_GROUP") for s in groups]
    if raw.get("Attachment") is not None:
        attachment = fields(
            raw["Attachment"], ("InstanceId", "InstanceAccountId", "AttachTime"), ("DeviceIndex",)
        )
        props.update({"attachment_" + k: v for k, v in attachment.items()})
        # InstanceAccountId is opaque provider account information, not documented UIN.
        props["attachment_resolution"] = "unresolved"
    addresses = []
    seen = {}
    for field, key, version in [
        ("PrivateIpAddressSet", "PrivateIpAddress", 4),
        ("Ipv6AddressSet", "Address", 6),
        ("Ipv6Addresses", "Address", 6),
    ]:
        rows = raw.get(field, [])
        if rows is None and version == 6:
            props[field + "_available"] = False
            rows = []
        if not isinstance(rows, list):
            raise CollectionError("InvalidInterfaceAddresses")
        for row in rows:
            p = fields(
                row,
                ("Description", "State", "QosLevel", "AddressType"),
                (),
                ("Primary", "IsWanIpBlocked"),
            )
            address = ip(row.get(key), version)
            p.update(
                address=address,
                ip_version=version,
                NetworkInterfaceId=identity,
                reachability_verified=False,
            )
            for scope in ("VpcId", "SubnetId"):
                if props.get(scope):
                    p[scope] = props[scope]
            if row.get("PublicIpAddress"):
                p["PublicIpAddress"] = ip(row["PublicIpAddress"], version)
            if row.get("AddressId"):
                p["AddressId"] = rid(row["AddressId"], "(?:eip|eipv6)")
            if address in seen:
                old, old_field = seen[address]
                if old_field == field or any(old[k] != p[k] for k in old.keys() & p.keys()):
                    raise CollectionError("DuplicateOrConflictingInterfaceAddress")
                old.update(p)
            else:
                addresses.append(p)
                seen[address] = (p, field)
    props["state"] = props.get("NetworkInterfaceState") or props.get("State", "")
    props["zone"] = props.get("Zone", "")
    return identity, props, refs, addresses


def eip(raw):
    props = fields(
        raw,
        (
            "AddressName",
            "AddressStatus",
            "AddressType",
            "InstanceType",
            "InstanceId",
            "InternetServiceProvider",
            "InternetChargeType",
            "CreatedTime",
            "DeadlineDate",
            "RenewFlag",
            "Egress",
            "AntiDDoSPackageId",
            "BandwidthPackageId",
            "UnVpcId",
            "DedicatedClusterId",
        ),
        ("Bandwidth",),
        ("IsArrears", "IsBlocked", "IsEipDirectConnection", "CascadeRelease", "LocalBgp"),
    )
    identity = rid(raw.get("AddressId"), "(?:eip|eipv6)")
    refs = []
    for key in ("AddressIp", "PrivateAddressIp"):
        if raw.get(key):
            props[key] = ip(raw[key])
    if raw.get("NetworkInterfaceId"):
        props["NetworkInterfaceId"] = rid(raw["NetworkInterfaceId"], "eni")
        refs.append(("vpc.networkinterface", props["NetworkInterfaceId"], "USES_INTERFACE"))
    mapping = {
        "CVM": ("ins", "cvm.instance"),
        "NAT": ("nat", "vpc.nat"),
        "ENI": ("eni", "vpc.networkinterface"),
        "CLB": ("lb", "clb.clb"),
        "HAVIP": ("havip", "vpc.havip"),
        "DHCPIP": ("dhcpip", "vpc.dhcpip"),
    }
    if props.get("InstanceId") and props.get("InstanceType") in mapping:
        prefix, kind = mapping[props["InstanceType"]]
        refs.append((kind, rid(props["InstanceId"], prefix), "ATTACHED_TO"))
    props["state"] = props.get("AddressStatus", "")
    props["target_resolution"] = (
        "explicit-provider-type"
        if props.get("InstanceType") in mapping and props.get("InstanceId")
        else "unsupported-provider-type"
        if props.get("InstanceId")
        else "unbound-or-unreported"
    )
    if props.get("UnVpcId"):
        refs.append(("vpc.vpc", rid(props["UnVpcId"], "vpc"), "IN_VPC"))
    if props.get("AddressIp"):
        props["ip_version"] = ipaddress.ip_address(props["AddressIp"]).version
    props["ip_addresses"] = props.get("AddressIp", "")
    props["reachability_verified"] = False
    return identity, props, refs, []


def collect(runner, spec, region):
    source = f"{spec.service}.{spec.action}"

    def operation(record):
        seen = set()
        for rows, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = [
                interface(r, region) if spec.kind == "vpc.networkinterface" else eip(r)
                for r in rows
            ]
            ids = [r[0] for r in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateNetworkResource")
            seen.update(ids)
            for identity, props, refs, addresses in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    identity,
                    props.get(spec.names[0]),
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(props)
                for kind, target, relation in refs:
                    other = runner.graph.add(
                        runner.account, region, kind, target, source=source, status="reference"
                    )
                    runner.graph.edge(nid, other, relation, source)
                for p in addresses:
                    aid = runner.graph.add(
                        runner.account,
                        region,
                        "vpc.interfaceaddress",
                        identity + "/" + p["address"],
                        p["address"],
                        source=source,
                    )
                    runner.graph.nodes[aid]["properties"].update(
                        p,
                        ip_addresses=", ".join(
                            v for v in [p["address"], p.get("PublicIpAddress")] if v
                        ),
                    )
                    runner.graph.edge(nid, aid, "HAS_ADDRESS", source)
                    for kind, target, relation in refs:
                        if relation in {"IN_VPC", "IN_SUBNET"}:
                            runner.graph.edge(
                                aid,
                                stable_id(runner.account, region, kind, target),
                                relation,
                                source,
                            )
                    if p.get("AddressId"):
                        eid = runner.graph.add(
                            runner.account,
                            region,
                            "vpc.eip",
                            p["AddressId"],
                            source=source,
                            status="reference",
                        )
                        runner.graph.edge(aid, eid, "USES_EIP", source)
                record["count"] += 1

    runner.scope(spec.service, spec.action, region, operation)


def link(graph):
    derived = {
        "Collected ENI attachment ID and CVM account/region/VPC",
        "EIP explicit ENI ID and private address",
        "Exact collected target IP and account/region/VPC",
        "Unique collected ENI address and attachment",
    }
    graph.edges = {k: e for k, e in graph.edges.items() if e.get("provenance") not in derived}
    vpcs = {}
    parents = {}
    for edge in list(graph.edges.values()):
        if edge["relationship"] == "IN_VPC":
            vpcs.setdefault(edge["source"], set()).add(edge["target"])
        if edge["relationship"] in {
            "HAS_LISTENER",
            "HAS_RULE",
            "HAS_TARGET_GROUP",
            "HAS_BACKEND",
            "FORWARDS_TO",
        }:
            parents.setdefault(edge["target"], set()).add(edge["source"])
    addresses = {}
    by_interface = {}
    attached = {}
    for n in list(graph.nodes.values()):
        p = n["properties"]
        scope = (n["account"], n["region"])
        if n["kind"] == "vpc.interfaceaddress" and n["status"] == "enriched":
            by_interface.setdefault((*scope, p["NetworkInterfaceId"], p["address"]), []).append(n)
            if p.get("VpcId"):
                addresses.setdefault((*scope, p["VpcId"], p["address"]), []).append(n)
        if (
            n["kind"] == "vpc.networkinterface"
            and n["status"] == "enriched"
            and p.get("Business") in (None, "", "cvm")
        ):
            instance = graph.nodes.get(
                stable_id(*scope, "cvm.instance", p.get("attachment_InstanceId", ""))
            )
            if (
                instance
                and instance["status"] == "enriched"
                and vpcs.get(n["id"])
                and vpcs.get(n["id"]) == vpcs.get(instance["id"])
            ):
                graph.edge(
                    n["id"],
                    instance["id"],
                    "ATTACHED_TO",
                    "Collected ENI attachment ID and CVM account/region/VPC",
                )
                p["attachment_resolution"] = "matched-collected-instance-and-vpc"
                attached[n["id"]] = instance["id"]
    for n in list(graph.nodes.values()):
        p = n["properties"]
        scope = (n["account"], n["region"])
        if n["kind"] == "vpc.eip" and n["status"] == "enriched":
            matches = by_interface.get(
                (*scope, p.get("NetworkInterfaceId"), p.get("PrivateAddressIp")), []
            )
            if len(matches) == 1:
                target = matches[0]
                other = target["properties"]
                if (other.get("AddressId") and other["AddressId"] != n["resource_id"]) or (
                    other.get("PublicIpAddress")
                    and p.get("AddressIp")
                    and other["PublicIpAddress"] != p["AddressIp"]
                ):
                    p["address_binding_resolution"] = "conflicting-metadata"
                    continue
                graph.edge(
                    n["id"],
                    target["id"],
                    "BINDS_ADDRESS",
                    "EIP explicit ENI ID and private address",
                )
                p["address_binding_resolution"] = "matched"
        if n["kind"] != "clb.target":
            continue
        try:
            address = ip(p.get("TargetAddress") or n["name"])
        except CollectionError:
            continue
        ancestry = set()
        pending = list(parents.get(n["id"], ()))
        while pending:
            parent = pending.pop()
            if parent in ancestry:
                continue
            ancestry.add(parent)
            pending.extend(parents.get(parent, ()))
        lbs = [graph.nodes[a] for a in ancestry if graph.nodes[a]["kind"] == "clb.clb"]
        scopes = set()
        for lb in lbs:
            if (lb["account"], lb["region"]) != scope:
                continue
            for vid in vpcs.get(lb["id"], ()):
                scopes.add(graph.nodes[vid]["resource_id"])
        matches = (
            addresses.get((*scope, next(iter(scopes)), address), []) if len(scopes) == 1 else []
        )
        if len(matches) != 1:
            p["address_resolution"] = "ambiguous" if len(matches) > 1 else "unresolved"
            continue
        target = matches[0]
        graph.edge(
            n["id"],
            target["id"],
            "MATCHES_INTERFACE_ADDRESS",
            "Exact collected target IP and account/region/VPC",
        )
        p["address_resolution"] = "matched"
        p["reachability_verified"] = False
        eni = stable_id(*scope, "vpc.networkinterface", target["properties"]["NetworkInterfaceId"])
        if eni in attached:
            graph.edge(
                n["id"],
                attached[eni],
                "RESOLVES_TO_INSTANCE",
                "Unique collected ENI address and attachment",
            )
