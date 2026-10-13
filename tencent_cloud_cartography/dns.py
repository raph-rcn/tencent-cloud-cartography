"""DNS configuration, scoped names/addresses and evidence-backed graph links."""

import ipaddress
import json

from .catalog import DNS_RECORDS
from .transport import CollectionError, pages


def normal_name(value):
    if value == ".":
        return value
    if (
        not isinstance(value, str)
        or not value
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise CollectionError("InvalidDnsName")
    value = value[:-1] if value.endswith(".") else value
    if not value or any(not label for label in value.split(".")) or any(c in value for c in "/:@"):
        raise CollectionError("InvalidDnsName")
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CollectionError("InvalidDnsName") from exc


def record_name(zone, name):
    if name in ("", "@"):
        return zone
    if not isinstance(name, str):
        raise CollectionError("InvalidDnsName")
    if name.endswith("."):
        fqdn = normal_name(name)
        if fqdn != zone and not fqdn.endswith("." + zone):
            raise CollectionError("DnsZoneMismatch")
        return fqdn
    return normal_name(name + "." + zone)


def target(graph, zone, value, address=False, source=""):
    private = zone["kind"] == "privatedns.zone"
    service = "privatedns" if private else "dnspod"
    rid = f"{zone['resource_id']}/{value}" if private else value
    nid = graph.add(
        zone["account"],
        "global",
        service + (".address" if address else ".name"),
        rid,
        value,
        source=source,
    )
    graph.nodes[nid]["properties"].update(
        dns_value=value, dns_scope=zone["id"] if private else "public"
    )
    return nid


def zone_configuration(graph, nid, raw, source):
    zone = graph.nodes[nid]
    private = zone["kind"] == "privatedns.zone"
    domain = normal_name(raw.get("Domain") if private else raw.get("Punycode") or raw.get("Name"))
    props = zone["properties"]
    props.update(dns_name=domain, private_zone=private)
    for key in (
        "TTL",
        "RecordCount",
        "DnsForwardStatus",
        "CnameSpeedupStatus",
        "CNAMESpeedup",
        "DNSStatus",
        "CreatedOn",
        "UpdatedOn",
        "ForwardRuleName",
        "ForwardRuleType",
        "ForwardAddress",
        "EndPointName",
        "IsCustomTld",
    ):
        if key in raw and isinstance(raw[key], (str, int, bool)):
            props[key] = raw[key]
    if not private:
        servers = raw.get("EffectiveDNS") or []
        if not isinstance(servers, list):
            raise CollectionError("InvalidResponse")
        for name in servers:
            ns = target(graph, zone, normal_name(name), source=source)
            graph.edge(nid, ns, "NAMESERVER", source)
        return
    bindings = []
    for entries, shared in (
        (raw.get("VpcSet") or [], False),
        (raw.get("AccountVpcSet") or [], True),
    ):
        for entry in entries:
            owner = str(entry.get("Uin", "")) if shared else zone["account"]
            region, vpc = entry.get("Region"), entry.get("UniqVpcId")
            bindings.append(dict(owner=owner, region=region, vpc_id=vpc))
            if (
                not owner.isdigit()
                or not region
                or not isinstance(vpc, str)
                or not vpc.startswith("vpc-")
            ):
                props["unresolved_vpc_bindings"] = props.get("unresolved_vpc_bindings", 0) + 1
                continue
            vid = graph.add(owner, region, "vpc.vpc", vpc, status="reference")
            graph.edge(nid, vid, "ASSOCIATED_WITH_VPC", source)
    # DeletedVpcSet deliberately does not create active bindings.
    props["vpc_bindings"] = json.dumps(bindings, sort_keys=True)


def add_record(graph, zid, raw, source):
    zone = graph.nodes[zid]
    private = zone["kind"] == "privatedns.zone"
    if private and raw.get("ZoneId") != zone["resource_id"]:
        raise CollectionError("DnsZoneMismatch")
    rid = raw.get("RecordId")
    if rid in (None, "", 0):
        raise CollectionError("InvalidDnsRecord")
    record_type = raw.get("RecordType" if private else "Type")
    value = raw.get("RecordValue" if private else "Value")
    if not isinstance(record_type, str) or not isinstance(value, str):
        raise CollectionError("InvalidDnsRecord")
    record_type = record_type.upper()
    fqdn = record_name(zone["properties"]["dns_name"], raw.get("SubDomain" if private else "Name"))
    destination, address = None, False
    if record_type in {"A", "AAAA"}:
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != (4 if record_type == "A" else 6):
                raise ValueError("Address family mismatch")
            destination, address = str(ip), True
        except ValueError as exc:
            raise CollectionError("InvalidDnsAddress") from exc
    elif record_type in {"CNAME", "NS", "PTR", "MX"}:
        # MX preference is the separate MX field in both provider APIs.
        if record_type != "MX" or value != ".":  # Null MX announces no mail service.
            destination = normal_name(value)
    elif record_type == "SRV":
        fields = value.split()
        if len(fields) == 4 and all(v.isdigit() for v in fields[:3]) and fields[3] != ".":
            destination = normal_name(fields[3])
    nid = graph.add(
        zone["account"],
        "global",
        "privatedns.record" if private else "dnspod.record",
        f"{zone['resource_id']}/{rid}",
        f"{fqdn} · {record_type}",
        source=source,
    )
    props = graph.nodes[nid]["properties"]
    props.update(
        dns_name=fqdn,
        record_type=record_type,
        record_value=value,
        dns_zone=zid,
        dns_scope=zid if private else "public",
    )
    for key in (
        "TTL",
        "MX",
        "Weight",
        "Line",
        "LineId",
        "Status",
        "Enabled",
        "UpdatedOn",
        "CreatedOn",
        "DefaultNS",
        "MonitorStatus",
    ):
        if key in raw and isinstance(raw[key], (str, int, bool)):
            props[key] = raw[key]
    status = raw.get("Status")
    if private and raw.get("Enabled") in (0, 1):
        props["enabled"] = raw["Enabled"] == 1
    elif status in {"ENABLE", "ENABLED", "DISABLE", "DISABLED"}:
        props["enabled"] = status in {"ENABLE", "ENABLED"}
    if "enabled" in props:
        props["state"] = "enabled" if props["enabled"] else "disabled"
    graph.edge(zid, nid, "HAS_RECORD", source)
    if destination:
        tid = target(graph, zone, destination, address, source)
        graph.edge(nid, tid, "CONFIGURED_DNS_TARGET", source)
    return nid


def collect_records(runner, zid, raw_zone):
    zone = runner.graph.nodes[zid]
    spec = DNS_RECORDS[zone["kind"]]

    def operation(record):
        params = (
            {"ZoneId": zone["resource_id"]}
            if spec.service == "privatedns"
            else {
                "Domain": raw_zone["Name"],
                "DomainId": int(zone["resource_id"]),
                "ErrorOnEmpty": "no",
            }
        )
        seen = set()
        for items, request_id in pages(runner.transport, spec, "global", params):
            if request_id:
                record["request_ids"].append(request_id)
            for item in items:
                rid = str(item.get("RecordId"))
                if rid in seen:
                    raise CollectionError("DuplicateDnsRecord")
                add_record(runner.graph, zid, item, f"{spec.service}.{spec.action}")
                seen.add(rid)
                record["count"] += 1

    runner.scope(spec.service, spec.action, "global", operation, zone["resource_id"])


def link_dns(graph):
    """No DNS queries: relate only the configuration and addresses already collected."""
    nodes = graph.nodes
    records = [n for n in nodes.values() if n["kind"] in {"dnspod.record", "privatedns.record"}]
    names = [n for n in nodes.values() if n["kind"] in {"dnspod.name", "privatedns.name"}]
    addresses = [n for n in nodes.values() if n["kind"] in {"dnspod.address", "privatedns.address"}]
    by_name = {}
    for record in records:
        p = record["properties"]
        by_name.setdefault((record["account"], p["dns_scope"], p["dns_name"]), []).append(
            record["id"]
        )
    for name in names:
        p = name["properties"]
        for rid in by_name.get((name["account"], p["dns_scope"], p["dns_value"]), []):
            graph.edge(name["id"], rid, "HAS_CONFIGURED_RECORD", "DNS name equality within scope")

    bindings, vpcs, subnets, nameservers, record_targets = {}, {}, {}, {}, {}
    for edge in list(graph.edges.values()):
        a, b, relation = edge["source"], edge["target"], edge["relationship"]
        if relation == "ASSOCIATED_WITH_VPC":
            bindings.setdefault(a, set()).add(b)
        elif relation == "IN_VPC":
            vpcs.setdefault(a, set()).add(b)
        elif relation == "IN_SUBNET":
            subnets.setdefault(a, set()).add(b)
        elif relation == "NAMESERVER":
            nameservers.setdefault(a, set()).add(b)
        elif relation == "CONFIGURED_DNS_TARGET":
            record_targets.setdefault(a, set()).add(b)
    for rid, sids in subnets.items():
        for sid in sids:
            vpcs.setdefault(rid, set()).update(vpcs.get(sid, set()))
    resources_by_ip = {}
    for resource in list(nodes.values()):
        for value in resource["properties"].get("ip_addresses", "").split(", "):
            try:
                ip = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            resources_by_ip.setdefault(ip, []).append(resource)
    for address in addresses:
        p = address["properties"]
        for resource in resources_by_ip.get(p["dns_value"], []):
            if p["dns_scope"] == "public":
                matches = (
                    address["account"] == resource["account"]
                    and ipaddress.ip_address(p["dns_value"]).is_global
                )
            else:
                matches = bool(
                    bindings.get(p["dns_scope"], set()) & vpcs.get(resource["id"], set())
                )
            if matches:
                graph.edge(
                    address["id"],
                    resource["id"],
                    "MATCHES_RESOURCE_ADDRESS",
                    "Collected DNS/IP and network scope",
                )

    public_zones = [
        n
        for n in nodes.values()
        if n["kind"] == "dnspod.domain" and n["properties"].get("dns_name")
    ]
    for record in records:
        p = record["properties"]
        if (
            record["kind"] != "dnspod.record"
            or p["record_type"] != "NS"
            or p.get("enabled") is not True
        ):
            continue
        parent = nodes[p["dns_zone"]]
        for child in public_zones:
            child_name = child["properties"]["dns_name"]
            if (
                child["account"] == parent["account"]
                and child["id"] != parent["id"]
                and child_name == p["dns_name"]
                and child_name.endswith("." + parent["properties"]["dns_name"])
                and record_targets.get(record["id"], set()) & nameservers.get(child["id"], set())
            ):
                graph.edge(
                    parent["id"],
                    child["id"],
                    "CONFIGURED_SUBZONE",
                    "NS record + child assigned nameserver",
                )
