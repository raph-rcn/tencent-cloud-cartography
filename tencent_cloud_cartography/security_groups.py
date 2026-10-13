"""Security-group rule selectors and their reusable template dependencies."""

import ipaddress
import json
from dataclasses import replace

from .transport import CollectionError, pages
from .vpc import fields, identity

# kind -> ID/name stem, provider prefix, members field, member kind
TEMPLATES = {
    "vpc.addresstemplate": ("AddressTemplate", "ipm", "AddressSet", "vpc.ruleaddress"),
    "vpc.addresstemplategroup": (
        "AddressTemplateGroup",
        "ipmg",
        "AddressTemplateIdSet",
        "vpc.addresstemplate",
    ),
    "vpc.servicetemplate": ("ServiceTemplate", "ppm", "ServiceSet", "vpc.serviceselector"),
    "vpc.servicetemplategroup": (
        "ServiceTemplateGroup",
        "ppmg",
        "ServiceTemplateIdSet",
        "vpc.servicetemplate",
    ),
}


def address(value, version=None):
    try:
        if not isinstance(value, str) or not value or "%" in value:
            raise ValueError("Invalid selector")
        if "-" in value:
            low, high = (ipaddress.ip_address(v) for v in value.split("-"))
            if low.version != high.version or int(low) > int(high):
                raise ValueError("Invalid range")
            normalized, family, typ = f"{low}-{high}", low.version, "range"
        elif "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            normalized, family, typ = str(network), network.version, "cidr"
        else:
            ip = ipaddress.ip_address(value)
            normalized, family, typ = str(ip), ip.version, "host"
        if version and family != version:
            raise ValueError("Wrong family")
        return normalized, dict(address=normalized, selector_type=typ, ip_version=family)
    except ValueError as exc:
        raise CollectionError("InvalidSecurityGroupAddress") from exc


def selector(raw, field, mappings):
    value = raw.get(field)
    if value is None:
        return []
    if not isinstance(value, dict):
        raise CollectionError("InvalidSecurityGroupTemplate")
    result = []
    for name, kind, prefix in mappings:
        if value.get(name) not in (None, ""):
            result.append((kind, identity(value[name], prefix), {}, "USES_TEMPLATE"))
    if len(result) > 1:
        raise CollectionError("ConflictingSecurityGroupTemplate")
    return result


def rule(raw, direction, version):
    props = fields(
        raw,
        (
            "Protocol",
            "Port",
            "CidrBlock",
            "Ipv6CidrBlock",
            "SecurityGroupId",
            "Action",
            "PolicyDescription",
            "ModifyTime",
        ),
        integers=("PolicyIndex", "Priority"),
    )
    if "PolicyIndex" not in props or props.get("Action") not in {"ACCEPT", "DROP"}:
        raise CollectionError("InvalidSecurityGroupRule")
    targets = selector(
        raw,
        "AddressTemplate",
        (
            ("AddressId", "vpc.addresstemplate", "ipm"),
            ("AddressGroupId", "vpc.addresstemplategroup", "ipmg"),
        ),
    )
    for name, family in (("CidrBlock", 4), ("Ipv6CidrBlock", 6)):
        if props.get(name):
            rid, meta = address(props[name], family)
            targets.append(("vpc.ruleaddress", rid, meta, "MATCHES_ADDRESS"))
    if props.get("SecurityGroupId"):
        targets.append(
            (
                "vpc.securitygroup",
                identity(props["SecurityGroupId"], "sg"),
                {},
                "REFERENCES_SECURITY_GROUP",
            )
        )
    if len(targets) != 1:
        raise CollectionError("InvalidSecurityGroupAddressSelector")
    services = selector(
        raw,
        "ServiceTemplate",
        (
            ("ServiceId", "vpc.servicetemplate", "ppm"),
            ("ServiceGroupId", "vpc.servicetemplategroup", "ppmg"),
        ),
    )
    explicit = bool(props.get("Protocol") or props.get("Port"))
    if (services and explicit) or (
        not services and not (props.get("Protocol") and props.get("Port"))
    ):
        raise CollectionError("InvalidSecurityGroupServiceSelector")
    props.update(direction=direction, policy_version=version, reachability_verified=False)
    return props, targets + services


def link_targets(graph, node, targets, source, relation=None):
    for kind, rid, metadata, edge in targets:
        target = graph.add(
            node["account"],
            node["region"],
            kind,
            rid,
            source=source,
            status="enriched" if metadata else "reference",
        )
        if metadata:
            graph.nodes[target]["properties"].update(metadata)
        graph.edge(node["id"], target, relation or edge, source)


def collect_rules(runner, region, groups):
    source = "vpc.DescribeSecurityGroupPolicies"
    for nid, raw in groups:

        def operation(record, nid=nid, raw=raw):
            response = runner.transport.call(
                "vpc",
                "DescribeSecurityGroupPolicies",
                region=region,
                SecurityGroupId=raw["SecurityGroupId"],
            )
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            policy = response.get("SecurityGroupPolicySet")
            if (
                not isinstance(policy, dict)
                or not isinstance(policy.get("Version"), str)
                or not policy["Version"]
            ):
                raise CollectionError("InvalidSecurityGroupPolicySet")
            prepared = []
            for direction in ("Ingress", "Egress"):
                rows = policy.get(direction)
                if not isinstance(rows, list):
                    raise CollectionError("InvalidSecurityGroupPolicySet")
                seen = set()
                for row in rows:
                    props, targets = rule(row, direction, policy["Version"])
                    index = props["PolicyIndex"]
                    if index in seen:
                        raise CollectionError("DuplicateSecurityGroupRule")
                    seen.add(index)
                    prepared.append((direction, index, props, targets))
            runner.graph.nodes[nid]["properties"]["policy_version"] = policy["Version"]
            for direction, index, props, targets in prepared:
                rid = f"{raw['SecurityGroupId']}/{direction}/{index}"
                service = (
                    f"{props['Protocol']}:{props['Port']}"
                    if props.get("Protocol")
                    else "service template"
                )
                name = f"{direction} {props['Action']} {service}"
                rid = runner.graph.add(
                    runner.account, region, "vpc.securitygrouprule", rid, name, source=source
                )
                node = runner.graph.nodes[rid]
                node["properties"].update(props)
                runner.graph.edge(nid, rid, "HAS_RULE", source)
                link_targets(runner.graph, node, targets, source)
                record["count"] += 1

        runner.scope(
            "vpc", "DescribeSecurityGroupPolicies", region, operation, raw["SecurityGroupId"]
        )


def template(raw, kind):
    stem, prefix, member_field, member_kind = TEMPLATES[kind]
    props = fields(raw, (stem + "Name", "CreatedTime", "UpdatedTime"))
    rid = identity(raw.get(stem + "Id"), prefix)
    rows = raw.get(member_field)
    if not isinstance(rows, list):
        raise CollectionError("InvalidSecurityTemplateMembers")
    targets, seen = [], set()
    for value in rows:
        if member_kind == "vpc.ruleaddress":
            mid, meta = address(value)
        elif member_kind == "vpc.serviceselector":
            if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
                raise CollectionError("InvalidServiceTemplateMember")
            mid, meta = value, {"service_selector": value, "reachability_verified": False}
        else:
            mid, meta = (
                identity(value, "ipm" if member_kind == "vpc.addresstemplate" else "ppm"),
                {},
            )
        if mid in seen:
            raise CollectionError("DuplicateSecurityTemplateMember")
        seen.add(mid)
        targets.append((member_kind, mid, meta, "HAS_MEMBER"))
    props["member_count"] = len(targets)
    if member_kind in {"vpc.ruleaddress", "vpc.serviceselector"}:
        # Preserve provider text as well as canonical address identities.
        props[member_field] = json.dumps(rows)
        field = "Address" if member_kind == "vpc.ruleaddress" else "Service"
        extras = raw.get(field + "ExtraSet")
        if extras is not None:
            if not isinstance(extras, list):
                raise CollectionError("InvalidTemplateMemberMetadata")
            metadata, annotated = [], set()
            for extra in extras:
                item = fields(extra, (field, "Description", "UpdatedTime"))
                value = item.get(field)
                key = address(value)[0] if field == "Address" else value
                if key not in seen or key in annotated:
                    raise CollectionError("ConflictingTemplateMemberMetadata")
                annotated.add(key)
                metadata.append(item)
            props["member_metadata"] = json.dumps(metadata)
    return rid, props, targets


def collect(runner, spec, region):
    source, groups = f"vpc.{spec.action}", []

    def operation(record):
        seen = set()
        for rows, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = []
            for raw in rows:
                if spec.kind in TEMPLATES:
                    rid, props, targets = template(raw, spec.kind)
                else:
                    props = fields(
                        raw,
                        (
                            "SecurityGroupName",
                            "SecurityGroupDesc",
                            "ProjectId",
                            "CreatedTime",
                            "UpdateTime",
                        ),
                        booleans=("IsDefault",),
                    )
                    rid = identity(raw.get("SecurityGroupId"), "sg")
                    targets = []
                prepared.append((rid, props, targets, raw))
            ids = [p[0] for p in prepared]
            if len(ids) != len(set(ids)) or seen.intersection(ids):
                raise CollectionError("DuplicateSecurityGroupResource")
            seen.update(ids)
            for rid, props, targets, raw in prepared:
                name = props.get(spec.names[0]) if spec.names else None
                nid = runner.graph.add(runner.account, region, spec.kind, rid, name, source=source)
                runner.graph.nodes[nid]["properties"].update(props)
                link_targets(runner.graph, runner.graph.nodes[nid], targets, source)
                if spec.kind == "vpc.securitygroup":
                    groups.append((nid, raw))
                record["count"] += 1

    runner.scope("vpc", spec.action, region, operation)
    collect_rules(runner, region, groups)
