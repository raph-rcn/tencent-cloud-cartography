"""Read-only network enrichment and conservative, owner-qualified reconciliation."""

import ipaddress
import json

from .catalog import Collector
from .model import stable_id
from .network_addresses import eip, ip
from .peering import location, owner
from .transport import CollectionError, pages
from .vpc import fields, identity

SOURCE = "network.corroboration"


def selected(graph, account, kind, region=None):
    return [
        n
        for n in list(graph.nodes.values())
        if n["kind"] == kind
        and n["account"] == account
        and n["status"] == "enriched"
        and (region is None or n["region"] == region)
    ]


def read_rows(
    runner, service, action, result, region, params, prepare, save, total="TotalCount", detail=""
):
    spec = Collector(service, action, result, "", (), total=total, require_total=True)

    def operation(record):
        seen = set()
        for rows, request in pages(runner.transport, spec, region, params):
            if request:
                record["request_ids"].append(request)
            prepared = [prepare(row) for row in rows]
            keys = [r[0] for r in prepared]
            if len(keys) != len(set(keys)) or seen.intersection(keys):
                raise CollectionError("DuplicateNetworkMetadata")
            seen.update(keys)
            for row in prepared:
                save(row)
                record["count"] += 1

    runner.scope(service, action, region, operation, detail)


def collect(runner, services):
    if not services or "clb" in services:
        from .clb_backends import collect as collect_backends

        for lb in selected(runner.graph, runner.account, "clb.clb"):
            forward = lb["properties"].get("Forward")
            if (forward is None or (type(forward) is int and forward == 1)) and lb[
                "region"
            ] in runner.regions_for("clb"):
                collect_backends(runner, lb)
                cross_targets(runner, lb)
    if services and "vpc" not in services:
        return
    for region in runner.regions_for("vpc"):
        for action, params in [("DescribeIp6Addresses", {})] + [
            (
                "DescribeIPv6Addresses",
                {"Traditional": False, "Filters": [{"Name": "address-type", "Values": [typ]}]},
            )
            for typ in ("EIPv6", "WanIPv6", "HighQualityEIPv6")
        ]:

            def prepare(row):
                result = eip(row)
                if (
                    not result[1].get("AddressIp")
                    or ipaddress.ip_address(result[1]["AddressIp"]).version != 6
                ):
                    raise CollectionError("InvalidPublicIpv6")
                return result

            def save(row, action=action):
                rid, props, refs, _ = row
                nid = runner.graph.add(
                    runner.account,
                    region,
                    "vpc.eip",
                    rid,
                    props.get("AddressName"),
                    source="vpc." + action,
                )
                old = runner.graph.nodes[nid]["properties"].get("AddressIp")
                if old and old != props["AddressIp"]:
                    raise CollectionError("ConflictingPublicAddress")
                runner.graph.nodes[nid]["properties"].update(props)
                for kind, target, relation in refs:
                    other = runner.graph.add(
                        runner.account, region, kind, target, status="reference"
                    )
                    runner.graph.edge(nid, other, relation, "vpc." + action)

            read_rows(
                runner,
                "vpc",
                action,
                "AddressSet",
                region,
                params,
                prepare,
                save,
                detail=json.dumps(params, sort_keys=True),
            )
        simple_networks(runner, region)
        private_nat(runner, region)
        from .gateway_metadata import collect as collect_gateways

        collect_gateways(runner, region)
        security_group_metadata(runner, region)
        for service in selected(runner.graph, runner.account, "vpc.endpointservice", region):
            endpoint_permissions(runner, service)
        for vpc in selected(runner.graph, runner.account, "vpc.vpc", region):
            shared_ccn(runner, vpc)


def simple_networks(runner, region):
    for action, result, kind, id_fields, prefix in (
        ("DescribeDhcpIps", "DhcpIpSet", "vpc.dhcpip", ("DhcpIpId",), "dhcpip"),
        (
            "DescribeLocalGateway",
            "LocalGatewaySet",
            "vpc.localgateway",
            ("LocalGatewayId", "UniqLocalGwId"),
            "lgw",
        ),
    ):

        def prepare(raw, id_fields=id_fields, prefix=prefix):
            props = fields(
                raw,
                (
                    "DhcpIpName",
                    "LocalGatewayName",
                    "State",
                    "CreatedTime",
                    "CreateTime",
                    "CdcId",
                    "NetworkInterfaceId",
                    "InstanceId",
                ),
            )
            values = {raw[k] for k in id_fields if raw.get(k)}
            if len(values) != 1:
                raise CollectionError("ConflictingNetworkIdentity")
            rid = identity(next(iter(values)), prefix)
            props["VpcId"] = identity(raw.get("VpcId"), "vpc")
            if raw.get("SubnetId"):
                props["SubnetId"] = identity(raw["SubnetId"], "subnet")
            for key in ("PrivateIpAddress", "AddressIp", "LocalGwIp"):
                if raw.get(key):
                    props[key] = ip(raw[key])
            return rid, props

        def save(row, kind=kind, action=action):
            rid, props = row
            nid = runner.graph.add(
                runner.account,
                region,
                kind,
                rid,
                props.get("DhcpIpName") or props.get("LocalGatewayName"),
                source="vpc." + action,
            )
            runner.graph.nodes[nid]["properties"].update(props)
            for key, target_kind, relation in (
                ("VpcId", "vpc.vpc", "IN_VPC"),
                ("SubnetId", "vpc.subnet", "IN_SUBNET"),
                ("NetworkInterfaceId", "vpc.networkinterface", "USES_INTERFACE"),
            ):
                if props.get(key):
                    target = runner.graph.add(
                        runner.account, region, target_kind, props[key], status="reference"
                    )
                    runner.graph.edge(nid, target, relation, "vpc." + action)

        read_rows(runner, "vpc", action, result, region, {}, prepare, save)


def endpoint_permissions(runner, service):
    def prepare(raw):
        props = fields(
            raw, ("UserUin", "Description", "CreateTime", "EndPointServiceId"), integers=("Owner",)
        )
        if props.get("EndPointServiceId") != service["resource_id"]:
            raise CollectionError("EndpointPermissionParentMismatch")
        uin = owner(props.get("UserUin"))
        if not uin:
            raise CollectionError("MissingEndpointPermissionOwner")
        props.update(UserUin=uin, effective_access_verified=False)
        return uin, props

    def save(row):
        uin, props = row
        nid = runner.graph.add(
            service["account"],
            service["region"],
            "vpc.endpointservicepermission",
            service["resource_id"] + "/" + uin,
            uin,
            source="vpc.DescribeVpcEndPointServiceWhiteList",
        )
        runner.graph.nodes[nid]["properties"].update(props)
        runner.graph.edge(
            service["id"], nid, "ALLOWS_ENDPOINT_ACCOUNT", "vpc.DescribeVpcEndPointServiceWhiteList"
        )

    read_rows(
        runner,
        "vpc",
        "DescribeVpcEndPointServiceWhiteList",
        "VpcEndpointServiceUserSet",
        service["region"],
        {"Filters": [{"Name": "end-point-service-id", "Values": [service["resource_id"]]}]},
        prepare,
        save,
        detail=service["resource_id"],
    )


def private_nat(runner, region):
    def prepare(raw):
        props = fields(
            raw,
            ("NatGatewayName", "Status", "CreatedTime", "NatType"),
            ("CrossDomain", "VpcType", "DeletionProtectionEnabled"),
        )
        rid = identity(raw.get("NatGatewayId"), "intranat")
        props["VpcId"] = identity(raw.get("VpcId"), "vpc")
        refs = []
        values = raw.get("DirectConnectGatewayIds") or []
        if not isinstance(values, list):
            raise CollectionError("InvalidPrivateNatGateways")
        refs.extend(
            ("vpc.directconnectgateway", identity(v, "dcg"), "ASSOCIATED_GATEWAY") for v in values
        )
        if raw.get("CcnId"):
            props["CcnId"] = identity(raw["CcnId"], "ccn")
        if raw.get("CrossDomainInfo") is not None:
            cross = fields(raw["CrossDomainInfo"], ("CcnId", "LocalVpcId", "PeerVpcId"))
            for key, value in cross.items():
                identity(value, "ccn" if key == "CcnId" else "vpc")
            if cross.get("CcnId") and props.get("CcnId") and cross["CcnId"] != props["CcnId"]:
                raise CollectionError("ConflictingPrivateNatCcn")
            props["cross_domain_info"] = json.dumps(cross, sort_keys=True)
            if cross.get("CcnId"):
                props["CcnId"] = cross["CcnId"]
        props.update(state=props.get("Status", ""), reachability_verified=False)
        return rid, props, refs

    def save(row):
        rid, props, refs = row
        nid = runner.graph.add(
            runner.account,
            region,
            "vpc.privatenat",
            rid,
            props.get("NatGatewayName"),
            source="vpc.DescribePrivateNatGateways",
        )
        runner.graph.nodes[nid]["properties"].update(props)
        for kind, rid, relation in [("vpc.vpc", props["VpcId"], "IN_VPC"), *refs]:
            target = runner.graph.add(runner.account, region, kind, rid, status="reference")
            runner.graph.edge(nid, target, relation, "vpc.DescribePrivateNatGateways")

    read_rows(
        runner,
        "vpc",
        "DescribePrivateNatGateways",
        "PrivateNatGatewaySet",
        region,
        {},
        prepare,
        save,
    )


def security_group_metadata(runner, region):
    groups = selected(runner.graph, runner.account, "vpc.securitygroup", region)
    for group in groups:
        group["properties"]["provider_scope"] = "account-region"
        for action, key in (
            ("DescribeSecurityGroupReferences", "ReferredSecurityGroupSet"),
            ("DescribeSecurityGroupAssociationStatistics", "SecurityGroupAssociationStatisticsSet"),
        ):

            def operation(record, group=group, action=action, key=key):
                response = runner.transport.call(
                    "vpc", action, region, SecurityGroupIds=[group["resource_id"]]
                )
                rows = response.get(key)
                if (
                    not isinstance(rows, list)
                    or len(rows) != 1
                    or not isinstance(rows[0], dict)
                    or rows[0].get("SecurityGroupId") != group["resource_id"]
                ):
                    raise CollectionError("SecurityGroupMetadataMismatch")
                raw = rows[0]
                if action == "DescribeSecurityGroupReferences":
                    ids = raw.get("ReferredSecurityGroupIds")
                    if not isinstance(ids, list) or len(set(ids)) != len(ids):
                        raise CollectionError("InvalidSecurityGroupReferences")
                    ids = [identity(v, "sg") for v in ids]
                    group["properties"]["reported_referring_group_ids"] = json.dumps(ids)
                else:
                    meta = fields(raw, integers=("CVM", "CDB", "ENI", "SG", "CLB", "TotalCount"))
                    group["properties"]["association_statistics"] = json.dumps(meta, sort_keys=True)
                if response.get("RequestId"):
                    record["request_ids"].append(response["RequestId"])
                record["count"] = 1

            runner.scope("vpc", action, region, operation, group["resource_id"])


def shared_ccn(runner, vpc):
    from .ccn import attachment

    def prepare(raw):
        root = owner(raw.get("CcnUin"))
        if (
            not root
            or owner(raw.get("InstanceUin")) != runner.account
            or raw.get("InstanceId") != vpc["resource_id"]
            or raw.get("InstanceType") != "VPC"
            or raw.get("InstanceRegion") != vpc["region"]
        ):
            raise CollectionError("SharedCcnScopeMismatch")
        parent = dict(resource_id=identity(raw.get("CcnId"), "ccn"), account=root)
        aid, props, target = attachment(raw, parent)
        return aid, props, target, parent

    def save(row):
        aid, props, target, parent = row
        pid = runner.graph.add(
            parent["account"],
            "global",
            "vpc.ccn",
            parent["resource_id"],
            status="reference",
            source="vpc.DescribeCcnAttachedInstances",
        )
        nid = runner.graph.add(
            parent["account"],
            "global",
            "vpc.ccnattachment",
            aid,
            props.get("InstanceName"),
            source="vpc.DescribeCcnAttachedInstances",
        )
        runner.graph.nodes[nid]["properties"].update(props, discovery_scope="local-vpc-attachment")
        runner.graph.edge(pid, nid, "HAS_ATTACHMENT", "vpc.DescribeCcnAttachedInstances")
        runner.graph.edge(nid, vpc["id"], "ATTACHED_NETWORK", "vpc.DescribeCcnAttachedInstances")

    read_rows(
        runner,
        "vpc",
        "DescribeCcnAttachedInstances",
        "InstanceSet",
        vpc["region"],
        {
            "Filters": [
                {"Name": "instance-id", "Values": [vpc["resource_id"]]},
                {"Name": "instance-type", "Values": ["VPC"]},
                {"Name": "instance-region", "Values": [vpc["region"]]},
            ]
        },
        prepare,
        save,
        detail="shared/" + vpc["resource_id"],
    )


def cross_targets(runner, lb):
    if not lb["properties"].get("VpcId"):
        return
    graph = runner.graph
    frontends = [
        graph.nodes[e["target"]]
        for e in list(graph.edges.values())
        if e["source"] == lb["id"] and e["relationship"] == "HAS_LISTENER"
    ]
    scopes = []
    for listener in frontends:
        rules = [
            graph.nodes[e["target"]]
            for e in graph.edges.values()
            if e["source"] == listener["id"] and e["relationship"] == "HAS_RULE"
        ]
        scopes.extend(
            (frontend, listener["properties"].get("ListenerId"))
            for frontend in (rules or [listener])
        )
    for frontend, lid in scopes:
        if not lid:
            continue
        loc = frontend["properties"].get("LocationId") if frontend["kind"] == "clb.rule" else None
        if frontend["kind"] == "clb.rule" and not loc:
            continue

        def prepare(raw):
            props = fields(
                raw,
                (
                    "LocalVpcId",
                    "VpcId",
                    "IP",
                    "VpcName",
                    "EniId",
                    "InstanceId",
                    "InstanceName",
                    "Region",
                ),
            )
            if props.get("LocalVpcId") != lb["properties"].get("VpcId"):
                raise CollectionError("CrossTargetLocalVpcMismatch")
            props["VpcId"] = identity(props.get("VpcId"), "vpc")
            props["IP"] = ip(props.get("IP"))
            props["Region"] = location(props.get("Region"))
            if not props["Region"] or not (props.get("EniId") or props.get("InstanceId")):
                raise CollectionError("IncompleteCrossTargetIdentity")
            for key, prefix in (("EniId", "eni"), ("InstanceId", "ins")):
                if props.get(key):
                    identity(props[key], prefix)
            key = stable_id(
                lb["resource_id"],
                lid,
                loc,
                props["Region"],
                props["VpcId"],
                props["IP"],
                props.get("EniId"),
                props.get("InstanceId"),
            )
            return key, props

        def save(row):
            rid, props = row
            nid = graph.add(
                runner.account,
                lb["region"],
                "clb.crosstarget",
                rid,
                props["IP"],
                source="clb.DescribeCrossTargets",
            )
            graph.nodes[nid]["properties"].update(
                props,
                LoadBalancerId=lb["resource_id"],
                ListenerId=lid,
                owner_resolution="requires-collected-inventory",
                reachability_verified=False,
            )
            if loc:
                graph.nodes[nid]["properties"]["LocationId"] = loc
            graph.edge(frontend["id"], nid, "HAS_CROSS_TARGET_METADATA", "clb.DescribeCrossTargets")

        read_rows(
            runner,
            "clb",
            "DescribeCrossTargets",
            "CrossTargetSet",
            lb["region"],
            {
                "Filters": [
                    {"Name": "vpc-id", "Values": [lb["properties"].get("VpcId")]},
                    {"Name": "listener-id", "Values": [lid]},
                ]
                + ([{"Name": "location-id", "Values": [loc]}] if loc else [])
            },
            prepare,
            save,
            detail=frontend["resource_id"],
        )


def indices(graph):
    links = {}
    for edge in graph.edges.values():
        links.setdefault((edge["source"], edge["relationship"]), set()).add(edge["target"])
    return links


def link(graph):
    # Deterministic when rerun, including after an import or a previously denied scope.
    obsolete = {
        n["id"]
        for n in graph.nodes.values()
        if n["sources"] == [SOURCE] and n["kind"] in {"vpc.eniattachment", "clb.target"}
    }
    graph.nodes = {k: n for k, n in graph.nodes.items() if k not in obsolete}
    graph.edges = {
        k: e
        for k, e in graph.edges.items()
        if e.get("provenance") != SOURCE
        and e["source"] not in obsolete
        and e["target"] not in obsolete
    }
    graph.coverage = [r for r in graph.coverage if r.get("action") != "ReconcileNetworkMetadata"]
    backend_references(graph)
    from .clb_backends import link_functions

    link_functions(graph)
    from .network_addresses import link as link_addresses

    link_addresses(graph)
    from .routes import link_next_hops

    link_next_hops(graph)
    links = indices(graph)
    nodes = list(graph.nodes.values())
    enriched = [n for n in nodes if n["status"] == "enriched"]
    subnets = [n for n in enriched if n["kind"] == "vpc.subnet"]
    groups = [n for n in enriched if n["kind"] == "vpc.securitygroup"]
    cidrs, defaults_by_scope, subnets_by_vpc = {}, {}, {}
    for node in enriched:
        key = (node["account"], node["region"], node["properties"].get("VpcId"))
        if node["kind"] == "vpc.cidr":
            cidrs.setdefault(key, []).append(node)
        if node["kind"] == "vpc.subnet":
            subnets_by_vpc.setdefault(key, []).append(node)
            if node["properties"].get("IsDefault") is True:
                defaults_by_scope.setdefault((*key, node["properties"].get("Zone")), []).append(
                    node
                )
    for node in enriched:
        p = node["properties"]
        if node["kind"] == "vpc.securitygroup":
            p["provider_scope"] = "account-region"
        if node["kind"] == "vpc.eip" and p.get("target_resolution") == "unsupported-provider-type":
            issue(graph, node, "UnresolvedEipTargetType")
        if node["kind"] == "vpc.securitygrouprule" and p.get("SecurityGroupId"):
            candidates = [
                g
                for g in groups
                if g["region"] == node["region"] and g["resource_id"] == p["SecurityGroupId"]
            ]
            local = [g for g in candidates if g["account"] == node["account"]]
            p["group_reference_resolution"] = (
                "matched-caller-account"
                if len(candidates) == 1 and len(local) == 1
                else "ambiguous-owner"
                if len(candidates) > 1
                else "unresolved-owner"
            )
            if p["group_reference_resolution"] != "matched-caller-account":
                issue(graph, node, "UnresolvedSecurityGroupOwner")
                graph.edges = {
                    k: e
                    for k, e in graph.edges.items()
                    if not (
                        e["source"] == node["id"]
                        and e["relationship"] == "REFERENCES_SECURITY_GROUP"
                    )
                }
            else:
                graph.edge(node["id"], local[0]["id"], "REFERENCES_SECURITY_GROUP", SOURCE)
        if node["kind"] == "vpc.networkinterface" and p.get("Business") not in (None, "", "cvm"):
            rid = node["resource_id"] + "/attachment"
            aid = graph.add(
                node["account"],
                node["region"],
                "vpc.eniattachment",
                rid,
                p.get("Business"),
                source=SOURCE,
            )
            graph.nodes[aid]["properties"].update(
                {
                    k: v
                    for k, v in p.items()
                    if k.startswith("attachment_") or k in {"Business", "AttachType", "EniType"}
                }
            )
            graph.nodes[aid]["properties"].update(
                owner_resolution="provider-account-namespace-unmapped",
                resource_resolution="provider-attachment-metadata",
                reachability_verified=False,
            )
            graph.edge(node["id"], aid, "HAS_REPORTED_ATTACHMENT", SOURCE)
        if node["kind"] == "vpc.peeringconnection":
            for side, relation in (("source", "SOURCE_VPC"), ("peer", "PEER_VPC")):
                targets = links.get((node["id"], relation), set())
                p[side + "_inventory_visibility"] = (
                    "collected"
                    if len(targets) == 1
                    and graph.nodes[next(iter(targets))]["status"] == "enriched"
                    else "reference-only-or-unresolved"
                )
    for subnet in subnets:
        p = subnet["properties"]
        key = (subnet["account"], subnet["region"], p.get("VpcId"))
        defaults = defaults_by_scope.get((*key, p.get("Zone")), ())
        if p.get("IsDefault") is True:
            p["default_scope_resolution"] = (
                "unique-collected-default-in-vpc-zone"
                if len(defaults) == 1 and p.get("Zone")
                else "ambiguous-or-unlocated-default"
            )
            if p["default_scope_resolution"] == "ambiguous-or-unlocated-default":
                issue(graph, subnet, "AmbiguousDefaultSubnetScope")
        for cidr_node in cidrs.get(key, ()):
            cp = cidr_node["properties"]
            if cidr_node["kind"] != "vpc.cidr" or (
                cidr_node["account"],
                cidr_node["region"],
                cp.get("VpcId"),
            ) != (subnet["account"], subnet["region"], p.get("VpcId")):
                continue
            value = p.get("CidrBlock" if cp.get("ip_version") == 4 else "Ipv6CidrBlock")
            if value and ipaddress.ip_network(value).subnet_of(ipaddress.ip_network(cp["cidr"])):
                graph.edge(subnet["id"], cidr_node["id"], "WITHIN_VPC_CIDR", SOURCE)
        associated = [
            a
            for a in (
                links.get((subnet["id"], "USES_NETWORK_ACL"), set())
                | links.get((subnet["id"], "REPORTED_NETWORK_ACL"), set())
            )
            if graph.nodes[a]["status"] == "enriched"
        ]
        explicit = p.get("NetworkAclId")
        conflicting = (
            len(associated) > 1
            or (p.get("network_acl_association") == "none" and associated)
            or any(
                graph.nodes[a]["kind"] != "vpc.networkacl"
                or (
                    graph.nodes[a]["account"],
                    graph.nodes[a]["region"],
                    graph.nodes[a]["properties"].get("VpcId"),
                )
                != (subnet["account"], subnet["region"], p.get("VpcId"))
                for a in associated
            )
            or (
                explicit
                and any(
                    graph.nodes[a]["resource_id"] != explicit
                    or graph.nodes[a]["properties"].get("VpcId") != p.get("VpcId")
                    for a in associated
                )
            )
        )
        if conflicting:
            issue(graph, subnet, "ConflictingNetworkAclAssociation")
            p["network_acl_resolution"] = "conflicting-provider-association"
            for aid in associated:
                graph.edge(subnet["id"], aid, "REPORTED_NETWORK_ACL", "vpc.reported-association")
            graph.edges = {
                k: e
                for k, e in graph.edges.items()
                if not (e["source"] == subnet["id"] and e["relationship"] == "USES_NETWORK_ACL")
            }
        else:
            p["network_acl_resolution"] = (
                "corroborated"
                if explicit and associated
                else "subnet-reported"
                if explicit
                else "none-reported"
                if p.get("network_acl_association") == "none"
                else "acl-reported"
                if associated
                else "unavailable"
            )
    # CCN associates whole networks. This edge records CIDR inclusion, not an AWS
    # attachment subnet, forwarding viability, or a synthesized route.
    for attachment in [n for n in enriched if n["kind"] == "vpc.ccnattachment"]:
        p = attachment["properties"]
        if p.get("InstanceType") != "VPC":
            continue
        blocks = [ipaddress.ip_network(c) for c in json.loads(p.get("CidrBlock", "[]"))]
        for subnet in subnets_by_vpc.get(
            (p.get("InstanceUin"), p.get("InstanceRegion"), p.get("InstanceId")), ()
        ):
            if (subnet["account"], subnet["region"], subnet["properties"].get("VpcId")) != (
                p.get("InstanceUin"),
                p.get("InstanceRegion"),
                p.get("InstanceId"),
            ):
                continue
            if any(
                ipaddress.ip_network(subnet["properties"][key]).version == block.version
                and ipaddress.ip_network(subnet["properties"][key]).subnet_of(block)
                for key in ("CidrBlock", "Ipv6CidrBlock")
                if subnet["properties"].get(key)
                for block in blocks
            ):
                graph.edge(attachment["id"], subnet["id"], "COVERS_SUBNET_CIDR", SOURCE)
    link_endpoints(graph, enriched, links)
    link_cross_targets(graph, enriched, links)
    graph.edges = dict(sorted(graph.edges.items()))


def link_endpoints(graph, nodes, links):
    for endpoint in [n for n in nodes if n["kind"] == "vpc.endpoint"]:
        p = endpoint["properties"]
        matches = [
            a
            for a in nodes
            if a["kind"] == "vpc.interfaceaddress"
            and (
                a["account"],
                a["region"],
                a["properties"].get("VpcId"),
                a["properties"].get("SubnetId"),
                a["properties"].get("address"),
            )
            == (
                endpoint["account"],
                endpoint["region"],
                p.get("VpcId"),
                p.get("SubnetId"),
                p.get("EndPointVip"),
            )
        ]
        p["interface_resolution"] = (
            "matched-collected-address"
            if len(matches) == 1
            else "ambiguous"
            if matches
            else "uncollected"
        )
        if len(matches) == 1:
            graph.edge(
                endpoint["id"], matches[0]["id"], "MATCHES_ENDPOINT_INTERFACE_ADDRESS", SOURCE
            )
            eni = graph.nodes.get(
                stable_id(
                    endpoint["account"],
                    endpoint["region"],
                    "vpc.networkinterface",
                    matches[0]["properties"].get("NetworkInterfaceId"),
                )
            )
            if (
                eni
                and eni["status"] == "enriched"
                and matches[0]["id"] in links.get((eni["id"], "HAS_ADDRESS"), ())
                and links.get((eni["id"], "IN_VPC")) == links.get((endpoint["id"], "IN_VPC"))
            ):
                graph.edge(endpoint["id"], eni["id"], "USES_COLLECTED_INTERFACE", SOURCE)
        records = [
            n
            for n in nodes
            if n["kind"] == "privatedns.record"
            and n["properties"].get("enabled") is True
            and n["properties"].get("record_type") in {"A", "AAAA"}
            and n["properties"].get("record_value") == p.get("EndPointVip")
        ]
        for record in records:
            zone = graph.nodes.get(record["properties"].get("dns_zone"))
            if (
                zone
                and zone["status"] == "enriched"
                and links.get((zone["id"], "ASSOCIATED_WITH_VPC"), set())
                & links.get((endpoint["id"], "IN_VPC"), set())
            ):
                graph.edge(record["id"], endpoint["id"], "CONFIGURED_ENDPOINT_DNS", SOURCE)


def ancestors(graph, nid, parents):
    node = graph.nodes[nid]
    result, pending = {nid}, list(parents.get(nid, ()))
    allowed = {"clb.clb", "clb.listener", "clb.rule", "clb.targetgroup", "clb.targetbinding"}
    while pending:
        candidate = pending.pop()
        other = graph.nodes[candidate]
        if (
            candidate not in result
            and other["kind"] in allowed
            and other["status"] == "enriched"
            and (other["account"], other["region"]) == (node["account"], node["region"])
        ):
            result.add(candidate)
            pending.extend(parents.get(candidate, ()))
    return result


def cross_resources(graph, evidence, addresses, links):
    """Recheck native identity and ownership rather than trusting derived edges."""
    p = evidence["properties"]
    if (
        evidence["status"] != "enriched"
        or not p.get("IP")
        or not (p.get("EniId") or p.get("InstanceId"))
    ):
        return [], "uncollected-target"
    candidates = []
    for address in addresses:
        ap = address["properties"]
        if (
            address["status"] != "enriched"
            or (address["region"], ap.get("VpcId"), ap.get("address"))
            != (p.get("Region"), p.get("VpcId"), p["IP"])
            or (p.get("EniId") and ap.get("NetworkInterfaceId") != p["EniId"])
        ):
            continue
        eni = graph.nodes.get(
            stable_id(
                address["account"],
                address["region"],
                "vpc.networkinterface",
                ap.get("NetworkInterfaceId"),
            )
        )
        vpc_id = stable_id(address["account"], address["region"], "vpc.vpc", p["VpcId"])
        if (
            not eni
            or eni["status"] != "enriched"
            or eni["properties"].get("VpcId") != p["VpcId"]
            or address["id"] not in links.get((eni["id"], "HAS_ADDRESS"), ())
            or any(links.get((n["id"], "IN_VPC")) != {vpc_id} for n in (eni, address))
        ):
            continue
        if (
            p.get("InstanceId")
            and eni["properties"].get("attachment_InstanceId") != p["InstanceId"]
        ):
            continue
        candidates.append((address, eni))
    if len(candidates) != 1:
        return [], "ambiguous-owner" if candidates else "uncollected-target"
    address, eni = candidates[0]
    resources = [address, eni]
    instance = graph.nodes.get(
        stable_id(address["account"], p["Region"], "cvm.instance", p.get("InstanceId"))
    )
    if (
        instance
        and instance["status"] == "enriched"
        and eni["properties"].get("Business") in (None, "", "cvm")
        and instance["id"] in links.get((eni["id"], "ATTACHED_TO"), ())
        and links.get((instance["id"], "IN_VPC")) == links.get((eni["id"], "IN_VPC"))
    ):
        resources.append(instance)
    return resources, "matched-collected-identity"


def cross_applies(graph, evidence, frontend, backend, ancestry, links):
    p = evidence["properties"]
    if (evidence["account"], evidence["region"]) != (frontend["account"], frontend["region"]):
        return False
    lbs = [
        graph.nodes[n]
        for n in ancestry
        if graph.nodes[n]["kind"] == "clb.clb"
        and graph.nodes[n]["resource_id"] == p.get("LoadBalancerId")
    ]
    listeners = [
        graph.nodes[n]
        for n in ancestry
        if graph.nodes[n]["kind"] == "clb.listener"
        and graph.nodes[n]["properties"].get("ListenerId") == p.get("ListenerId")
    ]
    rules = [graph.nodes[n] for n in ancestry if graph.nodes[n]["kind"] == "clb.rule"]
    scopes = (
        [n for n in rules if n["properties"].get("LocationId") == p.get("LocationId")]
        if p.get("LocationId")
        else listeners
        if not rules
        else []
    )
    if not any(
        evidence["id"] in links.get((n["id"], "HAS_CROSS_TARGET_METADATA"), ()) for n in scopes
    ):
        return False
    if (
        len(lbs) != 1
        or not listeners
        or lbs[0]["properties"].get("Forward") == 0
        or lbs[0]["properties"].get("VpcId") != p.get("LocalVpcId")
    ):
        return False
    local_vpc = stable_id(evidence["account"], evidence["region"], "vpc.vpc", p.get("LocalVpcId"))
    if links.get((lbs[0]["id"], "IN_VPC")) != {local_vpc}:
        return False
    bp = backend["properties"]
    if backend["kind"] == "cvm.instance":
        return backend["resource_id"] == p.get("InstanceId")
    if backend["kind"] == "vpc.networkinterface":
        return backend["resource_id"] == p.get("EniId")
    if backend["kind"] == "clb.target":
        target_id = bp.get("TargetId")
        if (
            target_id
            and target_id.startswith(("ins-", "eni-"))
            and target_id not in (p.get("InstanceId"), p.get("EniId"))
        ):
            return False
        return bp.get("TargetAddress") == p.get("IP")
    return False


def legacy_cross_resources(graph, lb, backend, links):
    """Resolve 1.0's explicit backend region/VPC and CVM ID without guessing owner."""
    value = lb["properties"].get("TargetRegionInfo")
    if not value:
        return None
    try:
        remote = json.loads(value)
    except (ValueError, TypeError):
        return []
    region, vpc = remote.get("Region"), remote.get("VpcId")
    if not region and not vpc:
        return None
    if (region, vpc) == (lb["region"], lb["properties"].get("VpcId")):
        return None
    if (
        not region
        or not isinstance(vpc, str)
        or not vpc.startswith("vpc-")
        or lb["properties"].get("Forward") == 0
    ):
        return []
    rid = (
        backend["resource_id"]
        if backend["kind"] == "cvm.instance"
        else backend["properties"].get("TargetId", "")
        if backend["kind"] == "clb.target"
        else ""
    )
    if not rid.startswith("ins-"):
        return []
    candidates = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "cvm.instance"
        and n["status"] == "enriched"
        and n["resource_id"] == rid
        and n["region"] == region
        and links.get((n["id"], "IN_VPC")) == {stable_id(n["account"], region, "vpc.vpc", vpc)}
    ]
    if len(candidates) != 1:
        return []
    instance = candidates[0]
    address = backend["properties"].get("TargetAddress")
    if address:
        evidence = dict(
            status="enriched", properties=dict(InstanceId=rid, IP=address, Region=region, VpcId=vpc)
        )
        resources, _ = cross_resources(
            graph,
            evidence,
            [n for n in graph.nodes.values() if n["kind"] == "vpc.interfaceaddress"],
            links,
        )
        return resources if any(n["id"] == instance["id"] for n in resources) else []
    return [instance]


def link_cross_targets(graph, nodes, links):
    parents = {}
    for edge in graph.edges.values():
        if edge["relationship"] in {"HAS_LISTENER", "HAS_RULE", "HAS_TARGET_GROUP", "HAS_BACKEND"}:
            parents.setdefault(edge["target"], set()).add(edge["source"])
    addresses = [n for n in nodes if n["kind"] == "vpc.interfaceaddress"]
    forwarding = [
        (e, ancestors(graph, e["source"], parents))
        for e in graph.edges.values()
        if e["relationship"] == "FORWARDS_TO"
        and graph.nodes[e["source"]]["kind"].startswith("clb.")
    ]
    for evidence in [n for n in nodes if n["kind"] == "clb.crosstarget"]:
        resources, resolution = cross_resources(graph, evidence, addresses, links)
        evidence["properties"]["owner_resolution"] = resolution
        if not resources:
            issue(graph, evidence, "UnresolvedCrossTargetOwner")
            continue
        for target in resources:
            graph.edge(evidence["id"], target["id"], "CORROBORATES_RESOURCE", SOURCE)
        for edge, ancestry in forwarding:
            frontend, backend = graph.nodes[edge["source"]], graph.nodes[edge["target"]]
            if cross_applies(graph, evidence, frontend, backend, ancestry, links):
                graph.edge(backend["id"], evidence["id"], "CORROBORATED_CROSS_TARGET", SOURCE)


def issue(graph, node, code):
    graph.coverage.append(
        dict(
            account=node["account"],
            region=node["region"],
            service="analysis",
            action="ReconcileNetworkMetadata",
            detail=node["kind"] + "/" + node["resource_id"],
            status="error",
            error=code,
            count=0,
            request_ids=[],
        )
    )


def backend_references(graph):
    """Preserve unsupported bindings as address targets instead of dropping them."""
    links = indices(graph)
    for binding in list(graph.nodes.values()):
        if (
            binding["kind"] != "clb.targetbinding"
            or binding["status"] != "enriched"
            or links.get((binding["id"], "FORWARDS_TO"))
        ):
            continue
        p = binding["properties"]
        values = json.loads(p.get("private_addresses", p.get("addresses", "[]"))) or [None]
        for value in values:
            rid = (
                binding["resource_id"]
                + "/target/"
                + str(value or p.get("InstanceId", "unreported"))
            )
            tid = graph.add(
                binding["account"],
                binding["region"],
                "clb.target",
                rid,
                value or p.get("InstanceId"),
                source=SOURCE,
            )
            graph.nodes[tid]["properties"].update(
                {
                    k: v
                    for k, v in {
                        "TargetAddress": value,
                        "TargetId": p.get("InstanceId"),
                        "TargetPort": p.get("Port"),
                        "Type": p.get("Type"),
                    }.items()
                    if v is not None
                }
            )
            graph.edge(binding["id"], tid, "FORWARDS_TO", SOURCE)
    # Explicit ENI/NAT/HAVIP identifiers remain scoped references. The exposure
    # evaluator still requires enriched, unambiguous same-VPC inventory.
    mapping = {"eni": "vpc.networkinterface", "nat": "vpc.nat", "havip": "vpc.havip"}
    for target in list(graph.nodes.values()):
        if target["kind"] != "clb.target" or target["status"] != "enriched":
            continue
        rid = target["properties"].get("TargetId", "")
        kind = mapping.get(rid.split("-")[0])
        if kind:
            identity(rid, rid.split("-")[0])
            nid = graph.add(target["account"], target["region"], kind, rid, status="reference")
            graph.edge(target["id"], nid, "REFERENCES_BACKEND_RESOURCE", SOURCE)
