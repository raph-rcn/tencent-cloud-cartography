"""Typed network/compute relationships. Configuration edges do not prove reachability."""

from .model import first, stable_id, walk_values


def enrich(graph, account, region, kind, nid, raw, source):
    if kind.startswith("cfs."):
        from .cfs import configuration

        configuration(graph, nid, raw, source)
    if kind == "monitor.policy":
        from .monitor import configuration

        configuration(graph, nid, raw, source)
    if kind == "cls.scheduledsql":
        from .cls_metrics import configuration

        configuration(graph, nid, raw, source)
    elif kind in {"cls.alarm", "cls.alarmnotice"}:
        from .cls_alarms import configuration

        configuration(graph, nid, raw, source)
    elif kind.startswith(("cls.", "cloudaudit.")):
        from .observability import configuration

        configuration(graph, nid, raw, source)
    if kind == "ssl.certificate":
        from .certificates import enrich_certificate

        enrich_certificate(graph.nodes[nid], raw)

    def reference(rid, target_kind, relation, owner=account, location=region):
        if rid:
            target = graph.add(owner, location, target_kind, rid, status="reference")
            graph.edge(nid, target, relation, source)
            return target
        return None

    if kind in {"dnspod.domain", "privatedns.zone"}:
        from .dns import zone_configuration

        zone_configuration(graph, nid, raw, source)
    if kind == "vpc.networkacl":
        for subnet in raw.get("SubnetSet") or []:
            subnet_id = subnet.get("SubnetId")
            if subnet_id:
                target = graph.add(account, region, "vpc.subnet", subnet_id, status="reference")
                graph.edge(target, nid, "USES_NETWORK_ACL", source)
        for direction in ("Ingress", "Egress"):
            for index, rule in enumerate(raw.get(direction + "Entries") or []):
                rid = f"{raw['NetworkAclId']}/{direction}/{first(rule, ('NetworkAclIpv4EntryId', 'NetworkAclIpv6EntryId'), str(index))}"
                rule_id = graph.add(
                    account,
                    region,
                    "vpc.networkaclrule",
                    rid,
                    f"{direction} {rule.get('Action', '')} {rule.get('Protocol', '')}:{rule.get('Port', '')}",
                    rule,
                    source,
                )
                graph.edge(nid, rule_id, "HAS_RULE", source)
    elif kind == "vpc.routetable":
        for association in raw.get("AssociationSet") or []:
            if association.get("SubnetId"):
                subnet = graph.add(
                    account, region, "vpc.subnet", association["SubnetId"], status="reference"
                )
                graph.edge(subnet, nid, "USES_ROUTE_TABLE", source)
        # GatewayId has type-dependent semantics: NORMAL_CVM is an IP, EIP is 0.
        # Retain those values on the route without inventing a CVM/EIP identity.
        types = {
            "NAT": ("vpc.nat", "nat-"),
            "VPN": ("vpc.vpngateway", "vpngw-"),
            "PEERCONNECTION": ("vpc.peeringconnection", "pcx-"),
            "DIRECTCONNECT": ("vpc.directconnectgateway", "dcg-"),
            "CVM": ("cvm.instance", "ins-"),
            "HAVIP": ("vpc.havip", "havip-"),
            "USER_CCN": ("vpc.ccn", "ccn-"),
        }
        for route in raw.get("RouteSet") or []:
            rid = str(
                route.get("RouteItemId")
                or stable_id(
                    raw["RouteTableId"],
                    route.get("DestinationCidrBlock"),
                    route.get("DestinationIpv6CidrBlock"),
                    route.get("GatewayType"),
                    route.get("GatewayId"),
                )
            )
            route_id = graph.add(
                account,
                region,
                "vpc.route",
                raw["RouteTableId"] + "/" + rid,
                first(route, ("DestinationCidrBlock", "DestinationIpv6CidrBlock"), rid),
                route,
                source,
            )
            graph.edge(nid, route_id, "HAS_ROUTE", source)
            gateway = types.get(route.get("GatewayType"))
            target_id = str(route.get("GatewayId") or "")
            if gateway and target_id.startswith(gateway[1]):
                target_region = "global" if gateway[0] == "vpc.ccn" else region
                target = graph.add(
                    account, target_region, gateway[0], target_id, status="reference"
                )
                graph.edge(route_id, target, "ROUTES_TO", source)
    elif kind == "vpc.peeringconnection":
        for side, keys, region_key, owner_key in (
            ("SOURCE_VPC", ("SourceVpcId",), "SourceRegion", "SourceUin"),
            ("PEER_VPC", ("DestinationVpcId", "PeerVpcId"), "DestinationRegion", "DestinationUin"),
        ):
            # AppId and UIN are different namespaces. Missing owners are not guessed.
            owner, location, rid = raw.get(owner_key), raw.get(region_key), first(raw, keys)
            if owner and str(owner).isdigit() and location and rid:
                reference(rid, "vpc.vpc", side, str(owner), location)
    elif kind == "vpc.ccnattachment":
        owner, location = raw.get("InstanceUin"), raw.get("InstanceRegion")
        target_kind = {
            "VPC": "vpc.vpc",
            "DIRECTCONNECT": "vpc.directconnectgateway",
            "BMVPC": "bmvpc.vpc",
        }.get(raw.get("InstanceType"))
        if owner and str(owner).isdigit() and location and target_kind:
            reference(raw.get("InstanceId"), target_kind, "ATTACHED_NETWORK", str(owner), location)
    elif kind == "vpc.endpoint":
        # Service endpoints can be shared cross-account. ServiceVpcId is not local.
        if raw.get("EndPointServiceId"):
            owner = raw.get("ServiceUin")
            if owner:
                reference(
                    raw["EndPointServiceId"],
                    "vpc.endpointservice",
                    "CONNECTS_TO_SERVICE",
                    str(owner),
                )
            else:
                graph.nodes[nid]["properties"]["endpoint_service_id"] = raw["EndPointServiceId"]
    elif kind == "vpc.endpointservice":
        service_id = raw.get("ServiceInstanceId")
        if isinstance(service_id, str) and service_id.startswith("lb-"):
            reference(service_id, "clb.clb", "SERVES_LOAD_BALANCER")
    elif kind == "cvm.keypair":
        for instance in raw.get("AssociatedInstanceIds") or []:
            target = graph.add(account, region, "cvm.instance", instance, status="reference")
            graph.edge(target, nid, "USES_KEY_PAIR", source)

    if kind in {"cvm.instance", "cvm.launchtemplateversion", "as.launch-configuration"}:
        for image_id in walk_values(raw, {"ImageId"}):
            reference(image_id, "cvm.image", "USES_IMAGE")
        for key_id in walk_values(raw, {"KeyIds"}):
            reference(key_id, "cvm.keypair", "USES_KEY_PAIR")
    if kind == "cvm.instance" and raw.get("AutoScalingGroupId"):
        group = graph.add(
            account, region, "as.auto-scaling-group", raw["AutoScalingGroupId"], status="reference"
        )
        graph.edge(group, nid, "HAS_INSTANCE", source)
    if kind in {"cvm.instance", "as.auto-scaling-group"}:
        reference(
            raw.get("LaunchConfigurationId"), "as.launch-configuration", "USES_LAUNCH_CONFIGURATION"
        )
    if kind == "as.auto-scaling-group":
        for lb in walk_values(raw, {"LoadBalancerIdSet", "LoadBalancerId"}):
            reference(lb, "clb.clb", "ATTACHED_LOAD_BALANCER")
    if kind == "cvm.launchtemplateversion":
        reference(raw.get("LaunchTemplateId"), "cvm.launchtemplate", "VERSION_OF")
    if kind == "cvm.image":
        for snapshot in walk_values(raw.get("SnapshotSet") or [], {"SnapshotId"}):
            reference(snapshot, "cbs.snapshot", "USES_SNAPSHOT")
    if kind == "cbs.snapshot":
        reference(raw.get("DiskId"), "cbs.disk", "SNAPSHOT_OF")

    if kind in {"cbs.disk", "ssm.secret", "cfs.filesystem"}:
        from .kms import configured_key

        configured_key(graph, nid, raw, source)
