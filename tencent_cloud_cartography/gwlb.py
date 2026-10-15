"""Native GWLB inventory, target groups, bindings and reported health metadata."""

import json

from .catalog import Collector
from .network_addresses import ip
from .network_parity import read_rows
from .transport import CollectionError, pages
from .vpc import fields, identity

SPEC = Collector(
    "gwlb",
    "DescribeGatewayLoadBalancers",
    "LoadBalancerSet",
    "clb.gatewayloadbalancer",
    ("LoadBalancerId",),
    ("LoadBalancerName",),
    require_total=True,
)


def collect(runner, spec, region):
    graph = runner.graph
    groups = set()

    def prepare(raw):
        props = fields(
            raw,
            ("LoadBalancerName", "CreateTime", "ChargeType", "IsolatedTime"),
            ("DeleteProtect", "OperateProtect"),
            ("Status", "Isolation"),
        )
        rid = identity(raw.get("LoadBalancerId"), "gwlb")
        for key, prefix in (("VpcId", "vpc"), ("SubnetId", "subnet"), ("TargetGroupId", "lbtg")):
            if raw.get(key):
                props[key] = identity(raw[key], prefix)
        addresses = raw.get("Vips")
        if not isinstance(addresses, list):
            raise CollectionError("InvalidGatewayLoadBalancerAddresses")
        props["ip_addresses"] = ", ".join(ip(v) for v in addresses)
        return rid, props

    def save(row):
        rid, props = row
        nid = graph.add(
            runner.account,
            region,
            spec.kind,
            rid,
            props.get("LoadBalancerName"),
            source="gwlb.DescribeGatewayLoadBalancers",
        )
        graph.nodes[nid]["properties"].update(props, reachability_verified=False)
        for key, kind, relation in (
            ("VpcId", "vpc.vpc", "IN_VPC"),
            ("SubnetId", "vpc.subnet", "IN_SUBNET"),
            ("TargetGroupId", "gwlb.targetgroup", "HAS_TARGET_GROUP"),
        ):
            if props.get(key):
                target = graph.add(runner.account, region, kind, props[key], status="reference")
                graph.edge(nid, target, relation, "gwlb.DescribeGatewayLoadBalancers")
        if props.get("TargetGroupId"):
            groups.add(props["TargetGroupId"])

    read_rows(runner, "gwlb", spec.action, spec.result, region, {}, prepare, save)

    # Discover unattached groups as well as groups explicitly referenced by GWLBs.
    def group_prepare(raw):
        rid = identity(raw.get("TargetGroupId"), "lbtg")
        props = fields(
            raw,
            (
                "TargetGroupName",
                "Protocol",
                "ScheduleAlgorithm",
                "CreatedTime",
                "UpdatedTime",
                "ForwardingMode",
            ),
            ("AllDeadToAlive", "RescheduleUnbindRs", "RescheduleUnhealthy"),
            (
                "Port",
                "RegisteredInstancesCount",
                "AssociatedRuleCount",
                "TcpIdleConnectTimeout",
                "OthersIdleConnectTimeout",
                "RescheduleUnbindRsStartTime",
                "RescheduleUnhealthyStartTime",
            ),
        )
        props["VpcId"] = identity(raw.get("VpcId"), "vpc")
        if raw.get("HealthCheck") is not None:
            health = fields(
                raw["HealthCheck"],
                ("Protocol",),
                integers=(
                    "HealthSwitch",
                    "Port",
                    "Timeout",
                    "IntervalTime",
                    "HealthNum",
                    "UnHealthNum",
                ),
            )
            props["health_check"] = json.dumps(health, sort_keys=True)
        associations = raw.get("AssociatedRule") or []
        if not isinstance(associations, list):
            raise CollectionError("InvalidGatewayGroupAssociations")
        associated = [identity(a.get("LoadBalancerId"), "gwlb") for a in associations]
        if len(set(associated)) != len(associated):
            raise CollectionError("DuplicateGatewayGroupAssociation")
        return rid, props, associated

    def group_save(row):
        rid, props, associated = row
        gid = graph.add(
            runner.account,
            region,
            "gwlb.targetgroup",
            rid,
            props.get("TargetGroupName"),
            source="gwlb.DescribeTargetGroups",
        )
        graph.nodes[gid]["properties"].update(props)
        vpc = graph.add(runner.account, region, "vpc.vpc", props["VpcId"], status="reference")
        graph.edge(gid, vpc, "IN_VPC", "gwlb.DescribeTargetGroups")
        for lb in associated:
            lid = graph.add(
                runner.account, region, "clb.gatewayloadbalancer", lb, status="reference"
            )
            graph.edge(lid, gid, "HAS_TARGET_GROUP", "gwlb.DescribeTargetGroups")
        groups.add(rid)

    read_rows(
        runner,
        "gwlb",
        "DescribeTargetGroups",
        "TargetGroupSet",
        region,
        {},
        group_prepare,
        group_save,
    )
    for rid in sorted(groups):

        def operation(record, rid=rid):
            spec = Collector(
                "gwlb",
                "DescribeTargetGroupInstances",
                "TargetGroupInstanceSet",
                "gwlb.targetbinding",
                (),
                total="RealCount",
                require_total=True,
            )
            seen = set()
            for batch, request in pages(
                runner.transport,
                spec,
                region,
                {"Filters": [{"Name": "TargetGroupId", "Values": [rid]}]},
            ):
                if request:
                    record["request_ids"].append(request)
                prepared = []
                for raw in batch:
                    if raw.get("TargetGroupId") != rid:
                        raise CollectionError("GatewayTargetGroupMismatch")
                    props = fields(
                        raw,
                        ("Type", "InstanceId", "EniId", "InstanceName", "RegisteredTime"),
                        integers=("Port", "Weight", "ZoneId"),
                    )
                    if not props.get("InstanceId") or "Port" not in props:
                        raise CollectionError("InvalidGatewayBackend")
                    values = raw.get("PrivateIpAddresses") or []
                    if not isinstance(values, list):
                        raise CollectionError("InvalidGatewayBackend")
                    props["private_addresses"] = json.dumps([ip(a) for a in values])
                    key = rid + "/" + props["InstanceId"] + ":" + str(props["Port"])
                    if key in seen:
                        raise CollectionError("DuplicateGatewayBackend")
                    seen.add(key)
                    prepared.append((key, props))
                for key, props in prepared:
                    nid = graph.add(
                        runner.account,
                        region,
                        "gwlb.targetbinding",
                        key,
                        props.get("InstanceName"),
                        source="gwlb.DescribeTargetGroupInstances",
                    )
                    graph.nodes[nid]["properties"].update(
                        props, TargetGroupId=rid, reachability_verified=False
                    )
                    parent = graph.add(
                        runner.account, region, "gwlb.targetgroup", rid, status="reference"
                    )
                    graph.edge(parent, nid, "HAS_BACKEND", "gwlb.DescribeTargetGroupInstances")
                    for typ, prefix, kind, key_name in (
                        ("CVM", "ins", "cvm.instance", "InstanceId"),
                        ("ENI", "eni", "vpc.networkinterface", "EniId"),
                    ):
                        target_id = props.get(key_name) or props.get("InstanceId")
                        if props.get("Type") == typ and target_id:
                            target = graph.add(
                                runner.account,
                                region,
                                kind,
                                identity(target_id, prefix),
                                status="reference",
                            )
                            graph.edge(
                                nid, target, "FORWARDS_TO", "gwlb.DescribeTargetGroupInstances"
                            )
                    record["count"] += 1

        runner.scope("gwlb", "DescribeTargetGroupInstances", region, operation, rid)

        def health(record, rid=rid):
            response = runner.transport.call(
                "gwlb", "DescribeTargetGroupInstanceStatus", region, TargetGroupId=rid
            )
            rows = response.get("TargetGroupInstanceSet")
            if not isinstance(rows, list):
                raise CollectionError("InvalidGatewayHealthResponse")
            bindings = [
                n
                for n in graph.nodes.values()
                if n["kind"] == "gwlb.targetbinding"
                and (n["account"], n["region"], n["properties"].get("TargetGroupId"))
                == (runner.account, region, rid)
            ]
            prepared, seen = [], set()
            for row in rows:
                props = fields(row, ("InstanceIp", "Status"))
                value = ip(props.get("InstanceIp"))
                if value in seen or props.get("Status") not in {"on", "off", "health", "unhealth"}:
                    raise CollectionError("InvalidGatewayHealthIdentity")
                seen.add(value)
                candidates = [
                    n
                    for n in bindings
                    if value in json.loads(n["properties"].get("private_addresses", "[]"))
                ]
                if len(candidates) != 1:
                    raise CollectionError("UnresolvedGatewayHealthBackend")
                prepared.append((candidates[0], props["Status"]))
            for node, status in prepared:
                node["properties"].update(
                    reported_health=status,
                    health_source="gwlb.DescribeTargetGroupInstanceStatus",
                    reachability_verified=False,
                )
                record["count"] += 1
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])

        runner.scope("gwlb", "DescribeTargetGroupInstanceStatus", region, health, rid)
