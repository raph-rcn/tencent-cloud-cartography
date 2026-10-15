"""Target groups, backend bindings, reported health and configured redirects."""

import ipaddress
import json

from .catalog import Collector
from .clb import identity, listener, rule
from .transport import CollectionError, pages
from .vpc import fields

GROUPS = Collector(
    "clb",
    "DescribeTargetGroups",
    "TargetGroupSet",
    "clb.targetgroup",
    ("TargetGroupId",),
    ("TargetGroupName",),
    require_total=True,
)
MEMBERS = Collector(
    "clb",
    "DescribeTargetGroupInstances",
    "TargetGroupInstanceSet",
    "clb.targetbinding",
    ("InstanceId",),
    total="RealCount",
    require_total=True,
)


def health(raw):
    if raw is None:
        return None
    props = fields(
        raw,
        (
            "Protocol",
            "CheckType",
            "HttpCheckDomain",
            "HttpCheckMethod",
            "HttpVersion",
            "ExtendedCode",
            "ContextType",
        ),
        ("JumboFrame",),
        (
            "Port",
            "CheckPort",
            "Timeout",
            "TimeOut",
            "GapTime",
            "IntervalTime",
            "GoodLimit",
            "HealthNum",
            "BadLimit",
            "UnHealthNum",
            "HttpCode",
            "SourceIpType",
        ),
    )
    if raw.get("HealthSwitch") is not None:
        if type(raw["HealthSwitch"]) not in (bool, int):
            raise CollectionError("InvalidClbHealthSwitch")
        props["HealthSwitch"] = raw["HealthSwitch"]
    if raw.get("HttpCheckPath") is not None:
        if not isinstance(raw["HttpCheckPath"], str):
            raise CollectionError("InvalidClbHealthPath")
        props["HttpCheckPath"] = raw["HttpCheckPath"].split("?")[0].split("#")[0]
    # Never persist custom probe request/response bodies.
    props["custom_probe_payload_retained"] = False
    return json.dumps(props, sort_keys=True)


def configuration(graph, node, raw, source):
    selected = health(raw.get("HealthCheck"))
    if selected is not None:
        node["properties"]["health_check"] = selected
    groups = raw.get("TargetGroupList") or []
    if raw.get("TargetGroup"):
        groups = [*groups, raw["TargetGroup"]]
    if not isinstance(groups, list):
        raise CollectionError("InvalidClbTargetGroup")
    for group in groups:
        rid = identity(group.get("TargetGroupId"), "lbtg-")
        gid = graph.add(
            node["account"],
            node["region"],
            "clb.targetgroup",
            rid,
            source=source,
            status="reference",
        )
        graph.edge(node["id"], gid, "HAS_TARGET_GROUP", source)


def collect(runner, region):
    graph = runner.graph
    selected = []

    def inventory(record):
        seen = set()
        for batch, request in pages(runner.transport, GROUPS, region):
            if request:
                record["request_ids"].append(request)
            prepared = []
            for raw in batch:
                rid = identity(raw.get("TargetGroupId"), "lbtg-")
                if rid in seen:
                    raise CollectionError("DuplicateClbTargetGroup")
                seen.add(rid)
                props = fields(
                    raw,
                    (
                        "TargetGroupName",
                        "Protocol",
                        "ScheduleAlgorithm",
                        "TargetGroupType",
                        "IpVersion",
                        "CreatedTime",
                        "UpdatedTime",
                    ),
                    ("FullListenSwitch", "KeepaliveEnable", "SnatEnable"),
                    (
                        "Port",
                        "Weight",
                        "AssociatedRuleCount",
                        "RegisteredInstancesCount",
                        "SessionExpireTime",
                    ),
                )
                props["health_check"] = health(raw.get("HealthCheck")) or "{}"
                vpc = identity(raw["VpcId"], "vpc-") if raw.get("VpcId") else ""
                associations = raw.get("AssociatedRule") or []
                if not isinstance(associations, list):
                    raise CollectionError("InvalidClbAssociations")
                associations = [
                    (
                        identity(a.get("LoadBalancerId"), "lb-"),
                        identity(a.get("ListenerId"), "lbl-"),
                        identity(a["LocationId"], "loc-") if a.get("LocationId") else "",
                    )
                    for a in associations
                ]
                prepared.append((rid, props, vpc, associations))
            for rid, props, vpc, associations in prepared:
                gid = graph.add(
                    runner.account,
                    region,
                    "clb.targetgroup",
                    rid,
                    props.get("TargetGroupName"),
                    source="clb.DescribeTargetGroups",
                )
                graph.nodes[gid]["properties"].update(props)
                if vpc:
                    vid = graph.add(runner.account, region, "vpc.vpc", vpc, status="reference")
                    graph.edge(gid, vid, "IN_VPC", "clb.DescribeTargetGroups")
                for lb, lid, loc in associations:
                    parent = graph.add(runner.account, region, "clb.clb", lb, status="reference")
                    frontend = listener(
                        graph, graph.nodes[parent], dict(ListenerId=lid), "clb.DescribeTargetGroups"
                    )
                    # Associations are references, not complete listener configuration.
                    if "clb.DescribeListeners" not in graph.nodes[frontend]["sources"]:
                        graph.nodes[frontend]["status"] = "reference"
                    if loc:
                        frontend = rule(
                            graph,
                            graph.nodes[frontend],
                            dict(LocationId=loc),
                            "clb.DescribeTargetGroups",
                        )
                        if "clb.DescribeListeners" not in graph.nodes[frontend]["sources"]:
                            graph.nodes[frontend]["status"] = "reference"
                    graph.edge(frontend, gid, "HAS_TARGET_GROUP", "clb.DescribeTargetGroups")
                selected.append(gid)
                record["count"] += 1

    runner.scope("clb", "DescribeTargetGroups", region, inventory)
    for gid in selected:
        members(runner, graph.nodes[gid])
    for lb in list(graph.nodes.values()):
        if (
            lb["kind"] == "clb.clb"
            and lb["account"] == runner.account
            and lb["region"] == region
            and lb["status"] == "enriched"
            and (
                lb["properties"].get("Forward") is None
                or (
                    type(lb["properties"].get("Forward")) is int
                    and lb["properties"]["Forward"] == 1
                )
            )
        ):
            rewrites(runner, lb)


def members(runner, group):
    graph = runner.graph

    def operation(record):
        seen = set()
        for batch, request in pages(
            runner.transport,
            MEMBERS,
            group["region"],
            dict(Filters=[dict(Name="TargetGroupId", Values=[group["resource_id"]])]),
        ):
            if request:
                record["request_ids"].append(request)
            prepared = []
            for raw in batch:
                if raw.get("TargetGroupId") != group["resource_id"]:
                    raise CollectionError("ClbTargetGroupMismatch")
                props = fields(
                    raw,
                    ("Type", "InstanceId", "EniId", "InstanceName", "RegisteredTime"),
                    integers=("Port", "Weight", "ZoneId"),
                )
                if not props.get("InstanceId") or type(props.get("Port")) is not int:
                    raise CollectionError("InvalidClbBackend")
                ips = raw.get("PrivateIpAddresses") or []
                if not isinstance(ips, list):
                    raise CollectionError("InvalidClbBackendAddress")
                props["private_addresses"] = json.dumps([str(ipaddress.ip_address(v)) for v in ips])
                key = (
                    group["resource_id"]
                    + "/"
                    + identity(props["InstanceId"])
                    + ":"
                    + str(props["Port"])
                )
                if key in seen:
                    raise CollectionError("DuplicateClbBackend")
                seen.add(key)
                prepared.append((key, props))
            for key, props in prepared:
                nid = graph.add(
                    runner.account,
                    group["region"],
                    "clb.targetbinding",
                    key,
                    props.get("InstanceName"),
                    source="clb.DescribeTargetGroupInstances",
                )
                graph.nodes[nid]["properties"].update(props, TargetGroupId=group["resource_id"])
                graph.edge(group["id"], nid, "HAS_BACKEND", "clb.DescribeTargetGroupInstances")
                if props["Type"] == "CVM" and props["InstanceId"].startswith("ins-"):
                    tid = graph.add(
                        runner.account,
                        group["region"],
                        "cvm.instance",
                        identity(props["InstanceId"], "ins-"),
                        status="reference",
                    )
                    graph.edge(nid, tid, "FORWARDS_TO", "clb.DescribeTargetGroupInstances")
                elif props["Type"] == "ENI" and props.get("EniId", props["InstanceId"]).startswith(
                    "eni-"
                ):
                    tid = graph.add(
                        runner.account,
                        group["region"],
                        "vpc.networkinterface",
                        identity(props.get("EniId") or props["InstanceId"], "eni-"),
                        status="reference",
                    )
                    graph.edge(nid, tid, "FORWARDS_TO", "clb.DescribeTargetGroupInstances")
                record["count"] += 1

    runner.scope(
        "clb", "DescribeTargetGroupInstances", group["region"], operation, group["resource_id"]
    )

    def status(record):
        data = runner.transport.call(
            "clb",
            "DescribeTargetGroupInstanceStatus",
            group["region"],
            TargetGroupId=group["resource_id"],
        )
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        batch = data.get("TargetGroupInstanceSet")
        if not isinstance(batch, list):
            raise CollectionError("InvalidClbHealthResponse")
        prepared = []
        for raw in batch:
            props = fields(raw, ("InstanceIp", "Status", "InstanceId", "EniId"), integers=("Port",))
            ipaddress.ip_address(props.get("InstanceIp"))
            candidates = [
                n
                for n in graph.nodes.values()
                if n["kind"] == "clb.targetbinding"
                and n["account"] == group["account"]
                and n["region"] == group["region"]
                and n["properties"].get("TargetGroupId") == group["resource_id"]
                and n["properties"].get("InstanceId") == props.get("InstanceId")
                and n["properties"].get("Port") == props.get("Port")
                and props["InstanceIp"] in json.loads(n["properties"]["private_addresses"])
            ]
            if len(candidates) != 1:
                raise CollectionError("UnresolvedClbHealthBackend")
            prepared.append((candidates[0], props))
        if len({n["id"] for n, _ in prepared}) != len(prepared):
            raise CollectionError("DuplicateClbHealthBackend")
        for node, props in prepared:
            node["properties"].update(
                reported_health=props["Status"],
                health_source="clb.DescribeTargetGroupInstanceStatus",
                reachability_verified=False,
            )
            record["count"] += 1

    runner.scope(
        "clb", "DescribeTargetGroupInstanceStatus", group["region"], status, group["resource_id"]
    )


def rewrites(runner, lb):
    graph = runner.graph

    def operation(record):
        data = runner.transport.call(
            "clb", "DescribeRewrite", lb["region"], LoadBalancerId=lb["resource_id"]
        )
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        batch = data.get("RewriteSet")
        if not isinstance(batch, list):
            raise CollectionError("InvalidClbRewriteResponse")
        prepared = []
        for raw in batch:
            lid, loc = (
                identity(raw.get("ListenerId"), "lbl-"),
                identity(raw.get("LocationId"), "loc-"),
            )
            target = raw.get("RewriteTarget")
            if not isinstance(target, dict):
                raise CollectionError("InvalidClbRewriteTarget")
            prepared.append(
                (
                    lid,
                    loc,
                    identity(target.get("TargetListenerId"), "lbl-"),
                    identity(target.get("TargetLocationId"), "loc-"),
                )
            )
        for lid, loc, tlid, tloc in prepared:
            refs = []
            for listener_id, rule_id in ((lid, loc), (tlid, tloc)):
                listener_key = lb["resource_id"] + "/" + listener_id
                lid_node = graph.add(
                    lb["account"], lb["region"], "clb.listener", listener_key, status="reference"
                )
                rid_node = graph.add(
                    lb["account"],
                    lb["region"],
                    "clb.rule",
                    listener_key + "/" + rule_id,
                    status="reference",
                )
                graph.edge(lb["id"], lid_node, "HAS_LISTENER", "clb.DescribeRewrite")
                graph.edge(lid_node, rid_node, "HAS_RULE", "clb.DescribeRewrite")
                refs.append(rid_node)
            graph.edge(refs[0], refs[1], "REDIRECTS_TO", "clb.DescribeRewrite")
            record["count"] += 1

    runner.scope("clb", "DescribeRewrite", lb["region"], operation, lb["resource_id"])
