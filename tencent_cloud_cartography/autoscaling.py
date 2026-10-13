"""Typed scaling-group and membership metadata; launch user data is never fetched."""

import json
import re
from dataclasses import replace

from .transport import CollectionError, pages


def identity(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Za-z0-9]+", value):
        raise CollectionError("InvalidAutoScalingIdentity")
    return value


def selected(raw, strings=(), integers=(), booleans=()):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidAutoScalingMetadata")
    props = {}
    for names, typ in ((strings, str), (integers, int), (booleans, bool)):
        for key in names:
            value = raw.get(key)
            if value is None:
                continue
            if type(value) is not typ or (typ is int and value < 0):
                raise CollectionError("InvalidAutoScalingMetadata")
            props[key] = value
    return props


def ids(raw, field, prefix):
    values = raw.get(field, [])
    if values is None:
        return []
    if not isinstance(values, list):
        raise CollectionError("InvalidAutoScalingIdentityList")
    result = [identity(v, prefix) for v in values]
    if len(set(result)) != len(result):
        raise CollectionError("DuplicateAutoScalingIdentity")
    return result


def prepare_group(raw, region):
    props = selected(
        raw,
        strings=(
            "AutoScalingGroupName",
            "AutoScalingGroupStatus",
            "CreatedTime",
            "EnabledStatus",
            "RetryPolicy",
            "InActivityStatus",
            "MultiZoneSubnetPolicy",
            "HealthCheckType",
            "InstanceAllocationPolicy",
            "LaunchConfigurationName",
        ),
        integers=(
            "DefaultCooldown",
            "DesiredCapacity",
            "InstanceCount",
            "InServiceInstanceCount",
            "MaxSize",
            "MinSize",
            "ProjectId",
            "Ipv6AddressCount",
            "LoadBalancerHealthCheckGracePeriod",
        ),
        booleans=("CapacityRebalance", "ConcurrentScaleOutForDesiredCapacity"),
    )
    rid = identity(raw.get("AutoScalingGroupId"), "asg")
    refs = []
    for field, prefix, kind, relation in (
        ("VpcId", "vpc", "vpc.vpc", "IN_VPC"),
        ("LaunchConfigurationId", "asc", "as.launch-configuration", "USES_LAUNCH_CONFIGURATION"),
    ):
        if raw.get(field) not in (None, ""):
            refs.append((kind, identity(raw[field], prefix), region, relation))
            props[field] = raw[field]
    subnets = ids(raw, "SubnetIdSet", "subnet")
    refs += [("vpc.subnet", v, region, "IN_SUBNET") for v in subnets]
    props["SubnetIdSet"] = json.dumps(subnets)
    for field in ("ZoneSet", "TerminationPolicySet"):
        value = raw.get(field)
        if value is not None:
            if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
                raise CollectionError("InvalidAutoScalingMetadata")
            if field == "ZoneSet" and any(
                not re.fullmatch(re.escape(region) + r"-\d+", v) for v in value
            ):
                raise CollectionError("AutoScalingRegionMismatch")
            props[field] = json.dumps(value)
    # ZoneSet is a placement choice set, never one actual group zone.
    for field, strings, integers, booleans in (
        (
            "ServiceSettings",
            ("ScalingMode", "ReplaceMode"),
            (),
            (
                "ReplaceMonitorUnhealthy",
                "ReplaceLoadBalancerUnhealthy",
                "AutoUpdateInstanceTags",
                "DesiredCapacitySyncWithMaxMinSize",
                "PriorityScaleInUnhealthy",
            ),
        ),
        (
            "SpotMixedAllocationPolicy",
            ("SpotAllocationStrategy",),
            ("BaseCapacity", "OnDemandPercentageAboveBaseCapacity"),
            ("CompensateWithBaseInstance",),
        ),
    ):
        if raw.get(field) is not None:
            props[field] = json.dumps(
                selected(raw[field], strings, integers, booleans), sort_keys=True
            )
    refs += [
        ("clb.clb", v, region, "ATTACHED_LOAD_BALANCER")
        for v in ids(raw, "LoadBalancerIdSet", "lb")
    ]
    forward = raw.get("ForwardLoadBalancerSet", [])
    if forward is None:
        forward = []
    if not isinstance(forward, list):
        raise CollectionError("InvalidAutoScalingLoadBalancers")
    lb_metadata = []
    for lb in forward:
        item = selected(lb, strings=("LoadBalancerId", "ListenerId", "LocationId", "Region"))
        lbid = identity(item.get("LoadBalancerId"), "lb")
        location = item.get("Region") or region
        if not re.fullmatch(r"[a-z]+-[a-z0-9]+(?:-[a-z0-9]+)*", location):
            raise CollectionError("InvalidAutoScalingRegion")
        refs.append(("clb.clb", lbid, location, "ATTACHED_LOAD_BALANCER"))
        targets = lb.get("TargetAttributes")
        if targets is not None:
            if not isinstance(targets, list):
                raise CollectionError("InvalidAutoScalingTargetAttributes")
            item["TargetAttributes"] = [selected(t, integers=("Port", "Weight")) for t in targets]
        lb_metadata.append(item)
    props["ForwardLoadBalancerSet"] = json.dumps(lb_metadata, sort_keys=True)
    props["state"] = props.get("AutoScalingGroupStatus", "")
    return rid, props, refs


def prepare_member(raw, region):
    props = selected(
        raw,
        strings=(
            "LifeCycleState",
            "HealthStatus",
            "CreationType",
            "AddTime",
            "InstanceType",
            "WarmupStatus",
            "AutoScalingGroupName",
            "LaunchConfigurationName",
            "Zone",
        ),
        integers=("VersionNumber",),
        booleans=("ProtectedFromScaleIn",),
    )
    rid = identity(raw.get("InstanceId"), "ins")
    props["AutoScalingGroupId"] = identity(raw.get("AutoScalingGroupId"), "asg")
    if raw.get("LaunchConfigurationId"):
        props["LaunchConfigurationId"] = identity(raw["LaunchConfigurationId"], "asc")
    if props.get("Zone") and not re.fullmatch(re.escape(region) + r"-\d+", props["Zone"]):
        raise CollectionError("AutoScalingRegionMismatch")
    return rid, props


def collect(runner, spec, region):
    if spec.action == "DescribeLaunchConfigurations":

        def unsupported(record):
            raise CollectionError("UnsupportedMetadataOnlyLaunchConfigurations")

        runner.scope(
            spec.service,
            spec.action,
            region,
            unsupported,
            "Disabled: API returns UserData payloads without a metadata-only projection. "
            "Group/member references preserve configuration IDs and names.",
        )
        return
    source = f"{spec.service}.{spec.action}"
    group_mode = spec.action == "DescribeAutoScalingGroups"

    def operation(record):
        seen = set()
        for rows, request_id in pages(runner.transport, replace(spec, require_total=True), region):
            if request_id:
                record["request_ids"].append(request_id)
            prepared = [(prepare_group if group_mode else prepare_member)(r, region) for r in rows]
            identifiers = [r[0] for r in prepared]
            if len(set(identifiers)) != len(identifiers) or seen.intersection(identifiers):
                raise CollectionError("DuplicateAutoScalingResource")
            seen.update(identifiers)
            for item in prepared:
                rid, props = item[:2]
                if group_mode:
                    nid = runner.graph.add(
                        runner.account,
                        region,
                        spec.kind,
                        rid,
                        props.get("AutoScalingGroupName"),
                        source=source,
                    )
                    runner.graph.nodes[nid]["properties"].update(props)
                    for kind, target, target_region, relation in item[2]:
                        other = runner.graph.add(
                            runner.account,
                            target_region,
                            kind,
                            target,
                            source=source,
                            status="reference",
                        )
                        if kind == "as.launch-configuration" and props.get(
                            "LaunchConfigurationName"
                        ):
                            runner.graph.nodes[other]["properties"]["referenced_name"] = props[
                                "LaunchConfigurationName"
                            ]
                        runner.graph.edge(nid, other, relation, source)
                else:
                    # Membership metadata must not overwrite CVM name/state or claim
                    # that a denied CVM inventory was successfully enriched.
                    nid = runner.graph.add(
                        runner.account,
                        region,
                        "cvm.instance",
                        rid,
                        source=source,
                        status="reference",
                    )
                    node = runner.graph.nodes[nid]
                    node["properties"].update({"as_" + k: v for k, v in props.items()})
                    node["sources"] = sorted(set(node["sources"] + [source]))
                    group = runner.graph.add(
                        runner.account,
                        region,
                        "as.auto-scaling-group",
                        props["AutoScalingGroupId"],
                        source=source,
                        status="reference",
                    )
                    runner.graph.edge(group, nid, "HAS_INSTANCE", source)
                    if props.get("LaunchConfigurationId"):
                        cfg = runner.graph.add(
                            runner.account,
                            region,
                            "as.launch-configuration",
                            props["LaunchConfigurationId"],
                            source=source,
                            status="reference",
                        )
                        runner.graph.edge(nid, cfg, "USES_LAUNCH_CONFIGURATION", source)
                record["count"] += 1

    runner.scope(spec.service, spec.action, region, operation)
