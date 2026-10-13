"""CCN metadata and owner-qualified attachment identities."""

import ipaddress
import json
import re
from dataclasses import replace

from .catalog import CHILDREN
from .model import stable_id
from .transport import CollectionError, pages


def text_fields(raw, strings=(), integers=(), booleans=()):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidCcnMetadata")
    props = {}
    for fields, typ in ((strings, str), (integers, int), (booleans, bool)):
        for field in fields:
            if raw.get(field) is not None:
                value = raw[field]
                if type(value) is not typ or (typ is int and value < 0):
                    raise CollectionError("InvalidCcnMetadata")
                props[field] = value
    return props


def identity(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Za-z0-9]+", value):
        raise CollectionError("InvalidCcnIdentity")
    return value


def uin(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise CollectionError("InvalidCcnOwner")
    return value


def network(raw):
    props = text_fields(
        raw,
        (
            "CcnName",
            "CcnDescription",
            "CreateTime",
            "State",
            "QosLevel",
            "InstanceChargeType",
            "InstanceMeteringType",
            "BandwidthLimitType",
        ),
        ("InstanceCount", "RouteTableCount", "ServiceLevelMode"),
        (
            "RoutePriorityFlag",
            "RouteTableFlag",
            "IsSecurityLock",
            "RouteBroadcastPolicyFlag",
            "RouteECMPFlag",
            "RouteOverlapFlag",
            "TrafficMarkingPolicyFlag",
            "RouteSelectPolicyFlag",
            "DirectConnectAccelerateChannelFlag",
            "Ipv6Flag",
            "MrtbAggregatePolicyFlag",
            "MrtbPolicyValueFlag",
            "RouteTablePolicyValueCommunityFlag",
            "PolicyBasedRoutingFlag",
        ),
    )
    nid = identity(raw.get("CcnId"), "ccn")
    props["CcnId"] = nid
    props["state"] = props.get("State", "")
    return nid, props


def attachment(raw, parent):
    props = text_fields(
        raw,
        (
            "CcnId",
            "InstanceType",
            "InstanceId",
            "InstanceName",
            "InstanceRegion",
            "InstanceUin",
            "State",
            "AttachedTime",
            "CcnUin",
            "InstanceArea",
            "Description",
            "RouteTableId",
            "RouteTableName",
            "AliasType",
            "AliasInstanceId",
        ),
    )
    if props.get("CcnId") != parent["resource_id"]:
        raise CollectionError("CcnAttachmentParentMismatch")
    owner = uin(props.get("CcnUin"))
    if owner != parent["account"]:
        raise CollectionError("CcnOwnerMismatch")
    instance_owner = uin(props.get("InstanceUin"))
    region = props.get("InstanceRegion")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region):
        raise CollectionError("InvalidCcnRegion")
    kind = props.get("InstanceType")
    instance = props.get("InstanceId")
    if (
        not isinstance(kind, str)
        or not kind
        or not isinstance(instance, str)
        or not instance
        or any(ord(c) < 32 for c in instance)
    ):
        raise CollectionError("InvalidCcnAttachedInstance")
    mapping = {
        "VPC": ("vpc.vpc", "vpc"),
        "DIRECTCONNECT": ("vpc.directconnectgateway", "dcg"),
        "BMVPC": ("bmvpc.vpc", "vpc"),
    }
    target = None
    if kind in mapping:
        target_kind, prefix = mapping[kind]
        identity(instance, prefix)
        target = (instance_owner, region, target_kind, instance)
    cidrs = raw.get("CidrBlock")
    if cidrs is not None:
        if not isinstance(cidrs, list) or any(not isinstance(c, str) for c in cidrs):
            raise CollectionError("InvalidCcnCidrs")
        try:
            props["CidrBlock"] = json.dumps(
                [str(ipaddress.ip_network(c, strict=True)) for c in cidrs]
            )
        except ValueError as exc:
            raise CollectionError("InvalidCcnCidrs") from exc
    if props.get("RouteTableId") and not re.fullmatch(
        r"ccn(?:rt|tr)-[A-Za-z0-9]+", props["RouteTableId"]
    ):
        raise CollectionError("InvalidCcnRouteTable")
    props["state"] = props.get("State", "")
    props["connectivity_verified"] = False
    props["active_reported"] = props.get("State") == "ACTIVE"
    # Including type avoids collisions between provider identifier namespaces.
    aid = stable_id(parent["resource_id"], kind, instance_owner, region, instance)
    return aid, props, target


def collect(runner, spec):
    collected = []
    source = "vpc.DescribeCcns"

    def inventory(record):
        seen = set()
        for rows, request in pages(runner.transport, replace(spec, require_total=True), "global"):
            if request:
                record["request_ids"].append(request)
            prepared = [network(r) for r in rows]
            ids = [r[0] for r in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateCcn")
            seen.update(ids)
            for identity, props in prepared:
                nid = runner.graph.add(
                    runner.account,
                    "global",
                    "vpc.ccn",
                    identity,
                    props.get("CcnName"),
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(props)
                collected.append(nid)
                record["count"] += 1

    runner.scope("vpc", spec.action, "global", inventory)
    for nid in collected:
        parent = runner.graph.nodes[nid]

        def members(record, parent=parent):
            source = "vpc.DescribeCcnAttachedInstances"
            seen = set()
            for rows, request in pages(
                runner.transport,
                replace(CHILDREN["vpc.ccn"], require_total=True),
                "global",
                {"CcnId": parent["resource_id"]},
            ):
                if request:
                    record["request_ids"].append(request)
                prepared = [attachment(r, parent) for r in rows]
                ids = [r[0] for r in prepared]
                if len(set(ids)) != len(ids) or seen.intersection(ids):
                    raise CollectionError("DuplicateCcnAttachment")
                seen.update(ids)
                for identity, props, target in prepared:
                    aid = runner.graph.add(
                        parent["account"],
                        "global",
                        "vpc.ccnattachment",
                        identity,
                        props.get("InstanceName") or props["InstanceId"],
                        source=source,
                    )
                    runner.graph.nodes[aid]["properties"].update(props)
                    runner.graph.edge(parent["id"], aid, "HAS_ATTACHMENT", source)
                    if target:
                        other = runner.graph.add(*target, source=source, status="reference")
                        # Retain configured association even if pending/deleted;
                        # the explicit reported state remains attached to this node.
                        runner.graph.edge(aid, other, "ATTACHED_NETWORK", source)
                    record["count"] += 1

        runner.scope(
            "vpc", "DescribeCcnAttachedInstances", "global", members, parent["resource_id"]
        )
