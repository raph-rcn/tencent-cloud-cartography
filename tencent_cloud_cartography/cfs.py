"""CFS mount/network and export-permission configuration, without mounting shares."""

import json
import math
import re

from .observability import retain, strings
from .transport import CollectionError


def identity(value, prefix):
    if prefix == "pgroup" and value == "pgroupbasic":
        return value
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[a-zA-Z0-9-]+", value):
        raise CollectionError("InvalidCfsIdentity")
    return value


def prepare(kind, raw, params):
    if kind == "cfs.filesystem":
        identity(raw.get("FileSystemId"), "cfs")
    elif kind == "cfs.permissiongroup":
        identity(raw.get("PGroupId"), "pgroup")
    elif kind == "cfs.mounttarget":
        fs = identity(params.get("FileSystemId"), "cfs")
        if raw.get("FileSystemId") != fs:
            raise CollectionError("CfsFileSystemMismatch")
        mid = identity(raw.get("MountTargetId"), "mount")
        return {**raw, "MountResourceId": f"{fs}/{mid}"}
    elif kind == "cfs.permissionrule":
        group = identity(params.get("PGroupId"), "pgroup")
        if raw.get("PGroupId") not in (None, group):
            raise CollectionError("CfsPermissionGroupMismatch")
        rule = identity(raw.get("RuleId"), "rule")
        return {**raw, "PGroupId": group, "RuleResourceId": f"{group}/{rule}"}
    return raw


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    kind = node["kind"]

    def ref(rid, prefix, target_kind, relation, region=None):
        target = graph.add(
            node["account"],
            region or node["region"],
            target_kind,
            identity(rid, prefix),
            source=source,
            status="reference",
        )
        graph.edge(nid, target, relation, source)

    if kind == "cfs.filesystem":
        retain(
            props,
            raw,
            (
                "CreationTime",
                "CreationToken",
                "LifeCycleState",
                "SizeByte",
                "SizeLimit",
                "ZoneId",
                "Protocol",
                "StorageType",
                "StorageResourcePkg",
                "BandwidthResourcePkg",
                "Encrypted",
                "KmsKeyId",
                "AutoSnapshotPolicyId",
                "SnapStatus",
                "Capacity",
                "TieringState",
                "Version",
                "MetaType",
                "Scenario",
                "FullDeleteMinTtl",
                "ExpireDeleteTtl",
            ),
        )
        for field in ("BandwidthLimit", "FullDeleteCapacityUsage"):
            value = raw.get(field)
            if value is not None:
                if type(value) not in (int, float) or not math.isfinite(value):
                    raise CollectionError("InvalidCfsCapacity")
                props[field] = value
        if raw.get("LifeCycleState"):
            props["state"] = raw["LifeCycleState"]
        group = raw.get("PGroup")
        if group is not None:
            if not isinstance(group, dict):
                raise CollectionError("InvalidCfsPermissionGroup")
            if group.get("PGroupId"):
                ref(group["PGroupId"], "pgroup", "cfs.permissiongroup", "USES_PERMISSION_GROUP")
    elif kind == "cfs.permissiongroup":
        retain(props, raw, ("DescInfo", "CDate", "BindCfsNum"))
    elif kind == "cfs.mounttarget":
        retain(
            props,
            raw,
            (
                "FileSystemId",
                "MountTargetId",
                "IpAddress",
                "FSID",
                "LifeCycleState",
                "NetworkInterface",
                "CcnID",
                "CidrBlock",
                "ServerListTruncated",
            ),
        )
        props["mount_verified"] = False
        if raw.get("LifeCycleState"):
            props["state"] = raw["LifeCycleState"]
        if raw.get("IpAddress"):
            props["ip_addresses"] = raw["IpAddress"]
        if raw.get("ServerList") is not None:
            props["allocated_server_ips"] = json.dumps(strings(raw["ServerList"]))
        network = raw.get("NetworkInterface")
        network = network.upper() if isinstance(network, str) else network
        if network == "VPC":
            if raw.get("VpcId"):
                ref(raw["VpcId"], "vpc", "vpc.vpc", "IN_VPC")
            if raw.get("SubnetId"):
                ref(raw["SubnetId"], "subnet", "vpc.subnet", "IN_SUBNET")
        elif network == "CCN":
            if raw.get("CcnID"):
                ref(raw["CcnID"], "ccn", "vpc.ccn", "ATTACHED_CCN", region="global")
        else:
            props["network_resolution"] = "unsupported-type"
    elif kind == "cfs.permissionrule":
        retain(
            props,
            raw,
            ("PGroupId", "RuleId", "AuthClientIp", "RWPermission", "UserPermission", "Priority"),
        )
        props["access_verified"] = False
        priority = raw.get("Priority")
        if type(priority) is not int or not 1 <= priority <= 100:
            raise CollectionError("InvalidCfsRulePriority")
        if raw.get("RWPermission") not in {"ro", "rw"} or raw.get("UserPermission") not in {
            "all_squash",
            "no_all_squash",
            "root_squash",
            "no_root_squash",
        }:
            raise CollectionError("InvalidCfsRulePermission")
        if not isinstance(raw.get("AuthClientIp"), str) or not raw["AuthClientIp"]:
            raise CollectionError("InvalidCfsRuleClient")
