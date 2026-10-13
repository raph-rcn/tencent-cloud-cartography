"""EMR inventory without the password-bearing DescribeInstances operation."""

import ipaddress
import json
import re

from .catalog import Collector
from .transport import CollectionError, pages

NODES = Collector(
    "emr",
    "DescribeClusterNodes",
    "NodeList",
    "emr.node",
    ("GraphId",),
    ("NameTag", "EmrResourceId", "SerialNo"),
    total="TotalCnt",
    paging="zero-offset-page",
    require_total=True,
)

CLUSTER_FIELDS = {
    str: "ClusterName StatusDesc AddTime RunTime EmrVersion ClusterClass VpcName SubnetName",
    int: "AppId ChargeType ProjectId RegionId ZoneId Status ProductId VpcId SubnetId IsWoodpeckerCluster",
    bool: "IsMultiZoneCluster IsHandsCluster IsSupportOutsideCluster "
    "IsDedicatedCluster IsSupportClone",
}
NODE_FIELDS = {
    str: "SerialNo EmrResourceId OrderNo NameTag Spec MemDesc ApplyTime FreeTime DiskSize "
    "Services Clients ServiceClient ServicesStatus ExpireTime DeviceClass DeviceName NodeGroupId NodeGroupName GpuDesc",
    int: "AppId Flag CpuNum MemSize RegionId ZoneId StorageType RootSize ChargeType CdbPort "
    "HwDiskSize HwMemSize IsAutoRenew Mutable Destroyable AutoFlag IsDynamicSpec "
    "SupportModifyPayMode RootStorageType IsFederation TradeVersion",
    bool: "DisableApiTermination TimingResource UnderwriteSetAutoRenew",
}


def identifier(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9-]+", value):
        raise CollectionError("InvalidEmrIdentity")
    return value


def selected(raw, fields):
    props = {}
    for typ, names in fields.items():
        for name in names.split():
            if raw.get(name) is not None:
                if type(raw[name]) is not typ:
                    raise CollectionError("InvalidEmrField")
                props[name] = raw[name]
    return props


def prepare(raw, region, cluster_type=None, parent=None, flag=None):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidEmrResource")
    props = selected(raw, CLUSTER_FIELDS if parent is None else NODE_FIELDS)
    links = []
    if parent is None:
        rid = identifier(raw.get("ClusterId"), "emr-")
        props["ClusterType"] = cluster_type
        for key, kind, relation, prefix in (
            ("UniqVpcId", "vpc.vpc", "IN_VPC", "vpc-"),
            ("UniqSubnetId", "vpc.subnet", "CONFIGURED_SUBNET", "subnet-"),
        ):
            if raw.get(key) not in (None, "", "--"):
                value = identifier(raw[key], prefix)
                props[key] = value
                # A multi-zone cluster's default subnet is not its only placement.
                if key == "UniqSubnetId" and raw.get("IsMultiZoneCluster") is False:
                    relation = "IN_SUBNET"
                links.append((value, kind, relation))
    else:
        for key in ("InstanceId", "ClusterId"):
            if raw.get(key) is not None and raw[key] != parent["resource_id"]:
                raise CollectionError("EmrClusterMismatch")
        for key in ("AppId", "RegionId"):
            expected = parent["properties"].get(key)
            if expected is not None and raw.get(key) is not None and raw[key] != expected:
                raise CollectionError("EmrScopeMismatch")
        if raw.get("EmrResourceId"):
            local_id = identifier(raw["EmrResourceId"], "emr-")
            identity_source = "EmrResourceId"
        else:
            local_id = identifier(raw.get("SerialNo"), "")
            identity_source = "SerialNo"
        rid = f"{parent['resource_id']}/{identity_source}/{local_id}"
        props.update(cluster_id=parent["resource_id"], identity_source=identity_source)
        hardware = raw.get("HardwareResourceType")
        if hardware is not None:
            if not isinstance(hardware, str) or not hardware:
                raise CollectionError("InvalidEmrHardwareType")
            props["HardwareResourceType"] = hardware
        if hardware and hardware.lower() == "host" and flag != "db" and not raw.get("CdbNodeInfo"):
            order = raw.get("OrderNo")
            if isinstance(order, str) and order.startswith("ins-"):
                links.append((identifier(order, "ins-"), "cvm.instance", "BACKED_BY"))
        if raw.get("TkeClusterId") not in (None, "", "--"):
            tke = identifier(raw["TkeClusterId"], "cls-")
            props["TkeClusterId"] = tke
            if hardware and hardware.lower() == "pod":
                links.append((tke, "tke.cluster", "RUNS_ON"))
        subnet = raw.get("SubnetInfo")
        if subnet is not None:
            if not isinstance(subnet, dict):
                raise CollectionError("InvalidEmrSubnet")
            props.update(selected(subnet, {str: "SubnetId SubnetName"}))
            if subnet.get("SubnetId") not in (None, "", "--"):
                links.append((identifier(subnet["SubnetId"], "subnet-"), "vpc.subnet", "IN_SUBNET"))
        cdb = raw.get("CdbNodeInfo")
        if cdb is not None:
            if not isinstance(cdb, dict):
                raise CollectionError("InvalidEmrDatabaseMetadata")
            props["CdbNodeInfo"] = json.dumps(
                selected(
                    cdb,
                    {
                        str: "InstanceName Ip Service SerialNo ExpireTime ApplyTime",
                        int: "Port MemSize Volume PayType Status IsAutoRenew ZoneId RegionId",
                        bool: "ExpireFlag",
                    },
                ),
                sort_keys=True,
            )
        props["inventory_node_flag"] = flag
    zone = raw.get("Zone")
    if zone not in (None, "", "--"):
        if not isinstance(zone, str) or not re.fullmatch(re.escape(region) + r"-\d+", zone):
            raise CollectionError("EmrZoneMismatch")
        props["Zone"] = zone
        if parent is not None or raw.get("IsMultiZoneCluster") is False:
            props["zone"] = zone
    ips = []
    for key in ("MasterIp",) if parent is None else ("Ip", "WanIp", "CdbIp"):
        value = raw.get(key)
        if value in (None, "", "--"):
            continue
        try:
            if not isinstance(value, str):
                raise ValueError
            value = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise CollectionError("InvalidEmrAddress") from exc
        props[key] = value
        ips.append(value)
    if ips:
        props["ip_addresses"] = ", ".join(sorted(set(ips)))
    if raw.get("Tags") is not None:
        tags = raw["Tags"]
        if not isinstance(tags, list) or any(
            not isinstance(t, dict)
            or any(type(t.get(k)) is not str for k in ("TagKey", "TagValue"))
            for t in tags
        ):
            raise CollectionError("InvalidEmrTags")
        props["tags"] = json.dumps(
            [{k: t[k] for k in ("TagKey", "TagValue")} for t in tags], sort_keys=True
        )
    props["configuration_only"] = True
    if "Status" in props:
        props["state"] = str(props["Status"])
    return {
        "ClusterId": rid,
        "GraphId": rid,
        "ClusterName": props.get("ClusterName", ""),
        "NameTag": props.get("NameTag", ""),
        "_properties": props,
        "_links": links,
    }


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = raw["_properties"]
    if "inventory_node_flag" in props:
        flags = set(json.loads(node["properties"].get("inventory_node_flags", "[]")))
        flags.add(props["inventory_node_flag"])
        props = {**props, "inventory_node_flags": json.dumps(sorted(flags))}
    node["properties"].update(props)
    for rid, kind, relation in raw["_links"]:
        target = graph.add(node["account"], node["region"], kind, rid, status="reference")
        graph.edge(nid, target, relation, source)


def collect_clusters(runner, spec, region):
    clusters, seen = [], set()
    for cluster_type in (0, 2):

        def inventory(record, cluster_type=cluster_type):
            params = dict(DisplayStrategy="clusterList", ClusterType=cluster_type)
            for rows, request_id in pages(runner.transport, spec, region, params):
                if request_id:
                    record["request_ids"].append(request_id)
                for row in rows:
                    raw = prepare(row, region, cluster_type=cluster_type)
                    if raw["ClusterId"] in seen:
                        raise CollectionError("DuplicateEmrCluster")
                    seen.add(raw["ClusterId"])
                    nid = runner.graph.native(
                        runner.account, region, spec, raw, "emr." + spec.action
                    )
                    clusters.append(nid)
                    record["count"] += 1

        runner.scope("emr", spec.action, region, inventory, f"ClusterType={cluster_type}")
    for nid in clusters:
        parent = runner.graph.nodes[nid]
        observations = {}
        # The API's literal spelling is recyle. all excludes CDB; db adds CDB;
        # recyle includes isolated nodes. Overlap across views merges by identity.
        for flag in ("all", "db", "recyle"):

            def nodes(record, parent=parent, flag=flag):
                seen_nodes = set()
                params = dict(
                    InstanceId=parent["resource_id"], NodeFlag=flag, HardwareResourceType="all"
                )
                for rows, request_id in pages(runner.transport, NODES, region, params):
                    if request_id:
                        record["request_ids"].append(request_id)
                    for row in rows:
                        raw = prepare(row, region, parent=parent, flag=flag)
                        if raw["GraphId"] in seen_nodes:
                            raise CollectionError("DuplicateEmrNode")
                        seen_nodes.add(raw["GraphId"])
                        observed = {
                            k: v
                            for k, v in raw["_properties"].items()
                            if k != "inventory_node_flag"
                        }
                        if (
                            raw["GraphId"] in observations
                            and observations[raw["GraphId"]] != observed
                        ):
                            raise CollectionError("EmrNodeChangedBetweenViews")
                        observations[raw["GraphId"]] = observed
                        child = runner.graph.native(
                            runner.account, region, NODES, raw, "emr.DescribeClusterNodes"
                        )
                        runner.graph.edge(
                            parent["id"], child, "HAS_NODE", "emr.DescribeClusterNodes"
                        )
                        record["count"] += 1

            runner.scope(
                "emr", NODES.action, region, nodes, f"{parent['resource_id']} NodeFlag={flag}"
            )
