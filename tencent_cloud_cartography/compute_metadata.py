"""Typed CVM and CBS inventory fields and declared lifecycle/network configuration."""

import json

from .vpc import fields


def enrich(graph, nid, raw, source):
    node = graph.nodes[nid]
    if node["kind"] == "cvm.instance":
        props = fields(
            raw,
            (
                "InstanceId",
                "InstanceName",
                "InstanceChargeType",
                "InstanceState",
                "OsName",
                "CreatedTime",
                "ExpiredTime",
                "RestrictState",
                "IsolatedSource",
                "CamRoleName",
                "HostName",
                "LicenseType",
                "StopChargingMode",
                "LatestOperation",
                "LatestOperationState",
                "DisasterRecoverGroupId",
                "DedicatedClusterId",
                "HpcClusterId",
                "Uuid",
            ),
            ("DisableApiTermination",),
            ("CPU", "Memory", "DefaultLoginPort"),
        )
        import ipaddress

        for key in ("PublicIpAddresses", "PrivateIpAddresses", "IPv6Addresses"):
            if raw.get(key) is not None:
                if not isinstance(raw[key], list):
                    from .transport import CollectionError

                    raise CollectionError("InvalidComputeAddresses")
                props[key] = json.dumps([str(ipaddress.ip_address(v)) for v in raw[key]])
        if raw.get("InternetAccessible") is not None:
            props["internet_configuration"] = json.dumps(
                fields(
                    raw["InternetAccessible"],
                    ("InternetChargeType",),
                    ("PublicIpAssigned",),
                    ("InternetMaxBandwidthOut",),
                ),
                sort_keys=True,
            )
        if raw.get("VirtualPrivateCloud") is not None:
            props["network_configuration"] = json.dumps(
                fields(
                    raw["VirtualPrivateCloud"],
                    ("VpcId", "SubnetId"),
                    ("AsVpcGateway",),
                    ("Ipv6AddressCount",),
                ),
                sort_keys=True,
            )
        disk_configs = []
        if raw.get("SystemDisk"):
            disk_configs.append(("system", raw["SystemDisk"]))
        for disk in raw.get("DataDisks") or []:
            disk_configs.append(("data", disk))
        prepared = []
        for role, disk in disk_configs:
            meta = fields(
                disk,
                ("DiskId", "DiskType", "CdcId", "KmsKeyId"),
                ("DeleteWithInstance", "Encrypt"),
                ("DiskSize", "ThroughputPerformance"),
            )
            meta["disk_role"] = role
            prepared.append(meta)
        props["configured_disks"] = json.dumps(prepared, sort_keys=True)
        for meta in prepared:
            if meta.get("DiskId"):
                did = graph.add(
                    node["account"],
                    node["region"],
                    "cbs.disk",
                    meta["DiskId"],
                    source=source,
                    status="reference",
                )
                graph.edge(nid, did, "USES_DISK", source)
                # Preserve configuration as a view of the disk; do not elevate a
                # nested disk to an independently enumerated CBS inventory node.
                if graph.nodes[did]["status"] != "enriched":
                    graph.nodes[did]["properties"].update(meta)
    elif node["kind"] == "cbs.disk":
        props = fields(
            raw,
            (
                "DiskId",
                "DiskName",
                "DiskState",
                "DiskType",
                "DiskUsage",
                "DiskChargeType",
                "CreateTime",
                "DeadlineTime",
                "RenewFlag",
                "AttachMode",
                "EncryptType",
                "KmsKeyId",
                "InstanceType",
            ),
            (
                "DeleteWithInstance",
                "Rollbacking",
                "Encrypt",
                "BackupDisk",
                "Migrating",
                "Attached",
                "Portable",
                "SnapshotAbility",
                "Shareable",
                "BurstPerformance",
            ),
            (
                "DiskSize",
                "SnapshotCount",
                "SnapshotSize",
                "ThroughputPerformance",
                "DiskBackupQuota",
                "DiskBackupCount",
                "DeleteSnapshot",
                "MigratePercent",
                "RollbackPercent",
            ),
        )
        members = raw.get("InstanceIdList")
        if members is not None:
            if not isinstance(members, list) or not all(
                isinstance(v, str) and v.startswith("ins-") for v in members
            ):
                from .transport import CollectionError

                raise CollectionError("InvalidDiskAttachments")
            for rid in members:
                target = graph.add(
                    node["account"],
                    node["region"],
                    "cvm.instance",
                    rid,
                    source=source,
                    status="reference",
                )
                graph.edge(nid, target, "ATTACHED_TO", source)
        # LastAttachInsId is history, not a current attachment.
        if isinstance(raw.get("LastAttachInsId"), str):
            props["last_attached_instance_id"] = raw["LastAttachInsId"]
    else:
        return
    node["properties"].update(props)
