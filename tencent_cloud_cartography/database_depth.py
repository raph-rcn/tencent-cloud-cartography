"""Metadata-only backup, availability, replica and proxy configuration."""

import ipaddress
import json
import re

from .transport import CollectionError
from .vpc import fields


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9-]+", value):
        raise CollectionError("InvalidDatabaseIdentity")
    return value


def batch(data, key, total=None):
    result = data.get(key)
    if not isinstance(result, list) or not all(isinstance(r, dict) for r in result):
        raise CollectionError("InvalidDatabaseConfiguration")
    if total and (type(data.get(total)) is not int or data[total] != len(result)):
        raise CollectionError("DatabaseConfigurationCountMismatch")
    return result


def network(props):
    for k in ("Vip", "Vipv6"):
        if props.get(k):
            props[k] = str(ipaddress.ip_address(props[k]))
    for k in ("VPort", "Vport"):
        if k in props and not 1 <= props[k] <= 65535:
            raise CollectionError("InvalidDatabasePort")
    for k, prefix in (("UniqVpcId", "vpc-"), ("UniqSubnetId", "subnet-")):
        if props.get(k) and not re.fullmatch(prefix + r"[a-z0-9]+", props[k]):
            raise CollectionError("InvalidDatabaseNetwork")
    return props


def add(graph, parent, kind, rid, props, source, relationship):
    nid = graph.add(
        parent["account"],
        parent["region"],
        kind,
        parent["resource_id"]
        + "/"
        + (rid if kind == "postgres.parameter" and rid in PG_PARAMETERS else identity(rid)),
        props.get("PlanName") or props.get("RoGroupName") or rid,
        source=source,
    )
    graph.nodes[nid]["properties"].update(props)
    graph.edge(parent["id"], nid, relationship, source)
    for key, kind in (("UniqVpcId", "vpc.vpc"), ("UniqSubnetId", "vpc.subnet")):
        if props.get(key):
            target = graph.add(
                parent["account"],
                parent["region"],
                kind,
                props[key],
                status="reference",
                source=source,
            )
            graph.edge(nid, target, "IN_VPC" if key == "UniqVpcId" else "IN_SUBNET", source)
    return graph.nodes[nid]


def proxies(graph, parent, data, source):
    selected = []
    for row in batch(data, "ProxyInfos", "Count"):
        props = fields(
            row,
            ("ProxyGroupId", "ProxyVersion", "Status", "TaskStatus"),
            ("SupportCreateProxyAddress",),
            ("ConnectionPoolLimit",),
        )
        identity(props.get("ProxyGroupId"))
        nodes, addresses = [], []
        for raw in batch(row, "ProxyNode"):
            p = fields(
                raw, ("ProxyId", "Status", "Zone", "Region"), integers=("Cpu", "Mem", "Connection")
            )
            identity(p.get("ProxyId"))
            if p.get("Region") not in (None, parent["region"]):
                raise CollectionError("DatabaseRegionMismatch")
            nodes.append(p)
        for raw in batch(row, "ProxyAddress"):
            p = network(
                fields(
                    raw,
                    (
                        "ProxyAddressId",
                        "UniqVpcId",
                        "UniqSubnetId",
                        "Vip",
                        "WeightMode",
                        "AccessMode",
                    ),
                    (
                        "ReadOnly",
                        "AutoAddRo",
                        "TransSplit",
                        "FailOver",
                        "ConnectionPool",
                        "AutoLoadBalance",
                        "IsKickOut",
                    ),
                    ("VPort", "MinCount", "MaxDelay"),
                )
            )
            identity(p.get("ProxyAddressId"))
            addresses.append(p)
        for values, key in ((nodes, "ProxyId"), (addresses, "ProxyAddressId")):
            if len({p[key] for p in values}) != len(values):
                raise CollectionError("DuplicateDatabaseConfiguration")
        selected.append((props, nodes, addresses))
    if len({p["ProxyGroupId"] for p, _, _ in selected}) != len(selected):
        raise CollectionError("DuplicateDatabaseConfiguration")
    for props, nodes, addresses in selected:
        group = add(
            graph, parent, "cdb.proxygroup", props["ProxyGroupId"], props, source, "HAS_PROXY_GROUP"
        )
        for values, kind, key in (
            (nodes, "cdb.proxynode", "ProxyId"),
            (addresses, "cdb.proxyaddress", "ProxyAddressId"),
        ):
            for p in values:
                add(
                    graph,
                    group,
                    kind,
                    p[key],
                    p,
                    source,
                    "HAS_PROXY_NODE" if key == "ProxyId" else "HAS_PROXY_ADDRESS",
                )


def rogroups(graph, parent, data, source):
    prepared = []
    for row in batch(data, "RoGroups"):
        p = network(
            fields(
                row,
                (
                    "RoGroupId",
                    "RoGroupName",
                    "RoGroupMode",
                    "WeightMode",
                    "Vip",
                    "UniqVpcId",
                    "UniqSubnetId",
                    "RoGroupRegion",
                    "RoGroupZone",
                ),
                integers=(
                    "Vport",
                    "RoOfflineDelay",
                    "RoMaxDelayTime",
                    "MinRoInGroup",
                    "DelayReplicationTime",
                ),
            )
        )
        identity(p.get("RoGroupId"))
        if p.get("RoGroupRegion") not in (None, parent["region"]):
            raise CollectionError("DatabaseRegionMismatch")
        members = []
        for row in batch(row, "RoInstances"):
            m = fields(
                row,
                (
                    "InstanceId",
                    "MasterInstanceId",
                    "Region",
                    "Zone",
                    "RoStatus",
                    "ReplicationStatus",
                ),
                integers=("Weight",),
            )
            identity(m.get("InstanceId"))
            if m.get("MasterInstanceId") != parent["resource_id"] or not re.fullmatch(
                r"[a-z]+-[a-z0-9-]+", m.get("Region", "")
            ):
                raise CollectionError("DatabaseReplicaMismatch")
            members.append(m)
        if len({(m["Region"], m["InstanceId"]) for m in members}) != len(members):
            raise CollectionError("DuplicateDatabaseConfiguration")
        prepared.append((p, members))
    if len({p["RoGroupId"] for p, _ in prepared}) != len(prepared):
        raise CollectionError("DuplicateDatabaseConfiguration")
    for p, members in prepared:
        group = add(graph, parent, "cdb.rogroup", p["RoGroupId"], p, source, "HAS_READ_ONLY_GROUP")
        group["properties"]["member_configuration"] = json.dumps(members, sort_keys=True)
        for m in members:
            target = graph.add(
                parent["account"],
                m["Region"],
                "cdb.instance",
                m["InstanceId"],
                source=source,
                status="reference",
            )
            graph.edge(group["id"], target, "HAS_READ_ONLY_MEMBER", source)


def apply(graph, node, service, action, data):
    if data.get("InstanceId") not in (None, node["resource_id"]):
        raise CollectionError("DatabaseIdentityMismatch")
    source = service + "." + action
    if action == "DescribeCdbProxyInfo":
        proxies(graph, node, data, source)
    elif action == "DescribeRoGroups":
        rogroups(graph, node, data, source)
    elif action == "DescribeBackupPlans":
        prepared = [
            fields(
                r,
                (
                    "PlanId",
                    "PlanName",
                    "PlanType",
                    "BackupPeriod",
                    "BackupPeriodType",
                    "MinBackupStartTime",
                    "MaxBackupStartTime",
                    "CreatedTime",
                    "UpdatedTime",
                ),
                integers=("BaseBackupRetentionPeriod", "LogBackupRetentionPeriod"),
            )
            for r in batch(data, "Plans")
        ]
        ids = [identity(p.get("PlanId")) for p in prepared]
        if len(set(ids)) != len(ids):
            raise CollectionError("DuplicateDatabaseConfiguration")
        for p in prepared:
            add(graph, node, "postgres.backupplan", p["PlanId"], p, source, "HAS_BACKUP_PLAN")
    elif action == "DescribeDBSecurityGroups":
        key = "SecurityGroupSet" if service == "sqlserver" else "Groups"
        ids = [r.get("SecurityGroupId") for r in batch(data, key)]
        if any(not isinstance(i, str) or not re.fullmatch(r"sg-[a-z0-9]+", i) for i in ids) or len(
            set(ids)
        ) != len(ids):
            raise CollectionError("InvalidDatabaseSecurityGroups")
        for rid in ids:
            target = graph.add(
                node["account"],
                node["region"],
                "vpc.securitygroup",
                rid,
                source=source,
                status="reference",
            )
            graph.edge(node["id"], target, "USES_SECURITY_GROUP", source)
    elif action == "DescribeDcnDetail":
        prepared = [
            fields(
                r,
                ("InstanceId", "InstanceName", "Region", "Zone", "StatusDesc"),
                integers=("Status", "DcnFlag", "DcnStatus", "EncryptStatus"),
            )
            for r in batch(data, "DcnDetails")
        ]
        ids = [(p.get("Region"), identity(p.get("InstanceId"))) for p in prepared]
        if any(
            not isinstance(r, str) or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", r) for r, _ in ids
        ) or len(set(ids)) != len(ids):
            raise CollectionError("DatabaseReplicaMismatch")
        node["properties"][action] = json.dumps(prepared, sort_keys=True)
        for p in prepared:
            if p["DcnFlag"] == 2 and p["InstanceId"] != node["resource_id"]:
                target = graph.add(
                    node["account"],
                    p["Region"],
                    "mariadb.instance",
                    p["InstanceId"],
                    source=source,
                    status="reference",
                )
                graph.edge(node["id"], target, "HAS_DCN_CONFIGURATION", source)
    else:
        schemas = {
            "DescribeBackupConfig": (
                (
                    "StartTimeMin",
                    "StartTimeMax",
                    "BackupMethod",
                    "EnableBackupPeriodSave",
                    "StartBackupPeriodSaveDate",
                    "EnableBackupArchive",
                    "EnableBinlogArchive",
                    "EnableBackupStandby",
                    "EnableBinlogStandby",
                ),
                (),
                (
                    "BackupExpireDays",
                    "BinlogExpireDays",
                    "BackupPeriodSaveDays",
                    "BackupPeriodSaveInterval",
                    "BackupPeriodSaveCount",
                    "BackupArchiveDays",
                    "BinlogArchiveDays",
                    "BackupStandbyDays",
                    "BinlogStandbyDays",
                ),
            ),
            "DescribeRemoteBackupConfig": (
                ("RemoteBackupSave", "RemoteBinlogSave"),
                (),
                ("ExpireDays",),
            ),
            "DescribeDBInstanceConfig": (("Zone",), ("Switched",), ("ProtectMode", "DeployMode")),
            "DescribeDBInstanceHAConfig": (
                ("SyncMode",),
                (),
                (
                    "MaxStandbyLatency",
                    "MaxStandbyLag",
                    "MaxSyncStandbyLatency",
                    "MaxSyncStandbyLag",
                ),
            ),
            "DescribeLogFileRetentionPeriod": ((), (), ("Days",)),
            "DescribeDBInstancesAttribute": (
                ("RegularBackupEnable", "RegularBackupStrategy", "RegularBackupStartTime"),
                (),
                (
                    "RegularBackupSaveDays",
                    "RegularBackupCounts",
                    "BlockedThreshold",
                    "EventSaveDays",
                ),
            ),
        }
        props = fields(data, *schemas[action])
        if action == "DescribeRemoteBackupConfig":
            for key in ("RemoteRegion", "RegionList"):
                if data.get(key) is not None:
                    if not isinstance(data[key], list) or not all(
                        isinstance(r, str) and re.fullmatch(r"[a-z]+-[a-z0-9-]+", r)
                        for r in data[key]
                    ):
                        raise CollectionError("InvalidDatabaseBackupRegion")
                    props[key] = data[key]
        if action == "DescribeDBInstancesAttribute":
            for key, strings, numbers in (
                ("TDEConfig", ("Encryption", "CertificateAttribution", "QuoteUin"), ()),
                ("SSLConfig", ("Encryption", "SSLValidityPeriod"), ("SSLValidity",)),
                (
                    "DrReadableInfo",
                    ("SlaveStatus", "ReadableStatus", "Vip", "UniqVpcId", "UniqSubnetId"),
                    ("VPort",),
                ),
            ):
                if data.get(key) is not None:
                    props[key] = network(fields(data[key], strings, integers=numbers))
            if data.get("OldVipList") is not None:
                props["historical_addresses"] = [
                    network(fields(r, ("Vip", "RecycleTime"), integers=("OldIpRetainTime",)))
                    for r in batch(data, "OldVipList")
                ]
        if action == "DescribeDBInstanceConfig":
            for key in ("SlaveConfig", "BackupConfig", "FourthConfig"):
                if data.get(key) is not None:
                    props[key] = network(
                        fields(data[key], ("ReplicationMode", "Zone", "Vip"), integers=("Vport",))
                    )
        if action == "DescribeBackupConfig" and data.get("BackupTimeWindow") is not None:
            window = data["BackupTimeWindow"]
            if not isinstance(window, dict):
                raise CollectionError("InvalidDatabaseBackupPlan")
            props["BackupTimeWindow"] = fields(
                window,
                (
                    "Monday",
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday",
                    "Sunday",
                    "BackupPeriodStrategy",
                    "BackupPeriodTime",
                ),
            )
            if window.get("Days") is not None:
                if not isinstance(window["Days"], list) or not all(
                    type(v) is int and 1 <= v <= 31 for v in window["Days"]
                ):
                    raise CollectionError("InvalidDatabaseBackupPlan")
                props["BackupTimeWindow"]["Days"] = window["Days"]
        if not props:
            raise CollectionError("MissingDatabaseConfiguration")
        node["properties"][action] = json.dumps(props, sort_keys=True)


ACTIONS = {
    "cdb": (
        "DescribeBackupConfig",
        "DescribeRemoteBackupConfig",
        "DescribeDBInstanceConfig",
        "DescribeCdbProxyInfo",
        "DescribeRoGroups",
    ),
    "postgres": ("DescribeBackupPlans", "DescribeDBInstanceHAConfig"),
    "sqlserver": ("DescribeDBSecurityGroups", "DescribeDBInstancesAttribute"),
    "mariadb": ("DescribeDBSecurityGroups", "DescribeLogFileRetentionPeriod", "DescribeDcnDetail"),
}


def collect(runner, node, service):
    if service == "postgres":
        postgres_parameters(runner, node)
        postgres_groups(runner, node)
        postgres_backups(runner, node)
    for action in ACTIONS.get(service, ()):

        def operation(record, action=action):
            params = {
                "DBInstanceId" if service == "postgres" else "InstanceId": node["resource_id"]
            }
            if service == "mariadb" and action == "DescribeDBSecurityGroups":
                params["Product"] = "mariadb"
            data = runner.transport.call(service, action, node["region"], **params)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            apply(runner.graph, node, service, action, data)
            record["count"] = 1

        runner.scope(service, action, node["region"], operation, node["resource_id"])


# Fixed server-side parameter selection: never request the unrestricted value list.
PG_PARAMETERS = frozenset(
    (
        "max_connections",
        "shared_buffers",
        "work_mem",
        "maintenance_work_mem",
        "statement_timeout",
        "idle_in_transaction_session_timeout",
        "wal_level",
        "max_wal_senders",
        "synchronous_commit",
        "log_statement",
        "log_min_duration_statement",
        "ssl",
    )
)


def postgres_parameters(runner, node):
    for name in sorted(PG_PARAMETERS):

        def operation(record, name=name):
            data = runner.transport.call(
                "postgres",
                "DescribeDBInstanceParameters",
                node["region"],
                DBInstanceId=node["resource_id"],
                ParamName=name,
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            values = batch(data, "Detail", "TotalCount")
            if len(values) > 1 or any(r.get("Name") != name for r in values):
                raise CollectionError("DatabaseParameterScopeMismatch")
            if not values:
                node["properties"].setdefault("unavailable_parameters", []).append(name)
                return
            p = fields(
                values[0],
                (
                    "Name",
                    "ParamValueType",
                    "Unit",
                    "DefaultValue",
                    "CurrentValue",
                    "LastModifyTime",
                ),
                ("NeedReboot", "Advanced", "SpecRelated"),
                ("ID", "StandbyRelated"),
            )
            if p.get("ParamValueType") not in (
                "integer",
                "real",
                "bool",
                "enum",
                "mutil_enum",
            ) or not isinstance(p.get("CurrentValue"), str):
                raise CollectionError("UnsupportedDatabaseParameterType")
            for key in ("Max", "Min"):
                if type(values[0].get(key)) in (int, float):
                    import math

                    if not math.isfinite(values[0][key]):
                        raise CollectionError("InvalidDatabaseParameterRange")
                    p[key] = values[0][key]
            if values[0].get("EnumValue") is not None:
                vals = values[0]["EnumValue"]
                if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals):
                    raise CollectionError("InvalidDatabaseParameterEnum")
                p["EnumValue"] = vals
            add(
                runner.graph,
                node,
                "postgres.parameter",
                name,
                p,
                "postgres.DescribeDBInstanceParameters",
                "HAS_PARAMETER",
            )
            record["count"] = 1

        runner.scope(
            "postgres",
            "DescribeDBInstanceParameters",
            node["region"],
            operation,
            node["resource_id"] + "/" + name,
        )


def postgres_groups(runner, node):
    def operation(record):
        seen = set()
        for page in range(1, 10001):
            data = runner.transport.call(
                "postgres",
                "DescribeReadOnlyGroups",
                node["region"],
                Filters=[dict(Name="db-master-instance-id", Values=[node["resource_id"]])],
                PageSize=99,
                PageNumber=page,
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            prepared = []
            for row in batch(data, "ReadOnlyGroupList"):
                p = fields(
                    row,
                    (
                        "ReadOnlyGroupId",
                        "ReadOnlyGroupName",
                        "MasterDBInstanceId",
                        "Region",
                        "Zone",
                        "Status",
                        "VpcId",
                        "SubnetId",
                    ),
                    integers=(
                        "MinDelayEliminateReserve",
                        "ReplayLatencyEliminate",
                        "ReplayLagEliminate",
                        "Rebalance",
                    ),
                )
                rid = identity(p.get("ReadOnlyGroupId"))
                if p.get("MasterDBInstanceId") != node["resource_id"] or p.get("Region") not in (
                    None,
                    node["region"],
                ):
                    raise CollectionError("DatabaseReplicaMismatch")
                members = [
                    identity(r.get("DBInstanceId")) for r in batch(row, "ReadOnlyDBInstanceList")
                ]
                if len(set(members)) != len(members):
                    raise CollectionError("DuplicateDatabaseConfiguration")
                for key, alias in (("VpcId", "UniqVpcId"), ("SubnetId", "UniqSubnetId")):
                    if p.get(key):
                        p[alias] = p[key]
                network(p)
                prepared.append((rid, p, members))
            ids = [r for r, _, _ in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids) or len(prepared) > 99:
                raise CollectionError("DuplicateDatabaseConfiguration")
            seen.update(ids)
            for rid, p, members in prepared:
                group = add(
                    runner.graph,
                    node,
                    "postgres.rogroup",
                    rid,
                    p,
                    "postgres.DescribeReadOnlyGroups",
                    "HAS_READ_ONLY_GROUP",
                )
                for value in members:
                    target = runner.graph.add(
                        node["account"],
                        node["region"],
                        "postgres.dbinstanceid",
                        value,
                        status="reference",
                        source="postgres.DescribeReadOnlyGroups",
                    )
                    runner.graph.edge(
                        group["id"],
                        target,
                        "HAS_READ_ONLY_MEMBER",
                        "postgres.DescribeReadOnlyGroups",
                    )
                record["count"] += 1
            if len(prepared) < 99:
                return
        raise CollectionError("DatabasePageLimit")

    runner.scope(
        "postgres", "DescribeReadOnlyGroups", node["region"], operation, node["resource_id"]
    )


def postgres_backups(runner, node):
    from .catalog import Collector
    from .transport import pages

    for action, result, kind in (
        ("DescribeBaseBackups", "BaseBackupSet", "postgres.basebackup"),
        ("DescribeLogBackups", "LogBackupSet", "postgres.logbackup"),
    ):

        def operation(record, action=action, result=result, kind=kind):
            # Override the API's default seven-day lower bound. The provider's
            # default upper bound is its current time; no download API is called.
            params = dict(
                Filters=[dict(Name="db-instance-id", Values=[node["resource_id"]])],
                MinFinishTime="1970-01-01 00:00:00",
            )
            spec = Collector("postgres", action, result, kind, ("Id",), require_total=True)
            seen = set()
            record["minimum_finish_time"] = params["MinFinishTime"]
            for rows, request in pages(runner.transport, spec, node["region"], params):
                if request:
                    record["request_ids"].append(request)
                prepared = [
                    fields(
                        r,
                        (
                            "Id",
                            "DBInstanceId",
                            "Name",
                            "BackupMethod",
                            "BackupMode",
                            "State",
                            "StartTime",
                            "FinishTime",
                            "ExpireTime",
                        ),
                        integers=("Size",),
                    )
                    for r in rows
                ]
                ids = [identity(p.get("Id")) for p in prepared]
                if any(p.get("DBInstanceId") != node["resource_id"] for p in prepared):
                    raise CollectionError("DatabaseBackupInstanceMismatch")
                if len(set(ids)) != len(ids) or seen.intersection(ids):
                    raise CollectionError("DuplicateDatabaseBackup")
                seen.update(ids)
                for p in prepared:
                    add(
                        runner.graph,
                        node,
                        kind,
                        p["Id"],
                        p,
                        "postgres." + action,
                        "HAS_BACKUP_METADATA",
                    )
                    record["count"] += 1

        runner.scope("postgres", action, node["region"], operation, node["resource_id"])
