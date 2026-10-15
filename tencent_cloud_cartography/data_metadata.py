"""Audited storage/database metadata projections; never acquire data or credentials.

Schemas deliberately enumerate fields. A successful read is configuration evidence,
not a database login, query authorization, POSIX access point or AWS equivalence.
"""

import ipaddress
import json
import re
from dataclasses import dataclass

from .catalog import Collector
from .model import stable_id
from .transport import CollectionError, pages


def schema(strings="", integers="", booleans="", arrays="", **children):
    return dict(
        strings=strings.split(),
        integers=integers.split(),
        booleans=booleans.split(),
        arrays=arrays.split(),
        children=children,
    )


def project(raw, spec):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidDataMetadata")
    result = {}
    for key, typ in (("strings", str), ("integers", int), ("booleans", bool)):
        for field in spec[key]:
            if raw.get(field) is not None:
                value = raw[field]
                if type(value) is not typ or (typ is str and any(ord(c) < 32 for c in value)):
                    raise CollectionError("InvalidDataMetadataField")
                result[field] = value
    for field in spec["arrays"]:
        if raw.get(field) is not None:
            values = raw[field]
            if not isinstance(values, list) or not all(type(v) is str for v in values):
                raise CollectionError("InvalidDataMetadataList")
            if any(any(ord(c) < 32 for c in v) for v in values):
                raise CollectionError("InvalidDataMetadataList")
            result[field] = values
    for field in ("Vip", "Vip6", "IPv6", "NodeIp", "PrivateNetworkIp"):
        if result.get(field):
            try:
                result[field] = str(ipaddress.ip_address(result[field]))
            except ValueError:
                raise CollectionError("InvalidDataMetadataAddress") from None
    for field in ("VPort", "Vport", "WanPort"):
        if field in result and not 0 <= result[field] <= 65535:
            raise CollectionError("InvalidDataMetadataPort")
    for field, prefix in (
        ("VpcId", "vpc"),
        ("UniqVpcId", "vpc"),
        ("SubnetId", "subnet"),
        ("UniqSubnetId", "subnet"),
    ):
        if result.get(field) and not re.fullmatch(prefix + r"-[A-Za-z0-9]+", result[field]):
            raise CollectionError("InvalidDataMetadataNetwork")
    for field, child in spec["children"].items():
        if raw.get(field) is not None:
            value = raw[field]
            if isinstance(child, list):
                if not isinstance(value, list):
                    raise CollectionError("InvalidDataMetadataList")
                result[field] = [project(row, child[0]) for row in value]
            else:
                result[field] = project(value, child)
    return result


def properties(selected):
    return {
        k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v
        for k, v in selected.items()
    }


def emit(
    graph,
    account,
    region,
    kind,
    rid,
    selected,
    source,
    parent=None,
    relationship="HAS_CONFIGURATION",
):
    nid = graph.add(
        account,
        region,
        kind,
        rid,
        selected.get("SnapshotName")
        or selected.get("PolicyName")
        or selected.get("LifecyclePolicyName")
        or rid,
        source=source,
    )
    node = graph.nodes[nid]
    node["properties"].update(properties(selected), metadata_only=True)
    if selected.get("Zone"):
        node["properties"]["zone"] = selected["Zone"]
    if parent:
        graph.edge(parent["id"], nid, relationship, source)
    for keys, kind, relation in (
        (("VpcId", "UniqVpcId"), "vpc.vpc", "IN_VPC"),
        (("SubnetId", "UniqSubnetId"), "vpc.subnet", "IN_SUBNET"),
    ):
        values = {selected[key] for key in keys if selected.get(key)}
        if len(values) == 1:
            target = graph.add(
                account, region, kind, values.pop(), source=source, status="reference"
            )
            graph.edge(nid, target, relation, source)
    return node


ADDRESS = schema("ResourceId UniqVpcId UniqSubnetId Vip WanDomain", "VPort WanPort")
CLUSTER_NODE = schema("NodeId Role Zone Status", "Weight")
PG_NODE = schema("ProxyNodeId Zone Status", "Cpu Mem Connection")
PG_ROUTE = schema("NodeId Role Status", "Weight")
PG_ADDRESS = schema(
    "AddressId Vip VpcId SubnetId Description WeightMode",
    "Vport ConnectionPoolLimit LatencyRemoveTime MinRouteNum LoadBalancePolicy",
    "ConnectionPool RwSplitEnable RoAutoAdd LatencyRemove FailOver",
    Routes=[PG_ROUTE],
)
BACKUP_POLICY = schema(
    "BeginDate Frequency", "MaxRetentionDays BackupCount", "EnableBackupPolicy", "WeekDays"
)
REDIS_MEMBER = schema(
    "InstanceId InstanceName Engine Role Vip Vip6 IPv6 CreateTime UpdateTime",
    "AppId RegionId ZoneId RedisReplicasNum RedisShardNum RedisShardSize DiskSize VpcID VPort Status ProductType",
)
CFS_MEMBER = schema(
    "CreationToken FileSystemId StorageType CreationTime", "SizeByte TotalSnapshotSize ZoneId"
)
LIFECYCLE_RULE = schema(
    "StorageType FileType Action Interval FileMaxSize FileMinSize PolicyType",
    "ExpireThreshold TargetThreshold",
    "IsOverwrite IsCreateRealTimeSync IsModifyRealTimeSync IsSyncDelete",
)
LIFECYCLE_PATH = schema("FileSystemId Path DataFlowId")
ES_BACKUP = schema(
    "BackupTime SnapshotName PaasEsRepository UserEsRepository CosBasePath RetainUntilDate RemoteCosRegion StrategyName Indices MaxSnapshotPerSec MaxRestorePerSec CreateTime InstanceId",
    "EsRepositoryType StorageDuration AutoBackupInterval CosRetention RetentionGraceTime RemoteCos MultiAz",
    "IsAutoBackup",
)


@dataclass(frozen=True)
class Read:
    service: str
    action: str
    kind: str
    spec: dict
    result: str | None = None
    ids: tuple = ()
    total: str | None = None
    paging: str = "none"
    parent: str | None = None
    argument: str = "InstanceId"
    children: tuple = ()


READS = (
    Read(
        "cdb",
        "DescribeClusterInfo",
        "cdb.clusterconfiguration",
        schema(
            "ClusterName",
            "ReadonlyLimit NodeCount",
            ReadWriteAddress=ADDRESS,
            ReadOnlyAddress=[ADDRESS],
            NodeList=[CLUSTER_NODE],
        ),
        parent="cdb.instance",
        children=(
            ("NodeList", "cdb.clusternode", "NodeId", "HAS_CLUSTER_NODE"),
            ("ReadOnlyAddress", "cdb.clusteraddress", "ResourceId", "HAS_READ_ONLY_ADDRESS"),
        ),
    ),
    Read(
        "cdb",
        "DescribeBackupEncryptionStatus",
        "cdb.backupencryption",
        schema("EncryptionStatus"),
        parent="cdb.instance",
    ),
    Read(
        "cdb",
        "DescribeBackupSummaries",
        "cdb.backupsummary",
        schema(
            "InstanceId",
            "AutoBackupCount AutoBackupVolume ManualBackupCount ManualBackupVolume DataBackupCount DataBackupVolume BinlogBackupCount BinlogBackupVolume BackupVolume",
        ),
        "Items",
        ("InstanceId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "postgres",
        "DescribeDBProxy",
        "postgres.proxygroup",
        schema(
            "ProxyGroupId Status TaskStatus Description ProxyVersion CreateTime",
            "ConnectionPoolLimit",
            ProxyNodeSet=[PG_NODE],
            ProxyAddressSet=[PG_ADDRESS],
        ),
        "ProxyInfos",
        ("ProxyGroupId",),
        "Count",
        parent="postgres.dbinstanceid",
        argument="DBInstanceId",
        children=(
            ("ProxyNodeSet", "postgres.proxynode", "ProxyNodeId", "HAS_PROXY_NODE"),
            ("ProxyAddressSet", "postgres.proxyaddress", "AddressId", "HAS_PROXY_ADDRESS"),
        ),
    ),
    Read(
        "sqlserver",
        "DescribeInstanceParams",
        "sqlserver.parameter",
        schema(
            "Name ParamType Default CurrentValue", "NeedReboot Max Min Status", arrays="EnumValue"
        ),
        "Items",
        ("Name",),
        "TotalCount",
        parent="sqlserver.instance",
    ),
    Read(
        "sqlserver",
        "DescribeBackupSummary",
        "sqlserver.backupsummary",
        schema(
            integers="FreeSpace ActualUsedSpace BackupFilesTotal BillingSpace DataBackupSpace DataBackupCount ManualBackupSpace ManualBackupCount AutoBackupSpace AutoBackupCount LogBackupSpace LogBackupCount LocalBackupFilesTotal CrossBackupFilesTotal CrossBillingSpace CrossAutoBackupSpace CrossAutoBackupCount LocalLogBackupSpace LocalLogBackupCount CrossLogBackupSpace CrossLogBackupCount"
        ),
    ),
    Read(
        "mariadb",
        "DescribeBackupConfigs",
        "mariadb.backupconfiguration",
        schema(
            "InstanceId StartBackupTime EndBackupTime",
            "Days ArchiveDays",
            arrays="WeekDays",
            BackupConfigSet=[BACKUP_POLICY],
        ),
        parent="mariadb.instance",
    ),
    Read(
        "redis",
        "DescribeReplicationGroup",
        "redis.replicationgroup",
        schema(
            "GroupId GroupName Remark",
            "AppId RegionId Status InstanceCount",
            Instances=[REDIS_MEMBER],
        ),
        "Groups",
        ("GroupId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "redis",
        "DescribeReplicationGroupInstance",
        "redis.replicationmembership",
        schema("GroupId GroupName InstanceRole", "AppId RegionId"),
        parent="redis.instance",
    ),
    Read(
        "redis",
        "DescribeAutoBackupConfig",
        "redis.backupconfiguration",
        schema(
            "TimePeriod", "AutoBackupType BackupStorageDays BinlogStorageDays", arrays="WeekDays"
        ),
        parent="redis.instance",
    ),
    Read(
        "redis",
        "DescribeInstanceBackups",
        "redis.backup",
        schema(
            "StartTime BackupId BackupType Remark InstanceId InstanceName Region EndTime FileType ExpireTime",
            "Status Locked BackupSize FullBackup InstanceType",
            "Encrypted",
        ),
        "BackupSet",
        ("BackupId",),
        "TotalCount",
        "offset",
        parent="redis.instance",
    ),
    Read(
        "redis",
        "DescribeInstancePasswordPolicy",
        "redis.passwordpolicy",
        schema(
            PasswordPolicy=schema(
                integers="MinLetterCount MinDigitCount MinSpecialCount MinLength",
                booleans="Enabled",
            )
        ),
        parent="redis.instance",
    ),
    Read(
        "cdwpg",
        "DescribeAccounts",
        "cdwpg.databaseaccount",
        schema("InstanceId UserName", arrays="Perms"),
        "Accounts",
        ("UserName",),
        "TotalCount",
        "offset",
        parent="cdwpg.instance",
    ),
    Read(
        "cdwpg",
        "DescribeUserHbaConfig",
        "cdwpg.hbarule",
        schema("Type Database User Address Method Mask"),
        "HbaConfigs",
        total="TotalCount",
        parent="cdwpg.instance",
    ),
    Read(
        "cdwpg",
        "DescribeInstanceNodes",
        "cdwpg.node",
        schema(
            "NodeType NodeIp PrivateNetworkIp NodeRole NodeName SpecName DataDiskType UUID Zone",
            "NodeId Cpu Memory DataDiskCount DataDiskSize",
        ),
        "InstanceNodes",
        ("NodeId",),
        parent="cdwpg.instance",
    ),
    Read(
        "cfs",
        "DescribeAutoSnapshotPolicies",
        "cfs.snapshotpolicy",
        schema(
            "AutoSnapshotPolicyId PolicyName CreationTime DayOfWeek Hour NextActiveTime Status RegionName DayOfMonth",
            "FileSystemNums IsActivated AppId AliveDays IntervalDays CrossRegionsAliveDays",
            FileSystems=[CFS_MEMBER],
        ),
        "AutoSnapshotPolicies",
        ("AutoSnapshotPolicyId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "cfs",
        "DescribeCfsSnapshots",
        "cfs.snapshot",
        schema(
            "CreationTime SnapshotName SnapshotId Status RegionName FileSystemId DeleteTime FsName SnapshotType SnapshotTime",
            "Size AliveDay Percent AppId",
        ),
        "Snapshots",
        ("SnapshotId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "cfs",
        "DescribeLifecyclePolicies",
        "cfs.lifecyclepolicy",
        schema(
            "CreateTime LifecyclePolicyID LifecyclePolicyName",
            LifecycleRules=[LIFECYCLE_RULE],
            Paths=[LIFECYCLE_PATH],
        ),
        "LifecyclePolicies",
        ("LifecyclePolicyID",),
        "TotalCount",
        "number-page",
    ),
    Read(
        "es",
        "DescribeRequestInstancePolicy",
        "es.requestpolicy",
        schema("UpdateTime Operator", booleans="IsDefault", arrays="GetPaths PostPaths PutPaths"),
        parent="es.instance",
    ),
    Read(
        "es",
        "DescribeCosBackupStrategyViews",
        "es.backupconfiguration",
        ES_BACKUP,
        "CosBackupList",
        parent="es.instance",
    ),
    Read(
        "es",
        "DescribeSnapshotViews",
        "es.snapshot",
        schema(
            "InstanceId Uuid SnapshotName Repository Version State StartTime EndTime UserBackUp PaasEsRepository UserEsRepository RetainUntilDate RemoteCosRegion KmsKey StrategyName MaxSnapshotPerSec",
            "DurationInMillis TotalShards FailedShards SuccessfulShards EsRepositoryType StorageDuration CosRetention RetentionGraceTime IsLocked RemoteCos CosEncryption MultiAz",
            arrays="Indices DataStreams",
        ),
        "Snapshots",
        ("Uuid",),
        parent="es.instance",
    ),
    Read(
        "tcaplusdb",
        "DescribeBackupRecords",
        "tcaplusdb.backup",
        schema(
            "TableName BackupType FileTag BackupBatchTime BackupSuccRate BackupExpireTime",
            "ZoneId ShardCount BackupFileSize AppId",
        ),
        "BackupRecords",
        ("ZoneId", "TableName", "BackupBatchTime", "FileTag"),
        "TotalCount",
        "offset",
        parent="tcaplusdb.cluster",
        argument="ClusterId",
    ),
    Read(
        "tcaplusdb",
        "DescribeSnapshots",
        "tcaplusdb.snapshot",
        schema(
            "TableGroupId TableName TaskId SnapshotName SnapshotTime SnapshotDeadTime SnapshotCreateTime ApplicationId",
            "SnapshotSize SnapshotStatus",
        ),
        "TableResults",
        ("TableGroupId", "TableName", "SnapshotName"),
        "TotalCount",
        parent="tcaplusdb.cluster",
        argument="ClusterId",
    ),
    Read(
        "cdb",
        "DescribeBackupDownloadRestriction",
        "cdb.backupdownloadrestriction",
        schema(
            "LimitType VpcComparisonSymbol IpComparisonSymbol",
            arrays="LimitIp",
            LimitVpc=[schema("Region", arrays="VpcList")],
        ),
        parent="cdb.instance",
    ),
    Read(
        "cdb",
        "DescribeLocalBinlogConfig",
        "cdb.binlogconfiguration",
        schema(
            LocalBinlogConfig=schema(integers="SaveHours MaxUsage"),
            LocalBinlogConfigDefault=schema(integers="SaveHours MaxUsage"),
        ),
        parent="cdb.instance",
    ),
    Read(
        "postgres",
        "DescribeDBProxySSLConfig",
        "postgres.proxysslconfiguration",
        schema("ConnectAddress", booleans="SSLEnabled"),
        parent="postgres.proxyaddress",
        argument="ProxyAddressId",
    ),
    Read(
        "sqlserver",
        "DescribeReadOnlyGroupList",
        "sqlserver.readonlygroup",
        schema(
            "ReadOnlyGroupId ReadOnlyGroupName RegionId ZoneId Vip VpcId SubnetId MasterInstanceId DnsPodDomain",
            "IsOfflineDelay ReadOnlyMaxDelayTime MinReadOnlyInGroup Vport Status TgwWanVPort ReadOnlyGroupType ReadOnlyGroupForcedUpgrade",
            ReadOnlyInstanceSet=[
                schema(
                    "InstanceId Name Uid CreateTime UpdateTime Version Type DelayTime SynStatus DatabaseDifference AccountDifference StartTime EndTime IsolateTime RegionId ZoneId",
                    "ProjectId Status Memory Storage Cpu Model PayMode Weight",
                )
            ],
        ),
        "ReadOnlyGroupSet",
        ("ReadOnlyGroupId",),
        parent="sqlserver.instance",
    ),
    Read(
        "dlc",
        "DescribeDLCCatalogAccess",
        "dlc.catalogaccess",
        schema("VpcId Product Description CreateTime"),
        "Rows",
        ("VpcId", "Product"),
        "TotalCount",
        "offset",
    ),
    Read(
        "dlc",
        "DescribeThirdPartyAccessUser",
        "dlc.thirdpartyaccessuser",
        schema(UserInfo=schema("Uin AppId CreateTime", "Id")),
    ),
)
ACTIONS = {(r.service, r.action) for r in READS} | {
    ("redis", "DescribeInstanceParams"),
    ("dlc", "DescribeSubUserAccessPolicy"),
    ("ssm", "DescribeRotationHistory"),
}
KINDS = (
    {r.kind for r in READS}
    | {c[1] for r in READS for c in r.children}
    | {
        "redis.parameter",
        "dlc.subuseraccesspolicy",
        "ssm.rotationaccount",
        "ssm.rotationhistory",
        "tcaplusdb.tablereference",
    }
)


def key_for(row, fields):
    values = [row.get(k) for k in fields]
    if not values:
        return stable_id(json.dumps(row, sort_keys=True))
    if any(type(v) not in (str, int) or v == "" or (type(v) is int and v < 0) for v in values):
        raise CollectionError("MissingDataMetadataIdentity")
    return str(values[0]) if len(values) == 1 else stable_id(*map(str, values))


def prepare(read, raw, parent):
    selected = project(raw, read.spec)
    if parent:
        for key in ("InstanceId", "InstanceID", "DBInstanceId", "ClusterId", "MasterInstanceId"):
            if raw.get(key) not in (None, parent["resource_id"]):
                raise CollectionError("DataMetadataIdentityMismatch")
    if raw.get("Error") is not None and (
        not isinstance(raw["Error"], dict) or raw["Error"].get("Code") not in (None, "", 0)
    ):
        raise CollectionError("DataMetadataItemError")
    if read.kind == "es.requestpolicy":
        # Only request path patterns; never retain query strings or credentials.
        for key in ("GetPaths", "PostPaths", "PutPaths"):
            if any(not p.startswith("/") or "?" in p or "#" in p for p in selected.get(key, [])):
                raise CollectionError("InvalidElasticsearchRequestPath")
    for field, _, idfield, _ in read.children:
        children = selected.get(field, [])
        keys = [key_for(c, (idfield,)) for c in children]
        if len(set(keys)) != len(keys):
            raise CollectionError("DuplicateDataMetadata")
    if read.action == "DescribeClusterInfo":
        if "NodeCount" in selected and selected["NodeCount"] != len(selected.get("NodeList", [])):
            raise CollectionError("DataMetadataCountMismatch")
        if selected.get("ReadWriteAddress"):
            key_for(selected["ReadWriteAddress"], ("ResourceId",))
    if not selected:
        raise CollectionError("MissingDataMetadata")
    return key_for(selected, read.ids) if read.result else "configuration", selected


def save(runner, read, region, rid, selected, parent):
    source = read.service + "." + read.action
    identity = stable_id(parent["resource_id"], rid) if parent else rid
    node = emit(
        runner.graph,
        runner.account,
        region,
        read.kind,
        identity,
        selected,
        source,
        parent,
        "HAS_METADATA",
    )
    if parent:
        node["properties"]["parent_resource_id"] = parent["resource_id"]
    for field, kind, idfield, relation in read.children:
        for child in selected.get(field, []):
            if read.action == "DescribeDBProxy":
                child = {
                    **child,
                    "DBInstanceId": parent["resource_id"],
                    "ProxyGroupId": selected["ProxyGroupId"],
                }
            emit(
                runner.graph,
                runner.account,
                region,
                kind,
                stable_id(identity, str(child[idfield])),
                child,
                source,
                node,
                relation,
            )
    if selected.get("ReadWriteAddress"):
        address = selected["ReadWriteAddress"]
        emit(
            runner.graph,
            runner.account,
            region,
            "cdb.clusteraddress",
            stable_id(identity, address["ResourceId"]),
            address,
            source,
            node,
            "HAS_READ_WRITE_ADDRESS",
        )
    return node


def collect_read(runner, read, region, parent=None, product=None):
    def operation(record):
        params = {read.argument: parent["resource_id"]} if parent else {}
        if read.action == "DescribeDBProxySSLConfig":
            params = {
                "ProxyAddressId": parent["properties"]["AddressId"],
                "DBInstanceId": parent["properties"]["DBInstanceId"],
                "ProxyGroupId": parent["properties"]["ProxyGroupId"],
            }
        if read.service == "es" and read.argument in params and read.result:
            params[read.argument] = [params[read.argument]]
        if read.action == "DescribeSnapshotViews":
            params.update(Duration=0, UserBackUp="")
            record["time_scope"] = "all_provider_snapshot_times"
        if read.action == "DescribeInstanceBackups":
            params["Status"] = [1, 2]
            record["time_scope"] = "provider_default_backup_window"
            record["all_historical_backups_verified"] = False
        if read.action == "DescribeBackupSummaries":
            params["Product"] = product or "mysql"
        seen = set()
        if read.paging == "none":
            data = runner.transport.call(read.service, read.action, region, **params)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            if data.get("ErrorMsg") or data.get("FailedMsgs"):
                raise CollectionError("DataMetadataProviderFailure")
            rawrows = data.get(read.result) if read.result else [data]
            if not isinstance(rawrows, list) or (
                read.total
                and (type(data.get(read.total)) is not int or data[read.total] != len(rawrows))
            ):
                raise CollectionError("DataMetadataCountMismatch")
            batches = [(rawrows, None)]
        else:
            spec = Collector(
                read.service,
                read.action,
                read.result,
                read.kind,
                read.ids,
                total=read.total,
                paging=read.paging,
                require_total=True,
            )
            batches = pages(runner.transport, spec, region, params)
        for rawrows, request_id in batches:
            if request_id:
                record["request_ids"].append(request_id)
            prepared = [prepare(read, raw, parent) for raw in rawrows]
            if read.kind == "cdwpg.hbarule":
                prepared = [
                    (str(i), {**selected, "rule_order": i})
                    for i, (_, selected) in enumerate(prepared)
                ]
            ids = [rid for rid, _ in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateDataMetadata")
            seen.update(ids)
            for rid, selected in prepared:
                if product:
                    selected["Product"] = product
                    rid = stable_id(product, rid)
                save(runner, read, region, rid, selected, parent)
                record["count"] += 1

    runner.scope(
        read.service,
        read.action,
        region,
        operation,
        parent["resource_id"] if parent else product or "",
    )


def link(graph):
    """Rebuild only exact, same-owner metadata relationships, also after import."""
    source = "analysis.data-metadata-links"
    stale = {i for i, n in graph.nodes.items() if n["kind"] == "tcaplusdb.tablereference"}
    graph.nodes = {i: n for i, n in graph.nodes.items() if i not in stale}
    graph.edges = {
        i: e
        for i, e in graph.edges.items()
        if e.get("provenance") != source and e["source"] not in stale and e["target"] not in stale
    }
    index = {
        (n["account"], n["region"], n["kind"], n["resource_id"]): n for n in graph.nodes.values()
    }

    def reference(node, kind, rid, relation, allow_reference=False):
        if not rid:
            return
        target = index.get((node["account"], node["region"], kind, rid))
        if not target and allow_reference:
            nid = graph.add(
                node["account"], node["region"], kind, rid, source=source, status="reference"
            )
            target = graph.nodes[nid]
            index[(node["account"], node["region"], kind, rid)] = target
        if target:
            graph.edge(node["id"], target["id"], relation, source)

    for node in list(graph.nodes.values()):
        p, kind = node["properties"], node["kind"]
        if kind in {"cfs.snapshot", "cfs.snapshotpolicy", "cfs.lifecyclepolicy"}:
            refs = (
                [dict(FileSystemId=p.get("FileSystemId"))]
                if kind == "cfs.snapshot"
                else json.loads(
                    p.get("Paths" if kind == "cfs.lifecyclepolicy" else "FileSystems", "[]")
                )
            )
            for ref in refs:
                reference(
                    node,
                    "cfs.filesystem",
                    ref.get("FileSystemId"),
                    "CONFIGURED_FOR_FILESYSTEM",
                    allow_reference=True,
                )
        if kind in {"cdb.backupsummary"}:
            reference(
                node,
                "cdb.instance",
                p.get("InstanceId"),
                "SUMMARIZES_BACKUPS_FOR",
                allow_reference=True,
            )
        if kind == "redis.replicationmembership" and p.get("GroupId"):
            reference(node, "redis.replicationgroup", p["GroupId"], "CONFIGURED_REPLICATION_GROUP")
        if kind == "postgres.proxyaddress":
            reference(node, "vpc.vpc", p.get("VpcId"), "IN_VPC")
            reference(node, "vpc.subnet", p.get("SubnetId"), "IN_SUBNET")
        if kind == "tcaplusdb.snapshot" and p.get("TableGroupId") and p.get("TableName"):
            table = emit(
                graph,
                node["account"],
                node["region"],
                "tcaplusdb.tablereference",
                stable_id(p["parent_resource_id"], p["TableGroupId"], p["TableName"]),
                dict(
                    ClusterId=p["parent_resource_id"],
                    TableGroupId=p["TableGroupId"],
                    TableName=p["TableName"],
                    table_inventory_complete=False,
                ),
                source,
            )
            table["status"] = "reference"
            graph.edge(node["id"], table["id"], "SNAPSHOT_OF_TABLE", source)


# The parameter API has no per-name filter. Its documented response is configuration
# metadata, not AUTH/ACL secret values. Retain only these known settings; unknown
# names and text fields never become graph properties or permission grants.
REDIS_PARAMETERS = frozenset(
    "maxmemory-policy maxmemory-samples timeout tcp-keepalive notify-keyspace-events hz slowlog-log-slower-than slowlog-max-len latency-monitor-threshold repl-backlog-size repl-timeout cluster-node-timeout databases lua-time-limit replica-read-only slave-read-only zset-max-ziplist-entries zset-max-ziplist-value hash-max-ziplist-entries hash-max-ziplist-value set-max-intset-entries proto-max-bulk-len client-query-buffer-limit".split()
)


def redis_parameters(runner, parent):
    def operation(record):
        data = runner.transport.call(
            "redis", "DescribeInstanceParams", parent["region"], InstanceId=parent["resource_id"]
        )
        rows = []
        for key in (
            "InstanceEnumParam",
            "InstanceIntegerParam",
            "InstanceTextParam",
            "InstanceMultiParam",
        ):
            values = data.get(key)
            if not isinstance(values, list) or not all(isinstance(v, dict) for v in values):
                raise CollectionError("InvalidRedisParameters")
            rows.extend(values)
        if type(data.get("TotalCount")) is not int or data["TotalCount"] != len(rows):
            raise CollectionError("DataMetadataCountMismatch")
        names = [r.get("ParamName") for r in rows]
        if any(not isinstance(n, str) or not n for n in names) or len(set(names)) != len(names):
            raise CollectionError("DuplicateDataMetadata")
        selected = [
            project(
                r,
                schema(
                    "ParamName ValueType NeedRestart DefaultValue CurrentValue Min Max Unit",
                    "Status",
                    arrays="EnumValue TextValue",
                ),
            )
            for r in rows
            if r["ParamName"] in REDIS_PARAMETERS
        ]
        for p in selected:
            emit(
                runner.graph,
                runner.account,
                parent["region"],
                "redis.parameter",
                stable_id(parent["resource_id"], p["ParamName"]),
                p,
                "redis.DescribeInstanceParams",
                parent,
                "HAS_PARAMETER",
            )
        record["count"] = len(selected)
        record["excluded_parameter_count"] = len(rows) - len(selected)
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])

    runner.scope(
        "redis", "DescribeInstanceParams", parent["region"], operation, parent["resource_id"]
    )


def dlc_policy(runner, region):
    from .cam import parse_document

    def operation(record):
        data = runner.transport.call("dlc", "DescribeSubUserAccessPolicy", region)
        document = parse_document(data.get("PolicyDocument"))
        emit(
            runner.graph,
            runner.account,
            region,
            "dlc.subuseraccesspolicy",
            "current-platform-subuser",
            dict(
                policy_document=json.dumps(document, sort_keys=True),
                evaluation_scope="current_third_party_platform_subuser",
                query_access_verified=False,
            ),
            "dlc.DescribeSubUserAccessPolicy",
        )
        record["count"] = 1
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])

    runner.scope("dlc", "DescribeSubUserAccessPolicy", region, operation)


def collect(runner, services=None):
    for read in READS:
        if services and read.service not in services:
            continue
        for region in runner.regions_for(read.service):
            parents = [
                n
                for n in list(runner.graph.nodes.values())
                if n["account"] == runner.account
                and n["region"] == region
                and n["kind"] == read.parent
                and (n["status"] == "enriched" or read.parent == "tcaplusdb.cluster")
            ]
            for parent in parents if read.parent else [None]:
                if read.parent == "tcaplusdb.cluster" and not parent["resource_id"].isdigit():
                    continue
                for product in (
                    ("mysql", "mysql-basic", "mysql-cluster")
                    if read.action == "DescribeBackupSummaries"
                    else [None]
                ):
                    collect_read(runner, read, region, parent, product)
    if not services or "redis" in services:
        for node in list(runner.graph.nodes.values()):
            if (
                node["kind"] == "redis.instance"
                and node["account"] == runner.account
                and node["status"] == "enriched"
                and node["region"] in runner.regions_for("redis")
            ):
                redis_parameters(runner, node)
    if not services or "dlc" in services:
        for region in runner.regions_for("dlc"):
            dlc_policy(runner, region)
            from .dlc_authorization_metadata import collect as collect_dlc_authorization

            collect_dlc_authorization(runner, region)
    if not services or "ssm" in services:
        for node in list(runner.graph.nodes.values()):
            if (
                node["kind"] == "ssm.secret"
                and node["account"] == runner.account
                and node["status"] == "enriched"
                and node["region"] in runner.regions_for("ssm")
            ):
                rotation_history(runner, node)
    link(runner.graph)
    from .dlc_authorization_metadata import link as link_dlc

    link_dlc(runner.graph)


def rotation_history(runner, node):
    def operation(record):
        data = runner.transport.call(
            "ssm", "DescribeRotationHistory", node["region"], SecretName=node["resource_id"]
        )
        selected = project(
            data,
            schema(
                integers="TotalCount",
                arrays="VersionIDs",
                AccountInfoList=[schema("AccountName Version RotatedTime", arrays="Host")],
            ),
        )
        versions = selected.get("VersionIDs")
        total = selected.get("TotalCount")
        if (
            versions is None
            or type(total) is not int
            or total < len(versions)
            or len(versions) > 10
            or len(set(versions)) != len(versions)
            or any(not v for v in versions)
        ):
            raise CollectionError("InvalidRotationHistory")
        accounts = selected.get("AccountInfoList", [])
        ids = [(p.get("AccountName"), tuple(p.get("Host", [])), p.get("Version")) for p in accounts]
        if len(set(ids)) != len(ids) or any(
            not name or not isinstance(state, str) or not state for name, _, state in ids
        ):
            raise CollectionError("InvalidRotationAccount")
        selected.update(
            history_scope="provider_visible_up_to_ten_versions",
            full_history_verified=False,
            historical_kms_verified=False,
            version_stages_verified=False,
        )
        history = emit(
            runner.graph,
            runner.account,
            node["region"],
            "ssm.rotationhistory",
            stable_id(node["resource_id"], "history"),
            selected,
            "ssm.DescribeRotationHistory",
            node,
            "HAS_ROTATION_HISTORY",
        )
        for p in accounts:
            emit(
                runner.graph,
                runner.account,
                node["region"],
                "ssm.rotationaccount",
                stable_id(node["resource_id"], json.dumps(p, sort_keys=True)),
                {**p, "version_semantics": "database_account_state_not_version_id"},
                "ssm.DescribeRotationHistory",
                history,
                "HAS_ROTATION_ACCOUNT",
            )
        record["count"] = 1
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        if total > len(versions):
            raise CollectionError("RotationHistoryTruncated")

    runner.scope("ssm", "DescribeRotationHistory", node["region"], operation, node["resource_id"])
