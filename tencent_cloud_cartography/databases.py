"""Typed database configuration; never execute queries or retrieve credentials."""

import ipaddress
import json
import re

from .transport import CollectionError, pages
from .vpc import fields

STRINGS = (
    "Name",
    "InstanceName",
    "DBInstanceName",
    "InstanceType",
    "EngineVersion",
    "EngineType",
    "DBEngine",
    "DBVersion",
    "DBMajorVersion",
    "DBKernelVersion",
    "DBInstanceClass",
    "DBInstanceStatus",
    "DBCharset",
    "Charset",
    "Version",
    "StatusDesc",
    "CreateTime",
    "ExpireTime",
    "DeadlineTime",
    "PayType",
    "PayMode",
    "DiskType",
    "DiskEncryption",
    "DestroyProtect",
    "Architecture",
    "Style",
    "HAFlag",
    "TdsqlVersion",
    "DbEngine",
    "DbVersion",
    "Collation",
    "TimeZone",
    "WanDomain",
    "DnsPodDomain",
    "WanStatus",
    "SslMode",
    "InstanceID",
)
NUMBERS = (
    "InstanceType",
    "Memory",
    "Volume",
    "Storage",
    "Cpu",
    "Qps",
    "ProjectId",
    "Status",
    "DeployMode",
    "InitFlag",
    "ProtectMode",
    "InstanceNodes",
    "ReadOnlyInstanceNum",
    "DBInstanceMemory",
    "DBInstanceStorage",
    "DBInstanceCpu",
    "NodeCount",
    "WanPort",
    "WanStatus",
    "WanStatusIpv6",
    "Vport",
    "Port",
    "AutoRenew",
    "BackupSaveDays",
    "IsSupportTDE",
    "IsEncryptSupported",
    "DcnFlag",
    "DcnStatus",
    "ProtectedProperty",
)
BOOLEANS = ("DeletionProtection", "RenewFlag", "IsDrZone", "SupportIpv6")


def scalar_configuration(raw):
    # Provider field names sometimes change type across services; validate against
    # the actual returned scalar type and exclude opaque configuration strings.
    return {
        key: value
        for key, value in raw.items()
        if (key in STRINGS and type(value) is str)
        or (key in NUMBERS and type(value) is int)
        or (key in BOOLEANS and type(value) is bool)
    }


def prepare(raw, spec, region):
    rid = next((raw[k] for k in spec.ids if raw.get(k)), None)
    if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9-]+", rid):
        raise CollectionError("InvalidDatabaseIdentity")
    if raw.get("Region") and raw["Region"] != region:
        raise CollectionError("DatabaseRegionMismatch")
    props = scalar_configuration(raw)
    zone = raw.get("Zone") or raw.get("ZoneName")
    if isinstance(zone, str) and zone.startswith(region + "-"):
        props["zone"] = zone
    links = []
    for keys, prefix, kind, relation in (
        (("UniqVpcId", "UniqueVpcId", "VpcId"), "vpc-", "vpc.vpc", "IN_VPC"),
        (("UniqSubnetId", "UniqueSubnetId", "SubnetId"), "subnet-", "vpc.subnet", "IN_SUBNET"),
    ):
        value = next(
            (raw.get(k) for k in keys if isinstance(raw.get(k), str) and raw[k].startswith(prefix)),
            None,
        )
        if value:
            links.append((region, kind, value, relation))
    endpoints = []
    for ip, port, access in (
        ("Vip", "Vport", "private"),
        ("WanVip", "WanPort", "public"),
        ("Vipv6", "Vport", "private"),
        ("WanVipv6", "WanPortIpv6", "public"),
    ):
        if raw.get(ip) and raw[ip] not in ("0.0.0.0", "::"):
            endpoints.append(
                dict(address=str(ipaddress.ip_address(raw[ip])), port=raw.get(port), access=access)
            )
    network = raw.get("DBInstanceNetInfo")
    if network is None:
        network = []
    if not isinstance(network, list):
        raise CollectionError("InvalidDatabaseEndpoints")
    for net in network:
        n = fields(
            net,
            ("Address", "Ip", "NetType", "Status", "ProtocolType", "VpcId", "SubnetId"),
            integers=("Port",),
        )
        if n.get("Ip"):
            ipaddress.ip_address(n["Ip"])
        endpoints.append(n)
    props["configured_endpoints"] = json.dumps(endpoints, sort_keys=True)
    if spec.kind == "postgres.dbinstanceid" and raw.get("MasterDBInstanceId"):
        links.append((region, spec.kind, raw["MasterDBInstanceId"], "REPLICA_OF"))
    if spec.kind == "cdb.instance":
        master = raw.get("MasterInfo")
        if isinstance(master, dict) and master.get("InstanceId") and master.get("Region"):
            links.append((master["Region"], spec.kind, master["InstanceId"], "REPLICA_OF"))
        for dr in raw.get("DrInfo") or []:
            if not isinstance(dr, dict) or not dr.get("InstanceId") or not dr.get("Region"):
                raise CollectionError("InvalidDatabaseReplica")
            links.append(
                (dr["Region"], spec.kind, dr["InstanceId"], "HAS_DISASTER_RECOVERY_REPLICA")
            )
    return rid, props, links


def collect(runner, spec, region, params=None):
    graph, selected = runner.graph, []

    def operation(record):
        seen = set()
        for batch, request in pages(runner.transport, spec, region, params):
            if request:
                record["request_ids"].append(request)
            prepared = [prepare(raw, spec, region) for raw in batch]
            ids = [p[0] for p in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateDatabaseIdentity")
            seen.update(ids)
            for rid, props, links in prepared:
                nid = graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    rid,
                    props.get("InstanceName") or props.get("DBInstanceName") or props.get("Name"),
                    source=spec.service + "." + spec.action,
                )
                graph.nodes[nid]["properties"].update(props)
                for target_region, kind, value, relation in links:
                    target = graph.add(
                        runner.account,
                        target_region,
                        kind,
                        value,
                        source=spec.service + "." + spec.action,
                        status="reference",
                    )
                    graph.edge(nid, target, relation, spec.service + "." + spec.action)
                selected.append(nid)
                record["count"] += 1

    runner.scope(spec.service, spec.action, region, operation)
    for nid in selected:
        details(runner, graph.nodes[nid], spec.service)


def details(runner, node, service):
    from .database_depth import collect as collect_depth

    collect_depth(runner, node, service)
    rid, region = node["resource_id"], node["region"]
    actions = {
        "cdb": [
            ("DescribeSSLStatus", dict(InstanceId=rid), ("Status",), (), ()),
            (
                "DescribeDBInstanceInfo",
                dict(InstanceId=rid),
                (
                    "InstanceId",
                    "InstanceName",
                    "Encryption",
                    "KeyId",
                    "KeyRegion",
                    "DefaultKmsRegion",
                ),
                (),
                (),
            ),
            ("DescribeDBSecurityGroups", dict(InstanceId=rid), (), (), ()),
        ],
        "postgres": [
            (
                "DescribeDBInstanceSSLConfig",
                dict(DBInstanceId=rid),
                ("ConnectAddress",),
                ("SSLEnabled",),
                (),
            ),
            ("DescribeDBInstanceSecurityGroups", dict(DBInstanceId=rid), (), (), ()),
        ],
        "redis": [
            (
                "DescribeSSLStatus",
                dict(InstanceId=rid),
                ("EncryptAddress",),
                ("SSLConfig", "FeatureSupport"),
                ("Status", "AddressType"),
            ),
            ("DescribeInstanceZoneInfo", dict(InstanceId=rid), (), (), ()),
            ("DescribeInstanceShards", dict(InstanceId=rid, FilterSlave=False), (), (), ()),
            ("DescribeInstanceSecurityGroup", dict(InstanceIds=[rid]), (), (), ()),
        ],
    }.get(service, [])
    for action, params, strings, booleans, numbers in actions:

        def operation(
            record,
            action=action,
            params=params,
            strings=strings,
            booleans=booleans,
            numbers=numbers,
        ):
            data = runner.transport.call(service, action, region, **params)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            props = fields(data, strings, booleans, numbers)
            if data.get("InstanceId") not in (None, rid):
                raise CollectionError("DatabaseIdentityMismatch")
            source = service + "." + action
            groups = None
            if action == "DescribeDBSecurityGroups":
                groups = data.get("Groups")
            elif action == "DescribeDBInstanceSecurityGroups":
                groups = data.get("SecurityGroupSet")
            elif action == "DescribeInstanceSecurityGroup":
                entries = data.get("InstanceSecurityGroupsDetail")
                if (
                    not isinstance(entries, list)
                    or any(d.get("InstanceId") != rid for d in entries)
                    or len(entries) > 1
                ):
                    raise CollectionError("DatabaseSecurityGroupIdentityMismatch")
                groups = entries[0].get("SecurityGroupDetails") if entries else []
            if groups is not None:
                if not isinstance(groups, list):
                    raise CollectionError("InvalidDatabaseSecurityGroups")
                ids = [g.get("SecurityGroupId") for g in groups]
                if any(
                    not isinstance(i, str) or not re.fullmatch(r"sg-[a-z0-9]+", i) for i in ids
                ) or len(set(ids)) != len(ids):
                    raise CollectionError("InvalidDatabaseSecurityGroups")
                for value in ids:
                    target = runner.graph.add(
                        runner.account,
                        region,
                        "vpc.securitygroup",
                        value,
                        source=source,
                        status="reference",
                    )
                    runner.graph.edge(node["id"], target, "USES_SECURITY_GROUP", source)
            elif action in ("DescribeDBSecurityGroups", "DescribeDBInstanceSecurityGroups"):
                raise CollectionError("MissingDatabaseSecurityGroups")
            if action == "DescribeInstanceZoneInfo":
                groups = data.get("ReplicaGroups")
                if not isinstance(groups, list) or len(groups) != data.get("TotalCount"):
                    raise CollectionError("CountMismatch")
                selected = []
                for group in groups:
                    meta = fields(group, ("GroupName", "ZoneId", "Role"), integers=("GroupId",))
                    if "GroupId" not in meta or not isinstance(group.get("RedisNodes"), list):
                        raise CollectionError("InvalidRedisReplicaGroup")
                    members = [
                        fields(n, ("NodeId", "Status", "Role", "Slot"), integers=("Keys",))
                        for n in group["RedisNodes"]
                    ]
                    if any(not n.get("NodeId") for n in members) or len(
                        {n["NodeId"] for n in members}
                    ) != len(members):
                        raise CollectionError("InvalidRedisNode")
                    selected.append((meta, members))
                if len({meta["GroupId"] for meta, _ in selected}) != len(selected):
                    raise CollectionError("DuplicateRedisGroup")
                for meta, members in selected:
                    gid = runner.graph.add(
                        runner.account,
                        region,
                        "redis.replicagroup",
                        rid + "/" + str(meta["GroupId"]),
                        meta.get("GroupName"),
                        source=source,
                    )
                    runner.graph.nodes[gid]["properties"].update(meta)
                    runner.graph.edge(node["id"], gid, "HAS_REPLICA_GROUP", source)
                    for member in members:
                        nid = runner.graph.add(
                            runner.account,
                            region,
                            "redis.node",
                            rid + "/" + str(meta["GroupId"]) + "/" + member["NodeId"],
                            source=source,
                        )
                        runner.graph.nodes[nid]["properties"].update(member)
                        runner.graph.edge(gid, nid, "HAS_NODE", source)
            if action == "DescribeInstanceShards":
                batch = data.get("InstanceShards")
                if not isinstance(batch, list) or len(batch) != data.get("TotalCount"):
                    raise CollectionError("CountMismatch")
                prepared = [
                    fields(
                        s,
                        ("ShardId", "ShardName", "Slots", "RunId", "Runid", "ZoneId"),
                        integers=("Role", "Connected", "ReplicasNodeId", "Keys", "Storage"),
                    )
                    for s in batch
                ]
                ids = [
                    (s.get("ShardId"), s.get("Role"), s.get("RunId") or s.get("Runid"))
                    for s in prepared
                ]
                if any(not i[0] or not i[2] for i in ids) or len(set(ids)) != len(ids):
                    raise CollectionError("InvalidRedisShard")
                for meta, key in zip(prepared, ids, strict=True):
                    nid = runner.graph.add(
                        runner.account,
                        region,
                        "redis.shard",
                        rid + "/" + "/".join(map(str, key)),
                        meta.get("ShardName"),
                        source=source,
                    )
                    runner.graph.nodes[nid]["properties"].update(meta)
                    runner.graph.edge(node["id"], nid, "HAS_SHARD", source)
            node["properties"][action] = json.dumps(props, sort_keys=True)
            if (
                action == "DescribeDBInstanceInfo"
                and props.get("Encryption") == "YES"
                and props.get("KeyId")
                and props.get("KeyRegion")
            ):
                if re.fullmatch(
                    r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", props["KeyId"]
                ):
                    kid = runner.graph.add(
                        runner.account,
                        props["KeyRegion"],
                        "kms.key",
                        props["KeyId"],
                        source=source,
                        status="reference",
                    )
                    runner.graph.edge(node["id"], kid, "CONFIGURED_ENCRYPTION_KEY", source)
            record["count"] = 1

        runner.scope(service, action, region, operation, rid)
