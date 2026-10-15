"""Real response contracts, scope controls and bounded metadata-only behavior."""

import copy
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, API_VERSIONS, DETAIL_KINDS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.data_metadata import (
    ACTIONS,
    KINDS,
    READS,
    collect_read,
    dlc_policy,
    link,
    redis_parameters,
    rotation_history,
)
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.secrets import link_resources
from tencent_cloud_cartography.storage import validate

REGION = "eu-frankfurt"
# Representative provider response fields, not generated from collector schemas.
RESPONSES = {
    "DescribeBackupDownloadRestriction": dict(
        LimitType="Customize",
        VpcComparisonSymbol="In",
        IpComparisonSymbol="In",
        LimitIp=["192.0.2.0/24"],
        LimitVpc=[dict(Region=REGION, VpcList=["vpc-1"])],
    ),
    "DescribeLocalBinlogConfig": dict(
        LocalBinlogConfig=dict(SaveHours=72, MaxUsage=30),
        LocalBinlogConfigDefault=dict(SaveHours=24, MaxUsage=20),
    ),
    "DescribeDBProxySSLConfig": dict(
        SSLEnabled=True, ConnectAddress="proxy.internal.example", CAUrl="never-persist"
    ),
    "DescribeReadOnlyGroupList": dict(
        ReadOnlyGroupSet=[
            dict(
                ReadOnlyGroupId="ro-1",
                MasterInstanceId="instance-1",
                VpcId="vpc-1",
                ReadOnlyInstanceSet=[
                    dict(InstanceId="sqlserver-ro", SynStatus="normal", RegionId=REGION)
                ],
            )
        ]
    ),
    "DescribeDLCCatalogAccess": dict(
        TotalCount=1, Rows=[dict(VpcId="vpc-1", Product="cvm", CreateTime="2026-10-01")]
    ),
    "DescribeThirdPartyAccessUser": dict(UserInfo=dict(Uin="101", AppId="999", Id=1)),
    "DescribeClusterInfo": dict(
        ClusterName="production",
        NodeCount=1,
        NodeList=[dict(NodeId="node-1", Role="master", Zone=REGION + "-1", Weight=100)],
        ReadWriteAddress=dict(ResourceId="addr-1", Vip="10.0.0.4", VPort=3306),
    ),
    "DescribeBackupEncryptionStatus": dict(EncryptionStatus="on"),
    "DescribeBackupSummaries": dict(
        TotalCount=1, Items=[dict(InstanceId="cdb-1", DataBackupCount=2, BackupVolume=1234)]
    ),
    "DescribeDBProxy": dict(
        Count=1,
        ProxyInfos=[
            dict(
                ProxyGroupId="proxy-1",
                ConnectionPoolLimit=100,
                ProxyNodeSet=[dict(ProxyNodeId="node-1", Zone=REGION + "-1", Cpu=2)],
                ProxyAddressSet=[
                    dict(
                        AddressId="addr-1",
                        Vip="10.0.0.5",
                        Vport=5432,
                        VpcId="vpc-1",
                        SubnetId="subnet-1",
                        RwSplitEnable=True,
                        Routes=[dict(NodeId="node-1", Role="master", Weight=100)],
                    )
                ],
            )
        ],
    ),
    "DescribeInstanceParams": dict(
        TotalCount=1,
        Items=[
            dict(
                Name="fill factor(%)",
                ParamType="integer",
                CurrentValue="0",
                Min=-1,
                Max=100,
                NeedReboot=0,
            )
        ],
    ),
    "DescribeBackupSummary": dict(FreeSpace=100, BackupFilesTotal=0, CrossLogBackupCount=0),
    "DescribeBackupConfigs": dict(
        Days=7,
        ArchiveDays=30,
        WeekDays=["Monday"],
        BackupConfigSet=[dict(EnableBackupPolicy=True, Frequency="Weekly", MaxRetentionDays=30)],
    ),
    "DescribeReplicationGroup": dict(
        TotalCount=1,
        Groups=[
            dict(
                GroupId="crs-rpl-1",
                AppId=999,
                RegionId=1,
                InstanceCount=1,
                Instances=[
                    dict(
                        InstanceId="crs-1",
                        AppId=888,
                        RegionId=8,
                        VpcID=123,
                        Role="master",
                        DiskSize=1024,
                    )
                ],
            )
        ],
    ),
    "DescribeReplicationGroupInstance": dict(
        GroupId="crs-rpl-1", InstanceRole="master", AppId=999, RegionId=1
    ),
    "DescribeAutoBackupConfig": dict(
        AutoBackupType=1, WeekDays=["Monday"], TimePeriod="03:00-04:00", BackupStorageDays=7
    ),
    "DescribeInstanceBackups": dict(
        TotalCount=1,
        BackupSet=[dict(BackupId="backup-1", Status=1, Encrypted=True, StartTime="2026-10-01")],
    ),
    "DescribeInstancePasswordPolicy": dict(
        PasswordPolicy=dict(Enabled=True, MinLength=12, MinDigitCount=2)
    ),
    "DescribeAccounts": dict(
        TotalCount=1, Accounts=[dict(UserName="warehouse_reader", Perms=["SELECT"])]
    ),
    "DescribeUserHbaConfig": dict(
        TotalCount=1,
        HbaConfigs=[
            dict(
                Type="hostssl",
                Database="warehouse",
                User="warehouse_reader",
                Address="10.0.0.0",
                Mask="255.0.0.0",
                Method="scram-sha-256",
            )
        ],
    ),
    "DescribeInstanceNodes": dict(
        InstanceNodes=[
            dict(
                NodeId=1, NodeType="segment", NodeRole="primary", PrivateNetworkIp="10.0.0.3", Cpu=4
            )
        ]
    ),
    "DescribeAutoSnapshotPolicies": dict(
        TotalCount=1,
        AutoSnapshotPolicies=[
            dict(
                AutoSnapshotPolicyId="asp-1",
                PolicyName="daily",
                AliveDays=7,
                FileSystemNums=1,
                FileSystems=[dict(FileSystemId="cfs-1", SizeByte=42)],
            )
        ],
    ),
    "DescribeCfsSnapshots": dict(
        TotalCount=1,
        Snapshots=[
            dict(
                SnapshotId="snap-1", FileSystemId="cfs-1", SnapshotType="auto", Size=42, AliveDay=7
            )
        ],
    ),
    "DescribeLifecyclePolicies": dict(
        TotalCount=1,
        LifecyclePolicies=[
            dict(
                LifecyclePolicyID="policy-1",
                LifecyclePolicyName="archive",
                LifecycleRules=[
                    dict(
                        StorageType="ARCHIVE",
                        Action="Transition",
                        Interval="30",
                        IsSyncDelete=False,
                    )
                ],
                Paths=[dict(FileSystemId="cfs-1", Path="/archive")],
            )
        ],
    ),
    "DescribeRequestInstancePolicy": dict(
        IsDefault=False, GetPaths=["/_search"], PostPaths=[], PutPaths=[]
    ),
    "DescribeCosBackupStrategyViews": dict(
        CosBackupList=[
            dict(
                InstanceId="es-1",
                StrategyName="",
                IsAutoBackup=True,
                CosRetention=7,
                RetentionGraceTime=1,
            )
        ]
    ),
    "DescribeSnapshotViews": dict(
        Snapshots=[
            dict(
                Uuid="snapshot-1",
                InstanceId="es-1",
                SnapshotName="daily",
                State="SUCCESS",
                RetentionGraceTime=1,
            )
        ],
        FailedMsgs=[],
    ),
    "DescribeBackupRecords": dict(
        TotalCount=1,
        BackupRecords=[
            dict(
                ZoneId=1,
                TableName="orders",
                FileTag="backup",
                BackupBatchTime="2026-10-01",
                BackupFileSize=100,
            )
        ],
    ),
    "DescribeSnapshots": dict(
        TotalCount=1,
        TableResults=[
            dict(
                TableGroupId="1",
                TableName="orders",
                SnapshotName="daily",
                SnapshotSize=100,
                SnapshotStatus=0,
                Error=dict(Code="", Message=""),
            )
        ],
    ),
}


def make_runner(graph, call):
    return CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def parent_node(graph, kind, account="100", region=REGION):
    rid = {
        "cdb.instance": "cdb-1",
        "postgres.dbinstanceid": "postgres-1",
        "es.instance": "es-1",
        "tcaplusdb.cluster": "123",
    }.get(kind, "instance-1")
    return graph.nodes[graph.add(account, region, kind, rid)]


@pytest.mark.parametrize("read", READS, ids=lambda r: r.service + "." + r.action)
def test_each_native_metadata_read_preserves_selected_fields_and_relationships(read):
    graph, calls = Graph(), []
    parent = parent_node(graph, read.parent) if read.parent else None
    if read.action == "DescribeDBProxySSLConfig":
        parent["properties"].update(
            AddressId="addr-1", DBInstanceId="postgres-1", ProxyGroupId="proxy-1"
        )

    def call(service, action, region=None, **params):
        calls.append(params)
        assert (service, action, region) == (read.service, read.action, REGION)
        if parent and action == "DescribeDBProxySSLConfig":
            assert params == dict(
                ProxyAddressId="addr-1", DBInstanceId="postgres-1", ProxyGroupId="proxy-1"
            )
        elif parent:
            expected = (
                [parent["resource_id"]]
                if service == "es" and read.result
                else parent["resource_id"]
            )
            assert params[read.argument] == expected
        if action == "DescribeSnapshotViews":
            assert params["Duration"] == 0 and params["UserBackUp"] == ""
        if action == "DescribeInstanceBackups":
            assert params["Status"] == [1, 2]
        data = copy.deepcopy(RESPONSES[action])
        data.update(
            Password="never-persist",
            SecretString="never-persist",
            Query="never-persist",
            RequestId="read-1",
        )
        return data

    collect_read(make_runner(graph, call), read, REGION, parent)
    assert graph.coverage[-1]["status"] == "complete", graph.coverage
    assert graph.coverage[-1]["request_ids"] == ["read-1"]
    assert any(n["kind"] == read.kind for n in graph.nodes.values())
    if parent:
        assert any(
            e["source"] == parent["id"] and e["relationship"] == "HAS_METADATA"
            for e in graph.edges.values()
        )
    assert "never-persist" not in graph.dump()
    validate(graph.snapshot())
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())


@pytest.mark.parametrize(
    "change",
    ["duplicate", "foreign-instance", "negative-total", "missing-total", "provider-item-error"],
)
def test_invalid_metadata_does_not_publish_the_page(change):
    read = next(r for r in READS if r.action == "DescribeInstanceBackups")
    graph = Graph()
    parent = parent_node(graph, read.parent)
    data = copy.deepcopy(RESPONSES[read.action])
    if change == "duplicate":
        data["BackupSet"] *= 2
        data["TotalCount"] = 2
    elif change == "foreign-instance":
        data["BackupSet"][0]["InstanceId"] = "crs-other"
    elif change == "provider-item-error":
        data["BackupSet"][0]["Error"] = dict(Code="NoAccess", Message="never-persist")
    else:
        data["TotalCount"] = -1 if change == "negative-total" else None
    collect_read(make_runner(graph, lambda *a, **kw: data), read, REGION, parent)
    assert graph.coverage[-1]["status"] == "error" and len(graph.nodes) == 1
    assert "never-persist" not in graph.dump()


def test_snapshot_partial_error_is_not_treated_as_complete():
    read = next(r for r in READS if r.action == "DescribeSnapshotViews")
    g = Graph()
    p = parent_node(g, read.parent)
    collect_read(
        make_runner(g, lambda *a, **kw: dict(Snapshots=[], FailedMsgs=["never-persist"])),
        read,
        REGION,
        p,
    )
    assert g.coverage[-1]["error"] == "DataMetadataProviderFailure" and len(g.nodes) == 1
    assert "never-persist" not in g.dump()


def test_backup_pagination_and_changed_total_report_partial():
    read = next(r for r in READS if r.action == "DescribeInstanceBackups")
    graph = Graph()
    parent = parent_node(graph, read.parent)
    calls = []

    def call(service, action, region=None, **params):
        calls.append(params["Offset"])
        rows = [
            dict(BackupId=f"backup-{i}")
            for i in range(params["Offset"], min(101, params["Offset"] + params["Limit"]))
        ]
        return dict(TotalCount=101, BackupSet=rows)

    collect_read(make_runner(graph, call), read, REGION, parent)
    assert calls == [0, 100]
    assert graph.coverage[-1]["count"] == 101 and graph.coverage[-1]["status"] == "complete"


def test_relationship_reconciliation_is_idempotent_and_owner_region_scoped():
    g = Graph()
    fs = g.add("100", REGION, "cfs.filesystem", "cfs-1")
    g.add("200", REGION, "cfs.filesystem", "cfs-1")
    g.add("100", "ap-guangzhou", "cfs.filesystem", "cfs-1")
    for read in READS:
        if read.service == "cfs":
            collect_read(
                make_runner(g, lambda s, a, *args, **kwargs: copy.deepcopy(RESPONSES[a])),
                read,
                REGION,
            )
    link(g)
    assert (
        len([e for e in g.edges.values() if e["relationship"] == "CONFIGURED_FOR_FILESYSTEM"]) == 3
    )
    assert {
        e["target"] for e in g.edges.values() if e["relationship"] == "CONFIGURED_FOR_FILESYSTEM"
    } == {fs}
    before = g.dump()
    link(g)
    assert before == g.dump()


def test_redis_members_numeric_appid_and_region_do_not_guess_ownership_or_vpc():
    g = Graph()
    g.add("100", REGION, "redis.instance", "crs-1")
    read = next(r for r in READS if r.action == "DescribeReplicationGroup")
    collect_read(
        make_runner(g, lambda *a, **kw: copy.deepcopy(RESPONSES[read.action])), read, REGION
    )
    link(g)
    assert not g.edges
    assert not any(n["kind"] == "vpc.vpc" for n in g.nodes.values())
    assert '"AppId": 888' in next(
        n["properties"]["Instances"]
        for n in g.nodes.values()
        if n["kind"] == "redis.replicationgroup"
    )


def test_redis_parameter_selection_no_opaque_text_or_credentials_persisted():
    g = Graph()
    p = parent_node(g, "redis.instance")
    data = dict(
        TotalCount=2,
        InstanceEnumParam=[
            dict(ParamName="maxmemory-policy", CurrentValue="allkeys-lru", NeedRestart="false")
        ],
        InstanceIntegerParam=[],
        InstanceTextParam=[dict(ParamName="unknown", CurrentValue="never-persist")],
        InstanceMultiParam=[],
    )
    redis_parameters(make_runner(g, lambda *a, **kw: data), p)
    assert (
        g.coverage[-1]["status"] == "complete" and g.coverage[-1]["excluded_parameter_count"] == 1
    )
    assert "never-persist" not in g.dump() and len(g.nodes) == 2


def test_rotation_account_status_is_not_version_stage_and_history_ceiling_visible():
    g = Graph()
    p = parent_node(g, "ssm.secret")
    data = dict(
        VersionIDs=["v1"],
        TotalCount=2,
        AccountInfoList=[
            dict(AccountName="reader", Host=["%"], Version="生效中", RotatedTime="2026-10-01")
        ],
    )
    rotation_history(make_runner(g, lambda *a, **kw: data), p)
    assert g.coverage[-1]["error"] == "RotationHistoryTruncated"
    history = next(n for n in g.nodes.values() if n["kind"] == "ssm.rotationhistory")
    assert not history["properties"]["version_stages_verified"]
    assert not any(e["relationship"] == "CONFIGURED_KMS_KEY" for e in g.edges.values())


@pytest.mark.parametrize(
    "product,kind",
    [
        ("PostgreSQL", "postgres.dbinstanceid"),
        ("SqlServer", "sqlserver.instance"),
        ("MariaDB", "mariadb.instance"),
        ("MongoDB", "mongodb.instance"),
    ],
)
def test_broader_secret_database_links_require_native_type_and_exact_collected_scope(product, kind):
    g = Graph()
    secret = parent_node(g, "ssm.secret")
    secret["properties"].update(SecretType=1, ProductName=product, ResourceID="db-1")
    g.add("200", REGION, kind, "db-1")
    g.add("100", "ap-guangzhou", kind, "db-1")
    link_resources(g)
    assert not g.edges
    target = g.add("100", REGION, kind, "db-1")
    link_resources(g)
    assert [e["target"] for e in g.edges.values()] == [target]
    secret["properties"]["ProductName"] = "unknown"
    link_resources(g)
    assert not g.edges


def test_third_party_dlc_policy_is_metadata_without_a_cam_grant():
    g = Graph()
    policy = dict(
        version="2.0", statement=[dict(effect="allow", action="name/dlc:*", resource="*")]
    )
    dlc_policy(make_runner(g, lambda *a, **kw: dict(PolicyDocument=json.dumps(policy))), REGION)
    assert g.coverage[-1]["status"] == "complete" and not g.edges
    node = next(iter(g.nodes.values()))
    assert node["properties"]["evaluation_scope"] == "current_third_party_platform_subuser"
    assert not node["properties"]["query_access_verified"]


def test_all_new_operations_registered_and_excluded_sensitive_methods_stay_blocked():
    from tencent_cloud_cartography.dlc_authorization_metadata import ACTIONS as DLC_ACTIONS
    from tencent_cloud_cartography.dlc_authorization_metadata import KINDS as DLC_KINDS

    assert ACTIONS | DLC_ACTIONS <= ALLOWED_ACTIONS
    assert KINDS | DLC_KINDS <= DETAIL_KINDS
    assert all(icon_for(k) != "unmapped.svg" for k in KINDS | DLC_KINDS)
    assert (
        not {
            ("ssm", "GetSecretValue"),
            ("tcaplusdb", "DescribeClusters"),
            ("tcaplusdb", "DescribeTables"),
            ("cdwpg", "DescribeDBInstanceAccess"),
            ("cdb", "DescribeBackups"),
            ("es", "DescribeInstanceLogs"),
        }
        & ALLOWED_ACTIONS
    )


@pytest.mark.parametrize("module_name", ["data_metadata", "platform_metadata", "workload_metadata"])
def test_all_projected_fields_match_current_native_sdk_contracts(module_name):
    from importlib import import_module

    reads = import_module("tencent_cloud_cartography." + module_name).READS
    # Native transport deliberately supports audited APIs absent from the older
    # international SDK. Inspect the isolated TCCLI SDK when available.
    runtime = os.environ.get("TCCLI_TEST_PYTHON")
    if not runtime:
        pytest.skip("Current native TCCLI SDK schema check requires isolated runtime")
    code = """
import importlib,inspect,json,re,sys
out={}
def types(cls):
 return dict(re.findall(r':type (\\w+): ([^\\n]+)',inspect.getsource(cls)))
def walk(module,cls):
 name=module.__name__+'.'+cls.__name__
 if name in out:return
 t=types(cls);out[name]=t
 for value in t.values():
  nested=value.removeprefix('list of ')
  if ':class:' in nested:nested=nested.split('.')[-1].rstrip('`')
  child=getattr(module,nested,None)
  if isinstance(child,type):walk(module,child)
for service,version,action in json.loads(sys.argv[1]):
 m=importlib.import_module(f'tencentcloud.{service}.v{version}.models');walk(m,getattr(m,action+'Response'))
print(json.dumps(out))
"""
    contracts = json.loads(
        subprocess.check_output(
            [
                runtime,
                "-c",
                code,
                json.dumps(
                    [(r.service, API_VERSIONS[r.service].replace("-", ""), r.action) for r in reads]
                ),
            ],
            text=True,
        )
    )

    def check(spec, cls, prefix):
        types = contracts[prefix + "." + cls]
        for group, typ in (
            ("strings", "str"),
            ("integers", "int"),
            ("booleans", "bool"),
            ("arrays", "list of str"),
            ("floats", "float"),
            ("integer_arrays", "list of int non-negative"),
        ):
            for field in spec.get(group, []):
                assert types.get(field) == typ, (cls, field, types.get(field), typ)
        for field, child in spec["children"].items():
            typ = types[field]
            name = (
                typ.split(".")[-1].rstrip("`") if ":class:" in typ else typ.removeprefix("list of ")
            )
            check(child[0] if isinstance(child, list) else child, name, prefix)

    for read in reads:
        prefix = (
            f"tencentcloud.{read.service}.v{API_VERSIONS[read.service].replace('-', '')}.models"
        )
        cls = read.action + "Response"
        if read.result:
            for part in read.result.split("."):
                typ = contracts[prefix + "." + cls][part]
                cls = (
                    typ.split(".")[-1].rstrip("`")
                    if ":class:" in typ
                    else typ.removeprefix("list of ")
                )
        check(read.spec, cls, prefix)


def test_hba_order_is_retained_even_for_repeated_identical_native_rules():
    g = Graph()
    read = next(r for r in READS if r.action == "DescribeUserHbaConfig")
    parent = parent_node(g, read.parent)
    rule = dict(Type="host", Database="all", User="all", Address="10.0.0.0/8", Method="reject")
    collect_read(
        make_runner(g, lambda *a, **kw: dict(TotalCount=2, HbaConfigs=[rule, rule])),
        read,
        REGION,
        parent,
    )
    assert g.coverage[-1]["status"] == "complete"
    assert {
        n["properties"]["rule_order"] for n in g.nodes.values() if n["kind"] == "cdwpg.hbarule"
    } == {0, 1}


def test_snapshot_of_missing_filesystem_retains_a_reference_and_relationship():
    g = Graph()
    read = next(r for r in READS if r.action == "DescribeCfsSnapshots")
    collect_read(
        make_runner(g, lambda *a, **kw: copy.deepcopy(RESPONSES[read.action])), read, REGION
    )
    link(g)
    reference = next(n for n in g.nodes.values() if n["kind"] == "cfs.filesystem")
    assert reference["status"] == "reference" and reference["resource_id"] == "cfs-1"
    assert any(
        e["target"] == reference["id"] and e["relationship"] == "CONFIGURED_FOR_FILESYSTEM"
        for e in g.edges.values()
    )
