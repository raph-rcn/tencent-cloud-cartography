import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import CHILDREN, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
KEY = "11111111-2222-3333-4444-555555555555"
SPECS = {s.kind: s for s in (*COLLECTORS, *CHILDREN.values()) if s.service == "cfs"}


def fs(i=1):
    return dict(
        FileSystemId=f"cfs-{i}",
        FsName="Shared files",
        LifeCycleState="available",
        SizeByte=512,
        SizeLimit=100,
        Protocol="NFS",
        StorageType="SD",
        Encrypted=True,
        KmsKeyId=KEY,
        Zone=REGION + "-1",
        BandwidthLimit=64.5,
        PGroup=dict(PGroupId="pgroup-1", Name="Application access"),
    )


def mount(i=1, fsid="cfs-1", **extra):
    return dict(
        FileSystemId=fsid,
        MountTargetId=f"mount-{i}",
        LifeCycleState="available",
        NetworkInterface="VPC",
        VpcId="vpc-1",
        SubnetId="subnet-1",
        IpAddress="10.0.0.7",
        FSID="root-1",
        **extra,
    )


def rule(i=1, **extra):
    return dict(
        RuleId=f"rule-{i}",
        AuthClientIp="10.0.0.0/24",
        RWPermission="ro",
        UserPermission="root_squash",
        Priority=i,
        **extra,
    )


def runner(g, call):
    return CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def native(g, kind, items, params=None, parent=None, relation=None):
    spec = SPECS[kind]
    response = {spec.result: items, "RequestId": "fixture"}
    if spec.total:
        response[spec.total] = len(items)
    return runner(g, lambda *a, **kw: response).native(spec, REGION, params, parent, relation)


def test_filesystem_mounts_groups_and_rules():
    g = Graph()
    fid = native(g, "cfs.filesystem", [fs()])[0][0]
    gid = native(
        g,
        "cfs.permissiongroup",
        [dict(PGroupId="pgroup-1", Name="Application access", BindCfsNum=1)],
    )[0][0]
    mid = native(
        g, "cfs.mounttarget", [mount()], dict(FileSystemId="cfs-1"), fid, "HAS_MOUNT_TARGET"
    )[0][0]
    rid = native(
        g, "cfs.permissionrule", [rule()], dict(PGroupId="pgroup-1"), gid, "HAS_ACCESS_RULE"
    )[0][0]
    assert g.nodes[fid]["properties"]["SizeByte"] == 512
    assert g.nodes[fid]["properties"]["BandwidthLimit"] == 64.5
    assert g.nodes[fid]["properties"]["state"] == "available"
    assert g.nodes[gid]["status"] == "enriched"
    assert g.nodes[mid]["resource_id"] == "cfs-1/mount-1"
    assert g.nodes[mid]["properties"]["FSID"] == "root-1"
    assert g.nodes[rid]["resource_id"] == "pgroup-1/rule-1"
    assert g.nodes[rid]["properties"]["UserPermission"] == "root_squash"
    assert g.nodes[rid]["properties"]["access_verified"] is False
    relationships = {e["relationship"] for e in g.edges.values()}
    assert {
        "HAS_MOUNT_TARGET",
        "HAS_ACCESS_RULE",
        "USES_PERMISSION_GROUP",
        "IN_VPC",
        "IN_SUBNET",
        "CONFIGURED_KMS_KEY",
    } <= relationships
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


def test_turbo_ccn_ignores_stale_vpc_fields_and_preserves_truncation():
    g = Graph()
    raw = {
        **mount(),
        "NetworkInterface": "CCN",
        "CcnID": "ccn-1",
        "CidrBlock": "10.0.0.0/24",
        "ServerList": ["10.0.0.2"],
        "ServerListTruncated": True,
    }
    mid = native(g, "cfs.mounttarget", [raw], dict(FileSystemId="cfs-1"))[0][0]
    assert g.nodes[mid]["properties"]["ServerListTruncated"] is True
    assert json.loads(g.nodes[mid]["properties"]["allocated_server_ips"]) == ["10.0.0.2"]
    assert {(n["kind"], n["region"]) for n in g.nodes.values()} == {
        ("cfs.mounttarget", REGION),
        ("vpc.ccn", "global"),
    }
    assert [e["relationship"] for e in g.edges.values()] == ["ATTACHED_CCN"]


def test_unknown_network_type_does_not_infer_placement():
    g = Graph()
    mid = native(
        g,
        "cfs.mounttarget",
        [{**mount(), "NetworkInterface": "future"}],
        dict(FileSystemId="cfs-1"),
    )[0][0]
    assert not g.edges and g.nodes[mid]["properties"]["network_resolution"] == "unsupported-type"


@pytest.mark.parametrize(
    "kind,row,params,error",
    [
        (
            "cfs.mounttarget",
            mount(fsid="cfs-2"),
            dict(FileSystemId="cfs-1"),
            "CfsFileSystemMismatch",
        ),
        (
            "cfs.mounttarget",
            {**mount(), "MountTargetId": "other"},
            dict(FileSystemId="cfs-1"),
            "InvalidCfsIdentity",
        ),
        (
            "cfs.permissionrule",
            rule(PGroupId="pgroup-2"),
            dict(PGroupId="pgroup-1"),
            "CfsPermissionGroupMismatch",
        ),
        (
            "cfs.permissionrule",
            {**rule(), "Priority": True},
            dict(PGroupId="pgroup-1"),
            "InvalidCfsRulePriority",
        ),
        (
            "cfs.permissionrule",
            {**rule(), "RWPermission": "all"},
            dict(PGroupId="pgroup-1"),
            "InvalidCfsRulePermission",
        ),
        (
            "cfs.permissionrule",
            {**rule(), "UserPermission": "unknown"},
            dict(PGroupId="pgroup-1"),
            "InvalidCfsRulePermission",
        ),
    ],
)
def test_invalid_child_configuration_is_partial(kind, row, params, error):
    g = Graph()
    native(g, kind, [row], params)
    assert g.coverage[-1]["error"] == error


def test_same_mount_and_rule_ids_are_scoped_to_their_parent():
    g = Graph()
    for i in (1, 2):
        native(g, "cfs.mounttarget", [mount(fsid=f"cfs-{i}")], dict(FileSystemId=f"cfs-{i}"))
        native(g, "cfs.permissionrule", [rule()], dict(PGroupId=f"pgroup-{i}"))
    assert {n["resource_id"] for n in g.nodes.values() if n["kind"] == "cfs.mounttarget"} == {
        "cfs-1/mount-1",
        "cfs-2/mount-1",
    }
    assert len([n for n in g.nodes.values() if n["kind"] == "cfs.permissionrule"]) == 2


def test_missing_or_inconsistent_mount_count_is_not_complete():
    for response, error in [
        (dict(MountTargets=[]), "InvalidTotal"),
        (dict(MountTargets=[], NumberOfMountTargets=True), "InvalidTotal"),
        (dict(MountTargets=[mount()], NumberOfMountTargets=2), "CountMismatch"),
    ]:
        g = Graph()
        runner(g, lambda *a, **kw: response).native(
            SPECS["cfs.mounttarget"], REGION, dict(FileSystemId="cfs-1")
        )
        assert g.coverage[-1]["error"] == error


def test_duplicate_rules_and_non_paginated_groups():
    g = Graph()
    native(g, "cfs.permissionrule", [rule(), rule()], dict(PGroupId="pgroup-1"))
    assert g.coverage[-1]["error"] == "DuplicateCfsResource"
    calls = []

    def call(*a, **kw):
        calls.append(kw)
        return dict(PGroupList=[dict(PGroupId="pgroup-1")])

    runner(g, call).native(SPECS["cfs.permissiongroup"], REGION)
    assert calls == [dict(region=REGION)]


@pytest.mark.parametrize(
    "encrypted,key,linked",
    [(True, KEY, True), (False, KEY, False), (True, "unverified-key-arn", False)],
)
def test_encryption_requires_explicit_compatible_key_metadata(encrypted, key, linked):
    g = Graph()
    native(g, "cfs.filesystem", [{**fs(), "Encrypted": encrypted, "KmsKeyId": key}])
    assert (
        bool([e for e in g.edges.values() if e["relationship"] == "CONFIGURED_KMS_KEY"]) == linked
    )


def test_whole_collection_continues_after_mount_and_rule_denials():
    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append((action, params))
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "DescribeCfsFileSystems":
                return dict(FileSystems=[fs(), fs(2)], TotalCount=2)
            if action == "DescribeMountTargets":
                assert set(params) == {"FileSystemId"}
                if params["FileSystemId"] == "cfs-1":
                    raise CollectionError("UnauthorizedOperation")
                return dict(MountTargets=[mount(fsid="cfs-2")], NumberOfMountTargets=1)
            if action == "DescribeCfsPGroups":
                return dict(PGroupList=[dict(PGroupId="pgroup-1"), dict(PGroupId="pgroup-2")])
            if action == "DescribeCfsRules":
                assert set(params) == {"PGroupId"}
                if params["PGroupId"] == "pgroup-1":
                    raise CollectionError("OperationDenied")
                return dict(RuleList=[rule()])
            raise AssertionError(action)

    data = collect(
        ["test"],
        [REGION],
        services={"cfs"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert len([c for c in data["coverage"] if c["status"] == "denied"]) == 2
    assert any(
        n["kind"] == "cfs.mounttarget" and n["resource_id"] == "cfs-2/mount-1"
        for n in data["nodes"]
    )
    assert any(
        n["kind"] == "cfs.permissionrule" and n["resource_id"] == "pgroup-2/rule-1"
        for n in data["nodes"]
    )


def test_documented_default_group_and_lowercase_network_type():
    g = Graph()
    raw = fs()
    raw["PGroup"] = {"PGroupId": "pgroupbasic"}
    fid = native(g, "cfs.filesystem", [raw])[0][0]
    gid = native(g, "cfs.permissiongroup", [dict(PGroupId="pgroupbasic", Name="Default")])[0][0]
    mid = native(
        g, "cfs.mounttarget", [{**mount(), "NetworkInterface": "vpc"}], dict(FileSystemId="cfs-1")
    )[0][0]
    assert any(e["source"] == fid and e["target"] == gid for e in g.edges.values())
    assert {e["relationship"] for e in g.edges.values() if e["source"] == mid} == {
        "IN_VPC",
        "IN_SUBNET",
    }
    assert g.nodes[gid]["status"] == "enriched"


def test_filesystem_pagination_requires_total_and_retains_request_ids():
    g, offsets = Graph(), []

    def call(*a, **kw):
        offset = kw["Offset"]
        offsets.append(offset)
        return dict(
            FileSystems=[fs(i) for i in range(offset, min(offset + 100, 101))],
            TotalCount=101,
            RequestId=str(offset),
        )

    runner(g, call).native(SPECS["cfs.filesystem"], REGION)
    assert offsets == [0, 100] and g.coverage[-1]["request_ids"] == ["0", "100"]
    runner(g, lambda *a, **kw: dict(FileSystems=[])).native(SPECS["cfs.filesystem"], REGION)
    assert g.coverage[-1]["error"] == "InvalidTotal"
