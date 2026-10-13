import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.emr import collect_clusters
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

SPEC = next(s for s in COLLECTORS if s.kind == "emr.cluster")
REGION = "eu-frankfurt"


def cluster(i=1, **kwargs):
    return dict(
        ClusterId=f"emr-{i}",
        ClusterName=f"Analytics {i}",
        AppId=12345,
        RegionId=9,
        Status=2,
        StatusDesc="Running",
        EmrVersion="EMR-V3.5.0",
        Zone="eu-frankfurt-1",
        UniqVpcId="vpc-a",
        UniqSubnetId="subnet-a",
        VpcId=123,
        SubnetId=456,
        IsMultiZoneCluster=False,
        MasterIp="10.0.0.1",
        **kwargs,
    )


def node(i=1):
    return dict(
        EmrResourceId=f"emr-vm-{i}",
        SerialNo=f"serial-{i}",
        OrderNo=f"ins-{i}",
        AppId=12345,
        RegionId=9,
        HardwareResourceType="HOST",
        NameTag=f"Worker {i}",
        Zone="eu-frankfurt-2",
        Ip="10.0.1.2",
        WanIp="--",
        DisableApiTermination=True,
        SubnetInfo=dict(SubnetId="subnet-b", SubnetName="Workers"),
        CpuNum=8,
        MemSize=17179869184,
        Services="DataNode,NodeManager",
        AutoFlag=1,
    )


def run(clusters=None, nodes=None, mutate=None):
    graph, calls = Graph(), []
    clusters = {0: [cluster()], 2: []} if clusters is None else clusters
    nodes = {"all": [node()], "db": [], "recyle": []} if nodes is None else nodes

    def call(service, action, **params):
        assert service == "emr"
        calls.append((action, params))
        if action == "DescribeInstancesList":
            assert params["DisplayStrategy"] == "clusterList"
            items = clusters[params["ClusterType"]]
            key = "InstancesList"
        else:
            assert action == "DescribeClusterNodes" and params["HardwareResourceType"] == "all"
            items = nodes[params["NodeFlag"]]
            key = "NodeList"
        if isinstance(items, Exception):
            raise items
        offset = params["Offset"] * params["Limit"]
        result = {
            key: items[offset : offset + params["Limit"]],
            "TotalCnt": len(items),
            "RequestId": str(len(calls)),
        }
        return mutate(action, params, result) if mutate else result

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect_clusters(runner, SPEC, REGION)
    return graph, calls


def resources(graph, kind):
    return [n for n in graph.nodes.values() if n["kind"] == kind]


def test_emr_metadata_explicit_links_icons_and_read_only_allowlist():
    graph, calls = run()
    c = resources(graph, "emr.cluster")[0]
    n = resources(graph, "emr.node")[0]
    assert c["properties"]["ClusterType"] == 0
    assert c["properties"]["state"] == "2"
    assert n["properties"]["DisableApiTermination"] is True
    assert n["properties"]["MemSize"] == 17179869184
    assert n["resource_id"] == "emr-1/EmrResourceId/emr-vm-1"
    assert all(x["account"] == "100" for x in graph.nodes.values())
    assert {e["relationship"] for e in graph.edges.values()} == {
        "IN_VPC",
        "IN_SUBNET",
        "HAS_NODE",
        "BACKED_BY",
    }
    assert all(icon_for(k) == "en-elastic-mapreduce.svg" for k in ("emr.cluster", "emr.node"))
    assert {a for s, a in ALLOWED_ACTIONS if s == "emr"} == {
        "DescribeInstancesList",
        "DescribeClusterNodes",
    }
    assert [p["NodeFlag"] for a, p in calls if a == "DescribeClusterNodes"] == [
        "all",
        "db",
        "recyle",
    ]
    assert [c["count"] for c in graph.coverage] == [1, 0, 1, 0, 0]


def test_tke_clusters_and_pods_use_tke_not_cvm_links():
    raw = {**node(), "HardwareResourceType": "POD", "TkeClusterId": "cls-tke"}
    graph, _ = run(clusters={0: [], 2: [cluster()]}, nodes={"all": [raw], "db": [], "recyle": []})
    assert resources(graph, "emr.cluster")[0]["properties"]["ClusterType"] == 2
    assert not resources(graph, "cvm.instance")
    assert resources(graph, "tke.cluster")[0]["resource_id"] == "cls-tke"


def test_zero_based_page_numbers_for_both_cluster_and_node_lists():
    graph, calls = run(
        clusters={0: [cluster(i) for i in range(101)], 2: []},
        nodes={"all": [], "db": [], "recyle": []},
    )
    assert [
        p["Offset"] for a, p in calls if a == "DescribeInstancesList" and p["ClusterType"] == 0
    ] == [0, 1]
    assert len(resources(graph, "emr.cluster")) == 101
    graph, calls = run(nodes={"all": [node(i) for i in range(101)], "db": [], "recyle": []})
    assert [
        p["Offset"] for a, p in calls if a == "DescribeClusterNodes" and p["NodeFlag"] == "all"
    ] == [0, 1]
    assert len(resources(graph, "emr.node")) == 101


def test_multizone_default_subnet_and_zone_do_not_become_single_placement():
    graph, _ = run(clusters={0: [{**cluster(), "IsMultiZoneCluster": True}], 2: []})
    c = resources(graph, "emr.cluster")[0]
    assert not c["properties"]["zone"]
    assert c["properties"]["Zone"] == "eu-frankfurt-1"
    assert {e["relationship"] for e in graph.edges.values() if e["source"] == c["id"]} == {
        "IN_VPC",
        "CONFIGURED_SUBNET",
        "HAS_NODE",
    }


def test_numeric_legacy_network_ids_do_not_produce_network_references():
    c = {**cluster(), "UniqVpcId": "", "UniqSubnetId": ""}
    graph, _ = run(clusters={0: [c], 2: []}, nodes={"all": [], "db": [], "recyle": []})
    assert not graph.edges
    assert resources(graph, "emr.cluster")[0]["properties"]["VpcId"] == 123


def test_database_nodes_serial_fallback_and_isolation_view_overlap():
    raw = {
        **node(),
        "EmrResourceId": "",
        "HardwareResourceType": "MNode",
        "CdbNodeInfo": dict(
            InstanceName="metadata",
            Ip="10.0.3.4",
            Port=3306,
            Status=1,
            ExpireFlag=False,
            Password="unexpected-omit",
        ),
    }
    graph, _ = run(nodes={"all": [], "db": [raw], "recyle": [raw]})
    n = resources(graph, "emr.node")[0]
    assert len(resources(graph, "emr.node")) == 1
    assert n["resource_id"] == "emr-1/SerialNo/serial-1"
    assert json.loads(n["properties"]["inventory_node_flags"]) == ["db", "recyle"]
    assert json.loads(n["properties"]["CdbNodeInfo"])["InstanceName"] == "metadata"
    assert not resources(graph, "cdb.instance") and not resources(graph, "cvm.instance")
    assert "unexpected-omit" not in graph.dump()


def test_nodes_scoped_to_their_cluster_even_when_native_ids_repeat():
    graph, _ = run(clusters={0: [cluster(1), cluster(2)], 2: []})
    assert len(resources(graph, "emr.node")) == 2


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"ClusterId": "ins-wrong"}, "InvalidEmrIdentity"),
        ({"IsMultiZoneCluster": 1}, "InvalidEmrField"),
        ({"Status": True}, "InvalidEmrField"),
        ({"Zone": "ap-guangzhou-1"}, "EmrZoneMismatch"),
        ({"UniqVpcId": 123}, "InvalidEmrIdentity"),
        ({"MasterIp": "not-an-ip"}, "InvalidEmrAddress"),
        ({"Tags": [{"TagKey": "a", "TagValue": {}}]}, "InvalidEmrTags"),
    ],
)
def test_invalid_cluster_fails_before_graph_mutation(patch, error):
    graph, _ = run(clusters={0: [{**cluster(), **patch}], 2: []})
    assert not graph.nodes
    assert graph.coverage[0]["error"] == error
    assert graph.coverage[0]["count"] == 0


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"ClusterId": "emr-other"}, "EmrClusterMismatch"),
        ({"AppId": 99}, "EmrScopeMismatch"),
        ({"RegionId": 99}, "EmrScopeMismatch"),
        ({"Zone": "ap-guangzhou-1"}, "EmrZoneMismatch"),
        ({"EmrResourceId": "", "SerialNo": ""}, "InvalidEmrIdentity"),
        ({"HardwareResourceType": []}, "InvalidEmrHardwareType"),
        ({"SubnetInfo": []}, "InvalidEmrSubnet"),
        ({"SubnetInfo": {"SubnetId": "vpc-wrong"}}, "InvalidEmrIdentity"),
        ({"CdbNodeInfo": []}, "InvalidEmrDatabaseMetadata"),
        ({"DisableApiTermination": "true"}, "InvalidEmrField"),
    ],
)
def test_invalid_child_is_partial_without_inferred_links(patch, error):
    graph, _ = run(nodes={"all": [{**node(), **patch}], "db": [], "recyle": []})
    assert not resources(graph, "emr.node")
    assert not resources(graph, "cvm.instance")
    assert graph.coverage[2]["error"] == error
    assert graph.coverage[2]["count"] == 0


def test_denied_child_scope_does_not_suppress_database_or_isolated_nodes():
    graph, calls = run(
        nodes={"all": CollectionError("AccessDenied"), "db": [node(2)], "recyle": [node(3)]}
    )
    assert graph.coverage[2]["status"] == "denied"
    assert len(resources(graph, "emr.node")) == 2
    assert len(calls) == 5


def test_duplicate_rows_are_partial_and_do_not_inflate_count():
    graph, _ = run(nodes={"all": [node(), node()], "db": [], "recyle": []})
    assert graph.coverage[2]["error"] == "DuplicateEmrNode"
    assert graph.coverage[2]["count"] == 1
    graph, _ = run(clusters={0: [cluster()], 2: [cluster()]})
    assert graph.coverage[1]["error"] == "DuplicateEmrCluster"
    assert len(resources(graph, "emr.cluster")) == 1


@pytest.mark.parametrize(
    "change,error",
    [
        (lambda r: {**r, "TotalCnt": None}, "InvalidTotal"),
        (lambda r: {**r, "InstancesList": None}, "InvalidResponse"),
        (lambda r: {**r, "TotalCnt": 2, "InstancesList": []}, "IncompletePagination"),
    ],
)
def test_missing_total_null_array_and_premature_empty_are_not_complete(change, error):
    graph, _ = run(mutate=lambda a, p, r: change(r) if a == SPEC.action else r)
    assert graph.coverage[0]["error"] == error


def test_only_selected_metadata_survives_no_nested_network_inference():
    c = {**cluster(), "ConfigDetail": {"VpcId": "vpc-foreign"}, "MetaDataPass": "never-persist"}
    n = {
        **node(),
        "DynamicPodSpec": "never-persist",
        "DetectDetail": "never-persist",
        "Other": {"SubnetId": "subnet-foreign"},
    }
    graph, _ = run(clusters={0: [c], 2: []}, nodes={"all": [n], "db": [], "recyle": []})
    assert "never-persist" not in graph.dump() and "foreign" not in graph.dump()


def test_overlapping_views_with_changed_placement_do_not_create_conflicting_links():
    changed = {**node(), "OrderNo": "ins-other", "SubnetInfo": {"SubnetId": "subnet-other"}}
    graph, _ = run(nodes={"all": [node()], "db": [], "recyle": [changed]})
    assert graph.coverage[-1]["error"] == "EmrNodeChangedBetweenViews"
    assert graph.coverage[-1]["count"] == 0
    assert resources(graph, "emr.node")[0]["properties"]["OrderNo"] == "ins-1"
    assert not any(n["resource_id"] in {"ins-other", "subnet-other"} for n in graph.nodes.values())
