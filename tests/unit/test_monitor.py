import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.monitor import collect_bindings, link_bindings
from tencent_cloud_cartography.transport import CollectionError

SPEC = next(s for s in COLLECTORS if s.kind == "monitor.policy")
REGION = "eu-frankfurt"


def policy(i=1, **extra):
    return dict(
        PolicyId=f"policy-{i}",
        PolicyName="CPU threshold",
        MonitorType="MT_QCE",
        Namespace="cvm_device",
        Enable=0,
        Region=["de", "gz"],
        **extra,
    )


def runner(graph, call):
    return CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def add(graph, raw):
    return graph.native("100", "global", SPEC, raw, "monitor.DescribeAlarmPolicies")


def binding(i=1, **extra):
    return dict(
        UniqueId=str(i),
        Dimensions=json.dumps({"unInstanceId": f"ins-{i}"}),
        Region="de",
        IsShielded=1,
        **extra,
    )


def bind(graph, nid, rows):
    collect_bindings(runner(graph, lambda *a, **kw: dict(List=rows, Total=len(rows))), [(nid, {})])
    link_bindings(graph)


def test_policy_conditions_notice_metadata_and_sensitive_field_exclusion():
    graph = Graph()
    nid = add(
        graph,
        policy(
            Condition=dict(
                IsUnionRule=2,
                ComplexExpression="1 && 2",
                Rules=[
                    dict(
                        MetricName="CpuUsage",
                        Operator="gt",
                        Value="80",
                        Period=60,
                        ContinuePeriod=5,
                        NoticeFrequency=300,
                        IsPowerNotice=0,
                        Filter=dict(
                            Type="DIMENSION",
                            Dimensions='[[{"name":"unInstanceId","value":"ins-1"}]]',
                        ),
                        HierarchicalValue=dict(Remind="80", Warn="90", Serious="95"),
                        ValueMax=100.0,
                        Opaque="SENSITIVE_SENTINEL",
                    )
                ],
            ),
            EventCondition=dict(
                Rules=[dict(MetricName="ping_unreachable", Operator="eq", Value="1")]
            ),
            NoticeIds=["notice-1", "notice-ref"],
            Notices=[
                dict(
                    Id="notice-1",
                    Name="operations",
                    NoticeType="ALL",
                    NoticeLanguage="en-US",
                    UserNotices=[
                        dict(
                            NoticeWay=["EMAIL", "SMS"],
                            PhoneOrder=[123],
                            VoiceConfirmKey="SENSITIVE_SENTINEL",
                        )
                    ],
                    URLNotices=[
                        dict(
                            URL="https://example.test/SENSITIVE_SENTINEL",
                            ValidationCode="SENSITIVE_SENTINEL",
                        )
                    ],
                )
            ],
            HierarchicalNotices=[
                dict(PolicyId="policy-1", NoticeId="notice-1", Classification=["Serious"])
            ],
            TriggerTasks=[dict(Type="AS", TaskConfig="SENSITIVE_SENTINEL")],
        ),
    )
    props = graph.nodes[nid]["properties"]
    assert props["Enable"] == 0 and props["evaluation_verified"] is False
    assert json.loads(props["Condition"])["IsUnionRule"] == 2
    assert graph.nodes[nid]["region"] == "global"
    rules = [n for n in graph.nodes.values() if n["kind"] == "monitor.rule"]
    assert {n["properties"]["category"] for n in rules} == {"metric", "event"}
    metric = json.loads(
        next(n for n in rules if n["properties"]["category"] == "metric")["properties"][
            "configuration"
        ]
    )
    assert metric["HierarchicalValue"]["Serious"] == "95" and metric["Period"] == 60
    notices = {n["resource_id"]: n for n in graph.nodes.values() if n["kind"] == "monitor.notice"}
    assert notices["notice-ref"]["status"] == "reference"
    assert notices["notice-1"]["properties"]["callback_count"] == 1
    assert json.loads(notices["notice-1"]["properties"]["channels"]) == ["EMAIL", "SMS"]
    assert "SENSITIVE_SENTINEL" not in json.dumps(graph.snapshot())
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())


def test_page_number_policy_list_and_independent_binding_denial():
    graph, calls = Graph(), []

    def call(service, action, region, **params):
        calls.append((action, region, params))
        assert service == "monitor" and region == "global" and params["Module"] == "monitor"
        if action == "DescribeAlarmPolicies":
            page = params["PageNumber"]
            assert params["PageSize"] == 10
            rows = [policy(i) for i in range(1, 11)] if page == 1 else [policy(11)]
            return dict(Policies=rows, TotalCount=11, RequestId=str(page))
        assert params["GroupId"] == 0 and params["Offset"] == 0
        if params["PolicyId"] == "policy-2":
            raise CollectionError("UnauthorizedOperation")
        return dict(List=None, Total=0, RequestId="bindings")

    r = runner(graph, call)
    rows = r.native(SPEC, "global")
    collect_bindings(r, rows)
    assert len(rows) == 11 and len(graph.coverage) == 12
    assert graph.coverage[0]["request_ids"] == ["1", "2"]
    assert sum(c["status"] == "denied" for c in graph.coverage) == 1
    assert graph.nodes[rows[0][0]]["properties"]["bindings_collected"]
    assert "bindings_collected" not in graph.nodes[rows[1][0]]["properties"]


def test_binding_pagination_and_instance_group():
    graph, calls = Graph(), []
    nid = add(graph, policy())

    def call(service, action, region, **params):
        calls.append(params)
        offset = params["Offset"]
        rows = [binding(i) for i in range(offset + 1, min(offset + 100, 101) + 1)]
        return dict(
            List=rows,
            Total=101,
            InstanceGroup=dict(
                InstanceGroupId=7,
                GroupName="fleet",
                ViewName="cvm_device",
                InstanceSum=101,
                Regions=["de"],
            ),
            RequestId=str(offset),
        )

    collect_bindings(runner(graph, call), [(nid, {})])
    assert [c["Offset"] for c in calls] == [0, 100]
    assert graph.coverage[0]["count"] == 101 and graph.coverage[0]["status"] == "complete"
    assert graph.coverage[0]["request_ids"] == ["0", "100"]
    assert len([n for n in graph.nodes.values() if n["kind"] == "monitor.instancegroup"]) == 1


@pytest.mark.parametrize(
    "owner,region,namespace,dimension,binding_region,status,expected",
    [
        ("100", REGION, "cvm_device", "ins-1", "de", "enriched", "resolved"),
        ("100", REGION, "cvm_device", "ins-1", REGION, "enriched", "resolved"),
        ("200", REGION, "cvm_device", "ins-1", "de", "enriched", "unresolved"),
        ("100", "ap-guangzhou", "cvm_device", "ins-1", "de", "enriched", "unresolved"),
        ("100", REGION, "cdb", "ins-1", "de", "enriched", "unsupported-namespace"),
        ("100", REGION, "cvm_device", "cdb-1", "de", "enriched", "unsupported-dimensions"),
        ("100", REGION, "cvm_device", "ins-1", "unknown", "enriched", "unknown-region"),
        ("100", REGION, "cvm_device", "ins-1", "de", "reference", "unresolved"),
    ],
)
def test_binding_isolation_and_shielding(
    owner, region, namespace, dimension, binding_region, status, expected
):
    graph = Graph()
    raw = policy()
    raw["Namespace"] = namespace
    nid = add(graph, raw)
    cvm = graph.add(owner, region, "cvm.instance", "ins-1", status=status)
    row = {
        **binding(),
        "Dimensions": json.dumps({"unInstanceId": dimension}),
        "Region": binding_region,
    }
    bind(graph, nid, [row])
    target = next(n for n in graph.nodes.values() if n["kind"] == "monitor.binding")
    assert target["properties"]["IsShielded"] == 1
    assert target["properties"]["resource_resolution"] == expected
    edges = [e for e in graph.edges.values() if e["relationship"] == "CONFIGURED_ALARM_OBJECT"]
    assert len(edges) == (expected == "resolved")
    if edges:
        assert edges[0]["target"] == cvm


@pytest.mark.parametrize(
    "changes,error",
    [
        (
            {"Dimensions": '{"unInstanceId":"ins-1","unInstanceId":"ins-2"}'},
            "AmbiguousAlarmDimensions",
        ),
        ({"Dimensions": '[{"unInstanceId":"ins-1"}]'}, "InvalidAlarmDimensions"),
        ({"IsShielded": True}, "InvalidAlarmBinding"),
        ({"Region": ""}, "InvalidObservabilityIdentity"),
    ],
)
def test_malformed_binding_preserves_error_coverage(changes, error):
    graph = Graph()
    nid = add(graph, policy())
    bind(graph, nid, [{**binding(), **changes}])
    assert graph.coverage[-1]["status"] == "error" and graph.coverage[-1]["error"] == error
    assert not any(e["relationship"] == "CONFIGURED_ALARM_OBJECT" for e in graph.edges.values())


def test_changing_group_and_duplicate_binding_are_incomplete():
    for duplicate in (False, True):
        graph = Graph()
        nid = add(graph, policy())

        def call(*a, **params):
            offset = params["Offset"]
            group = 1 if not offset or duplicate else 2
            rows = (
                [binding(i) for i in range(1, 101)]
                if not offset
                else [binding(1 if duplicate else 101)]
            )
            return dict(List=rows, Total=101, InstanceGroup={"InstanceGroupId": group})

        collect_bindings(runner(graph, call), [(nid, {})])
        assert graph.coverage[-1]["error"] == (
            "DuplicateAlarmBinding" if duplicate else "InventoryChanged"
        )
        assert "bindings_collected" not in graph.nodes[nid]["properties"]


def test_monitor_only_run_links_collected_cvm_and_uses_one_account_scope():
    class Transport:
        def call(self, service, action, region=None, **params):
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if service == "monitor" and action == "DescribeAlarmPolicies":
                assert region == "global" and params["Module"] == "monitor"
                return dict(Policies=[policy()], TotalCount=1)
            if service == "monitor":
                return dict(List=[binding()], Total=1)
            raise AssertionError(action)

    data = collect(
        ["test"],
        [REGION, "ap-guangzhou"],
        services={"monitor"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert len([c for c in data["coverage"] if c["action"] == "DescribeAlarmPolicies"]) == 1
    assert any(n["kind"] == "monitor.binding" for n in data["nodes"])


@pytest.mark.parametrize(
    "rows,error",
    [
        ([{**policy(), "PolicyId": 1}], "InvalidAlarmPolicyId"),
        ([policy(), policy()], "DuplicateAlarmPolicy"),
    ],
)
def test_invalid_or_duplicate_policy_identity(rows, error):
    graph = Graph()
    runner(graph, lambda *a, **kw: dict(Policies=rows, TotalCount=len(rows))).native(SPEC, "global")
    assert graph.coverage[-1]["error"] == error


def test_truncated_bindings_and_missing_totals_remain_partial():
    for response, error in [
        (dict(List=[], Total=1), "IncompletePagination"),
        (dict(List=[]), "InvalidTotal"),
        (dict(List=None, Total=True), "InvalidResponse"),
    ]:
        graph = Graph()
        nid = add(graph, policy())
        collect_bindings(runner(graph, lambda *a, **kw: response), [(nid, {})])
        assert graph.coverage[-1]["error"] == error
        assert "bindings_collected" not in graph.nodes[nid]["properties"]


@pytest.mark.parametrize(
    "namespace,kind,key,rid",
    [
        ("cdb_detail", "cdb.instance", "uInstanceId", "cdb-one"),
        ("redis_mem_proxy", "redis.instance", "instanceid", "crs-one"),
        ("redis_mem_edition", "redis.instance", "InstanceId", "crs-one"),
        ("BS", "cbs.disk", "diskid", "disk-one"),
        ("cmongo_instance", "mongodb.instance", "target", "cmgo-one"),
        ("COS", "cos.bucket", "bucket", "bucket-12345"),
        ("nat_tc_stat", "vpc.nat", "uniq_nat_id", "nat-one"),
        ("DC_GW", "vpc.directconnectgateway", "directconnectgatewayid", "dcg-one"),
        ("vpc_region_conn", "vpc.peeringconnection", "peeringconnectionid", "pcx-one"),
        ("CKAFKA_INSTANCE", "ckafka.instance", "instance_id", "ckafka-one"),
        ("cfs_monitor", "cfs.filesystem", "FileSystemId", "cfs-one"),
        ("ces_monitor", "es.instance", "cluster_name", "es-one"),
        ("k8s_cluster2", "tke.cluster", "tke_cluster_instance_id", "cls-one"),
    ],
)
def test_documented_product_dimensions_link_only_exact_collected_owner_region(
    namespace, kind, key, rid
):
    graph = Graph()
    nid = graph.add("100", "global", "monitor.binding", "binding-one")
    graph.nodes[nid]["properties"].update(
        MonitorType="MT_QCE",
        Namespace=namespace,
        binding_region="de",
        dimensions=json.dumps({key: rid, "appid": "200"}),
    )
    graph.add("200", REGION, kind, rid)
    graph.add("100", "ap-guangzhou", kind, rid)
    link_bindings(graph)
    assert not graph.edges
    target = graph.add("100", REGION, kind, rid)
    link_bindings(graph)
    assert [e["target"] for e in graph.edges.values()] == [target]
    graph.nodes[nid]["properties"]["dimensions"] = json.dumps({key: "different"})
    link_bindings(graph)
    assert not graph.edges
