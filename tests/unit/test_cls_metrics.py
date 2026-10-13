import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPEC = next(s for s in COLLECTORS if s.kind == "cls.scheduledsql")


def task(i=1, **extra):
    return dict(
        TaskId=f"task-{i}",
        Name="Error metrics",
        SrcTopicId="source-topic",
        SrcTopicRegion=REGION,
        ScheduledSqlContent="status:500 | select count(*) as errors",
        EnableFlag=2,
        Status=5,
        ProcessPeriod=30,
        ProcessPeriodUnit=2,
        ProcessTimeWindow="@m-5m,@m",
        ProcessDelay=60,
        ProcessType=1,
        DstResource=dict(
            TopicId="metrics-topic",
            Region=REGION,
            BizType=1,
            MetricName="legacy",
            MetricNames=["errors", "requests"],
            MetricLabels=["service"],
            CustomTime="timestamp",
            CustomMetricLabels=[dict(Key="environment", Value="prod")],
        ),
        **extra,
    )


def add(g, raw, account="100", region=REGION):
    return g.native(account, region, SPEC, raw, "cls.DescribeScheduledSqlInfo")


def run(g, response):
    r = CollectorRunner(
        g, SimpleNamespace(call=lambda *a, **kw: response), "100", [REGION], lambda _: None
    )
    return r.native(SPEC, REGION)


def test_metric_mapping_precedence_schedule_and_disabled_state():
    g = Graph()
    nid = add(g, task())
    props = g.nodes[nid]["properties"]
    assert props["EnableFlag"] == 2 and props["Status"] == 5
    assert props["ProcessPeriodUnit"] == 2 and props["ProcessPeriod"] == 30
    assert props["ScheduledSqlContent"] == task()["ScheduledSqlContent"]
    config = json.loads(props["destination_configuration"])
    assert config["CustomMetricLabels"] == [{"Key": "environment", "Value": "prod"}]
    assert config["MetricName"] == "legacy" and config["CustomTime"] == "timestamp"
    metrics = [n for n in g.nodes.values() if n["kind"] == "cls.metric"]
    assert {n["name"] for n in metrics} == {"errors", "requests"}
    assert all(
        n["properties"]["configuration_only"] and not n["properties"]["samples_observed"]
        for n in metrics
    )
    assert len(g.edges) == 6
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


@pytest.mark.parametrize(
    "biz_type,metric_names,expected", [(1, [], ["legacy"]), (0, ["ignored"], [])]
)
def test_legacy_single_metric_and_log_destinations(biz_type, metric_names, expected):
    g = Graph()
    raw = task()
    raw["DstResource"].update(BizType=biz_type, MetricNames=metric_names)
    add(g, raw)
    assert [n["name"] for n in g.nodes.values() if n["kind"] == "cls.metric"] == expected
    assert any(e["relationship"] == "CONFIGURED_OUTPUT_TOPIC" for e in g.edges.values())


def test_shared_metric_keeps_each_producers_labels_separate():
    g = Graph()
    first = task()
    second = task(2)
    first["DstResource"]["MetricNames"] = ["errors"]
    second["DstResource"].update(
        MetricNames=["errors"], CustomMetricLabels=[dict(Key="environment", Value="test")]
    )
    n1, n2 = add(g, first), add(g, second)
    assert len([n for n in g.nodes.values() if n["kind"] == "cls.metric"]) == 1
    for nid, value in [(n1, "prod"), (n2, "test")]:
        assert (
            json.loads(g.nodes[nid]["properties"]["destination_configuration"])[
                "CustomMetricLabels"
            ][0]["Value"]
            == value
        )
    assert len([e for e in g.edges.values() if e["relationship"] == "DECLARES_METRIC_OUTPUT"]) == 2


def test_explicit_regions_and_account_isolation():
    g = Graph()
    raw = task()
    raw["SrcTopicRegion"] = "ap-guangzhou"
    raw["DstResource"].update(Region="ap-shanghai", MetricNames=["errors"])
    add(g, raw)
    add(g, raw, account="200")
    topics = [n for n in g.nodes.values() if n["kind"] == "cls.topic"]
    assert {(n["account"], n["region"], n["resource_id"]) for n in topics} == {
        (a, r, t)
        for a in ("100", "200")
        for r, t in (("ap-guangzhou", "source-topic"), ("ap-shanghai", "metrics-topic"))
    }
    assert all(
        g.nodes[e["source"]]["account"] == g.nodes[e["target"]]["account"] for e in g.edges.values()
    )
    assert len([n for n in g.nodes.values() if n["kind"] == "cls.metric"]) == 2


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("Region", "", "InvalidScheduledSqlRegion"),
        ("Region", "global", "InvalidScheduledSqlRegion"),
        ("BizType", True, "InvalidScheduledSqlTopicType"),
        ("BizType", 2, "InvalidScheduledSqlTopicType"),
        ("MetricNames", ["errors", "errors"], "DuplicateScheduledMetricName"),
        ("MetricNames", [""], "MissingScheduledMetricName"),
        (
            "CustomMetricLabels",
            [{"Key": "env", "Value": "prod"}, {"Key": "env", "Value": "test"}],
            "InvalidScheduledMetricLabels",
        ),
    ],
)
def test_invalid_destination_is_partial_without_dependency_edges(field, value, error):
    g = Graph()
    raw = task()
    raw["DstResource"][field] = value
    run(g, dict(ScheduledSqlTaskInfos=[raw], TotalCount=1))
    assert g.coverage[-1]["error"] == error and not g.edges


def test_missing_source_region_is_not_inferred_from_cli():
    g = Graph()
    raw = task()
    del raw["SrcTopicRegion"]
    run(g, dict(ScheduledSqlTaskInfos=[raw], TotalCount=1))
    assert g.coverage[-1]["error"] == "InvalidScheduledSqlRegion" and not g.edges


def test_pagination_duplicate_and_truncation_controls():
    g, offsets = Graph(), []

    def call(*a, **kw):
        offset = kw["Offset"]
        offsets.append(offset)
        return dict(
            ScheduledSqlTaskInfos=[task(i) for i in range(offset, min(offset + 100, 101))],
            TotalCount=101,
            RequestId=str(offset),
        )

    CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None).native(
        SPEC, REGION
    )
    assert offsets == [0, 100] and g.coverage[-1]["count"] == 101
    assert g.coverage[-1]["request_ids"] == ["0", "100"]
    for response, error in [
        (dict(ScheduledSqlTaskInfos=[task(), task()], TotalCount=2), "DuplicateScheduledSqlTask"),
        (dict(ScheduledSqlTaskInfos=[], TotalCount=1), "IncompletePagination"),
        (dict(ScheduledSqlTaskInfos=[]), "InvalidTotal"),
    ]:
        run(g, response)
        assert g.coverage[-1]["error"] == error


def test_unknown_payload_fields_do_not_create_fake_links_or_persist_values():
    g = Graph()
    raw = task(InternalPayload=dict(InstanceId="ins-fake", PrivateIpAddress="SENSITIVE_SENTINEL"))
    raw["DstResource"]["Secret"] = "SENSITIVE_SENTINEL"
    add(g, raw)
    assert "SENSITIVE_SENTINEL" not in json.dumps(g.snapshot())
    assert not any(n["kind"] == "cvm.instance" for n in g.nodes.values())


def test_collection_continues_after_one_region_is_denied():
    class Transport:
        def call(self, service, action, region=None, **params):
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == SPEC.action:
                if region == "ap-guangzhou":
                    raise CollectionError("OperationDenied.ACLFailed")
                return dict(ScheduledSqlTaskInfos=[task()], TotalCount=1)
            spec = next(s for s in COLLECTORS if s.service == service and s.action == action)
            return {spec.result: [], "TotalCount": 0}

    data = collect(
        ["test"],
        ["ap-guangzhou", REGION],
        services={"cls"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    scopes = [c for c in data["coverage"] if c["action"] == SPEC.action]
    assert [c["status"] for c in scopes] == ["denied", "complete"]
    assert any(n["kind"] == "cls.scheduledsql" for n in data["nodes"])
