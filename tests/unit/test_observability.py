import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.observability import collect_track_details, link_destinations
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
OTHER = "ap-guangzhou"
KEY = "11111111-2222-3333-4444-555555555555"
SPECS = {s.kind: s for s in COLLECTORS if s.service in {"cls", "cloudaudit"}}


def track(tid=1, **extra):
    return dict(
        TrackId=tid,
        Name="audit-" + str(tid),
        ActionType="Write",
        ResourceType="cam",
        Status=0,
        EventNames=["CreateUser"],
        Storage=dict(
            StorageType="cos", StorageRegion=OTHER, StorageName="audit-logs", StorageAppId="12345"
        ),
        **extra,
    )


def runner(graph, call):
    return CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def add(graph, kind, raw, owner="100", region=REGION):
    return graph.native(
        owner, region, SPECS[kind], raw, SPECS[kind].service + "." + SPECS[kind].action
    )


def test_audit_page_numbers_and_independent_details():
    graph, calls = Graph(), []

    def call(service, action, region, **params):
        calls.append((action, params))
        if action == "DescribeAuditTracks":
            assert params["PageSize"] == 10
            rows = [track(i) for i in range(1, 11)] if params["PageNumber"] == 1 else [track(11)]
            return dict(Tracks=rows, TotalCount=11, RequestId="page-" + str(params["PageNumber"]))
        if params["TrackId"] == 2:
            raise CollectionError("UnauthorizedOperation")
        data = track(params["TrackId"])
        del data["TrackId"]
        data.update(
            TrackForAllMembers=1,
            Filters={"ResourceFields": [dict(ResourceType="cam", ActionType="*", EventNames=[""])]},
            RequestId="detail",
        )
        return data

    r = runner(graph, call)
    collected = r.native(SPECS["cloudaudit.track"], REGION)
    collect_track_details(r, collected)
    assert len(collected) == 11 and calls[1] == (
        "DescribeAuditTracks",
        {"PageNumber": 2, "PageSize": 10},
    )
    assert len(graph.coverage) == 12 and sum(c["status"] == "denied" for c in graph.coverage) == 1
    assert graph.coverage[0]["request_ids"] == ["page-1", "page-2"]
    first = graph.nodes[collected[0][0]]["properties"]
    assert first["Status"] == 0 and first["TrackForAllMembers"] == 1
    assert json.loads(first["event_filters"])[0]["EventNames"] == [""]
    assert first["delivery_verified"] is False


def test_audit_detail_name_change_does_not_overwrite_list():
    graph = Graph()
    original = track()
    nid = add(graph, "cloudaudit.track", original)
    collect_track_details(
        runner(graph, lambda *a, **kw: {**track(), "Name": "changed"}), [(nid, original)]
    )
    assert graph.coverage[-1]["error"] == "AuditTrackChanged"
    assert "detail_collected" not in graph.nodes[nid]["properties"]


@pytest.mark.parametrize(
    "owner,region,appid,expected",
    [
        ("100", OTHER, "12345", "resolved"),
        ("12345", OTHER, "12345", "unresolved"),
        ("100", REGION, "12345", "unresolved"),
        ("100", OTHER, "wrong", "unresolved"),
    ],
)
def test_audit_cos_requires_account_region_and_appid(owner, region, appid, expected):
    graph = Graph()
    raw = track()
    raw["Storage"]["StorageAppId"] = appid
    nid = add(graph, "cloudaudit.track", raw)
    bucket = graph.add(owner, region, "cos.bucket", "audit-logs-12345")
    link_destinations(graph)
    assert graph.nodes[nid]["properties"]["destination_resolution"] == expected
    assert any(e["target"] == bucket for e in graph.edges.values()) == (expected == "resolved")


def test_audit_cross_account_cls_reference_and_no_event_payload():
    graph = Graph()
    raw = track()
    raw["Storage"] = dict(
        StorageType="cls",
        StorageName="topic-foreign",
        StorageRegion=OTHER,
        StorageAccountId="999",
        StorageAppId="12345",
        SecretKey="exclude-me",
    )
    raw["EventContent"] = "exclude-me"
    nid = add(graph, "cloudaudit.track", raw)
    link_destinations(graph)
    dest = next(n for n in graph.nodes.values() if n["kind"] == "cls.topic")
    assert dest["account"] == "999" and dest["region"] == OTHER and dest["status"] == "reference"
    assert graph.nodes[nid]["properties"]["destination_resolution"] == "reference"
    assert "exclude-me" not in graph.dump()


def fixture():
    graph = Graph(mode="demo")
    graph.accounts["100"] = {"id": "100", "display": "Logging synthetic validation"}
    bucket = graph.add("100", OTHER, "cos.bucket", "audit-logs-12345")
    add(graph, "cls.logset", dict(LogsetId="set-one", LogsetName="audit-logs", TopicCount=1))
    topic = add(
        graph,
        "cls.topic",
        dict(
            TopicId="topic-one",
            TopicName="audit-events",
            LogsetId="set-one",
            BizType=0,
            Period=30,
            HotPeriod=7,
            Index=True,
            Status=False,
            IsWebTracking=False,
            CustomKmsInfo={"KmsRegion": OTHER, "KmsKeyId": KEY, "KeyMaterial": "exclude-me"},
        ),
    )
    shipper = add(
        graph,
        "cls.shipper",
        dict(
            ShipperId="ship-one",
            ShipperName="archive",
            TopicId="topic-one",
            Bucket="audit-logs-12345",
            Status=False,
            TaskStatus=0,
            Interval=300,
            Prefix="audit/",
            ExternalId="exclude-me",
            Content={"body": "exclude-me"},
        ),
    )
    raw = track()
    raw["Storage"] = dict(StorageType="cls", StorageRegion=REGION, StorageName="topic-one")
    audit = add(graph, "cloudaudit.track", raw)
    link_destinations(graph)
    return graph, bucket, topic, shipper, audit


def test_cls_logset_topic_kms_shipper_and_audit_chain():
    graph, bucket, topic, shipper, audit = fixture()
    edges = list(graph.edges.values())
    assert len(graph.nodes) == 6 and len(edges) == 5
    assert any(e["source"] == shipper and e["target"] == bucket for e in edges)
    assert any(e["source"] == audit and e["target"] == topic for e in edges)
    key = next(n for n in graph.nodes.values() if n["kind"] == "kms.key")
    assert key["region"] == OTHER
    assert graph.nodes[topic]["properties"]["Period"] == 30
    assert graph.nodes[shipper]["properties"]["Status"] is False
    assert "exclude-me" not in graph.dump()
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())


def test_topic_categories_are_separately_requested_by_runner():
    graph, calls = Graph(), []

    def call(service, action, region=None, **params):
        if service == "cloudrc":
            return dict(Resources=[])
        calls.append((action, params))
        if action == "DescribeTopics":
            kind = params["BizType"]
            return dict(
                Topics=[
                    dict(
                        TopicId="topic-" + str(kind),
                        TopicName="metrics" if kind else "logs",
                        LogsetId="set-one",
                        BizType=kind,
                    )
                ],
                TotalCount=1,
            )
        spec = next(s for s in SPECS.values() if s.action == action)
        return {spec.result: [], "TotalCount": 0}

    runner(graph, call).run({"cls"})
    assert [p["BizType"] for a, p in calls if a == "DescribeTopics"] == [0, 1]
    assert {
        n["properties"]["BizType"] for n in graph.nodes.values() if n["kind"] == "cls.topic"
    } == {0, 1}


@pytest.mark.parametrize("biz", [None, 0, True])
def test_missing_wrong_or_boolean_topic_category_fails_closed(biz):
    graph = Graph()
    r = runner(
        graph, lambda *a, **kw: dict(Topics=[dict(TopicId="wrong", BizType=biz)], TotalCount=1)
    )
    r.native(SPECS["cls.topic"], REGION, {"BizType": 1})
    assert graph.coverage[-1]["error"] == "TopicTypeMismatch" and not graph.nodes


@pytest.mark.parametrize("tid", [0, -1, "1", True])
def test_invalid_audit_track_ids_never_become_detail_targets(tid):
    graph = Graph()
    r = runner(graph, lambda *a, **kw: dict(Tracks=[track(tid)], TotalCount=1))
    assert r.native(SPECS["cloudaudit.track"], REGION) == []
    assert graph.coverage[-1]["error"] == "InvalidAuditTrackId"


def test_duplicate_bucket_identity_is_ambiguous_not_arbitrary():
    graph, bucket, _, shipper, _ = fixture()
    graph.add("999", REGION, "cos.bucket", graph.nodes[bucket]["resource_id"])
    # A fresh snapshot would perform resolution only once; clear derived links for this control.
    graph.edges = {eid: e for eid, e in graph.edges.items() if e["source"] != shipper}
    link_destinations(graph)
    assert graph.nodes[shipper]["properties"]["destination_resolution"] == "ambiguous"
    assert not any(e["source"] == shipper for e in graph.edges.values())


@pytest.mark.parametrize("parent_owner,expected", [("100", "resolved"), ("999", "unresolved")])
def test_kafka_destination_requires_scoped_instance_membership(parent_owner, expected):
    graph = Graph()
    raw = track()
    raw["Storage"] = dict(
        StorageType="ckafka", StorageRegion=REGION, StorageName="ckafka-one/events"
    )
    nid = add(graph, "cloudaudit.track", raw)
    instance = graph.add(parent_owner, REGION, "ckafka.instance", "ckafka-one")
    topic = graph.add("100", REGION, "ckafka.topic", "topic-id", "events")
    graph.edge(instance, topic, "HAS_TOPIC")
    link_destinations(graph)
    assert graph.nodes[nid]["properties"]["destination_resolution"] == expected
    assert any(e["source"] == nid for e in graph.edges.values()) == (expected == "resolved")
