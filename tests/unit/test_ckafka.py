import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.ckafka import TOPICS, collect_instance
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.observability import configuration as audit_config
from tencent_cloud_cartography.observability import link_destinations
from tencent_cloud_cartography.scf import link_trigger_sources
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPEC = next(s for s in COLLECTORS if s.kind == "ckafka.instance")


def runner(graph, call):
    return CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def topic(i=1):
    return dict(TopicId=f"topic-{i}", TopicName=f"events-{i}")


def attributes(i=1):
    return dict(
        TopicId=f"topic-{i}",
        PartitionNum=1,
        ReplicaNum=2,
        Partitions=[dict(Partition=0, LeaderStatus=0, IsrNum=2, ReplicaNum=2)],
        EnableWhiteList=1,
        IpWhiteList=["10.0.0.0/24"],
        EnableAclRule=1,
        Config=dict(Retention=86400000, MinInsyncReplicas=2, CleanUpPolicy="delete"),
        QuotaConfig=dict(QuotaProducerByteRate=1000),
        AclRuleList=[
            dict(
                InstanceId="ckafka-1",
                RuleName="readers",
                Pattern="events-",
                PatternType="PREFIXED",
                AclList="unparsed",
                Password="excluded",
            )
        ],
    )


def graph_instance():
    g = Graph()
    nid = g.native("100", REGION, SPEC, dict(InstanceId="ckafka-1", InstanceName="Queue"), "test")
    return g, nid


def call(action, params, count=1):
    if action == "DescribeInstanceAttributes":
        return dict(
            Result=dict(
                InstanceId=params["InstanceId"],
                VpcId="vpc-1",
                SubnetId="subnet-1",
                CustomCertId="cert1",
                ZoneIds=[200001],
                Status=1,
                VipList=[dict(Vip="10.0.0.7", Vport="9092", Password="excluded")],
                Config=dict(AutoCreateTopicsEnable=False, DefaultNumPartitions=3),
            )
        )
    if action == "DescribeTopic":
        assert params["Limit"] == 50
        offset = params["Offset"]
        return dict(
            Result=dict(
                TopicList=[topic(i) for i in range(offset + 1, min(offset + 50, count) + 1)],
                TotalCount=count,
            ),
            RequestId=f"page-{offset}",
        )
    if action == "DescribeTopicAttributes":
        return dict(Result=attributes(int(params["TopicName"].split("-")[-1])), RequestId="detail")
    raise AssertionError(action)


def test_metadata_network_partitions_and_payload_exclusion():
    g, nid = graph_instance()
    collect_instance(runner(g, lambda s, a, region=None, **p: call(a, p)), nid)
    topic_node = next(n for n in g.nodes.values() if n["kind"] == "ckafka.topic")
    props = topic_node["properties"]
    assert topic_node["resource_id"] == "ckafka-1/topic-1"
    assert json.loads(props["Config"])["Retention"] == 86400000
    assert props["detail_collected"] and not props["access_verified"]
    assert props["acl_entries_collected"] is False
    assert {e["relationship"] for e in g.edges.values()} == {
        "IN_VPC",
        "IN_SUBNET",
        "USES_CERTIFICATE",
        "HAS_TOPIC",
        "HAS_PARTITION",
    }
    assert "excluded" not in json.dumps(g.nodes) and "unparsed" not in json.dumps(g.nodes)
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())
    cert = next(n for n in g.nodes.values() if n["kind"] == "ssl.certificate")
    assert cert["region"] == "global"


def test_51_topics_use_50_item_pages_and_per_topic_details():
    g, nid = graph_instance()
    calls = []

    def transport(s, a, region=None, **p):
        calls.append((a, p))
        return call(a, p, count=51)

    collect_instance(runner(g, transport), nid)
    assert [p["Offset"] for a, p in calls if a == "DescribeTopic"] == [0, 50]
    assert len([a for a, p in calls if a == "DescribeTopicAttributes"]) == 51
    listing = next(c for c in g.coverage if c["action"] == "DescribeTopic")
    assert listing["count"] == 51 and listing["request_ids"] == ["page-0", "page-50"]


@pytest.mark.parametrize(
    "alter,error",
    [
        (lambda d: d.update(TopicId="topic-other"), "KafkaDetailIdentityMismatch"),
        (lambda d: d.update(PartitionNum=2), "KafkaPartitionCountMismatch"),
        (lambda d: d.update(Partitions=[dict(Partition=True)]), "InvalidKafkaPartitionId"),
        (
            lambda d: d.update(Partitions=[dict(Partition=0), dict(Partition=0)], PartitionNum=2),
            "InvalidKafkaPartitionId",
        ),
        (
            lambda d: d.update(AclRuleList=[dict(InstanceId="ckafka-other")]),
            "KafkaInstanceMismatch",
        ),
    ],
)
def test_invalid_details_are_partial(alter, error):
    g, nid = graph_instance()

    def transport(s, a, region=None, **p):
        result = call(a, p)
        if a == "DescribeTopicAttributes":
            alter(result["Result"])
        return result

    collect_instance(runner(g, transport), nid)
    assert g.coverage[-1]["error"] == error
    node = next(n for n in g.nodes.values() if n["kind"] == "ckafka.topic")
    assert "detail_collected" not in node["properties"]


def test_parent_scope_and_duplicate_topic_names():
    g = Graph()
    for instance in ("ckafka-1", "ckafka-2"):
        runner(g, lambda *a, **kw: dict(Result=dict(TopicList=[topic()], TotalCount=1))).native(
            TOPICS, REGION, dict(InstanceId=instance)
        )
    assert len(g.nodes) == 2
    runner(
        g,
        lambda *a, **kw: dict(
            Result=dict(TopicList=[topic(), {**topic(2), "TopicName": "events-1"}], TotalCount=2)
        ),
    ).native(TOPICS, REGION, dict(InstanceId="ckafka-3"))
    assert g.coverage[-1]["error"] == "DuplicateKafkaResource"


@pytest.mark.parametrize(
    "response,error",
    [
        (dict(Result=dict(TopicList=[])), "InvalidTotal"),
        (dict(Result=dict(TopicList=[], TotalCount=True)), "InvalidTotal"),
        (dict(Result=dict(TopicList=[], TotalCount=1)), "IncompletePagination"),
        (
            dict(Result=dict(TopicList=[{**topic(), "InstanceId": "ckafka-2"}], TotalCount=1)),
            "KafkaInstanceMismatch",
        ),
    ],
)
def test_invalid_list_is_partial(response, error):
    g = Graph()
    runner(g, lambda *a, **kw: response).native(TOPICS, REGION, dict(InstanceId="ckafka-1"))
    assert g.coverage[-1]["error"] == error


def test_denied_details_do_not_prevent_other_topics_or_instances():
    class Transport:
        def call(self, s, a, region=None, **p):
            if s == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if s == "cloudrc":
                return dict(Resources=[])
            if a == "DescribeInstances":
                return dict(
                    Result=dict(
                        InstanceList=[dict(InstanceId="ckafka-1"), dict(InstanceId="ckafka-2")],
                        TotalCount=2,
                    )
                )
            if a == "DescribeInstanceAttributes":
                raise CollectionError("UnauthorizedOperation")
            if a == "DescribeTopicAttributes" and p["TopicName"] == "events-1":
                raise CollectionError("OperationDenied")
            data = call(a, p, count=2)
            if a == "DescribeTopicAttributes":
                data["Result"]["AclRuleList"] = []
            return data

    data = collect(
        ["test"],
        [REGION],
        services={"ckafka"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert data["status"] == "partial"
    assert len([c for c in data["coverage"] if c["status"] == "denied"]) == 4
    assert (
        len(
            [
                n
                for n in data["nodes"]
                if n["kind"] == "ckafka.topic" and n["properties"].get("detail_collected")
            ]
        )
        == 2
    )


@pytest.mark.parametrize(
    "account,region,linked",
    [("100", REGION, True), ("200", REGION, False), ("100", "ap-guangzhou", False)],
)
def test_audit_and_scf_link_only_collected_topic_in_correct_scope(account, region, linked):
    g, nid = graph_instance()
    collect_instance(runner(g, lambda s, a, region=None, **p: call(a, p)), nid)
    audit = g.add(account, region, "cloudaudit.track", "1")
    audit_config(
        g,
        audit,
        dict(
            Storage=dict(
                StorageType="ckafka", StorageRegion=region, StorageName="ckafka-1/events-1"
            )
        ),
        "fixture",
    )
    trigger = g.add(account, region, "scf.trigger", "trigger", raw={})
    g.nodes[trigger]["properties"].update(
        trigger_type="ckafka", TriggerName="ckafka-1-events-1", configuration="{}"
    )
    link_destinations(g)
    link_trigger_sources(g)
    assert g.nodes[trigger]["properties"]["event_topic_resolved"] is linked
    assert any(e["source"] == audit for e in g.edges.values()) is linked


@pytest.mark.parametrize(
    "action",
    [
        "FetchMessageByOffset",
        "FetchMessageListByOffset",
        "FetchMessageListByTimestamp",
        "DescribeUser",
    ],
)
def test_message_and_credential_apis_remain_blocked(action):
    assert ("ckafka", action) not in ALLOWED_ACTIONS


@pytest.mark.parametrize("bad", ["wrong-instance", "null-partitions", "nested-config"])
def test_detail_binding_and_configuration_boundaries(bad):
    g, nid = graph_instance()

    def transport(s, a, region=None, **params):
        response = call(a, params)
        if a == "DescribeInstanceAttributes" and bad == "wrong-instance":
            response["Result"]["InstanceId"] = "ckafka-other"
        if a == "DescribeTopicAttributes" and bad == "null-partitions":
            response["Result"]["Partitions"] = None
        if bad == "nested-config":
            response["Result"]["Unexpected"] = dict(VpcId="vpc-wrong", Password="hidden")
        return response

    collect_instance(runner(g, transport), nid)
    if bad == "wrong-instance":
        assert g.coverage[0]["error"] == "KafkaDetailIdentityMismatch"
        assert "detail_collected" not in g.nodes[nid]["properties"]
        assert not any(n["kind"] == "vpc.vpc" for n in g.nodes.values())
        assert any(n["kind"] == "ckafka.partition" for n in g.nodes.values())
    elif bad == "null-partitions":
        assert g.coverage[-1]["error"] == "InvalidKafkaPartitions"
    else:
        assert "vpc-wrong" not in json.dumps(g.nodes) and "hidden" not in json.dumps(g.nodes)
        assert all(c["status"] == "complete" for c in g.coverage)
