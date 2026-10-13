import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.cmq import SUBSCRIPTIONS, collect_resource, link_destinations
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPECS = {s.kind: s for s in (*COLLECTORS, SUBSCRIPTIONS) if s.service == "tdmq"}


def queue(i=1, **extra):
    return dict(
        QueueId=f"cmqq-{i}",
        QueueName=f"Queue-{i}",
        MsgRetentionSeconds=3600,
        VisibilityTimeout=30,
        PollingWaitSeconds=10,
        CreateUin=987,
        **extra,
    )


def topic(i=1):
    return dict(
        TopicId=f"cmqt-{i}",
        TopicName=f"Topic-{i}",
        FilterType=2,
        MsgRetentionSeconds=86400,
        SubscriptionCount=1,
    )


def subscription(i=1, **extra):
    return dict(
        SubscriptionId=f"subsc-{i}",
        SubscriptionName=f"Sub-{i}",
        TopicName="Topic-1",
        Protocol="queue",
        Endpoint="Queue-1",
        TopicOwner=777,
        BindingKey=["events.*"],
        FilterTags=[],
        NotifyStrategy="BACKOFF_RETRY",
        **extra,
    )


def runner(g, call):
    return CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def native(g, kind, rows, parent=None, name="Topic-1"):
    spec = SPECS[kind]
    params = dict(TopicName=name, QueryType="topic") if parent else None
    return runner(g, lambda *a, **kw: {spec.result: rows, "TotalCount": len(rows)}).native(
        spec, REGION, params, parent, "HAS_SUBSCRIPTION"
    )


def test_queue_topic_subscriptions_and_dead_letter_configuration():
    g = Graph()
    qid = native(
        g,
        "tdmq.cmqqueue",
        [
            queue(
                DeadLetterPolicy=dict(DeadLetterQueue="Queue-2", Policy=0, MaxReceiveCount=3),
                TransactionPolicy=dict(FirstQueryInterval=10, MaxQueryCount=5),
            ),
            queue(2),
        ],
    )[0][0]
    tid = native(g, "tdmq.cmqtopic", [topic()])[0][0]
    sid = native(g, "tdmq.cmqsubscription", [subscription()], tid)[0][0]
    link_destinations(g)
    assert g.nodes[sid]["resource_id"] == "cmqt-1/subsc-1"
    assert g.nodes[sid]["properties"]["owner_appid"] == 777
    assert all(n["account"] == "100" for n in g.nodes.values())
    assert g.nodes[qid]["properties"]["VisibilityTimeout"] == 30
    assert json.loads(g.nodes[qid]["properties"]["DeadLetterPolicy"])["MaxReceiveCount"] == 3
    assert json.loads(g.nodes[sid]["properties"]["BindingKey"]) == ["events.*"]
    assert {e["relationship"] for e in g.edges.values()} == {
        "HAS_SUBSCRIPTION",
        "CONFIGURED_QUEUE_DESTINATION",
        "HAS_DEADLETTER_QUEUE",
    }
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


def test_http_destination_excludes_credentials_and_untrusted_nested_metadata():
    g = Graph()
    tid = native(g, "tdmq.cmqtopic", [topic()])[0][0]
    raw = {
        **subscription(),
        "Protocol": "HTTP",
        "Endpoint": "https://user:password@hooks.example.test:8443/private-token?secret=value#token",
        "Unexpected": dict(VpcId="vpc-fabricated", Password="hidden"),
    }
    sid = native(g, "tdmq.cmqsubscription", [raw], tid)[0][0]
    props = g.nodes[sid]["properties"]
    assert props["endpoint_origin"] == "https://hooks.example.test:8443"
    assert props["endpoint_redacted"] is True
    rendered = json.dumps(g.nodes)
    for secret in ("password", "private-token", "secret=value", "hidden", "vpc-fabricated"):
        assert secret not in rendered
    assert {e["relationship"] for e in g.edges.values()} == {
        "HAS_SUBSCRIPTION",
        "CONFIGURED_HTTP_DESTINATION",
    }


@pytest.mark.parametrize("kind", ["tdmq.cmqqueue", "tdmq.cmqtopic", "tdmq.cmqsubscription"])
def test_fifty_item_pagination_with_required_totals(kind):
    g, calls = Graph(), []
    parent = (
        g.add("100", REGION, "tdmq.cmqtopic", "cmqt-1", "Topic-1")
        if kind.endswith("subscription")
        else None
    )
    row = subscription if parent else queue if kind.endswith("queue") else topic
    spec = SPECS[kind]

    def call(*args, **params):
        assert params["Limit"] == 50
        offset = params["Offset"]
        calls.append(offset)
        return {
            spec.result: [row(i) for i in range(offset, min(offset + 50, 51))],
            "TotalCount": 51,
            "RequestId": str(offset),
        }

    runner(g, call).native(
        spec, REGION, dict(TopicName="Topic-1", QueryType="topic") if parent else None, parent
    )
    assert calls == [0, 50]
    assert g.coverage[-1]["status"] == "complete" and g.coverage[-1]["count"] == 51
    assert g.coverage[-1]["request_ids"] == ["0", "50"]


@pytest.mark.parametrize(
    "row,error",
    [
        ({**subscription(), "TopicName": "Wrong"}, "CmqTopicMismatch"),
        ({**subscription(), "SubscriptionId": ""}, "InvalidCmqIdentity"),
        (
            {**subscription(), "Protocol": "HTTP", "Endpoint": "file:///etc/passwd"},
            "InvalidCmqEndpoint",
        ),
        ({**subscription(), "BindingKey": "not-a-list"}, "InvalidResponse"),
    ],
)
def test_invalid_subscription_metadata_is_partial(row, error):
    g = Graph()
    tid = native(g, "tdmq.cmqtopic", [topic()])[0][0]
    native(g, "tdmq.cmqsubscription", [row], tid)
    assert g.coverage[-1]["error"] == error


@pytest.mark.parametrize("scope", ["account", "region", "ambiguous", "missing"])
def test_queue_names_do_not_link_across_scopes_or_ambiguity(scope):
    g = Graph()
    tid = native(g, "tdmq.cmqtopic", [topic()])[0][0]
    sid = native(g, "tdmq.cmqsubscription", [subscription()], tid)[0][0]
    if scope == "account":
        g.add("200", REGION, "tdmq.cmqqueue", "cmqq-1", "Queue-1")
    if scope == "region":
        g.add("100", "ap-guangzhou", "tdmq.cmqqueue", "cmqq-1", "Queue-1")
    if scope == "ambiguous":
        g.add("100", REGION, "tdmq.cmqqueue", "cmqq-1", "Queue-1")
        g.add("100", REGION, "tdmq.cmqqueue", "cmqq-2", "Queue-1")
    link_destinations(g)
    assert g.nodes[sid]["properties"]["destination_resolution"] == "unresolved-or-ambiguous"
    assert not any(e["source"] == sid for e in g.edges.values())


def test_duplicate_and_parent_scoped_subscription_ids():
    g = Graph()
    for i in (1, 2):
        tid = native(g, "tdmq.cmqtopic", [topic(i)])[0][0]
        native(
            g,
            "tdmq.cmqsubscription",
            [{**subscription(), "TopicName": f"Topic-{i}"}],
            tid,
            f"Topic-{i}",
        )
    assert len([n for n in g.nodes.values() if n["kind"] == "tdmq.cmqsubscription"]) == 2
    tid = next(
        n["id"] for n in g.nodes.values() if n["kind"] == "tdmq.cmqtopic" and n["name"] == "Topic-1"
    )
    native(g, "tdmq.cmqsubscription", [subscription(), subscription()], tid)
    assert g.coverage[-1]["error"] == "DuplicateCmqResource"


@pytest.mark.parametrize(
    "policy,error",
    [
        (
            dict(DeadLetterQueue="Queue-2", Policy=True, MaxReceiveCount=3),
            "InvalidCmqDeadLetterPolicy",
        ),
        (
            dict(DeadLetterQueue="Queue-2", Policy=0, MaxReceiveCount=0),
            "InvalidCmqDeadLetterThreshold",
        ),
        (
            dict(DeadLetterQueue="Queue-2", Policy=1, MaxTimeToLive=1),
            "InvalidCmqDeadLetterThreshold",
        ),
    ],
)
def test_invalid_dead_letter_policies_are_partial(policy, error):
    g = Graph()
    native(g, "tdmq.cmqqueue", [queue(DeadLetterPolicy=policy)])
    assert g.coverage[-1]["error"] == error


@pytest.mark.parametrize(
    "policy,linked",
    [
        (None, True),
        ({}, False),
        (dict(DeadLetterQueue="Queue-3", Policy=0, MaxReceiveCount=1), False),
    ],
)
def test_reverse_dead_letter_sources_respect_explicit_forward_configuration(policy, linked):
    g = Graph()
    q1, q2 = [
        nid
        for nid, _ in native(
            g,
            "tdmq.cmqqueue",
            [
                queue(DeadLetterPolicy=policy),
                queue(2, DeadLetterSource=[dict(QueueId="cmqq-1", QueueName="Queue-1")]),
            ],
        )
    ]
    link_destinations(g)
    assert any(e["source"] == q1 and e["target"] == q2 for e in g.edges.values()) is linked
    assert g.nodes[q2]["properties"]["unresolved_dead_letter_sources"] == (0 if linked else 1)


def test_collection_continues_after_detail_denials_and_rejects_changed_identity():
    class Transport:
        def call(self, s, a, region=None, **p):
            if s == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if s == "cloudrc":
                return dict(Resources=[])
            if a == "DescribeCmqQueues":
                return dict(QueueList=[queue()], TotalCount=1)
            if a == "DescribeCmqTopics":
                return dict(TopicList=[topic(), topic(2)], TotalCount=2)
            if a == "DescribeCmqQueueDetail":
                return dict(QueueDescribe=queue(2), RequestId="changed")
            if a == "DescribeCmqTopicDetail":
                raise CollectionError("UnauthorizedOperation")
            if a == "DescribeCmqSubscriptionDetail":
                if p["TopicName"] == "Topic-1":
                    raise CollectionError("OperationDenied")
                assert p["QueryType"] == "topic" and p["Limit"] == 50
                return dict(
                    SubscriptionSet=[{**subscription(), "TopicName": "Topic-2"}], TotalCount=1
                )
            raise AssertionError(a)

    data = collect(
        ["test"],
        [REGION],
        services={"tdmq"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert data["status"] == "partial"
    assert len([c for c in data["coverage"] if c["status"] == "denied"]) == 3
    assert any(c.get("error") == "CmqDetailIdentityMismatch" for c in data["coverage"])
    assert any(
        n["kind"] == "tdmq.cmqsubscription" and n["resource_id"] == "cmqt-2/subsc-1"
        for n in data["nodes"]
    )


@pytest.mark.parametrize(
    "action", ["SendCmqMsg", "PublishCmqMsg", "ReceiveMessage", "ClearCmqQueue", "RewindCmqQueue"]
)
def test_message_and_mutation_apis_are_excluded(action):
    assert ("tdmq", action) not in ALLOWED_ACTIONS


@pytest.mark.parametrize("kind", ["tdmq.cmqqueue", "tdmq.cmqtopic"])
def test_detail_enrichment_requires_matching_id_and_name(kind):
    g = Graph()
    is_queue = kind.endswith("queue")
    row = queue() if is_queue else {**topic(), "SubscriptionCount": 0}
    nid = native(g, kind, [row])[0][0]
    calls = []

    def call(service, action, region=None, **params):
        calls.append((action, params))
        if action == "DescribeCmqSubscriptionDetail":
            return dict(SubscriptionSet=[], TotalCount=0)
        field = "Queue" if is_queue else "Topic"
        assert params == {field + "Name": row[field + "Name"]}
        return {
            field + "Describe": {
                **row,
                "MsgRetentionSeconds": 9000,
                "Tags": [dict(TagKey="environment", TagValue="test")],
            },
            "RequestId": "detail-request",
        }

    collect_resource(runner(g, call), nid)
    assert g.nodes[nid]["properties"]["detail_collected"] is True
    assert g.nodes[nid]["properties"]["MsgRetentionSeconds"] == 9000
    assert json.loads(g.nodes[nid]["properties"]["tags"]) == [
        dict(TagKey="environment", TagValue="test")
    ]
    assert any(c["request_ids"] == ["detail-request"] for c in g.coverage)
    assert len(calls) == (1 if is_queue else 2)


@pytest.mark.parametrize(
    "total,error", [(None, "InvalidTotal"), (True, "InvalidTotal"), (1, "IncompletePagination")]
)
def test_missing_and_inconsistent_queue_totals_are_partial(total, error):
    g = Graph()
    runner(g, lambda *a, **kw: dict(QueueList=[], TotalCount=total)).native(
        SPECS["tdmq.cmqqueue"], REGION
    )
    assert g.coverage[-1]["error"] == error


def test_subscription_count_change_is_visible():
    g = Graph()
    tid = native(g, "tdmq.cmqtopic", [topic()])[0][0]

    def call(service, action, region=None, **params):
        if action == "DescribeCmqTopicDetail":
            return dict(TopicDescribe=topic())
        return dict(SubscriptionSet=[], TotalCount=0)

    collect_resource(runner(g, call), tid)
    assert g.coverage[-1]["error"] == "CmqSubscriptionCountChanged"
