import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.eventbridge import RULES, TARGETS, collect_bus, link_targets
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph

REGION = "eu-frankfurt"
BUS = next(s for s in COLLECTORS if s.kind == "eb.bus")
SPECS = {s.kind: s for s in (BUS, RULES, TARGETS)}
KAFKA = f"qcs::ckafka:{REGION}:uin/100:ckafkaId/uin/100/ckafka-1"


def bus(i=1):
    return dict(EventBusId=f"eb-{i}", EventBusName=f"Events-{i}", Type="Custom")


def rule(i=1, bid="eb-1"):
    return dict(
        EventBusId=bid, RuleId=f"rule-{i}", RuleName=f"Rule-{i}", Enable=False, Status="Active"
    )


def target(i=1, bid="eb-1", rid="rule-1"):
    return dict(
        EventBusId=bid,
        RuleId=rid,
        TargetId=f"target-{i}",
        Type="ckafka",
        TargetDescription=dict(
            ResourceDescription=KAFKA,
            CkafkaTargetParams=dict(
                TopicName="events",
                EventDeliveryFormat="CloudEvent",
                RetryPolicy=dict(RetryInterval=60, MaxRetryAttempts=3),
            ),
        ),
    )


def runner(g, call):
    return CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def native(g, kind, rows, params=None, parent=None):
    spec = SPECS[kind]
    return runner(g, lambda *a, **kw: {spec.result: rows, "TotalCount": len(rows)}).native(
        spec, REGION, params, parent
    )


def kafka(g, owner="100", region=REGION):
    kid = g.add(owner, region, "ckafka.instance", "ckafka-1")
    tid = g.add(owner, region, "ckafka.topic", "ckafka-1/topic-1", "events")
    g.edge(kid, tid, "HAS_TOPIC", "fixture")
    return tid


def test_bus_rule_target_configuration_and_deadletter_topic_links():
    g = Graph()
    kid = kafka(g)
    bid = native(g, "eb.bus", [bus()])[0][0]
    rid = native(
        g,
        "eb.rule",
        [
            {
                **rule(),
                "EventPattern": '{"source":["test"]}',
                "DeadLetterConfig": dict(
                    DisposeMethod="DLQ",
                    CkafkaDeliveryParams=dict(ResourceDescription=KAFKA, TopicName="events"),
                ),
            }
        ],
        dict(EventBusId="eb-1"),
        bid,
    )[0][0]
    tid = native(g, "eb.target", [target()], dict(EventBusId="eb-1", RuleId="rule-1"), rid)[0][0]
    link_targets(g)
    assert g.nodes[rid]["properties"]["Enable"] is False
    assert json.loads(g.nodes[rid]["properties"]["EventPattern"]) == dict(source=["test"])
    assert (
        json.loads(g.nodes[tid]["properties"]["CkafkaTargetParams"])["RetryPolicy"][
            "MaxRetryAttempts"
        ]
        == 3
    )
    assert any(
        e["source"] == rid
        and e["target"] == kid
        and e["relationship"] == "CONFIGURED_DEADLETTER_TOPIC"
        for e in g.edges.values()
    )
    assert any(e["source"] == tid and e["target"] == kid for e in g.edges.values())
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


@pytest.mark.parametrize("kind", ["eb.bus", "eb.rule", "eb.target"])
def test_101_item_pagination_and_request_ids(kind):
    g = Graph()
    spec = SPECS[kind]
    calls = []
    row = {"eb.bus": bus, "eb.rule": rule, "eb.target": target}[kind]
    params = {} if kind == "eb.bus" else dict(EventBusId="eb-1")
    if kind == "eb.target":
        params["RuleId"] = "rule-1"

    def call(*a, **p):
        calls.append(p["Offset"])
        return {
            spec.result: [row(i) for i in range(p["Offset"], min(101, p["Offset"] + 100))],
            "TotalCount": 101,
            "RequestId": str(p["Offset"]),
        }

    runner(g, call).native(spec, REGION, params)
    assert calls == [0, 100] and g.coverage[-1]["count"] == 101
    assert g.coverage[-1]["request_ids"] == ["0", "100"]


@pytest.mark.parametrize(
    "kind,row,params,error",
    [
        ("eb.rule", rule(bid="eb-other"), dict(EventBusId="eb-1"), "EventBridgeBusMismatch"),
        (
            "eb.target",
            target(rid="rule-other"),
            dict(EventBusId="eb-1", RuleId="rule-1"),
            "EventBridgeRuleMismatch",
        ),
        ("eb.rule", {**rule(), "Enable": 1}, dict(EventBusId="eb-1"), "InvalidEventBridgeEnable"),
        (
            "eb.rule",
            {**rule(), "EventPattern": "[]"},
            dict(EventBusId="eb-1"),
            "InvalidEventBridgePattern",
        ),
        (
            "eb.rule",
            {**rule(), "DeadLetterConfig": dict(DisposeMethod="unexpected")},
            dict(EventBusId="eb-1"),
            "InvalidEventBridgeDisposeMethod",
        ),
        (
            "eb.rule",
            {**rule(), "DeadLetterConfig": dict(DisposeMethod="DLQ", CkafkaDeliveryParams={})},
            dict(EventBusId="eb-1"),
            "InvalidEventBridgeDeadLetter",
        ),
    ],
)
def test_invalid_metadata_is_partial(kind, row, params, error):
    g = Graph()
    native(g, kind, [row], params)
    assert g.coverage[-1]["error"] == error


def test_ids_are_scoped_and_duplicates_rejected():
    g = Graph()
    for b in ("eb-1", "eb-2"):
        native(g, "eb.rule", [rule(bid=b)], dict(EventBusId=b))
        native(g, "eb.target", [target(bid=b)], dict(EventBusId=b, RuleId="rule-1"))
    assert len(g.nodes) == 4
    native(g, "eb.rule", [rule(), rule()], dict(EventBusId="eb-1"))
    assert g.coverage[-1]["error"] == "DuplicateEventBridgeResource"


@pytest.mark.parametrize(
    "owner,region,resource,expected",
    [
        ("200", REGION, KAFKA, "unresolved-or-ambiguous"),
        ("100", "ap-guangzhou", KAFKA, "unresolved-or-ambiguous"),
        ("100", REGION, KAFKA.replace("ckafkaId/uin/100", "ckafkaId/uin/200"), "conflicting-owner"),
        ("100", REGION, KAFKA.replace("uin/100:", "appid/100:"), "unsupported-resource-format"),
    ],
)
def test_kafka_ownership_region_and_appid_controls(owner, region, resource, expected):
    g = Graph()
    kafka(g, owner, region)
    raw = target()
    raw["TargetDescription"]["ResourceDescription"] = resource
    tid = native(g, "eb.target", [raw], dict(EventBusId="eb-1", RuleId="rule-1"))[0][0]
    link_targets(g)
    assert g.nodes[tid]["properties"]["target_resolution"] == expected
    assert not any(e["source"] == tid for e in g.edges.values())


@pytest.mark.parametrize(
    "qualifier,kind",
    [("7", "scf.version"), ("$LATEST", "scf.version"), ("production", "scf.alias")],
)
def test_scf_targets_preserve_namespace_and_qualifier(qualifier, kind):
    g = Graph()
    fn = g.add("100", REGION, "scf.function", "fn-id", "worker", raw=dict(Namespace="jobs"))
    raw = {
        **target(),
        "Type": "scf",
        "TargetDescription": dict(
            ResourceDescription=f"qcs::scf:{REGION}:uin/100:namespace/jobs/function/worker/{qualifier}"
        ),
    }
    tid = native(g, "eb.target", [raw], dict(EventBusId="eb-1", RuleId="rule-1"))[0][0]
    link_targets(g)
    q = next(n for n in g.nodes.values() if n["kind"] == kind)
    assert q["resource_id"] == "fn-id/" + qualifier and q["status"] == "reference"
    assert any(e["source"] == fn and e["target"] == q["id"] for e in g.edges.values())
    assert any(e["source"] == tid and e["target"] == q["id"] for e in g.edges.values())


@pytest.mark.parametrize(
    "service,path,owner,kind,rid",
    [
        ("cls", "topic/topic-1", "uin/200", "cls.topic", "topic-1"),
        ("es", "instance/es-1", "appid/999/uin/200", "es.instance", "es-1"),
    ],
)
def test_explicit_foreign_account_references_preserve_owner(service, path, owner, kind, rid):
    g = Graph()
    raw = {
        **target(),
        "Type": service,
        "TargetDescription": dict(
            ResourceDescription=f"qcs::{service}:ap-guangzhou:{owner}:{path}"
        ),
    }
    native(g, "eb.target", [raw], dict(EventBusId="eb-1", RuleId="rule-1"))
    link_targets(g)
    n = next(n for n in g.nodes.values() if n["kind"] == kind)
    assert n["account"] == "200" and n["region"] == "ap-guangzhou" and n["resource_id"] == rid


def test_drop_mode_and_unknown_nested_fields_do_not_create_links():
    g = Graph()
    kafka(g)
    raw = {
        **rule(),
        "DeadLetterConfig": dict(
            DisposeMethod="DROP",
            CkafkaDeliveryParams=dict(ResourceDescription=KAFKA, TopicName="events"),
        ),
        "Unexpected": dict(VpcId="vpc-wrong", Password="private"),
    }
    rid = native(g, "eb.rule", [raw], dict(EventBusId="eb-1"))[0][0]
    link_targets(g)
    assert not any(e["source"] == rid for e in g.edges.values())
    assert "private" not in json.dumps(g.nodes) and "vpc-wrong" not in json.dumps(g.nodes)


def test_whole_collection_survives_detail_denials():
    from tencent_cloud_cartography.transport import CollectionError

    class Transport:
        def call(self, s, a, region=None, **p):
            if s == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if s == "cloudrc":
                return dict(Resources=[])
            if a == "ListEventBuses":
                return dict(EventBuses=[bus()], TotalCount=1)
            if a == "GetEventBus":
                raise CollectionError("UnauthorizedOperation")
            if a == "ListRules":
                return dict(Rules=[rule(), rule(2)], TotalCount=2)
            if a == "GetRule":
                raise CollectionError("OperationDenied")
            if a == "ListTargets":
                return dict(Targets=[target(rid=p["RuleId"])], TotalCount=1)
            raise AssertionError(a)

    data = collect(
        ["test"],
        [REGION],
        services={"eb"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert len([n for n in data["nodes"] if n["kind"] == "eb.target"]) == 2
    assert len([c for c in data["coverage"] if c["status"] == "denied"]) == 3
    assert data["status"] == "partial"


def test_details_and_log_references_keep_request_identity():
    g = Graph()
    bid = native(g, "eb.bus", [bus()])[0][0]

    def call(s, a, region=None, **params):
        if a == "GetEventBus":
            return {
                **bus(),
                "ClsTopicId": "topic-logs",
                "ClsLogsetId": "logset-1",
                "RequestId": "bus",
            }
        if a == "ListRules":
            return dict(Rules=[rule()], TotalCount=1)
        if a == "GetRule":
            return {**rule(), "EventPattern": '{"source":["audit"]}', "RequestId": "rule"}
        if a == "ListTargets":
            return dict(Targets=[], TotalCount=0)
        raise AssertionError(a)

    collect_bus(runner(g, call), bid)
    assert g.nodes[bid]["properties"]["detail_collected"] is True
    assert {e["relationship"] for e in g.edges.values()} == {
        "CONFIGURED_LOG_TOPIC",
        "CONFIGURED_LOGSET",
        "HAS_RULE",
    }
    assert any(c["request_ids"] == ["rule"] for c in g.coverage)


@pytest.mark.parametrize(
    "action",
    ["ListConnections", "SearchLog", "PutEvents", "PublishEvent", "CheckRule", "GetTransformation"],
)
def test_secret_payload_and_event_operations_are_excluded(action):
    assert ("eb", action) not in ALLOWED_ACTIONS


@pytest.mark.parametrize("bad", ["bus", "rule", "total"])
def test_detail_identity_and_missing_total_fail_visibly(bad):
    g = Graph()
    bid = native(g, "eb.bus", [bus()])[0][0]

    def call(s, a, region=None, **params):
        if a == "GetEventBus":
            return bus(2) if bad == "bus" else bus()
        if a == "ListRules":
            return dict(Rules=[]) if bad == "total" else dict(Rules=[rule()], TotalCount=1)
        if a == "GetRule":
            return rule(bid="eb-other") if bad == "rule" else rule()
        if a == "ListTargets":
            return dict(Targets=[], TotalCount=0)
        raise AssertionError(a)

    collect_bus(runner(g, call), bid)
    expected = {
        "bus": "EventBridgeBusMismatch",
        "rule": "EventBridgeRuleMismatch",
        "total": "InvalidTotal",
    }[bad]
    assert any(c.get("error") == expected for c in g.coverage)


@pytest.mark.parametrize("pattern", ['{"value":NaN}', '{"incomplete":'])
def test_invalid_json_patterns_are_reported_as_configuration_errors(pattern):
    g = Graph()
    native(g, "eb.rule", [{**rule(), "EventPattern": pattern}], dict(EventBusId="eb-1"))
    assert g.coverage[-1]["error"] == "InvalidEventBridgePattern"
