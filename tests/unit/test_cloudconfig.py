import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.cloudconfig import (
    collect_rule_details,
    collect_settings,
    link_delivery,
)
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

SPEC = next(s for s in COLLECTORS if s.kind == "config.rule")
QCS = "qcs::cos:eu-frankfurt:uid/12345:prefix//12345/audit/config/*"


def rule(i=1):
    return dict(
        ConfigRuleId=f"cr-{i}",
        RuleName=f"Rule {i}",
        Identifier="cvm-instance-check",
        IdentifierType="SYSTEM",
        Status="NO_ACTIVE",
        RiskLevel=3,
        RuleOwnerId=100,
        ResourceType=["QCS::CVM::Instance"],
        RegionsScope=["eu-frankfurt"],
        TagsScope=[dict(TagKey="team", TagValue="security")],
        ExcludeResourceIdsScope=["ins-excluded"],
        InputParameter=[dict(ParameterKey="cpu", Type="Require", Value="2")],
        SourceCondition=[
            dict(
                EmptyAs="NOT_APPLICABLE",
                SelectPath="$.Cpu",
                Operator="GreaterOrEquals",
                Required=False,
                DesiredValue="2",
            )
        ],
        TriggerType=[
            dict(MessageType="ScheduledNotification", MaximumExecutionFrequency="TwentyFour_Hours")
        ],
        ComplianceResult="NON_COMPLIANT",
        ConfigRuleInvokedTime="2026-10-13 12:00:00",
    )


def recorder():
    return dict(
        Status=1,
        Items=[
            dict(Product="CVM", ResourceType="QCS::CVM::Instance", ResourceTypeName="CVM instance")
        ],
        TriggerCount=1,
    )


def delivery():
    return dict(
        Status=1,
        DeliverType="COS",
        TargetArn=QCS,
        DeliverPrefix="config/",
        DeliverName="Audit export",
        DeliverContentType=3,
    )


def run(raw=None, rec=None, deliver=None, details=None):
    graph, calls = Graph(), []

    def call(service, action, **kw):
        calls.append((action, kw))
        if action == "ListConfigRules":
            values = [rule()] if raw is None else raw
            return dict(Items=values, Total=len(values), RequestId="list")
        value = {
            "DescribeConfigRecorder": recorder() if rec is None else rec,
            "DescribeConfigDeliver": delivery() if deliver is None else deliver,
            "DescribeConfigRule": dict(ConfigRule=rule()) if details is None else details,
        }[action]
        if isinstance(value, Exception):
            raise value
        return {**value, "RequestId": action}

    runner = CollectorRunner(
        graph, SimpleNamespace(call=call), "100", ["eu-frankfurt"], lambda _: None
    )
    collect_settings(runner)
    collect_rule_details(runner, runner.native(SPEC, "global"))
    return graph, calls


def test_config_scopes_and_rules_preserve_configuration_and_official_icons():
    graph, calls = run()
    nodes = list(graph.nodes.values())
    assert {n["kind"] for n in nodes} == {
        "config.rule",
        "config.recorder",
        "config.delivery",
        "config.resourcetype",
    }
    assert all(n["region"] == "global" for n in nodes)
    props = next(n["properties"] for n in nodes if n["kind"] == "config.rule")
    assert props["state"] == "NO_ACTIVE" and props["RiskLevel"] == 3
    assert not props["compliance_independently_verified"]
    assert props["ComplianceResult"] == "NON_COMPLIANT"
    assert json.loads(props["RegionsScope"]) == ["eu-frankfurt"]
    assert json.loads(props["ExcludeResourceIdsScope"]) == ["ins-excluded"]
    assert json.loads(props["SourceCondition"])[0]["Required"] is False
    assert json.loads(props["InputParameter"])[0]["Value"] == "2"
    assert json.loads(props["TriggerType"])[0]["MaximumExecutionFrequency"] == "TwentyFour_Hours"
    assert {e["relationship"] for e in graph.edges.values()} == {
        "APPLIES_TO_RESOURCE_TYPE",
        "CONFIGURED_RECORDING_TYPE",
    }
    assert all(icon_for(n["kind"]) == "en-cloudconfig.svg" for n in nodes)
    assert all(kw["region"] == "global" for _, kw in calls)
    assert all(c["status"] == "complete" for c in graph.coverage)


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"ConfigRuleId": ""}, "InvalidConfigRuleId"),
        ({"ConfigRuleId": 2}, "InvalidConfigRuleId"),
        ({"RiskLevel": True}, "InvalidConfigNumber"),
        ({"RuleOwnerId": -1}, "InvalidConfigNumber"),
        ({"ResourceType": ["cvm.instance"]}, "InvalidConfigResourceType"),
        (
            {"ResourceType": ["QCS::CVM::Instance", "qcs::cvm::instance"]},
            "DuplicateConfigResourceType",
        ),
        ({"RegionsScope": {}}, "InvalidConfigArray"),
        ({"TagsScope": [{"TagKey": {}}]}, "InvalidConfigField"),
        ({"SourceCondition": [{"Required": "false"}]}, "InvalidConfigField"),
        ({"InputParameter": [{"Value": {"Password": "omit"}}]}, "InvalidConfigField"),
    ],
)
def test_invalid_rule_does_not_create_native_identity(patch, error):
    graph, _ = run(raw=[{**rule(), **patch}])
    assert graph.coverage[-1]["error"] == error
    assert not any(n["kind"] == "config.rule" for n in graph.nodes.values())


def test_changed_scope_replaces_only_rule_edges_and_keeps_owner_bound():
    changed = {**rule(), "ResourceType": ["QCS::COS::Bucket"], "Status": "ACTIVE"}
    graph, _ = run(details=dict(ConfigRule=changed))
    node = next(n for n in graph.nodes.values() if n["kind"] == "config.rule")
    links = [e for e in graph.edges.values() if e["source"] == node["id"]]
    assert len(links) == 1 and graph.nodes[links[0]["target"]]["resource_id"] == "qcs::cos::bucket"
    assert json.loads(node["properties"]["changed_since_list"]) == ["ResourceType", "Status"]
    assert any(
        e["relationship"] == "CONFIGURED_RECORDING_TYPE"
        and graph.nodes[e["target"]]["resource_id"] == "qcs::cvm::instance"
        for e in graph.edges.values()
    )


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"ConfigRuleId": "cr-other"}, "ConfigRuleIdentityMismatch"),
        ({"RuleOwnerId": 200}, "ConfigRuleOwnerChanged"),
        ({"SourceCondition": [{"Required": 4}]}, "InvalidConfigField"),
    ],
)
def test_invalid_detail_preserves_list_definition(patch, error):
    graph, _ = run(details=dict(ConfigRule={**rule(), **patch}))
    node = next(n for n in graph.nodes.values() if n["kind"] == "config.rule")
    assert not node["properties"].get("detail_collected")
    assert graph.coverage[-1]["error"] == error
    assert graph.coverage[-1]["request_ids"] == ["DescribeConfigRule"]


def test_null_recorder_scope_is_unknown_not_empty_and_does_not_stop_rules():
    graph, _ = run(rec=dict(Status=0, Items=None))
    node = next(n for n in graph.nodes.values() if n["kind"] == "config.recorder")
    assert node["properties"]["Status"] == 0 and not node["properties"]["resource_types_known"]
    assert graph.coverage[0]["error"] == "ConfigRecorderScopeUnavailable"
    assert graph.coverage[0]["count"] == 1 and graph.coverage[-1]["status"] == "complete"


@pytest.mark.parametrize(
    "response,error",
    [
        (dict(Status=True, Items=[]), "InvalidConfigStatus"),
        (dict(Status=1, Items={}), "InvalidConfigArray"),
        (dict(Status=1, Items=[{}]), "InvalidConfigResourceType"),
        (dict(Status=1, Items=recorder()["Items"] * 2), "DuplicateConfigResourceType"),
    ],
)
def test_invalid_recorder(response, error):
    graph, _ = run(rec=response)
    assert graph.coverage[0]["error"] == error
    assert not any(n["kind"] == "config.recorder" for n in graph.nodes.values())


def test_known_absent_delivery_and_denied_recorder_still_collect_rules():
    graph, _ = run(
        rec=CollectionError("UnauthorizedOperation"),
        deliver=CollectionError("ResourceNotFound.DeliverIsNotExist"),
    )
    assert [c["status"] for c in graph.coverage] == ["denied", "empty", "complete", "complete"]
    assert not any(
        n["kind"] in {"config.recorder", "config.delivery"} for n in graph.nodes.values()
    )


@pytest.mark.parametrize(
    "response,error",
    [
        (dict(Status=2), "InvalidConfigStatus"),
        ({**delivery(), "DeliverContentType": True}, "InvalidConfigDeliveryContent"),
        ({**delivery(), "TargetArn": None}, "ConfigDeliveryTargetUnavailable"),
    ],
)
def test_invalid_delivery_is_not_complete(response, error):
    graph, _ = run(deliver=response)
    assert graph.coverage[1]["error"] == error
    assert graph.coverage[-1]["status"] == "complete"


@pytest.mark.parametrize(
    "qcs",
    [
        QCS,
        "qcs::cos:eu-frankfurt:uid/12345:prefix/audit",
        "qcs::cos:eu-frankfurt:uid/12345:audit-12345/config/*",
    ],
)
def test_cos_delivery_uses_collected_bucket_owner_never_appid_as_uin(qcs):
    graph, _ = run(deliver={**delivery(), "TargetArn": qcs, "Status": 0})
    target = graph.add("200", "eu-frankfurt", "cos.bucket", "audit-12345")
    graph.add("100", "ap-guangzhou", "cos.bucket", "audit-12345")
    link_delivery(graph)
    links = [e for e in graph.edges.values() if e["relationship"] == "CONFIGURED_LOG_DESTINATION"]
    assert len(links) == 1 and links[0]["target"] == target
    props = graph.nodes[links[0]["source"]]["properties"]
    assert props["Status"] == 0 and not props["delivery_verified"]
    assert not any(n["account"] == "12345" for n in graph.nodes.values())


@pytest.mark.parametrize(
    "qcs",
    [
        "qcs::cos:eu-frankfurt:12345:prefix/audit",
        "qcs::cos:eu-frankfurt:uid/12345:prefix//99999/audit",
        "qcs::cos:eu-frankfurt:uid/12345:audit-99999/*",
        "qcs::cos:eu-frankfurt:uid/12345:prefix/*",
    ],
)
def test_ambiguous_or_conflicting_cos_identifiers_do_not_link(qcs):
    graph, _ = run(deliver={**delivery(), "TargetArn": qcs})
    graph.add("100", "eu-frankfurt", "cos.bucket", "audit-12345")
    link_delivery(graph)
    assert not any(e["relationship"] == "CONFIGURED_LOG_DESTINATION" for e in graph.edges.values())


def test_cls_explicit_cross_account_and_region_reference_and_type_conflict():
    graph, _ = run(
        deliver={
            **delivery(),
            "DeliverType": "CLS",
            "TargetArn": "qcs::cls:ap-guangzhou:uin/200:topic/topic-1",
        }
    )
    link_delivery(graph)
    node = next(n for n in graph.nodes.values() if n["kind"] == "cls.topic")
    assert (node["account"], node["region"], node["status"]) == ("200", "ap-guangzhou", "reference")
    graph, _ = run(deliver={**delivery(), "DeliverType": "CLS"})
    link_delivery(graph)
    assert not any(e["relationship"] == "CONFIGURED_LOG_DESTINATION" for e in graph.edges.values())


def test_payloads_are_selected_and_no_snapshot_or_mutation_api_is_allowed():
    raw = {
        **rule(),
        "Annotation": {"Configuration": "omit-password"},
        "Unexpected": {"VpcId": "vpc-wrong"},
    }
    raw["InputParameter"][0]["Password"] = "omit-password"
    graph, _ = run(raw=[raw], details=dict(ConfigRule=raw))
    assert "omit-password" not in graph.dump() and "vpc-wrong" not in graph.dump()
    assert {a for s, a in ALLOWED_ACTIONS if s == "config"} == {
        "ListConfigRules",
        "DescribeConfigRule",
        "DescribeConfigRecorder",
        "DescribeConfigDeliver",
        "ListAggregators",
        "DescribeAggregator",
        "DescribeAggregateConfigDeliver",
    }


def test_pagination_partial_detail_denial_and_multi_region_single_account_scope():
    calls = []

    class Transport:
        def __init__(self, profile):
            self.account = profile

        def call(self, service, action, region=None, **kw):
            calls.append((self.account, action, region, kw))
            if service == "sts":
                return dict(AccountId=self.account, PrincipalId=self.account, Arn=self.account)
            if service == "cloudrc":
                return dict(Resources=[])
            assert region == "global"
            if action == "DescribeConfigRecorder":
                return recorder()
            if action == "DescribeConfigDeliver":
                raise CollectionError("ResourceNotFound.DeliverIsNotExist")
            if action == "ListAggregators":
                return dict(Items=[], Total=0)
            if action == "ListConfigRules":
                assert set(kw) == {"Offset", "Limit"} and kw["Limit"] == 100
                data = [{**rule(i), "RuleOwnerId": int(self.account)} for i in range(101)]
                return dict(Items=data[kw["Offset"] : kw["Offset"] + 100], Total=101)
            if action == "DescribeConfigRule":
                if kw["RuleId"] == "cr-0":
                    raise CollectionError("UnauthorizedOperation")
                return dict(
                    ConfigRule={**rule(int(kw["RuleId"][3:])), "RuleOwnerId": int(self.account)}
                )
            pytest.fail(action)

    data = collect(
        ["100", "200"],
        ["eu-frankfurt", "ap-guangzhou"],
        services=["config"],
        transport_factory=Transport,
        progress=lambda _: None,
    )
    assert len([n for n in data["nodes"] if n["kind"] == "config.rule"]) == 202
    assert all(n["region"] == "global" for n in data["nodes"])
    assert sum(a == "DescribeConfigRecorder" for _, a, _, _ in calls) == 2
    assert [p["Offset"] for _, a, _, p in calls if a == "ListConfigRules"] == [0, 100, 0, 100]
    assert sum(c["status"] == "denied" for c in data["coverage"]) == 2


@pytest.mark.parametrize("total", [None, True, -1, "1"])
def test_required_rule_total_is_validated(total):
    graph = Graph()
    runner = CollectorRunner(
        graph,
        SimpleNamespace(call=lambda *a, **kw: dict(Items=[], Total=total)),
        "100",
        [],
        lambda _: None,
    )
    runner.native(SPEC, "global")
    assert graph.coverage[0]["error"] == "InvalidTotal" and not graph.nodes


def test_duplicate_rule_preserves_first_identity_and_exact_partial_count():
    graph, _ = run(raw=[rule(), rule()])
    record = next(c for c in graph.coverage if c["action"] == "ListConfigRules")
    assert record["error"] == "DuplicateConfigRule" and record["count"] == 1
    assert len([n for n in graph.nodes.values() if n["kind"] == "config.rule"]) == 1


def test_missing_and_ambiguous_bucket_inventory_never_fabricates_destination():
    graph, _ = run()
    link_delivery(graph)
    channel = next(n for n in graph.nodes.values() if n["kind"] == "config.delivery")
    assert channel["properties"]["destination_resolution"] == "unresolved"
    graph.add("100", "eu-frankfurt", "cos.bucket", "audit-12345")
    graph.add("200", "eu-frankfurt", "cos.bucket", "audit-12345")
    link_delivery(graph)
    assert channel["properties"]["destination_resolution"] == "ambiguous"
    assert not any(e["relationship"] == "CONFIGURED_LOG_DESTINATION" for e in graph.edges.values())


def test_disabled_delivery_without_target_is_not_reported_as_bad_qcs():
    graph, _ = run(deliver=dict(Status=0, DeliverType="COS", TargetArn=None))
    link_delivery(graph)
    node = next(n for n in graph.nodes.values() if n["kind"] == "config.delivery")
    assert node["properties"]["destination_resolution"] == "not-configured"
    assert graph.coverage[1]["status"] == "complete"
